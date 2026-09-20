//go:build integration

// Package integration validates gosh end-to-end against a genuine sshd +
// mosh-server. By default the rig is a container this package builds and
// starts (testcontainers-go), which is what `make integration-test` runs and
// needs a Docker daemon; setting GOSH_IT_SSH_PORT instead points the suite at
// an sshd the caller started, which is how the macOS and Windows CI jobs
// reach a mosh-server without Docker. See rig.go.
package integration

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/gosh/internal/client"
)

// TestMain releases the rig once every test has finished with it.
func TestMain(m *testing.M) {
	code := m.Run()
	if rigVal != nil && rigVal.close != nil {
		rigVal.close()
	}
	os.Exit(code)
}

// syncBuffer is a concurrency-safe output sink with substring waiting.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) waitFor(t *testing.T, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), substr) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in session output; got:\n%s", substr, b.String())
}

// TestSessionEndToEnd drives the full library path: SSH bootstrap, UDP
// session, remote command execution, and the shutdown handshake on `exit`.
func TestSessionEndToEnd(t *testing.T) {
	r := startRig(t)
	addr, res := bootstrapSession(t, r, "60001")

	inR, inW := io.Pipe()
	var out syncBuffer

	session, err := client.New(client.Config{
		Addr:          addr,
		Key:           res.Key,
		Input:         inR,
		Output:        &out,
		Size:          func() (int, int) { return 120, 40 },
		DisableEscape: true,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	runDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() { runDone <- session.Run(ctx) }()

	// The shell prompt proves the first server frame arrived and decrypted.
	out.waitFor(t, "$", 30*time.Second)

	// Type a command; its output proves the keystroke path (client->server)
	// and the diff path (server->client) both work.
	if _, err := inW.Write([]byte("echo gosh-roundtrip-$((6*7))\r")); err != nil {
		t.Fatal(err)
	}
	out.waitFor(t, "gosh-roundtrip-42", 30*time.Second)

	// `exit` ends the login shell; mosh-server initiates shutdown and the
	// client must complete the handshake and return without error.
	if _, err := inW.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("session.Run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("session did not shut down after exit; output:\n%s", out.String())
	}
}

// TestCLIEndToEnd exercises the built gosh binary in `connect` mode against
// the containerised mosh-server: the same UDP protocol path a user gets,
// minus only the local PTY.
func TestCLIEndToEnd(t *testing.T) {
	r := startRig(t)
	addr, res := bootstrapSession(t, r, "60002")

	bin := buildGosh(t)
	host, port, ok := strings.Cut(addr, ":")
	if !ok {
		t.Fatalf("bad addr %q", addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "connect", host, port)
	cmd.Env = append(os.Environ(), "MOSH_KEY="+res.Key.String())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	out.waitFor(t, "$", 30*time.Second)
	if _, err := stdin.Write([]byte("echo cli-roundtrip-$((7*8))\r")); err != nil {
		t.Fatal(err)
	}
	out.waitFor(t, "cli-roundtrip-56", 30*time.Second)
	if _, err := stdin.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("gosh exited with error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[gosh is exiting.]") {
		t.Fatalf("missing exit banner; output:\n%s", out.String())
	}
}

func buildGosh(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gosh")
	if runtime.GOOS == "windows" {
		// CreateProcess needs the extension; `go build -o` writes exactly the
		// name it is given.
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "github.com/goodtune/gosh/cmd/gosh")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// TestClipboardEndToEnd pins the OSC 52 clipboard path through a real
// mosh-server: a clipboard write reaches the client's terminal untouched,
// while the read query that mosh-server happily relays does not — answering
// it would put the local clipboard on the wire back to the remote host.
func TestClipboardEndToEnd(t *testing.T) {
	r := startRig(t)
	addr, res := bootstrapSession(t, r, "60003")

	inR, inW := io.Pipe()
	var out syncBuffer

	session, err := client.New(client.Config{
		Addr:          addr,
		Key:           res.Key,
		Input:         inR,
		Output:        &out,
		Size:          func() (int, int) { return 120, 40 },
		DisableEscape: true,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- session.Run(ctx) }()

	out.waitFor(t, "$", 30*time.Second)

	// Typed as backslash escapes, so the shell's echo of the command line
	// cannot be mistaken for the sequences themselves.
	const (
		write = "\x1b]52;c;Z29zaC1jbGlwYm9hcmQ=\x07" // base64 of "gosh-clipboard"
		query = "\x1b]52;c;?\x07"
	)
	// One step at a time, each waiting on a marker the server can only print
	// after the sequence: the clipboard is *state* in mosh's terminal, so a
	// query sent before the write has been diffed to the client would
	// overwrite it and the write would never reach the wire. The markers are
	// computed by the shell so the echo of the command line cannot satisfy
	// the wait.
	for _, step := range []struct{ cmd, marker string }{
		{`printf '\033]52;c;Z29zaC1jbGlwYm9hcmQ=\007'; echo clip-write-$((6*7))`, "clip-write-42"},
		{`printf '\033]52;c;?\007'; echo clip-query-$((7*8))`, "clip-query-56"},
	} {
		if _, err := inW.Write([]byte(step.cmd + "\r")); err != nil {
			t.Fatal(err)
		}
		out.waitFor(t, step.marker, 30*time.Second)
	}

	if !strings.Contains(out.String(), write) {
		t.Errorf("clipboard write did not reach the terminal; output:\n%q", out.String())
	}
	if strings.Contains(out.String(), query) {
		t.Errorf("clipboard read query was forwarded to the terminal; output:\n%q", out.String())
	}

	if _, err := inW.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("session.Run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("session did not shut down after exit; output:\n%s", out.String())
	}
}
