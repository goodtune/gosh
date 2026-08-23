//go:build integration

// Package integration validates gosh end-to-end against a genuine sshd +
// mosh-server running in a container (testcontainers-go). Run via
// `make integration-test`; requires a Docker daemon.
package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	"github.com/goodtune/gosh/internal/bootstrap"
	"github.com/goodtune/gosh/internal/client"
)

const (
	sshUser     = "gosh"
	sshPassword = "gosh-integration"
)

// rig is the shared container: one sshd, multiple mosh-server sessions on
// distinct fixed UDP ports.
type rig struct {
	container testcontainers.Container
	sshPort   int
	udpPorts  map[string]int // container port ("60001") -> mapped host port
}

var (
	rigOnce sync.Once
	rigVal  *rig
	rigErr  error
)

func startRig(t *testing.T) *rig {
	t.Helper()
	rigOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		req := testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context: "testdata",
			},
			ExposedPorts: []string{"22/tcp", "60001/udp", "60002/udp", "60003/udp"},
			WaitingFor:   wait.ForListeningPort("22/tcp").WithStartupTimeout(2 * time.Minute),
		}
		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			rigErr = err
			return
		}
		r := &rig{container: container, udpPorts: map[string]int{}}
		sshMapped, err := container.MappedPort(ctx, "22/tcp")
		if err != nil {
			rigErr = err
			return
		}
		r.sshPort = int(sshMapped.Num())
		for _, p := range []string{"60001", "60002", "60003"} {
			mapped, err := container.MappedPort(ctx, p+"/udp")
			if err != nil {
				rigErr = err
				return
			}
			r.udpPorts[p] = int(mapped.Num())
		}
		rigVal = r
	})
	if rigErr != nil {
		t.Fatalf("start container: %v", rigErr)
	}
	return rigVal
}

// bootstrapSession launches mosh-server in the container on the given fixed
// container-side UDP port and returns the host-side UDP address plus key.
func bootstrapSession(t *testing.T, r *rig, containerPort string) (addr string, res *bootstrap.Result) {
	t.Helper()
	res, err := bootstrap.Run(bootstrap.Options{
		User:            sshUser,
		Host:            "127.0.0.1",
		SSHPort:         r.sshPort,
		UDPPort:         containerPort,
		Term:            "xterm-256color",
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if res.Port != atoi(t, containerPort) {
		t.Fatalf("mosh-server bound port %d, requested %s", res.Port, containerPort)
	}
	// The port mosh-server printed is container-internal; dial the mapping.
	return fmt.Sprintf("127.0.0.1:%d", r.udpPorts[containerPort]), res
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
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
