//go:build !windows

package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sockDir returns a temp dir whose path is short enough to hold a Unix
// socket. t.TempDir() bakes the test's own name and a random suffix into the
// path, and on darwin roots that at /var/folders/<32 chars>/T — together
// they overrun sockaddr_un.sun_path's 104 bytes and every bind fails with
// EINVAL. /tmp is POSIX, and short on both platforms.
func sockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gosh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// serveKeyring serves an in-memory ssh-agent (one fresh Ed25519 key) on a
// Unix socket at path, returning the key's public half.
func serveKeyring(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn) //nolint:errcheck
		}
	}()
	return pub
}

// TestAgentAuthAggregatesDotvaultSocket proves a dotvault-style agent socket
// at the default location is discovered and its identities offered, alongside
// the SSH_AUTH_SOCK agent's.
func TestAgentAuthAggregatesDotvaultSocket(t *testing.T) {
	rt := sockDir(t)
	if err := os.MkdirAll(filepath.Join(rt, "dotvault"), 0o700); err != nil {
		t.Fatal(err)
	}
	dotvaultPub := serveKeyring(t, filepath.Join(rt, "dotvault", "agent.sock"))

	authSock := filepath.Join(sockDir(t), "ssh-agent.sock")
	envPub := serveKeyring(t, authSock)

	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("SSH_AUTH_SOCK", authSock)

	callback := agentSigners(DotvaultAuto)
	if callback == nil {
		t.Fatal("agentSigners returned nil with two live agents")
	}
	signers, err := callback()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 {
		t.Fatalf("got %d signers, want 2 (env agent + dotvault)", len(signers))
	}
	// SSH_AUTH_SOCK's key must come first (explicit user config wins), then
	// dotvault's.
	if got := ssh.FingerprintSHA256(signers[0].PublicKey()); got != ssh.FingerprintSHA256(envPub) {
		t.Errorf("first signer = %s, want the SSH_AUTH_SOCK key", got)
	}
	if got := ssh.FingerprintSHA256(signers[1].PublicKey()); got != ssh.FingerprintSHA256(dotvaultPub) {
		t.Errorf("second signer = %s, want the dotvault key", got)
	}
}

func TestAgentAuthDotvaultOff(t *testing.T) {
	rt := sockDir(t)
	if err := os.MkdirAll(filepath.Join(rt, "dotvault"), 0o700); err != nil {
		t.Fatal(err)
	}
	serveKeyring(t, filepath.Join(rt, "dotvault", "agent.sock"))
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("SSH_AUTH_SOCK", "")

	if callback := agentSigners(DotvaultOff); callback != nil {
		t.Fatal("agentSigners with dotvault off found an agent; expected none")
	}
	if method := AgentAuth(DotvaultOff); method != nil {
		t.Fatal("AgentAuth with dotvault off returned a method; expected nil")
	}
}

// TestDialOwnAgentRejectsForeignSocket drives the branch that actually
// matters for the trust check: a live, reachable agent socket whose owner is
// not us must be refused outright. Proving that needs a uid that isn't ours,
// which a test machine doesn't have — so currentUID is bent instead. Every
// platform funnels its verdict through it (peer credentials on linux/darwin,
// the socket file's owner elsewhere), so this exercises the real rejection
// path on all of them, not a stub.
func TestDialOwnAgentRejectsForeignSocket(t *testing.T) {
	path := filepath.Join(sockDir(t), "a.sock")
	serveKeyring(t, path)

	conn := dialOwnAgent(path)
	if conn == nil {
		t.Fatal("dialOwnAgent rejected our own agent socket, before any uid was bent")
	}
	conn.Close()

	orig := currentUID
	t.Cleanup(func() { currentUID = orig })
	currentUID = func() int { return orig() + 1 }

	if conn := dialOwnAgent(path); conn != nil {
		conn.Close()
		t.Fatal("dialOwnAgent accepted an agent socket served by another uid")
	}
}

// TestDialOwnAgentAbsentSocket pins the common "dotvault not running" case:
// a missing socket is skipped quietly, not reported as a failure.
func TestDialOwnAgentAbsentSocket(t *testing.T) {
	if conn := dialOwnAgent(filepath.Join(sockDir(t), "absent.sock")); conn != nil {
		conn.Close()
		t.Fatal("dialOwnAgent returned a connection for a nonexistent socket")
	}
}

func TestAgentAuthExplicitDotvaultPath(t *testing.T) {
	sock := filepath.Join(sockDir(t), "custom.sock")
	pub := serveKeyring(t, sock)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("XDG_RUNTIME_DIR", sockDir(t)) // empty dir: no default socket

	callback := agentSigners(sock)
	if callback == nil {
		t.Fatal("agentSigners returned nil for explicit socket path")
	}
	signers, err := callback()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 || ssh.FingerprintSHA256(signers[0].PublicKey()) != ssh.FingerprintSHA256(pub) {
		t.Fatalf("signers = %v", signers)
	}
}
