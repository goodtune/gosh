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
	rt := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rt, "dotvault"), 0o700); err != nil {
		t.Fatal(err)
	}
	dotvaultPub := serveKeyring(t, filepath.Join(rt, "dotvault", "agent.sock"))

	authSock := filepath.Join(t.TempDir(), "ssh-agent.sock")
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
	rt := t.TempDir()
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

func TestAgentAuthExplicitDotvaultPath(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "custom.sock")
	pub := serveKeyring(t, sock)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) // empty dir: no default socket

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
