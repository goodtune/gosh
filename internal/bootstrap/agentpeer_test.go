//go:build linux || darwin

package bootstrap

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// dialSelfServedAgent serves an agent on a fresh socket and connects to it,
// returning the client end.
func dialSelfServedAgent(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	path := filepath.Join(sockDir(t), "a.sock")
	serveKeyring(t, path)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.UnixConn), path
}

// TestAgentPeerUIDSurvivesPathRemoval is the TOCTOU regression test. The
// ownership check must describe the peer gosh is connected to, not the
// filesystem entry that led there. Removing the socket path after the dial
// stands in for the swap an attacker performs in that window: a stat-based
// check consults the (now gone, or replaced) path and gets an answer about
// something other than the live connection, while a peer-credential check is
// untouched because it asks the kernel about the socket already open.
// Reverting agentPeerUID to a path stat fails this test.
func TestAgentPeerUIDSurvivesPathRemoval(t *testing.T) {
	conn, path := dialSelfServedAgent(t)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	uid, ok := agentPeerUID(conn)
	if !ok {
		t.Fatal("agentPeerUID failed once the socket path was gone: the check is still bound to the path, not the connection")
	}
	if want := uint32(os.Geteuid()); uid != want {
		t.Fatalf("agentPeerUID = %d, want the current euid %d", uid, want)
	}
}

// TestAgentPeerUIDFailsClosedOnDeadConn pins that agentPeerUID is a real
// syscall against the socket rather than something reconstructed from our
// own process. A closed fd is the one input whose peer credentials cannot be
// looked up, so an implementation that simply returned the current uid — the
// degenerate shape TestAgentPeerUIDSurvivesPathRemoval alone would accept —
// fails here. Failing closed also matters in its own right: agentPeerTrusted
// turns !ok into a refusal.
func TestAgentPeerUIDFailsClosedOnDeadConn(t *testing.T) {
	conn, _ := dialSelfServedAgent(t)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if uid, ok := agentPeerUID(conn); ok {
		t.Fatalf("agentPeerUID reported uid %d for a closed connection; it is answering from something other than the socket", uid)
	}
}
