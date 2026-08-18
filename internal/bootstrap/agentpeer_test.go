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

// TestDialOwnAgentRejectsSymlinkedForeignSocket answers the symlink variant
// of the reported race directly. The attack plants a symlink where the agent
// socket belongs: an owner check that stats the path follows the link to
// some victim-owned file and passes, and the dial that follows resolves the
// link a second time — so flipping it in between lands the connection on the
// attacker's socket. Here the path is a symlink and the peer reads as
// another uid; the connection must still be refused. Nothing about the path,
// symlink or not, can buy the attacker anything, because the verdict comes
// from the peer on the far end of the socket that was actually opened.
func TestDialOwnAgentRejectsSymlinkedForeignSocket(t *testing.T) {
	dir := sockDir(t)
	real := filepath.Join(dir, "r.sock")
	serveKeyring(t, real)

	link := filepath.Join(dir, "l.sock")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// Through the symlink, our own agent is still reachable and accepted:
	// gosh does not reject symlinks here, it just doesn't trust them.
	conn := dialOwnAgent(link)
	if conn == nil {
		t.Fatal("dialOwnAgent refused a symlink to our own agent socket")
	}
	conn.Close()

	orig := currentUID
	t.Cleanup(func() { currentUID = orig })
	currentUID = func() int { return orig() + 1 }

	if conn := dialOwnAgent(link); conn != nil {
		conn.Close()
		t.Fatal("dialOwnAgent accepted a symlinked socket served by another uid: the symlink bypassed the ownership check")
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
