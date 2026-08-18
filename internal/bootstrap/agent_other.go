//go:build !windows

package bootstrap

import (
	"net"
	"os"
	"runtime"
)

// dialAgents connects to every reachable ssh-agent, most explicit first:
// SSH_AUTH_SOCK, then the dotvault agent socket (per the dotvault setting —
// DotvaultAuto resolves the default path, DotvaultOff skips it, anything
// else is an explicit socket path).
func dialAgents(dotvault string) []net.Conn {
	var conns []net.Conn
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		// Deliberately unchecked: SSH_AUTH_SOCK is the environment telling
		// us which agent to use, and OpenSSH honours it as-is. Demanding
		// current-uid ownership here would break forwarded and system-broker
		// agents that legitimately run under another uid.
		if conn, err := net.Dial("unix", sock); err == nil {
			conns = append(conns, conn)
		}
	}
	if path := resolveDotvaultEndpoint(dotvault, dotvaultAgentSocket(runtime.GOOS, os.Getenv, homeDir())); path != "" {
		if conn := dialOwnAgent(path); conn != nil {
			conns = append(conns, conn)
		}
	}
	return conns
}

// dialOwnAgent connects to the dotvault agent socket at path and keeps the
// connection only if the process serving it runs as the current user. gosh
// offers every identity an agent hands it to the remote host, so a socket
// someone else planted must not be trusted. Applies to both the
// auto-resolved default and an explicit --dotvault-agent path, as it did
// before; SSH_AUTH_SOCK is the only endpoint taken on faith (see above).
// Returns nil when the socket is absent (the common "dotvault not running"
// case), unreachable, or fails that check.
//
// Two seams, because the platforms disagree about what can be checked and
// when. agentPeerTrusted interrogates the *connection* and is the real
// check: stat-then-dial — what this used to do everywhere — is a TOCTOU
// race, since whatever the stat approved can be swapped for an attacker's
// socket before the dial lands, so the ownership guarantee it appears to
// make is not one it can keep. Peer credentials come from the kernel for
// the socket actually connected to, leaving no window. agentPathTrusted is
// the pre-dial gate for platforms that have no cgo-free way to ask, so they
// keep refusing to *connect* to a foreign socket at all rather than
// connecting first and judging after; on peercred platforms it is a no-op.
func dialOwnAgent(path string) net.Conn {
	if !agentPathTrusted(path) {
		return nil
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok { // unreachable: network "unix" always yields a *net.UnixConn
		conn.Close()
		return nil
	}
	if !agentPeerTrusted(unixConn) {
		conn.Close()
		return nil
	}
	return conn
}

// currentUID is os.Geteuid, indirected so tests can exercise the rejection
// branch — proving a foreign-owned socket is actually refused needs a uid
// that isn't ours, and a test machine has only the one.
var currentUID = os.Geteuid

// isCurrentUser is the trust policy both seams share, kept in one place:
// gosh offers identities only from an agent its own user is running.
// Effective uid on both sides — SO_PEERCRED and LOCAL_PEERCRED each report
// the peer's euid, so euid-to-euid is the exact pairing.
func isCurrentUser(uid uint32) bool { return uid == uint32(currentUID()) }
