//go:build !windows

package bootstrap

import (
	"net"
	"os"
	"runtime"
	"syscall"
)

// dialAgents connects to every reachable ssh-agent, most explicit first:
// SSH_AUTH_SOCK, then the dotvault agent socket (per the dotvault setting —
// DotvaultAuto resolves the default path, DotvaultOff skips it, anything
// else is an explicit socket path).
func dialAgents(dotvault string) []net.Conn {
	var conns []net.Conn
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			conns = append(conns, conn)
		}
	}
	if path := resolveDotvaultEndpoint(dotvault, dotvaultAgentSocket(runtime.GOOS, os.Getenv, homeDir())); path != "" {
		// Stat first: an absent socket is the common "dotvault not running"
		// case and skips the dial noise. Require current-uid ownership — the
		// default locations are owner-only in practice, but an auto-dialled
		// endpoint should not trust a socket someone else planted.
		if st, err := os.Stat(path); err == nil && ownedByCurrentUser(st) {
			if conn, err := net.Dial("unix", path); err == nil {
				conns = append(conns, conn)
			}
		}
	}
	return conns
}

func ownedByCurrentUser(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(sys.Uid) == os.Getuid()
}
