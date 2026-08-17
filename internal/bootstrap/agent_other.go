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
		if conn, err := net.Dial("unix", sock); err == nil {
			conns = append(conns, conn)
		}
	}
	if path := resolveDotvaultEndpoint(dotvault); path != "" {
		// Stat first: an absent socket is the common "dotvault not running"
		// case and skips the dial noise.
		if _, err := os.Stat(path); err == nil {
			if conn, err := net.Dial("unix", path); err == nil {
				conns = append(conns, conn)
			}
		}
	}
	return conns
}

func resolveDotvaultEndpoint(dotvault string) string {
	switch dotvault {
	case DotvaultOff:
		return ""
	case DotvaultAuto, "":
		return dotvaultAgentSocket(runtime.GOOS, os.Getenv, homeDir())
	default:
		return dotvault
	}
}
