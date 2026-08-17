//go:build windows

package bootstrap

import (
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

// openSSHAgentPipe is the fixed pipe name of Windows' native OpenSSH agent
// (the ssh-agent service that ships with Windows 10+).
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// pipeDialTimeout bounds each named-pipe connection attempt; an absent pipe
// fails immediately, this only guards a present-but-wedged one.
var pipeDialTimeout = 500 * time.Millisecond

// dialAgents connects to every reachable ssh-agent, most explicit first:
// SSH_AUTH_SOCK when set (Cygwin / MSYS2 emulation — Windows supports
// AF_UNIX), then the dotvault agent named pipe (per the dotvault setting),
// then the native OpenSSH agent pipe.
func dialAgents(dotvault string) []net.Conn {
	var conns []net.Conn
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			conns = append(conns, conn)
		}
	}
	if pipe := resolveDotvaultEndpoint(dotvault); pipe != "" {
		if conn, err := winio.DialPipe(pipe, &pipeDialTimeout); err == nil {
			conns = append(conns, conn)
		}
	}
	if conn, err := winio.DialPipe(openSSHAgentPipe, &pipeDialTimeout); err == nil {
		conns = append(conns, conn)
	}
	return conns
}

func resolveDotvaultEndpoint(dotvault string) string {
	switch dotvault {
	case DotvaultOff:
		return ""
	case DotvaultAuto, "":
		return dotvaultAgentPipe
	default:
		// An explicit value is used verbatim — a \\.\pipe\... name.
		return dotvault
	}
}
