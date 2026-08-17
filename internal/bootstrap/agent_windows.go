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
//
// Residual risk, accepted and documented: the named-pipe namespace is
// machine-global and first-come-first-served, so another local user could
// squat a pipe name before its real owner binds it. The exposure is bounded —
// an agent client holds no key material, a rogue server sees only list/sign
// requests (the SSH session hash, which includes the remote username) and can
// at worst fail the auth — and this mirrors how every Windows SSH client
// already treats the fixed openssh-ssh-agent pipe name. dotvault's own pipe
// carries an owner-only DACL, so squatting it requires winning the race, not
// just being present. Use --dotvault-agent off on hostile multi-user hosts.
func dialAgents(dotvault string) []net.Conn {
	var conns []net.Conn
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			conns = append(conns, conn)
		}
	}
	if pipe := resolveDotvaultEndpoint(dotvault, dotvaultAgentPipe); pipe != "" {
		if conn, err := winio.DialPipe(pipe, &pipeDialTimeout); err == nil {
			conns = append(conns, conn)
		}
	}
	if conn, err := winio.DialPipe(openSSHAgentPipe, &pipeDialTimeout); err == nil {
		conns = append(conns, conn)
	}
	return conns
}
