//go:build windows

package bootstrap

import (
	"net"
	"os"

	"github.com/Microsoft/go-winio"
)

// openSSHAgentPipe is the fixed pipe name of Windows' native OpenSSH agent
// (the ssh-agent service that ships with Windows 10+).
const openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to an ssh-agent: SSH_AUTH_SOCK first when set (Cygwin /
// MSYS2 / third-party agents expose Unix-socket emulation Go can dial since
// Windows supports AF_UNIX), then the native OpenSSH agent named pipe.
func dialAgent() net.Conn {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			return conn
		}
	}
	conn, err := winio.DialPipe(openSSHAgentPipe, nil)
	if err != nil {
		return nil
	}
	return conn
}
