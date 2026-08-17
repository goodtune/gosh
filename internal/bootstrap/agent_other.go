//go:build !windows

package bootstrap

import (
	"net"
	"os"
)

// dialAgent connects to the ssh-agent named by SSH_AUTH_SOCK, or returns nil
// when none is reachable.
func dialAgent() net.Conn {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	return conn
}
