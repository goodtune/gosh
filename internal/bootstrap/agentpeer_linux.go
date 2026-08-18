//go:build linux

package bootstrap

import (
	"net"

	"golang.org/x/sys/unix"
)

// agentPeerUID returns the effective uid of the process on the other end of
// conn, via SO_PEERCRED. The kernel stamps those credentials onto the socket
// pair at connect time, so the answer describes the peer gosh is actually
// talking to rather than whatever the path happens to point at now — nothing
// here can be raced by swapping the filesystem entry. ok is false when the
// lookup fails, which callers must treat as untrusted.
func agentPeerUID(conn *net.UnixConn) (uint32, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	// Control holds the fd open for the callback's duration; its own error
	// covers the fd being unusable, credErr the getsockopt itself.
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return 0, false
	}
	return cred.Uid, true
}
