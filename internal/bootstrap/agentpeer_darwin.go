//go:build darwin

package bootstrap

import (
	"net"

	"golang.org/x/sys/unix"
)

// agentPeerUID returns the effective uid of the process on the other end of
// conn, via LOCAL_PEERCRED — darwin's equivalent of Linux's SO_PEERCRED, and
// race-free for the same reason: the credentials describe the connected
// peer, not the path. ok is false when the lookup fails, which callers must
// treat as untrusted.
//
// FreeBSD exposes the same call and could join this file; it stays on
// agentpeer_fallback.go's stat only because gosh neither ships nor tests a
// FreeBSD build.
func agentPeerUID(conn *net.UnixConn) (uint32, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred    *unix.Xucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil || credErr != nil {
		return 0, false
	}
	// GetsockoptXucred discards the length the kernel reports, so a short
	// write would leave a zeroed struct that reads as a perfectly good
	// "uid 0" — trusted, if gosh itself is running as root. Darwin's
	// XUCRED_VERSION is 0, so the Version field cannot tell an unwritten
	// buffer from a written one; an all-zero struct can, because a real
	// answer always carries at least the peer's primary group. Reject only
	// that exact shape: a genuine root-owned agent still passes.
	if cred.Version == 0 && cred.Uid == 0 && cred.Ngroups == 0 {
		return 0, false
	}
	return cred.Uid, true
}
