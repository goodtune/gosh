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
// Xucred carries a Version field that this deliberately does not check: gosh
// has no macOS runtime to confirm the expected value against, and a wrong
// guess would fail closed, silently dropping dotvault support on every Mac.
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
	return cred.Uid, true
}
