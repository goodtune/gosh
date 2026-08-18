//go:build !windows && !linux && !darwin

package bootstrap

import (
	"net"
	"os"
	"syscall"
)

// agentPathTrusted falls back to the socket file's owner on Unix platforms
// whose peer-credential call gosh cannot reach without cgo (CGO_ENABLED=0 is
// a hard invariant here). It runs *before* the dial, which is the best these
// platforms can do: a foreign socket is then never connected to at all,
// rather than connected to and judged afterwards.
//
// Lstat, not Stat, and the endpoint must be a socket: os.Stat follows
// symlinks, so a symlink planted at path and aimed at any victim-owned file
// would pass an owner check while the dial that follows resolves the link
// again — and an attacker who flips it in between lands the connection on
// their own socket. Refusing to follow the link closes that variant; a
// socket cannot be a symlink, so the type check subsumes it.
//
// It does not close the general race — an attacker with write access to the
// directory can still rename a real, foreign-owned socket over the path
// between this call and the dial — which is exactly why the shipped
// platforms ask the kernel about the connected peer instead of vetting a
// path at all. This is the strongest check available without a cgo-free
// peer-credential call, kept rather than failing closed because it is
// strictly better than what these platforms had before, and failing closed
// would silently drop dotvault support for anyone building from source on
// them. gosh ships binaries only for linux, darwin and windows, all of
// which get the race-free check; FreeBSD is one GetsockoptXucred call from
// joining them if it ever becomes a shipped target (see
// agentpeer_darwin.go). Until then, prefer --dotvault-agent off on a
// multi-user host of one of these platforms.
//
// Note this rejects a legitimately symlinked agent socket, which the
// peercred platforms accept. That asymmetry is deliberate: there, the
// symlink is harmless because the verdict never comes from the path.
func agentPathTrusted(path string) bool {
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if st.Mode()&os.ModeSocket == 0 {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return isCurrentUser(uint32(sys.Uid))
}

// agentPeerTrusted has nothing left to add here: agentPathTrusted already
// made the only determination this platform can. Returning true is not a
// blanket trust, it just avoids rejecting what the pre-dial gate passed.
func agentPeerTrusted(*net.UnixConn) bool { return true }
