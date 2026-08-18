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
// This remains the TOCTOU race the connection-based implementations exist to
// close — the entry approved here can in principle be swapped before the
// dial lands. It is kept rather than failing closed because it is no weaker
// than what these platforms had before, and failing closed would silently
// drop dotvault support for anyone building from source on them. gosh ships
// binaries only for linux, darwin and windows, all of which get a race-free
// check; FreeBSD is one GetsockoptXucred call from joining them if it ever
// becomes a shipped target (see agentpeer_darwin.go). Until then, prefer
// --dotvault-agent off on a multi-user host of one of these platforms.
func agentPathTrusted(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
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
