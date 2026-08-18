//go:build linux || darwin

package bootstrap

import "net"

// agentPathTrusted is a no-op on platforms with a peer-credential call. The
// real check is agentPeerTrusted; gating on a stat here would only add a
// second, weaker opinion about a path that can change before the dial lands
// — the very race these implementations exist to close.
func agentPathTrusted(string) bool { return true }

// agentPeerTrusted derives the trust decision from the platform's
// peer-credential lookup (agentPeerUID, per GOOS). A lookup that fails is
// treated as untrusted: gosh must never hand identities to a socket whose
// owner it could not establish.
func agentPeerTrusted(conn *net.UnixConn) bool {
	uid, ok := agentPeerUID(conn)
	return ok && isCurrentUser(uid)
}
