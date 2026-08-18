// Package transport implements mosh's State Synchronization Protocol layer:
// instructions carrying zlib-compressed state diffs, fragmented into sealed
// datagrams, with acknowledgment-driven retransmission (client side).
package transport

import (
	"errors"
	"fmt"
	"time"

	"github.com/goodtune/gosh/internal/statesync"
	"github.com/goodtune/gosh/internal/wire"
)

// ErrVersionMismatch is fatal: the peer speaks a different protocol version.
var ErrVersionMismatch = errors.New("transport: mosh protocol version mismatch")

// Transport drives one client session: outgoing UserStream sync plus incoming
// server-state instructions. Diffs of newly received states are handed to the
// apply callback (terminal bytes, resizes, echo acks). Not safe for
// concurrent use; the client loop owns it.
type Transport struct {
	Sender *sender

	assembly assembly

	// latestNum is the server state currently rendered on the terminal —
	// the only reference state diffs can be applied against, and the only
	// state this client ever acknowledges (see Recv).
	latestNum uint64

	// Apply receives the diff of each new server state, in order.
	Apply func(diff []byte) error

	// RemoteShutdown flips when the server starts the shutdown handshake.
	remoteShutdown bool
}

// New creates a Transport over a connection (anything satisfying the sender's
// needs; in production a *network.Connection).
func New(conn senderConn, apply func(diff []byte) error) *Transport {
	return &Transport{
		Sender: newSender(conn),
		Apply:  apply,
	}
}

// Recv processes one datagram payload (a transport fragment). A complete,
// in-window instruction updates acks and applies the diff.
func (t *Transport) Recv(payload []byte) error {
	frag, err := parseFragment(payload)
	if err != nil {
		return err
	}
	instBytes, err := t.assembly.add(frag)
	if err != nil || instBytes == nil {
		return err
	}
	inst, err := wire.UnmarshalInstruction(instBytes)
	if err != nil {
		return fmt.Errorf("transport: bad instruction: %w", err)
	}
	if inst.ProtocolVersion != ProtocolVersion {
		return ErrVersionMismatch
	}

	t.Sender.ProcessAcknowledgmentThrough(inst.AckNum)
	t.Sender.RemoteHeard(time.Now())
	t.Sender.NoteRoundtripSuccess()

	if inst.NewNum == ShutdownNum {
		// The server is shutting down (logout). Note the intent immediately
		// so the client can begin its own handshake, but acceptance —
		// rendering the final diff and acking the shutdown state — goes
		// through the same reference-matching path as any other state:
		// acking before rendering would let the server exit with the last
		// output undisplayed, and rendering outside the reference rule would
		// reintroduce the double-paint this receiver exists to prevent.
		// ShutdownNum is the max uint64, so once accepted it latches
		// latestNum and every retransmit dedupes below.
		t.remoteShutdown = true
	}

	// Acceptance is stricter than reference mosh, deliberately. mosh applies
	// a diff to a stored *copy* of any reference state it still holds, then
	// renders through its framebuffer — so overlapping diffs from the same
	// reference are idempotent. gosh writes diff bytes straight to the
	// terminal (see CLAUDE.md "No terminal emulator"), so a diff is only
	// safe to render when its reference is exactly the state on screen:
	// applying two diffs that share an old_num would paint the shared
	// content twice. We therefore render and acknowledge only old_num ==
	// latestNum, and the server converges by re-diffing from our last ack —
	// this subsumes mosh's "old_num must be a held state" idempotency rule
	// (the only held state is the displayed one).
	if inst.NewNum <= t.latestNum { // duplicate or stale retransmit
		return nil
	}
	if inst.OldNum != t.latestNum { // reference is not what the screen shows
		return nil
	}

	if len(inst.Diff) > 0 {
		t.Sender.SetDataAck()
		if err := t.Apply(inst.Diff); err != nil {
			return err
		}
	}
	t.latestNum = inst.NewNum
	t.Sender.SetAckNum(inst.NewNum)
	return nil
}

// RemoteShutdown reports whether the server has begun shutdown.
func (t *Transport) RemoteShutdown() bool { return t.remoteShutdown }

// UserStream exposes the outgoing state for pushing keystrokes/resizes.
func (t *Transport) UserStream() *statesync.UserStream { return t.Sender.State() }
