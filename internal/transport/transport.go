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

// receivedState tracks one server state we have acknowledged receipt of.
type receivedState struct {
	num        uint64
	receivedAt time.Time
}

// Transport drives one client session: outgoing UserStream sync plus incoming
// server-state instructions. Diffs of newly received states are handed to the
// apply callback (terminal bytes, resizes, echo acks). Not safe for
// concurrent use; the client loop owns it.
type Transport struct {
	Sender *sender

	assembly       assembly
	receivedStates []receivedState
	latestNum      uint64

	// Apply receives the diff of each new server state, in order.
	Apply func(diff []byte) error

	// RemoteShutdown flips when the server starts the shutdown handshake.
	remoteShutdown bool
}

// New creates a Transport over a connection (anything satisfying the sender's
// needs; in production a *network.Connection).
func New(conn senderConn, apply func(diff []byte) error) *Transport {
	return &Transport{
		Sender:         newSender(conn),
		receivedStates: []receivedState{{num: 0, receivedAt: time.Now()}},
		Apply:          apply,
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

	if inst.NewNum == ShutdownNum {
		t.remoteShutdown = true
	}

	// Drop states we already have.
	for _, rs := range t.receivedStates {
		if rs.num == inst.NewNum {
			return nil
		}
	}
	// The reference (old) state must still be in our window; this is
	// security-sensitive idempotency enforcement, exactly as in mosh.
	found := false
	for _, rs := range t.receivedStates {
		if rs.num == inst.OldNum {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	t.processThrowawayUntil(inst.ThrowawayNum)

	now := time.Now()
	t.receivedStates = append(t.receivedStates, receivedState{num: inst.NewNum, receivedAt: now})
	if len(t.receivedStates) > 1024 { // mirror mosh's receiver queue bound
		t.receivedStates = t.receivedStates[len(t.receivedStates)-1024:]
	}

	// Acknowledge the numerically largest state we hold (mosh acks the back
	// of its sorted receive queue; an out-of-order arrival must not regress
	// the ack).
	if inst.NewNum == ShutdownNum || inst.NewNum > t.latestNum {
		t.Sender.SetAckNum(inst.NewNum)
	}
	t.Sender.RemoteHeard(now)
	if len(inst.Diff) > 0 {
		t.Sender.SetDataAck()
		// Render only forward progress: a retransmitted diff targeting a
		// state older than what we've already applied would rewind the
		// display (we keep no framebuffer to diff against, unlike mosh).
		if inst.NewNum > t.latestNum || inst.NewNum == ShutdownNum {
			if err := t.Apply(inst.Diff); err != nil {
				return err
			}
		}
	}
	if inst.NewNum > t.latestNum && inst.NewNum != ShutdownNum {
		t.latestNum = inst.NewNum
	}
	return nil
}

func (t *Transport) processThrowawayUntil(throwaway uint64) {
	kept := t.receivedStates[:0]
	for _, rs := range t.receivedStates {
		if rs.num >= throwaway {
			kept = append(kept, rs)
		}
	}
	t.receivedStates = kept
}

// RemoteShutdown reports whether the server has begun shutdown.
func (t *Transport) RemoteShutdown() bool { return t.remoteShutdown }

// UserStream exposes the outgoing state for pushing keystrokes/resizes.
func (t *Transport) UserStream() *statesync.UserStream { return t.Sender.State() }
