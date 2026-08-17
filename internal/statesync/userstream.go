// Package statesync implements the client-side synchronized objects: the
// outgoing UserStream (keystrokes and resizes) and a thin view of the
// server's terminal state.
package statesync

import (
	"bytes"

	"github.com/goodtune/gosh/internal/wire"
)

// UserStream is the mosh client's outgoing state: an append-only sequence of
// user events. Synchronization sends the suffix a peer state lacks.
type UserStream struct {
	events []wire.UserEvent
}

// PushKeys appends keystroke bytes as individual byte events, coalescing is
// done at diff time exactly like mosh (which stores per-byte events too).
func (u *UserStream) PushKeys(b []byte) {
	for _, c := range b {
		u.events = append(u.events, wire.UserEvent{Keys: []byte{c}})
	}
}

// PushResize appends a resize event.
func (u *UserStream) PushResize(width, height int) {
	u.events = append(u.events, wire.UserEvent{Resize: true, Width: width, Height: height})
}

// Clone returns an independent copy sharing no mutable storage.
func (u *UserStream) Clone() *UserStream {
	c := &UserStream{events: make([]wire.UserEvent, len(u.events))}
	copy(c.events, u.events)
	return c
}

// Equal reports whether two streams contain the same event sequence.
func (u *UserStream) Equal(o *UserStream) bool {
	if len(u.events) != len(o.events) {
		return false
	}
	for i := range u.events {
		a, b := u.events[i], o.events[i]
		if a.Resize != b.Resize || a.Width != b.Width || a.Height != b.Height || !bytes.Equal(a.Keys, b.Keys) {
			return false
		}
	}
	return true
}

// Subtract removes the shared prefix; prefix must be a prefix of u (the
// transport sender guarantees this by construction, as in mosh).
func (u *UserStream) Subtract(prefix *UserStream) {
	n := len(prefix.events)
	if n > len(u.events) {
		n = len(u.events)
	}
	u.events = u.events[n:]
}

// DiffFrom serializes the events u has beyond existing as a UserMessage,
// coalescing consecutive keystroke events into one Keystroke instruction.
func (u *UserStream) DiffFrom(existing *UserStream) []byte {
	if len(existing.events) >= len(u.events) {
		return nil
	}
	suffix := u.events[len(existing.events):]
	var coalesced []wire.UserEvent
	for _, ev := range suffix {
		if ev.Resize {
			coalesced = append(coalesced, ev)
			continue
		}
		if n := len(coalesced); n > 0 && !coalesced[n-1].Resize {
			coalesced[n-1].Keys = append(coalesced[n-1].Keys, ev.Keys...)
			continue
		}
		coalesced = append(coalesced, wire.UserEvent{Keys: append([]byte(nil), ev.Keys...)})
	}
	return wire.MarshalUserMessage(coalesced)
}
