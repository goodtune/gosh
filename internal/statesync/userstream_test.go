package statesync

import (
	"bytes"
	"testing"

	"github.com/goodtune/gosh/internal/wire"
)

func TestDiffFromCoalescesKeystrokes(t *testing.T) {
	var base, cur UserStream
	cur.PushKeys([]byte("ab"))
	cur.PushResize(80, 24)
	cur.PushKeys([]byte("cd"))

	events, err := wire.UnmarshalUserMessage(cur.DiffFrom(&base))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3 (keys, resize, keys)", len(events))
	}
	if !bytes.Equal(events[0].Keys, []byte("ab")) || !events[1].Resize || !bytes.Equal(events[2].Keys, []byte("cd")) {
		t.Fatalf("events = %+v", events)
	}
}

func TestDiffFromSuffixOnly(t *testing.T) {
	var cur UserStream
	cur.PushKeys([]byte("abc"))
	base := cur.Clone()
	cur.PushKeys([]byte("def"))

	events, err := wire.UnmarshalUserMessage(cur.DiffFrom(base))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !bytes.Equal(events[0].Keys, []byte("def")) {
		t.Fatalf("events = %+v", events)
	}
	if d := cur.DiffFrom(cur.Clone()); d != nil {
		t.Fatalf("self diff = %x, want empty", d)
	}
}

func TestSubtractAndEqual(t *testing.T) {
	var a UserStream
	a.PushKeys([]byte("xyz"))
	a.PushResize(100, 50)
	prefix := &UserStream{}
	prefix.PushKeys([]byte("xy"))

	b := a.Clone()
	if !a.Equal(b) {
		t.Fatal("clone not equal")
	}
	a.Subtract(prefix)
	if a.Equal(b) {
		t.Fatal("subtract did not change stream")
	}
	if len(a.events) != 2 {
		t.Fatalf("after subtract: %d events, want 2", len(a.events))
	}
	// Clone independence: mutating the clone must not touch the original.
	b.PushKeys([]byte("!"))
	if len(a.events) != 2 {
		t.Fatal("clone shares storage with original")
	}
}
