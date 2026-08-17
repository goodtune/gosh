package transport

import (
	"bytes"
	"testing"
	"time"

	"github.com/goodtune/gosh/internal/wire"
)

// fakeConn captures sent payloads and returns canned link parameters.
type fakeConn struct {
	sent [][]byte
	mtu  int
}

func (f *fakeConn) Send(p []byte) error {
	f.sent = append(f.sent, append([]byte(nil), p...))
	return nil
}
func (f *fakeConn) SRTT() float64          { return 100 }
func (f *fakeConn) Timeout() time.Duration { return 200 * time.Millisecond }
func (f *fakeConn) MTU() int               { return f.mtu }

func decodeSent(t *testing.T, payloads [][]byte) []*wire.Instruction {
	t.Helper()
	var out []*wire.Instruction
	var asm assembly
	for _, p := range payloads {
		frag, err := parseFragment(p)
		if err != nil {
			t.Fatal(err)
		}
		instBytes, err := asm.add(frag)
		if err != nil {
			t.Fatal(err)
		}
		if instBytes == nil {
			continue
		}
		inst, err := wire.UnmarshalInstruction(instBytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, inst)
	}
	return out
}

func TestSenderSendsKeystrokeDiff(t *testing.T) {
	conn := &fakeConn{mtu: 472}
	tr := New(conn, func([]byte) error { return nil })

	tr.UserStream().PushKeys([]byte("ls\r"))
	if err := tr.Sender.Tick(); err != nil {
		t.Fatal(err)
	}
	insts := decodeSent(t, conn.sent)
	if len(insts) != 1 {
		t.Fatalf("got %d instructions, want 1", len(insts))
	}
	inst := insts[0]
	if inst.ProtocolVersion != 2 || inst.OldNum != 0 || inst.NewNum != 1 {
		t.Fatalf("unexpected instruction header: %+v", inst)
	}
	events, err := wire.UnmarshalUserMessage(inst.Diff)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !bytes.Equal(events[0].Keys, []byte("ls\r")) {
		t.Fatalf("diff events = %+v", events)
	}
}

func TestSenderRetransmitsUntilAcked(t *testing.T) {
	conn := &fakeConn{mtu: 472}
	tr := New(conn, func([]byte) error { return nil })

	tr.UserStream().PushKeys([]byte("x"))
	if err := tr.Sender.Tick(); err != nil {
		t.Fatal(err)
	}
	first := len(conn.sent)
	if first == 0 {
		t.Fatal("nothing sent")
	}
	// Before the RTO there is nothing to do; wait time must be positive.
	if w := tr.Sender.WaitTime(time.Now()); w <= 0 {
		t.Fatalf("WaitTime = %v, want > 0", w)
	}
	// Simulate the RTO elapsing by backdating the sent state.
	for i := range tr.Sender.sentStates {
		tr.Sender.sentStates[i].sentAt = tr.Sender.sentStates[i].sentAt.Add(-time.Second)
	}
	if err := tr.Sender.Tick(); err != nil {
		t.Fatal(err)
	}
	if len(conn.sent) == first {
		t.Fatal("no retransmission after RTO")
	}

	// Ack state 1: sender prunes and goes quiet (no diff pending).
	tr.Sender.ProcessAcknowledgmentThrough(1)
	if tr.Sender.sentStates[0].num != 1 {
		t.Fatalf("front num = %d, want 1", tr.Sender.sentStates[0].num)
	}
}

// serverHarness builds server->client instructions the way mosh-server would.
type serverHarness struct {
	frag    fragmenter
	nextNum uint64
	ackNum  uint64
}

func (h *serverHarness) instruction(oldNum uint64, diff []byte) [][]byte {
	h.nextNum++
	inst := &wire.Instruction{
		ProtocolVersion: 2,
		OldNum:          oldNum,
		NewNum:          h.nextNum,
		AckNum:          h.ackNum,
		ThrowawayNum:    0,
		Diff:            diff,
	}
	var out [][]byte
	for _, f := range h.frag.makeFragments(inst.Marshal(), 472) {
		out = append(out, f.marshal())
	}
	return out
}

func TestTransportAppliesServerDiffsInOrder(t *testing.T) {
	conn := &fakeConn{mtu: 472}
	var applied [][]byte
	tr := New(conn, func(d []byte) error { applied = append(applied, append([]byte(nil), d...)); return nil })

	h := &serverHarness{}
	for _, p := range h.instruction(0, []byte("frame-1")) {
		if err := tr.Recv(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range h.instruction(1, []byte("frame-2")) {
		if err := tr.Recv(p); err != nil {
			t.Fatal(err)
		}
	}
	if len(applied) != 2 || string(applied[0]) != "frame-1" || string(applied[1]) != "frame-2" {
		t.Fatalf("applied = %q", applied)
	}
	if tr.Sender.ackNum != 2 {
		t.Fatalf("ackNum = %d, want 2", tr.Sender.ackNum)
	}
}

func TestTransportIgnoresDuplicateAndOrphanStates(t *testing.T) {
	conn := &fakeConn{mtu: 472}
	var applied int
	tr := New(conn, func([]byte) error { applied++; return nil })

	h := &serverHarness{}
	frames := h.instruction(0, []byte("frame-1"))
	for _, p := range frames {
		if err := tr.Recv(p); err != nil {
			t.Fatal(err)
		}
	}
	// Replay of the same state must not re-apply. (A replayed fragment set
	// reassembles again — dedup happens at the state level.)
	for _, p := range frames {
		if err := tr.Recv(p); err != nil {
			t.Fatal(err)
		}
	}
	if applied != 1 {
		t.Fatalf("applied %d times, want 1", applied)
	}
	// An instruction whose old state we never had is dropped.
	orphan := &serverHarness{nextNum: 50}
	for _, p := range orphan.instruction(40, []byte("orphan")) {
		if err := tr.Recv(p); err != nil {
			t.Fatal(err)
		}
	}
	if applied != 1 {
		t.Fatalf("orphan applied; count = %d", applied)
	}
}

func TestTransportVersionMismatch(t *testing.T) {
	conn := &fakeConn{mtu: 472}
	tr := New(conn, func([]byte) error { return nil })
	inst := &wire.Instruction{ProtocolVersion: 3, NewNum: 1}
	var fr fragmenter
	for _, f := range fr.makeFragments(inst.Marshal(), 472) {
		if err := tr.Recv(f.marshal()); err != ErrVersionMismatch {
			t.Fatalf("err = %v, want ErrVersionMismatch", err)
		}
	}
}

func TestShutdownHandshake(t *testing.T) {
	conn := &fakeConn{mtu: 472}
	tr := New(conn, func([]byte) error { return nil })

	tr.Sender.StartShutdown()
	// The shutdown state is paced at the send interval; backdate the last
	// transmission so the tick fires immediately.
	for i := range tr.Sender.sentStates {
		tr.Sender.sentStates[i].sentAt = tr.Sender.sentStates[i].sentAt.Add(-time.Second)
	}
	if err := tr.Sender.Tick(); err != nil {
		t.Fatal(err)
	}
	insts := decodeSent(t, conn.sent)
	if len(insts) == 0 || insts[len(insts)-1].NewNum != ShutdownNum {
		t.Fatalf("no shutdown instruction sent: %+v", insts)
	}
	if tr.Sender.ShutdownAcknowledged() {
		t.Fatal("shutdown acked prematurely")
	}
	tr.Sender.ProcessAcknowledgmentThrough(ShutdownNum)
	if !tr.Sender.ShutdownAcknowledged() {
		t.Fatal("shutdown not acknowledged after ack")
	}
}

func TestFragmentationRoundTrip(t *testing.T) {
	// A diff larger than one MTU must split and reassemble. Incompressible
	// pseudorandom bytes so zlib can't fold it back under one MTU.
	big := make([]byte, 3200)
	state := uint32(0x2545F491)
	for i := range big {
		state = state*1664525 + 1013904223
		big[i] = byte(state >> 24)
	}
	inst := &wire.Instruction{ProtocolVersion: 2, NewNum: 1, Diff: big}
	var fr fragmenter
	frags := fr.makeFragments(inst.Marshal(), 100)
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}
	var asm assembly
	var got []byte
	// Deliver out of order: swap first two fragments.
	order := append([]fragment(nil), frags...)
	order[0], order[1] = order[1], order[0]
	for _, f := range order {
		b, err := asm.add(f)
		if err != nil {
			t.Fatal(err)
		}
		if b != nil {
			got = b
		}
	}
	if got == nil {
		t.Fatal("assembly never completed")
	}
	back, err := wire.UnmarshalInstruction(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Diff, big) {
		t.Fatal("reassembled diff mismatch")
	}
}
