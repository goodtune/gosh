package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestInstructionRoundTrip(t *testing.T) {
	in := &Instruction{
		ProtocolVersion: 2,
		OldNum:          3,
		NewNum:          ^uint64(0), // shutdown sentinel must survive
		AckNum:          7,
		ThrowawayNum:    1,
		Diff:            []byte("some diff"),
		Chaff:           []byte{0x00, 0xFF, 0x80},
	}
	got, err := UnmarshalInstruction(in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.ProtocolVersion != in.ProtocolVersion || got.OldNum != in.OldNum ||
		got.NewNum != in.NewNum || got.AckNum != in.AckNum ||
		got.ThrowawayNum != in.ThrowawayNum ||
		!bytes.Equal(got.Diff, in.Diff) || !bytes.Equal(got.Chaff, in.Chaff) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, in)
	}
}

// TestInstructionInteropFixture pins the exact bytes protobuf (proto2,
// C++ libprotobuf as used by mosh) produces for a known instruction, captured
// from a reference encoding. Field order in libprotobuf output is ascending
// by field number, same as Marshal.
func TestInstructionInteropFixture(t *testing.T) {
	in := &Instruction{ProtocolVersion: 2, OldNum: 0, NewNum: 1, AckNum: 0, ThrowawayNum: 0, Diff: []byte("hi"), Chaff: nil}
	got := in.Marshal()
	// 08 02 = protocol_version 2; 10 00 old; 18 01 new; 20 00 ack; 28 00 throwaway;
	// 32 02 "hi" diff; 3A 00 empty chaff.
	expect, _ := hex.DecodeString("08021000180120002800320268693a00")
	if !bytes.Equal(got, expect) {
		t.Fatalf("Marshal = %x, want %x", got, expect)
	}
}

func TestUserMessageRoundTrip(t *testing.T) {
	events := []UserEvent{
		{Keys: []byte("ls -la\r")},
		{Resize: true, Width: 120, Height: 40},
		{Keys: []byte{0x03}},
	}
	got, err := UnmarshalUserMessage(MarshalUserMessage(events))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d events, want %d", len(got), len(events))
	}
	for i := range events {
		if events[i].Resize != got[i].Resize || !bytes.Equal(events[i].Keys, got[i].Keys) ||
			events[i].Width != got[i].Width || events[i].Height != got[i].Height {
			t.Errorf("event %d mismatch: %+v vs %+v", i, got[i], events[i])
		}
	}
}

// TestUserMessageFixture pins the wire form of a keystroke + resize message so
// interop with mosh-server's parser can't silently drift.
func TestUserMessageFixture(t *testing.T) {
	got := MarshalUserMessage([]UserEvent{
		{Keys: []byte("a")},
		{Resize: true, Width: 80, Height: 24},
	})
	// Instruction{keystroke{keys:"a"}}: 0a 05 12 03 22 01 61
	// Instruction{resize{width:80,height:24}}: 0a 06 1a 04 28 50 30 18
	want, _ := hex.DecodeString("0a0512032201610a061a0428503018")
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalUserMessage = %x, want %x", got, want)
	}
}

func TestUnmarshalHostMessage(t *testing.T) {
	// Hand-build a HostMessage: hostbytes "hello", resize 100x30, echoack 5.
	var msg []byte
	hb := appendBytesField(nil, 4, []byte("hello"))
	msg = appendBytesField(msg, 1, appendBytesField(nil, 2, hb))
	var rm []byte
	rm = appendUint64Field(rm, 5, 100)
	rm = appendUint64Field(rm, 6, 30)
	msg = appendBytesField(msg, 1, appendBytesField(nil, 3, rm))
	ea := appendUint64Field(nil, 8, 5)
	msg = appendBytesField(msg, 1, appendBytesField(nil, 7, ea))

	events, err := UnmarshalHostMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	if string(events[0].Bytes) != "hello" {
		t.Errorf("bytes event = %q", events[0].Bytes)
	}
	if !events[1].Resize || events[1].Width != 100 || events[1].Height != 30 {
		t.Errorf("resize event = %+v", events[1])
	}
	if !events[2].EchoAck || events[2].EchoAckNum != 5 {
		t.Errorf("echoack event = %+v", events[2])
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	in := (&Instruction{ProtocolVersion: 2, Diff: []byte("d")}).Marshal()
	// Append an unknown varint field 15 and an unknown bytes field 16.
	in = appendUint64Field(in, 15, 42)
	in = appendBytesField(in, 16, []byte("future"))
	got, err := UnmarshalInstruction(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProtocolVersion != 2 || string(got.Diff) != "d" {
		t.Fatalf("unexpected decode: %+v", got)
	}
}

func TestTruncatedInputErrors(t *testing.T) {
	full := (&Instruction{ProtocolVersion: 2, Diff: bytes.Repeat([]byte("x"), 50)}).Marshal()
	// A cut inside the trailing diff bytes must error (earlier prefixes can
	// be valid messages in their own right — every field is optional).
	if _, err := UnmarshalInstruction(full[:len(full)-1]); err == nil {
		t.Fatal("expected error for truncation inside diff bytes")
	}
	if _, err := UnmarshalInstruction([]byte{0x32, 0xFF}); err == nil {
		t.Fatal("expected error for truncated bytes-field length")
	}
	if _, err := UnmarshalInstruction([]byte{0x08}); err == nil {
		t.Fatal("expected error for truncated varint")
	}
}
