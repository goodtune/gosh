// Package wire hand-encodes the three tiny proto2 messages the mosh
// protocol exchanges (TransportBuffers.Instruction, ClientBuffers.UserMessage,
// HostBuffers.HostMessage). The messages are small and frozen — mosh has not
// changed them since 2012 — so a ~200-line codec beats a protoc toolchain
// dependency and generated code. Field numbers mirror the upstream .proto
// files verbatim; see the package tests for round-trip and interop fixtures.
package wire

import (
	"errors"
	"fmt"
	"math"
)

const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

var errTruncated = errors.New("wire: truncated message")

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendTag(b []byte, field int, typ int) []byte {
	return appendVarint(b, uint64(field)<<3|uint64(typ))
}

func appendBytesField(b []byte, field int, v []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendUint64Field(b []byte, field int, v uint64) []byte {
	b = appendTag(b, field, wireVarint)
	return appendVarint(b, v)
}

func readVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b); i++ {
		if i >= 10 {
			return 0, 0, errors.New("wire: varint overflow")
		}
		v |= uint64(b[i]&0x7F) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errTruncated
}

// field is one decoded key/value pair.
type field struct {
	num   int
	typ   int
	varix uint64 // for wireVarint
	data  []byte // for wireBytes (aliases the input)
}

// parseFields walks a serialized message, skipping over wire types we can
// carry but don't interpret, so unknown fields never break decoding.
func parseFields(b []byte, visit func(f field) error) error {
	for len(b) > 0 {
		key, n, err := readVarint(b)
		if err != nil {
			return err
		}
		b = b[n:]
		f := field{num: int(key >> 3), typ: int(key & 7)}
		if f.num == 0 {
			return errors.New("wire: field number zero")
		}
		switch f.typ {
		case wireVarint:
			f.varix, n, err = readVarint(b)
			if err != nil {
				return err
			}
			b = b[n:]
		case wireBytes:
			l, n, err := readVarint(b)
			if err != nil {
				return err
			}
			b = b[n:]
			if l > uint64(len(b)) {
				return errTruncated
			}
			f.data = b[:l]
			b = b[l:]
		case wireI64:
			if len(b) < 8 {
				return errTruncated
			}
			b = b[8:]
		case wireI32:
			if len(b) < 4 {
				return errTruncated
			}
			b = b[4:]
		default:
			return fmt.Errorf("wire: unsupported wire type %d", f.typ)
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}

// Instruction is TransportBuffers.Instruction — the one transport-layer
// message, carried (zlib-compressed, fragmented) in every mosh datagram.
type Instruction struct {
	ProtocolVersion uint32
	OldNum          uint64
	NewNum          uint64
	AckNum          uint64
	ThrowawayNum    uint64
	Diff            []byte
	Chaff           []byte
}

// Marshal serializes the instruction. Every field is always emitted, matching
// the upstream sender which sets all seven fields on every instruction.
func (in *Instruction) Marshal() []byte {
	b := make([]byte, 0, 64+len(in.Diff)+len(in.Chaff))
	b = appendUint64Field(b, 1, uint64(in.ProtocolVersion))
	b = appendUint64Field(b, 2, in.OldNum)
	b = appendUint64Field(b, 3, in.NewNum)
	b = appendUint64Field(b, 4, in.AckNum)
	b = appendUint64Field(b, 5, in.ThrowawayNum)
	b = appendBytesField(b, 6, in.Diff)
	b = appendBytesField(b, 7, in.Chaff)
	return b
}

// UnmarshalInstruction parses a TransportBuffers.Instruction.
func UnmarshalInstruction(b []byte) (*Instruction, error) {
	in := &Instruction{}
	err := parseFields(b, func(f field) error {
		switch f.num {
		case 1:
			if f.varix > math.MaxUint32 {
				return errors.New("wire: protocol_version overflow")
			}
			in.ProtocolVersion = uint32(f.varix)
		case 2:
			in.OldNum = f.varix
		case 3:
			in.NewNum = f.varix
		case 4:
			in.AckNum = f.varix
		case 5:
			in.ThrowawayNum = f.varix
		case 6:
			in.Diff = append([]byte(nil), f.data...)
		case 7:
			in.Chaff = append([]byte(nil), f.data...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return in, nil
}

// UserEvent is one entry in a ClientBuffers.UserMessage diff: either a run of
// keystroke bytes or a terminal resize. Exactly one of the two is active.
type UserEvent struct {
	Keys   []byte // keystroke bytes; nil for a resize event
	Resize bool
	Width  int
	Height int
}

// MarshalUserMessage serializes events as a ClientBuffers.UserMessage.
// Layout per event: Instruction{ keystroke ext (field 2) = Keystroke{keys=4} }
// or Instruction{ resize ext (field 3) = ResizeMessage{width=5, height=6} }.
func MarshalUserMessage(events []UserEvent) []byte {
	var out []byte
	for _, ev := range events {
		var inner []byte
		if ev.Resize {
			// proto2 int32 encodes negatives sign-extended to 64 bits;
			// terminal sizes are never negative, but follow the rule anyway.
			var rm []byte
			rm = appendUint64Field(rm, 5, uint64(int64(ev.Width)))
			rm = appendUint64Field(rm, 6, uint64(int64(ev.Height)))
			inner = appendBytesField(nil, 3, rm)
		} else {
			ks := appendBytesField(nil, 4, ev.Keys)
			inner = appendBytesField(nil, 2, ks)
		}
		out = appendBytesField(out, 1, inner)
	}
	return out
}

// UnmarshalUserMessage parses a ClientBuffers.UserMessage into its events.
func UnmarshalUserMessage(b []byte) ([]UserEvent, error) {
	var events []UserEvent
	err := parseFields(b, func(f field) error {
		if f.num != 1 || f.typ != wireBytes {
			return nil
		}
		return parseFields(f.data, func(ext field) error {
			switch {
			case ext.num == 2 && ext.typ == wireBytes: // keystroke
				return parseFields(ext.data, func(k field) error {
					if k.num == 4 && k.typ == wireBytes {
						events = append(events, UserEvent{Keys: append([]byte(nil), k.data...)})
					}
					return nil
				})
			case ext.num == 3 && ext.typ == wireBytes: // resize
				ev := UserEvent{Resize: true}
				if err := parseFields(ext.data, func(r field) error {
					switch r.num {
					case 5:
						ev.Width = int(int64(r.varix))
					case 6:
						ev.Height = int(int64(r.varix))
					}
					return nil
				}); err != nil {
					return err
				}
				events = append(events, ev)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// HostEvent is one entry in a HostBuffers.HostMessage: terminal bytes to
// apply, a resize, or an echo acknowledgment.
type HostEvent struct {
	Bytes      []byte // hostbytes.hoststring; nil unless this is a bytes event
	Resize     bool
	Width      int
	Height     int
	EchoAck    bool
	EchoAckNum uint64
}

// UnmarshalHostMessage parses a HostBuffers.HostMessage.
// Extensions: hostbytes=2 (HostBytes{hoststring=4}), resize=3
// (ResizeMessage{width=5,height=6}), echoack=7 (EchoAck{echo_ack_num=8}).
func UnmarshalHostMessage(b []byte) ([]HostEvent, error) {
	var events []HostEvent
	err := parseFields(b, func(f field) error {
		if f.num != 1 || f.typ != wireBytes {
			return nil
		}
		return parseFields(f.data, func(ext field) error {
			switch {
			case ext.num == 2 && ext.typ == wireBytes: // hostbytes
				return parseFields(ext.data, func(h field) error {
					if h.num == 4 && h.typ == wireBytes {
						events = append(events, HostEvent{Bytes: append([]byte(nil), h.data...)})
					}
					return nil
				})
			case ext.num == 3 && ext.typ == wireBytes: // resize
				ev := HostEvent{Resize: true}
				if err := parseFields(ext.data, func(r field) error {
					switch r.num {
					case 5:
						ev.Width = int(int64(r.varix))
					case 6:
						ev.Height = int(int64(r.varix))
					}
					return nil
				}); err != nil {
					return err
				}
				events = append(events, ev)
			case ext.num == 7 && ext.typ == wireBytes: // echoack
				ev := HostEvent{EchoAck: true}
				if err := parseFields(ext.data, func(e field) error {
					if e.num == 8 {
						ev.EchoAckNum = e.varix
					}
					return nil
				}); err != nil {
					return err
				}
				events = append(events, ev)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}
