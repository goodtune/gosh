package network

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/goodtune/gosh/internal/crypto"
)

// Direction of a packet on the wire; encoded as the top bit of the nonce.
type Direction uint64

const (
	ToServer Direction = 0
	ToClient Direction = 1
)

const (
	directionMask = uint64(1) << 63
	sequenceMask  = ^directionMask
)

// Packet is one decrypted mosh datagram: sequence number, direction, a pair
// of 16-bit millisecond timestamps for RTT measurement, and the payload
// (a transport-layer fragment).
type Packet struct {
	Seq            uint64
	Direction      Direction
	Timestamp      uint16
	TimestampReply uint16
	Payload        []byte
}

// tsMissing is the sentinel for "no timestamp reply available".
const tsMissing = uint16(0xFFFF)

var errShortPacket = errors.New("network: packet too short for timestamps")

// packetFromMessage decodes a decrypted crypto message into a packet.
func packetFromMessage(m crypto.Message) (Packet, error) {
	if len(m.Text) < 4 {
		return Packet{}, errShortPacket
	}
	p := Packet{
		Seq:            m.NonceVal & sequenceMask,
		Timestamp:      binary.BigEndian.Uint16(m.Text[0:2]),
		TimestampReply: binary.BigEndian.Uint16(m.Text[2:4]),
		Payload:        m.Text[4:],
	}
	if m.NonceVal&directionMask != 0 {
		p.Direction = ToClient
	}
	return p, nil
}

// toMessage encodes a packet for sealing.
func (p Packet) toMessage() crypto.Message {
	text := make([]byte, 4+len(p.Payload))
	binary.BigEndian.PutUint16(text[0:2], p.Timestamp)
	binary.BigEndian.PutUint16(text[2:4], p.TimestampReply)
	copy(text[4:], p.Payload)
	return crypto.Message{
		NonceVal: uint64(p.Direction)<<63 | (p.Seq & sequenceMask),
		Text:     text,
	}
}

// timestamp16 is the current time in milliseconds truncated to 16 bits,
// avoiding the 0xFFFF "missing" sentinel exactly as mosh does.
func timestamp16(now time.Time) uint16 {
	ts := uint16(now.UnixMilli() % 65536)
	if ts == tsMissing {
		ts++
	}
	return ts
}

// timestampDiff returns the elapsed milliseconds between two wrapped 16-bit
// timestamps.
func timestampDiff(tsnew, tsold uint16) uint16 {
	return tsnew - tsold // uint16 arithmetic wraps exactly like mosh's
}
