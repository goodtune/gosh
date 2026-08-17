package transport

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// fragHeaderLen is the fragment header: 8-byte instruction id + 2-byte
// fragment number whose top bit marks the final fragment.
const fragHeaderLen = 10

// fragment is one datagram payload: a slice of a compressed instruction.
type fragment struct {
	id       uint64
	num      uint16
	final    bool
	contents []byte
}

func (f fragment) marshal() []byte {
	out := make([]byte, fragHeaderLen+len(f.contents))
	binary.BigEndian.PutUint64(out[0:8], f.id)
	combined := f.num
	if f.final {
		combined |= 0x8000
	}
	binary.BigEndian.PutUint16(out[8:10], combined)
	copy(out[10:], f.contents)
	return out
}

var errShortFragment = errors.New("transport: fragment shorter than header")

func parseFragment(b []byte) (fragment, error) {
	if len(b) < fragHeaderLen {
		return fragment{}, errShortFragment
	}
	combined := binary.BigEndian.Uint16(b[8:10])
	return fragment{
		id:       binary.BigEndian.Uint64(b[0:8]),
		num:      combined & 0x7FFF,
		final:    combined&0x8000 != 0,
		contents: append([]byte(nil), b[10:]...),
	}, nil
}

// compress applies the zlib framing mosh's Compressor uses.
func compress(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b) //nolint:errcheck // bytes.Buffer writes cannot fail
	w.Close()  //nolint:errcheck
	return buf.Bytes()
}

const maxUncompressed = 4 << 20 // generous bound; mosh caps its buffer at 4 MB

func uncompress(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("transport: bad compressed payload: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxUncompressed+1))
	if err != nil {
		return nil, fmt.Errorf("transport: decompress: %w", err)
	}
	if len(out) > maxUncompressed {
		return nil, errors.New("transport: decompressed payload too large")
	}
	return out, nil
}

// fragmenter splits compressed instructions into MTU-sized fragments,
// assigning a fresh id whenever the instruction bytes (or MTU) change so
// retransmissions of an unchanged instruction reuse their id.
type fragmenter struct {
	nextID      uint64
	lastPayload []byte
	lastMTU     int
}

func (fr *fragmenter) makeFragments(instruction []byte, mtu int) []fragment {
	payload := compress(instruction)
	if !bytes.Equal(payload, fr.lastPayload) || mtu != fr.lastMTU {
		fr.nextID++
		fr.lastPayload = payload
		fr.lastMTU = mtu
	}
	chunk := mtu - fragHeaderLen
	var frags []fragment
	for num := uint16(0); ; num++ {
		f := fragment{id: fr.nextID, num: num}
		if len(payload) > chunk {
			f.contents = payload[:chunk]
			payload = payload[chunk:]
		} else {
			f.contents = payload
			f.final = true
			frags = append(frags, f)
			break
		}
		frags = append(frags, f)
	}
	return frags
}

// assembly reassembles fragments into complete instructions, tolerating loss
// (a new id abandons the old partial) and duplication.
type assembly struct {
	currentID uint64
	haveID    bool
	frags     []*fragment
	arrived   int
	total     int // -1 until the final fragment pins it
}

// add ingests one fragment; it returns the assembled instruction bytes
// (decompressed) when the fragment completes one, else nil.
func (a *assembly) add(f fragment) ([]byte, error) {
	if !a.haveID || a.currentID != f.id {
		a.currentID = f.id
		a.haveID = true
		a.frags = make([]*fragment, f.num+1)
		a.frags[f.num] = &f
		a.arrived = 1
		a.total = -1
	} else {
		if int(f.num) < len(a.frags) && a.frags[f.num] != nil {
			// duplicate — ignore
		} else {
			for int(f.num) >= len(a.frags) {
				a.frags = append(a.frags, nil)
			}
			a.frags[f.num] = &f
			a.arrived++
		}
	}
	if f.final {
		a.total = int(f.num) + 1
		if len(a.frags) > a.total {
			// Fragments beyond final are protocol garbage; drop them.
			a.frags = a.frags[:a.total]
			a.arrived = 0
			for _, fp := range a.frags {
				if fp != nil {
					a.arrived++
				}
			}
		}
	}
	if a.total == -1 || a.arrived != a.total {
		return nil, nil
	}
	var buf bytes.Buffer
	for _, fp := range a.frags {
		if fp == nil {
			return nil, nil // still missing a middle fragment
		}
		buf.Write(fp.contents)
	}
	a.haveID = false // reset so a retransmitted id reassembles cleanly
	return uncompress(buf.Bytes())
}
