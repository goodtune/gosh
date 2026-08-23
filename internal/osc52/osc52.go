// Package osc52 implements the terminal clipboard sequence — OSC 52, from
// xterm's Operating System Command set — on the server-to-client byte path.
//
// The sequence is `ESC ] 52 ; Pc ; Pd BEL` (or ST, `ESC \`), where Pc names
// the selection to touch ("c" is the system clipboard, "p" the X11 primary,
// empty means xterm's default of "s0") and Pd is the base64 payload, or a
// literal "?" asking the terminal to *report* the current selection.
//
// gosh has no terminal emulator, so terminal bytes from the server reach the
// local terminal untouched and a clipboard write already works end to end.
// This filter exists for the two places where "untouched" is the wrong
// answer:
//
//   - A read query (Pd == "?") is answered by the terminal on the client's
//     *input* stream, which gosh forwards straight to the remote host. Passing
//     it on would hand any process on the far end a copy of the local
//     clipboard on request. mosh-server forwards the query verbatim (its
//     emulator stores "?" as the clipboard contents and re-emits it in the
//     next diff), so this is reachable in practice, not theoretical. Policy
//     Write — the default — drops it; Full opts back in.
//
//   - An empty Pc means "s0" (primary selection plus cut buffer 0) in xterm's
//     table, not the system clipboard, and that is what tmux emits by default.
//     Rewriting it to "c" makes the write land where the user meant it to.
//
// Everything else passes through byte for byte, including OSC sequences that
// are not 52 and malformed 52s.
package osc52

import (
	"bytes"
	"fmt"
)

// Policy decides what happens to an OSC 52 sequence on its way to the local
// terminal.
type Policy int

const (
	// Write forwards clipboard writes (normalizing an empty selection to the
	// system clipboard) and drops clipboard read queries. It is the zero
	// value, and the default.
	Write Policy = iota
	// Full additionally forwards read queries, letting the remote end read
	// the local clipboard on any terminal that answers them.
	Full
	// Off drops every OSC 52 sequence, leaving the local clipboard entirely
	// out of reach of the remote host.
	Off
)

// ParsePolicy maps the --clipboard flag values onto a Policy.
func ParsePolicy(s string) (Policy, error) {
	switch s {
	case "write":
		return Write, nil
	case "full":
		return Full, nil
	case "off":
		return Off, nil
	}
	return Write, fmt.Errorf("unknown clipboard policy %q: want write, full, or off", s)
}

func (p Policy) String() string {
	switch p {
	case Full:
		return "full"
	case Off:
		return "off"
	default:
		return "write"
	}
}

const (
	esc = 0x1B
	bel = 0x07
	can = 0x18 // CAN and SUB abort a control string in progress
	sub = 0x1A

	// maxSequence caps how much of an in-progress sequence is held back
	// before giving up and releasing it verbatim. mosh-server's own OSC
	// buffer stops at 16 KiB, so anything longer than this cannot be a
	// clipboard write that survived the far end anyway; the cap only bounds
	// what a hostile or broken server can make the client buffer.
	maxSequence = 64 << 10
)

var prefix = []byte("52;") // what follows "ESC ]" in a clipboard sequence

type state int

const (
	stText    state = iota // outside any escape sequence
	stEsc                  // seen ESC
	stPrefix               // seen "ESC ]", matching "52;"
	stBody                 // inside an OSC 52 body, looking for a terminator
	stBodyEsc              // seen ESC inside the body: ST, or an abort
)

// Filter rewrites the server's terminal bytes according to a Policy. It is a
// streaming filter: a sequence split across writes is held until it completes,
// so the zero-copy fast path (no ESC in the chunk) stays a plain copy.
//
// A Filter is not safe for concurrent use; gosh applies server diffs from a
// single goroutine.
type Filter struct {
	policy Policy
	state  state
	buf    []byte // bytes held back: always starts with ESC
}

// New returns a Filter enforcing policy.
func New(policy Policy) *Filter { return &Filter{policy: policy} }

// Filter appends the filtered form of src to dst and returns the result.
// Bytes belonging to an incomplete sequence are retained for the next call.
func (f *Filter) Filter(dst, src []byte) []byte {
	for i := 0; i < len(src); {
		c := src[i]
		switch f.state {
		case stText:
			// Copy up to the next ESC in one go.
			n := bytes.IndexByte(src[i:], esc)
			if n < 0 {
				return append(dst, src[i:]...)
			}
			dst = append(dst, src[i:i+n]...)
			f.buf = append(f.buf[:0], esc)
			f.state = stEsc
			i += n + 1

		case stEsc:
			if c == ']' {
				f.buf = append(f.buf, c)
				f.state = stPrefix
				i++
				continue
			}
			// Not an OSC introducer: release the ESC and re-read this byte
			// as ordinary text, so "ESC ESC ] 52 ;" still matches.
			dst = f.release(dst)

		case stPrefix:
			p := f.buf[2:] // what we have matched of "52;" so far
			if len(p) < len(prefix) && c == prefix[len(p)] {
				f.buf = append(f.buf, c)
				i++
				if len(f.buf)-2 == len(prefix) {
					f.state = stBody
				}
				continue
			}
			dst = f.release(dst)

		case stBody:
			switch {
			case c == bel:
				f.buf = append(f.buf, c)
				i++
				dst = f.emit(dst)
			case c == esc:
				f.buf = append(f.buf, c)
				f.state = stBodyEsc
				i++
			case c == can || c == sub:
				// The host aborted the string; pass the wreckage through
				// unchanged rather than guessing at its intent.
				f.buf = append(f.buf, c)
				i++
				dst = f.release(dst)
			case len(f.buf) >= maxSequence:
				dst = f.release(dst)
			default:
				f.buf = append(f.buf, c)
				i++
			}

		case stBodyEsc:
			if c == '\\' { // ST
				f.buf = append(f.buf, c)
				i++
				dst = f.emit(dst)
				continue
			}
			// ESC followed by anything else ends the control string without
			// completing it.
			dst = f.release(dst)
		}
	}
	return dst
}

// release flushes held bytes verbatim and returns to plain text. The byte
// under the cursor is deliberately not consumed: callers re-read it in the
// text state.
func (f *Filter) release(dst []byte) []byte {
	dst = append(dst, f.buf...)
	f.buf = f.buf[:0]
	f.state = stText
	return dst
}

// emit applies the policy to the completed sequence in buf.
func (f *Filter) emit(dst []byte) []byte {
	seq := f.buf
	f.buf = f.buf[:0]
	f.state = stText

	if f.policy == Off {
		return dst
	}

	termLen := 1 // BEL
	if seq[len(seq)-1] == '\\' {
		termLen = 2 // ST
	}
	body := seq[len(prefix)+2 : len(seq)-termLen]

	sep := bytes.IndexByte(body, ';')
	if sep < 0 {
		// No Pd at all: not a clipboard operation we understand.
		return append(dst, seq...)
	}
	pc, pd := body[:sep], body[sep+1:]

	if bytes.Equal(pd, []byte("?")) {
		if f.policy == Full {
			return append(dst, seq...)
		}
		return dst
	}
	if len(pc) == 0 {
		pc = []byte("c")
	}

	dst = append(dst, esc, ']')
	dst = append(dst, prefix...)
	dst = append(dst, pc...)
	dst = append(dst, ';')
	dst = append(dst, pd...)
	return append(dst, seq[len(seq)-termLen:]...)
}
