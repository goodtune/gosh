// Package osc52 implements the terminal clipboard sequence — OSC 52, from
// xterm's Operating System Command set — on the mosh session's byte paths.
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
//     clipboard on request. mosh-server relays the query rather than answering
//     it — its emulator stores "?" as the clipboard contents and re-emits it
//     in the next diff, verified against mosh 1.4.0 — so this is reachable in
//     practice, not theoretical. Policy Write, the default, drops it; Full
//     opts back in.
//
//   - A write naming no selection (`52;;`) means "s0" — primary selection plus
//     cut buffer 0 — in xterm's table, not the system clipboard the copying
//     program meant, so it is rewritten to `52;c;`. tmux emits that form for
//     every copy; mosh-server 1.4.0 discards it before any client sees it (it
//     recognizes only `52;c;`), so through mosh the rewrite matters for the
//     forms that do arrive, and for servers less strict than mosh.
//
// Sequences that are not OSC 52, and OSC 52s the policy accepts, pass through
// byte for byte. Once a sequence *is* recognized as OSC 52, none of its bytes
// ever reach the terminal verbatim: it is either re-emitted whole from its
// parsed parts or dropped, because terminals differ on what a truncated or
// aborted control string means — the vte-based ones dispatch the string on
// any exit from the OSC state, which would otherwise let a server smuggle a
// read query past the policy by never terminating it. For the same reason a
// sequence that outgrows maxSequence is consumed and dropped rather than
// released; mosh-server's own OSC buffer stops at 16 KiB, so no conforming
// server can produce one.
//
// The OSC number is parsed as a number, not matched as text: `ESC ] 052 ; c ;`
// is OSC 52 to xterm and to libvte, and so it is here. The 8-bit forms of OSC
// (0x9D) and ST (0x9C) are deliberately *not* recognized: mosh requires a
// UTF-8 locale on both ends, so those bytes are UTF-8 continuation bytes in a
// mosh session and treating them as controls would corrupt legitimate text.
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

	// oscNumber is the command number this filter claims.
	oscNumber = 52
	// maxDigits bounds how long an OSC number may be before the sequence is
	// released as something else's business.
	maxDigits = 8

	// maxSequence caps how much of an in-progress sequence is held before the
	// filter stops holding it and drops the rest. mosh-server's own OSC
	// buffer stops at 16 KiB, so a longer sequence cannot have come from a
	// conforming server; the cap bounds what a hostile one can make the
	// client buffer.
	maxSequence = 64 << 10
	// keepBuffer is the largest held buffer carried between sequences; a
	// bigger one is released so an oversized sequence does not pin memory for
	// the life of the session.
	keepBuffer = 8 << 10
)

type state int

const (
	stText    state = iota // outside any escape sequence
	stEsc                  // seen ESC
	stPrefix               // seen "ESC ]", reading the OSC number
	stBody                 // inside an OSC 52 body, looking for a terminator
	stBodyEsc              // seen ESC inside the body: ST, or an abort
)

// Filter rewrites terminal bytes according to a Policy. It is a streaming
// filter: a sequence split across writes is held until it completes, exactly
// as a terminal's own parser would hold it.
//
// A Filter is not safe for concurrent use; gosh applies server diffs from a
// single goroutine.
type Filter struct {
	policy Policy
	state  state
	buf    []byte // bytes held back: always starts with ESC
	num    int    // OSC number being read in stPrefix
	digits int
	// dropping marks a sequence past maxSequence: it is consumed to its
	// terminator without being held, and discarded.
	dropping bool
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
				f.num, f.digits = 0, 0
				f.state = stPrefix
				i++
				continue
			}
			// Not an OSC introducer: release the ESC and re-read this byte as
			// ordinary text, so "ESC ESC ] 52 ;" still matches.
			dst = f.release(dst)

		case stPrefix:
			switch {
			case c >= '0' && c <= '9' && f.digits < maxDigits:
				f.num = f.num*10 + int(c-'0')
				f.digits++
				f.buf = append(f.buf, c)
				i++
			case c == ';' && f.digits > 0 && f.num == oscNumber:
				f.buf = append(f.buf, c)
				f.state = stBody
				i++
			default:
				// Some other OSC — a title, a hyperlink, an over-long number.
				dst = f.release(dst)
			}

		case stBody:
			switch {
			case c == bel:
				i++
				dst = f.emit(dst, bel)
			case c == esc:
				// Held out of buf: it is either the first half of ST, or the
				// byte that aborts this sequence and may introduce the next.
				f.state = stBodyEsc
				i++
			case c == can || c == sub:
				// The host abandoned the string. Terminals disagree on
				// whether the fragment still counts, so drop it rather than
				// let a partial clipboard operation through.
				i++
				f.discard()
			case !f.dropping && len(f.buf) >= maxSequence:
				f.dropping = true
				f.buf = f.buf[:0]
			default:
				if !f.dropping {
					f.buf = append(f.buf, c)
				}
				i++
			}

		case stBodyEsc:
			if c == '\\' { // ST
				i++
				dst = f.emit(dst, esc)
				continue
			}
			// ESC ended the control string without completing it — and may
			// introduce the next one, which is how a terminal reads it, so
			// hand the ESC back to the escape state instead of letting the
			// remainder stream through as text.
			f.discard()
			f.buf = append(f.buf[:0], esc)
			f.state = stEsc
		}
	}
	return dst
}

// Flush releases any bytes held from an incomplete sequence and returns the
// filter to its initial state. It is for callers that must not withhold
// bytes across calls — local input, where holding back a partial sequence
// would swallow keystrokes a person is typing.
func (f *Filter) Flush(dst []byte) []byte {
	if f.state == stText {
		return dst
	}
	if f.dropping {
		f.discard()
		return dst
	}
	if f.state == stBodyEsc {
		f.buf = append(f.buf, esc) // the half-seen ST, kept out of buf until now
	}
	return f.release(dst)
}

// FilterChunk filters src as a self-contained chunk: nothing is held for a
// later call.
func (f *Filter) FilterChunk(dst, src []byte) []byte {
	return f.Flush(f.Filter(dst, src))
}

// release flushes held bytes verbatim and returns to plain text. It is only
// correct before the filter has committed to an OSC 52; after that, see
// discard. The byte under the cursor is deliberately not consumed: callers
// re-read it in the text state.
func (f *Filter) release(dst []byte) []byte {
	dst = append(dst, f.buf...)
	f.reset()
	return dst
}

// discard drops held bytes and returns to plain text.
func (f *Filter) discard() { f.reset() }

func (f *Filter) reset() {
	if cap(f.buf) > keepBuffer {
		f.buf = nil
	} else {
		f.buf = f.buf[:0]
	}
	f.state = stText
	f.dropping = false
}

// emit applies the policy to the completed sequence in buf, which arrived
// with the given terminator (bel, or esc for ST). The terminating byte(s)
// have already been consumed from the input; the sequence is rebuilt from
// its parts rather than forwarded as it arrived.
func (f *Filter) emit(dst []byte, term byte) []byte {
	seq := f.buf
	dropped := f.dropping
	defer f.reset()

	if dropped || f.policy == Off {
		return dst
	}

	body := seq[len("\x1b]"):] // the OSC number, ';', then Pc ';' Pd
	body = body[bytes.IndexByte(body, ';')+1:]

	sep := bytes.IndexByte(body, ';')
	if sep < 0 {
		// No Pd at all: not a clipboard operation we understand. Rebuilding
		// keeps the canonical number, which is all that changed.
		return f.appendSequence(dst, nil, body, term)
	}
	pc, pd := body[:sep], body[sep+1:]

	if bytes.Equal(pd, []byte("?")) {
		if f.policy == Full {
			return f.appendSequence(dst, pc, pd, term)
		}
		return dst
	}
	if len(pc) == 0 {
		pc = []byte("c")
	}
	return f.appendSequence(dst, pc, pd, term)
}

// appendSequence writes `ESC ] 52 ; Pc ; Pd` closed by the terminator the
// sequence arrived with. The OSC number is written canonically — `ESC ] 052`
// is OSC 52 to a terminal, and reducing it keeps what leaves here in one
// form.
func (f *Filter) appendSequence(dst, pc, pd []byte, term byte) []byte {
	dst = append(dst, esc, ']', '5', '2', ';')
	if pc != nil {
		dst = append(dst, pc...)
		dst = append(dst, ';')
	}
	dst = append(dst, pd...)
	if term == esc {
		return append(dst, esc, '\\')
	}
	return append(dst, bel)
}
