package client

import (
	"bytes"
	"testing"

	"github.com/goodtune/gosh/internal/osc52"
)

func TestProcessEscapes(t *testing.T) {
	s := &Session{}
	cases := []struct {
		name string
		in   []string
		out  string
		quit bool
	}{
		{"plain", []string{"hello"}, "hello", false},
		{"quit", []string{"\x1e."}, "", true},
		{"quit split across reads", []string{"\x1e", "."}, "", true},
		{"literal escape", []string{"\x1e\x1e"}, "\x1e", false},
		{"escape then other", []string{"\x1eq"}, "\x1eq", false},
		{"text then quit", []string{"ok\x1e."}, "ok", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pending bool
			var got []byte
			var quit bool
			for _, chunk := range tc.in {
				out, q := s.processEscapes([]byte(chunk), &pending)
				got = append(got, out...)
				if q {
					quit = true
					break
				}
			}
			if !bytes.Equal(got, []byte(tc.out)) || quit != tc.quit {
				t.Fatalf("got %q quit=%v, want %q quit=%v", got, quit, tc.out, tc.quit)
			}
		})
	}
}

// hostDiff hand-encodes a HostBuffers.HostMessage carrying one hostbytes
// event, the shape mosh-server sends for terminal output.
func hostDiff(s string) []byte {
	field := func(tag byte, payload []byte) []byte {
		out := []byte{tag}
		for n := len(payload); ; n >>= 7 {
			if n < 0x80 {
				out = append(out, byte(n))
				break
			}
			out = append(out, byte(n)|0x80)
		}
		return append(out, payload...)
	}
	hoststring := field(0x22, []byte(s)) // hostbytes.hoststring = 4
	hostbytes := field(0x12, hoststring) // instruction.hostbytes = 2
	return field(0x0a, hostbytes)        // HostMessage.instruction = 1
}

// TestApplyFiltersClipboardSequences pins the OSC 52 policy at the seam where
// server diffs meet the local terminal.
func TestApplyFiltersClipboardSequences(t *testing.T) {
	const diff = "x\x1b]52;;YQ==\x07\x1b]52;c;?\x07y"
	cases := []struct {
		policy osc52.Policy
		want   string
	}{
		{osc52.Write, "x\x1b]52;c;YQ==\x07y"},
		{osc52.Full, "x\x1b]52;c;YQ==\x07\x1b]52;c;?\x07y"},
		{osc52.Off, "xy"},
	}
	for _, tc := range cases {
		t.Run(tc.policy.String(), func(t *testing.T) {
			var out bytes.Buffer
			s := &Session{cfg: Config{Output: &out}, clip: osc52.New(tc.policy)}
			if err := s.apply(hostDiff(diff)); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if out.String() != tc.want {
				t.Fatalf("apply wrote %q, want %q", out.String(), tc.want)
			}
		})
	}
}

// TestFilterInputWithholdsClipboardAnswers pins the far end of the clipboard
// boundary: a terminal's answer to a read query must not be relayed to the
// remote host, while ordinary typing — including a half-typed escape
// sequence — passes through untouched.
func TestFilterInputWithholdsClipboardAnswers(t *testing.T) {
	answer := "\x1b]52;c;c2VjcmV0\x07"

	guarded := &Session{clipIn: osc52.New(osc52.Off)}
	if got := string(guarded.filterInput([]byte("ls -l\r"))); got != "ls -l\r" {
		t.Errorf("ordinary input was altered: %q", got)
	}
	if got := guarded.filterInput([]byte(answer)); len(got) != 0 {
		t.Errorf("clipboard answer was forwarded to the remote: %q", got)
	}
	if got := string(guarded.filterInput([]byte("\x1b]52;"))); got != "\x1b]52;" {
		t.Errorf("a partly typed sequence was withheld: %q", got)
	}

	// The full policy asks for transparency in both directions.
	open := &Session{}
	if got := string(open.filterInput([]byte(answer))); got != answer {
		t.Errorf("full policy altered input: %q", got)
	}
}
