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
	hoststring := append([]byte{0x22, byte(len(s))}, s...)                  // hostbytes.hoststring = 4
	hostbytes := append([]byte{0x12, byte(len(hoststring))}, hoststring...) // instruction.hostbytes = 2
	return append([]byte{0x0a, byte(len(hostbytes))}, hostbytes...)         // HostMessage.instruction = 1
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
