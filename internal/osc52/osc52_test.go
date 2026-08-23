package osc52

import (
	"bytes"
	"strings"
	"testing"
)

// run feeds src through a Filter in a single call.
func run(p Policy, src string) string {
	return string(New(p).Filter(nil, []byte(src)))
}

// runSplit feeds src through a Filter one byte at a time, which must produce
// the same bytes as a single call — sequences straddle diff boundaries.
func runSplit(p Policy, src string) string {
	f := New(p)
	var out []byte
	for i := 0; i < len(src); i++ {
		out = f.Filter(out, []byte(src[i:i+1]))
	}
	return string(out)
}

func TestFilter(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		in     string
		want   string
	}{
		{
			name: "plain text is untouched",
			in:   "hello\r\nworld\x07",
			want: "hello\r\nworld\x07",
		},
		{
			name: "unrelated escape sequences are untouched",
			in:   "\x1b[1;31mred\x1b[0m\x1b]0;title\x07\x1b]8;;http://x\x1b\\",
			want: "\x1b[1;31mred\x1b[0m\x1b]0;title\x07\x1b]8;;http://x\x1b\\",
		},
		{
			name: "clipboard write passes through",
			in:   "a\x1b]52;c;aGVsbG8=\x07b",
			want: "a\x1b]52;c;aGVsbG8=\x07b",
		},
		{
			name: "clipboard write with ST terminator passes through",
			in:   "\x1b]52;c;aGVsbG8=\x1b\\",
			want: "\x1b]52;c;aGVsbG8=\x1b\\",
		},
		{
			name: "empty selection is normalized to the system clipboard",
			in:   "\x1b]52;;aGVsbG8=\x07",
			want: "\x1b]52;c;aGVsbG8=\x07",
		},
		{
			name: "empty selection is normalized with ST too",
			in:   "\x1b]52;;aGVsbG8=\x1b\\",
			want: "\x1b]52;c;aGVsbG8=\x1b\\",
		},
		{
			name: "an explicit selection is left alone",
			in:   "\x1b]52;p;aGVsbG8=\x07",
			want: "\x1b]52;p;aGVsbG8=\x07",
		},
		{
			name: "read query is dropped under the default policy",
			in:   "before\x1b]52;c;?\x07after",
			want: "beforeafter",
		},
		{
			name:   "read query survives under the full policy",
			policy: Full,
			in:     "\x1b]52;c;?\x07",
			want:   "\x1b]52;c;?\x07",
		},
		{
			name:   "off drops writes as well",
			policy: Off,
			in:     "x\x1b]52;c;aGVsbG8=\x07y\x1b]52;c;?\x07z",
			want:   "xyz",
		},
		{
			name:   "off leaves other sequences alone",
			policy: Off,
			in:     "\x1b]0;title\x07\x1b[Kx",
			want:   "\x1b]0;title\x07\x1b[Kx",
		},
		{
			name: "a clipboard write with no payload separator is passed through",
			in:   "\x1b]52;c\x07",
			want: "\x1b]52;c\x07",
		},
		{
			name: "an empty payload (clipboard clear) is preserved",
			in:   "\x1b]52;c;\x07",
			want: "\x1b]52;c;\x07",
		},
		{
			name: "a doubled escape still finds the sequence",
			in:   "\x1b\x1b]52;;aGk=\x07",
			want: "\x1b\x1b]52;c;aGk=\x07",
		},
		{
			name: "CAN aborts the sequence and releases it verbatim",
			in:   "\x1b]52;c;aGk=\x18rest",
			want: "\x1b]52;c;aGk=\x18rest",
		},
		{
			name: "ESC that is not ST aborts the sequence",
			in:   "\x1b]52;c;aGk=\x1b[0m",
			want: "\x1b]52;c;aGk=\x1b[0m",
		},
		{
			name: "back-to-back sequences are handled independently",
			in:   "\x1b]52;;YQ==\x07\x1b]52;c;?\x07\x1b]52;c;Yg==\x07",
			want: "\x1b]52;c;YQ==\x07\x1b]52;c;Yg==\x07",
		},
		{
			name: "a near miss on the prefix is released",
			in:   "\x1b]5;x\x07\x1b]521;y\x07",
			want: "\x1b]5;x\x07\x1b]521;y\x07",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.policy, tc.in); got != tc.want {
				t.Errorf("Filter(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got := runSplit(tc.policy, tc.in); got != tc.want {
				t.Errorf("byte-at-a-time Filter(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFilterTrailingPartialIsHeld pins the streaming contract: an incomplete
// sequence is withheld until it completes, and nothing before it is lost.
func TestFilterTrailingPartialIsHeld(t *testing.T) {
	f := New(Write)
	got := string(f.Filter(nil, []byte("visible\x1b]52;c;aGk")))
	if got != "visible" {
		t.Fatalf("first chunk = %q, want %q", got, "visible")
	}
	got = string(f.Filter(nil, []byte("=\x07tail")))
	if want := "\x1b]52;c;aGk=\x07tail"; got != want {
		t.Fatalf("second chunk = %q, want %q", got, want)
	}
}

// TestFilterOversizedSequenceIsReleased keeps a server (or a hostile one)
// from making the client buffer without bound: past the cap the sequence is
// released verbatim and filtering resumes.
func TestFilterOversizedSequenceIsReleased(t *testing.T) {
	payload := strings.Repeat("A", maxSequence+1024)
	in := "\x1b]52;c;" + payload + "\x07tail"
	got := run(Write, in)
	if got != in {
		t.Fatalf("oversized sequence was not passed through verbatim (got %d bytes, want %d)", len(got), len(in))
	}
	// Filtering must still work afterwards.
	got = run(Write, in+"\x1b]52;c;?\x07")
	if got != in {
		t.Fatalf("filtering did not resume after an oversized sequence: %q", got[len(in):])
	}
}

// TestFilterPreservesEverythingElse is a cheap structural check that the
// filter never invents or reorders bytes outside OSC 52.
func TestFilterPreservesEverythingElse(t *testing.T) {
	var in bytes.Buffer
	for i := 0; i < 256; i++ {
		in.WriteByte(byte(i))
	}
	src := in.String()
	if got := run(Full, src); got != src {
		t.Errorf("full policy altered a byte-range sweep")
	}
	if got := runSplit(Full, src); got != src {
		t.Errorf("full policy altered a byte-range sweep fed one byte at a time")
	}
}

func TestParsePolicy(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Policy
	}{{"write", Write}, {"full", Full}, {"off", Off}} {
		got, err := ParsePolicy(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParsePolicy(%q) = %v, %v", tc.in, got, err)
		}
		if got.String() != tc.in {
			t.Errorf("Policy(%q).String() = %q", tc.in, got.String())
		}
	}
	if _, err := ParsePolicy("on"); err == nil {
		t.Error("ParsePolicy(\"on\") should be rejected")
	}
}
