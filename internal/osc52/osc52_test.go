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
			name: "CAN drops the unfinished sequence",
			in:   "\x1b]52;c;aGk=\x18rest",
			want: "rest",
		},
		{
			name: "ESC that is not ST drops the unfinished sequence",
			in:   "\x1b]52;c;aGk=\x1b[0m",
			want: "\x1b[0m",
		},
		{
			name: "an unterminated sequence cannot smuggle the next one past the policy",
			in:   "\x1b]52;c;\x1b]52;c;?\x07",
			want: "",
		},
		{
			name:   "an unterminated sequence is dropped under off, not streamed",
			policy: Off,
			in:     "\x1b]52;c;aGk=\x1b]52;c;YQ==\x07tail",
			want:   "tail",
		},
		{
			name: "a leading-zero OSC number is still OSC 52",
			in:   "\x1b]052;c;?\x07x",
			want: "x",
		},
		{
			name: "a leading-zero write is normalized to the canonical number",
			in:   "\x1b]052;;YQ==\x07",
			want: "\x1b]52;c;YQ==\x07",
		},
		{
			name: "a query with no selection is a query",
			in:   "\x1b]52;;?\x07",
			want: "",
		},
		{
			name: "an ST-terminated query is dropped too",
			in:   "\x1b]52;c;?\x1b\\",
			want: "",
		},
		{
			name: "an over-long OSC number is somebody else's sequence",
			in:   "\x1b]000000052;c;?\x07",
			want: "\x1b]000000052;c;?\x07",
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

// TestFilterOversizedSequenceIsDropped keeps a hostile server from making the
// client buffer without bound *and* from using length to slip a sequence past
// the policy: past the cap the rest is consumed and discarded, and filtering
// resumes on the next sequence.
func TestFilterOversizedSequenceIsDropped(t *testing.T) {
	oversized := "\x1b]52;c;" + strings.Repeat("A", maxSequence+1024) + "\x07"
	if got := run(Write, oversized+"tail"); got != "tail" {
		t.Fatalf("oversized sequence leaked %d bytes: %.80q", len(got), got)
	}
	if got := run(Off, oversized+"tail"); got != "tail" {
		t.Fatalf("oversized sequence leaked past the off policy: %.80q", got)
	}
	if got := run(Write, oversized+"\x1b]52;c;?\x07\x1b]52;;YQ==\x07"); got != "\x1b]52;c;YQ==\x07" {
		t.Fatalf("filtering did not resume after an oversized sequence: %q", got)
	}
}

// TestFilterChunkDoesNotWithholdInput pins the contract the input path needs:
// an incomplete sequence is passed through rather than held, so a person
// typing ESC ] 5 2 ; does not lose their keystrokes, while a complete
// sequence arriving in one read — how a terminal answers a clipboard query —
// is still filtered.
func TestFilterChunkDoesNotWithholdInput(t *testing.T) {
	f := New(Off)
	var out []byte
	for _, chunk := range []string{"\x1b", "]", "5", "2", ";"} {
		out = f.FilterChunk(out, []byte(chunk))
	}
	if string(out) != "\x1b]52;" {
		t.Fatalf("typed prefix was withheld: %q", out)
	}
	out = f.FilterChunk(nil, []byte("\x1b]52;c;c2VjcmV0\x07"))
	if len(out) != 0 {
		t.Fatalf("complete sequence in one chunk was not filtered: %q", out)
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
