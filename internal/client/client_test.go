package client

import (
	"bytes"
	"testing"
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
