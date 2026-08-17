package crypto

import (
	"bytes"
	"testing"
)

func TestParseBase64Key(t *testing.T) {
	k, err := ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	if err != nil {
		t.Fatal(err)
	}
	if k.String() != "zr0jtuYVKJnfJHP/XOOsbQ" {
		t.Fatalf("round trip = %q", k.String())
	}
	for _, bad := range []string{"", "short", "zr0jtuYVKJnfJHP/XOOsb!", "zr0jtuYVKJnfJHP/XOOsbQQQ"} {
		if _, err := ParseBase64Key(bad); err == nil {
			t.Errorf("ParseBase64Key(%q) accepted", bad)
		}
	}
	// Non-canonical trailing bits: 'R' shares the leading bits of 'Q' but has
	// low bits set that decode then re-encode differently.
	if _, err := ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbR"); err == nil {
		t.Error("non-canonical key accepted")
	}
}

func TestSessionRoundTrip(t *testing.T) {
	k, _ := ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	s, err := NewSession(k)
	if err != nil {
		t.Fatal(err)
	}
	const dirClient = uint64(1) << 63
	for _, val := range []uint64{0, 1, 12345, dirClient | 7} {
		plain := Message{NonceVal: val, Text: []byte("four score and seven years ago")}
		wire, err := s.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Decrypt(wire)
		if err != nil {
			t.Fatalf("val %d: %v", val, err)
		}
		if got.NonceVal != val || !bytes.Equal(got.Text, plain.Text) {
			t.Fatalf("val %d: got %+v", val, got)
		}
	}
}

func TestDecryptRejectsGarbage(t *testing.T) {
	k, _ := ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	s, _ := NewSession(k)
	if _, err := s.Decrypt([]byte("short")); err == nil {
		t.Fatal("short datagram accepted")
	}
	wire, _ := s.Encrypt(Message{NonceVal: 9, Text: []byte("payload")})
	wire[len(wire)-1] ^= 1
	if _, err := s.Decrypt(wire); err == nil {
		t.Fatal("tampered datagram accepted")
	}
}
