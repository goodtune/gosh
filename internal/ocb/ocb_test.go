package ocb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 7253 Appendix A test vectors for AES-128 OCB with 128-bit tag,
// restricted to the empty-AD cases (mosh never uses associated data).
var rfcVectors = []struct {
	nonce, plaintext, output string
}{
	{
		"BBAA99887766554433221100",
		"",
		"785407BFFFC8AD9EDCC5520AC9111EE6",
	},
	{
		"BBAA99887766554433221103",
		"0001020304050607",
		"45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9",
	},
	{
		"BBAA99887766554433221106",
		"000102030405060708090A0B0C0D0E0F",
		"5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D",
	},
	{
		"BBAA99887766554433221109",
		"000102030405060708090A0B0C0D0E0F1011121314151617",
		"221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF",
	},
	{
		"BBAA9988776655443322110C",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF",
	},
	{
		"BBAA9988776655443322110F",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
		"4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC7253Vectors(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rfcVectors {
		nonce := mustHex(t, v.nonce)
		pt := mustHex(t, v.plaintext)
		want := mustHex(t, v.output)

		got, err := c.Seal(nil, nonce, pt)
		if err != nil {
			t.Fatalf("Seal(%s): %v", v.nonce, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Seal(%s) = %X, want %X", v.nonce, got, want)
		}

		back, err := c.Open(nil, nonce, want)
		if err != nil {
			t.Fatalf("Open(%s): %v", v.nonce, err)
		}
		if !bytes.Equal(back, pt) {
			t.Errorf("Open(%s) = %X, want %X", v.nonce, back, pt)
		}
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	c, _ := New(key)
	nonce := mustHex(t, "BBAA99887766554433221106")
	ct, err := c.Seal(nil, nonce, []byte("attack at dawn!!"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ct {
		mangled := bytes.Clone(ct)
		mangled[i] ^= 0x01
		if _, err := c.Open(nil, nonce, mangled); err == nil {
			t.Fatalf("Open accepted ciphertext mangled at byte %d", i)
		}
	}
	if _, err := c.Open(nil, mustHex(t, "BBAA99887766554433221107"), ct); err == nil {
		t.Fatal("Open accepted wrong nonce")
	}
	if _, err := c.Open(nil, nonce, ct[:TagLen-1]); err == nil {
		t.Fatal("Open accepted truncated input")
	}
}

func TestRoundTripSizes(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	c, _ := New(key)
	nonce := mustHex(t, "BBAA99887766554433221100")
	for size := 0; size <= 130; size++ {
		pt := bytes.Repeat([]byte{byte(size)}, size)
		ct, err := c.Seal(nil, nonce, pt)
		if err != nil {
			t.Fatal(err)
		}
		back, err := c.Open(nil, nonce, ct)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}
