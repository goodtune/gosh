package bootstrap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testHostKey returns a fresh public key of the named type.
func testHostKey(t *testing.T, keyType string) ssh.PublicKey {
	t.Helper()
	switch keyType {
	case ssh.KeyAlgoED25519:
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return key
	case ssh.KeyAlgoECDSA256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return key
	case ssh.KeyAlgoRSA:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	t.Fatalf("unhandled key type %q", keyType)
	return nil
}

// writeKnownHosts writes one known_hosts line per key and returns the path.
func writeKnownHosts(t *testing.T, host string, keys ...ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	var out []byte
	for _, key := range keys {
		out = append(out, knownhosts.Line([]string{host}, key)...)
		out = append(out, '\n')
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// indexOf reports where algo sits in the preference list, or -1.
func indexOf(algos []string, algo string) int {
	return slices.Index(algos, algo)
}

// TestKnownHostKeyAlgorithmsPrefersRecordedType is the regression test for
// the reported failure: a host recorded only under ssh-ed25519 could not be
// verified, because x/crypto's fixed preference lists ssh-ed25519 last and so
// asked a multi-key server for some other type, which known_hosts then had no
// line for — reported as a key mismatch, indistinguishable in wording from a
// real MITM. The recorded type must come first.
func TestKnownHostKeyAlgorithmsPrefersRecordedType(t *testing.T) {
	const addr = "example.com:22"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoED25519))

	algos := knownHostKeyAlgorithms(path, addr)
	if len(algos) == 0 {
		t.Fatal("no preference derived for a host with an ed25519 entry")
	}
	ed := indexOf(algos, ssh.KeyAlgoED25519)
	if ed < 0 {
		t.Fatalf("ssh-ed25519 missing from the preference: %v", algos)
	}
	for _, other := range []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA} {
		if i := indexOf(algos, other); i >= 0 && i < ed {
			t.Errorf("%s is preferred over the recorded ssh-ed25519 (%d < %d): %v", other, i, ed, algos)
		}
	}
}

// TestKnownHostKeyAlgorithmsRSARecordPrefersSHA2 guards the SHA-1 trap:
// known_hosts stores the key type, so an RSA host reads as "ssh-rsa", but
// advertising that alone asks for the SHA-1 signature OpenSSH has refused by
// default since 8.8. The SHA-2 algorithms must come first, and plain ssh-rsa
// must still be present so nothing that works today stops working.
func TestKnownHostKeyAlgorithmsRSARecordPrefersSHA2(t *testing.T) {
	const addr = "rsa.example.com:22"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoRSA))

	algos := knownHostKeyAlgorithms(path, addr)
	sha256At, sha512At := indexOf(algos, ssh.KeyAlgoRSASHA256), indexOf(algos, ssh.KeyAlgoRSASHA512)
	sha1At := indexOf(algos, ssh.KeyAlgoRSA)
	if sha256At < 0 || sha512At < 0 {
		t.Fatalf("rsa-sha2 algorithms missing for an ssh-rsa entry: %v", algos)
	}
	if sha1At < 0 {
		t.Fatalf("ssh-rsa dropped entirely, which would break SHA-1-only hosts: %v", algos)
	}
	if sha1At < sha256At || sha1At < sha512At {
		t.Errorf("ssh-rsa (SHA-1) preferred over rsa-sha2: %v", algos)
	}
}

// TestKnownHostKeyAlgorithmsCertsPrecedePlain pins the partition that keeps
// @cert-authority hosts working. knownhosts reports a CA line's key through
// the same KeyError.Want as a plain entry, so the derivation cannot tell it
// promoted a CA key. Hoisting that recorded type's *plain* algorithm above
// the other certificate algorithms would make a host whose certificate is one
// type and whose plain key is another negotiate the plain key no line covers.
// Certificates first, always; recorded types lead within each half.
func TestKnownHostKeyAlgorithmsCertsPrecedePlain(t *testing.T) {
	const addr = "example.com:22"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoED25519))

	algos := knownHostKeyAlgorithms(path, addr)
	lastCert, firstPlain := -1, -1
	for i, a := range algos {
		if isCertAlgorithm(a) {
			lastCert = i
		} else if firstPlain < 0 {
			firstPlain = i
		}
	}
	if lastCert < 0 || firstPlain < 0 {
		t.Fatalf("expected both certificate and plain algorithms: %v", algos)
	}
	if lastCert > firstPlain {
		t.Errorf("a plain algorithm at %d precedes a certificate one at %d: %v", firstPlain, lastCert, algos)
	}
	// The recorded type still leads its half.
	if got := algos[0]; got != ssh.CertAlgoED25519v01 {
		t.Errorf("first certificate algorithm = %s, want the recorded type's: %v", got, algos)
	}
	if got := algos[firstPlain]; got != ssh.KeyAlgoED25519 {
		t.Errorf("first plain algorithm = %s, want the recorded type's: %v", got, algos)
	}
}

// TestKnownHostKeyAlgorithmsKeepsEverySupportedAlgorithm pins the safety
// property that stops this reordering breaking a working connection: nothing
// x/crypto considers supported is dropped, so whatever negotiates today still
// can, only in a different order.
//
// The weak algorithms are the deliberate exception — they appear only when
// the host is recorded under one. Listing them unconditionally would widen
// the offer beyond the library's own default under GODEBUG=fips140, which
// prunes them; and omitting them costs nothing, because an algorithm this
// host has no line for could only ever produce a key mismatch anyway.
func TestKnownHostKeyAlgorithmsKeepsEverySupportedAlgorithm(t *testing.T) {
	const addr = "example.com:22"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoED25519))

	algos := knownHostKeyAlgorithms(path, addr)
	for _, want := range ssh.SupportedAlgorithms().HostKeys {
		if !slices.Contains(algos, want) {
			t.Errorf("supported algorithm %s dropped: %v", want, algos)
		}
	}
	for _, weak := range ssh.InsecureAlgorithms().HostKeys {
		if slices.Contains(algos, weak) {
			t.Errorf("weak algorithm %s offered for a host not recorded under it: %v", weak, algos)
		}
	}
	seen := map[string]bool{}
	for _, a := range algos {
		if seen[a] {
			t.Errorf("algorithm %s listed twice: %v", a, algos)
		}
		seen[a] = true
	}
}

// TestKnownHostKeyAlgorithmsRecordedWeakAlgorithmSurvives is the other half
// of that exception: a host genuinely recorded under ssh-rsa must still be
// offered ssh-rsa, or this would break a connection that works today.
func TestKnownHostKeyAlgorithmsRecordedWeakAlgorithmSurvives(t *testing.T) {
	const addr = "old.example.com:22"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoRSA))

	if algos := knownHostKeyAlgorithms(path, addr); !slices.Contains(algos, ssh.KeyAlgoRSA) {
		t.Errorf("ssh-rsa not offered to a host recorded under it: %v", algos)
	}
}

// TestKnownHostKeyAlgorithmsRanksRecordedTypesCanonically checks that among
// several recorded types the stronger one leads, rather than whichever line
// happens to come first in the file.
func TestKnownHostKeyAlgorithmsRanksRecordedTypesCanonically(t *testing.T) {
	const addr = "mixed.example.com:22"
	// ssh-rsa written first, ed25519 second: file order would put RSA ahead.
	path := writeKnownHosts(t, addr,
		testHostKey(t, ssh.KeyAlgoRSA),
		testHostKey(t, ssh.KeyAlgoED25519),
	)

	algos := knownHostKeyAlgorithms(path, addr)
	sha1At, edAt := indexOf(algos, ssh.KeyAlgoRSA), indexOf(algos, ssh.KeyAlgoED25519)
	if sha1At < 0 || edAt < 0 {
		t.Fatalf("both recorded types should be offered: %v", algos)
	}
	if sha1At < edAt {
		t.Errorf("ssh-rsa (SHA-1) outranks the recorded ssh-ed25519 on file order: %v", algos)
	}
}

// TestKnownHostKeyAlgorithmsUnknownHost covers the accept-new path: with no
// entry for the host there is nothing to prefer, and returning nil leaves the
// library's own defaults in force rather than constraining a first contact.
func TestKnownHostKeyAlgorithmsUnknownHost(t *testing.T) {
	path := writeKnownHosts(t, "other.example.com:22", testHostKey(t, ssh.KeyAlgoED25519))

	if algos := knownHostKeyAlgorithms(path, "unknown.example.com:22"); algos != nil {
		t.Fatalf("unknown host constrained to %v, want no preference", algos)
	}
}

// TestKnownHostKeyAlgorithmsNoPathOrFile covers the degenerate inputs: an
// empty path must read nothing at all (a library caller that never opted in
// should not have a file read behind its back), and a missing file is simply
// nothing to learn from rather than an error.
func TestKnownHostKeyAlgorithmsNoPathOrFile(t *testing.T) {
	if algos := knownHostKeyAlgorithms("", "example.com:22"); algos != nil {
		t.Errorf("empty path derived %v, want no preference", algos)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if algos := knownHostKeyAlgorithms(missing, "example.com:22"); algos != nil {
		t.Errorf("missing file derived %v, want no preference", algos)
	}
}

// TestKnownHostKeyAlgorithmsDoesNotWriteKnownHosts is a safety regression
// test. The derivation probes the verifier with a throwaway key it expects to
// be rejected; done through the acceptNew wrapper instead of the bare
// verifier, that probe would treat an unknown host as a new one and append
// the throwaway key to the user's known_hosts — silently trusting a key
// nobody has.
func TestKnownHostKeyAlgorithmsDoesNotWriteKnownHosts(t *testing.T) {
	const addr = "example.com:22"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoED25519))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Assert the known-host probe produced something, so the file-unchanged
	// check below is known to have exercised the probe rather than an early
	// return.
	if got := knownHostKeyAlgorithms(path, addr); len(got) == 0 {
		t.Fatal("probe of a known host derived nothing; the check below would be vacuous")
	}
	knownHostKeyAlgorithms(path, "brand.new.host:22") // unknown host

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("known_hosts modified by algorithm derivation:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestKnownHostKeyAlgorithmsMultipleRecordedTypes checks a host recorded
// under several types: all of them outrank the algorithms the file says
// nothing about, so the server may pick any key the user actually has.
func TestKnownHostKeyAlgorithmsMultipleRecordedTypes(t *testing.T) {
	const addr = "multi.example.com:22"
	path := writeKnownHosts(t, addr,
		testHostKey(t, ssh.KeyAlgoED25519),
		testHostKey(t, ssh.KeyAlgoECDSA256),
	)

	algos := knownHostKeyAlgorithms(path, addr)
	ed, ecdsa256 := indexOf(algos, ssh.KeyAlgoED25519), indexOf(algos, ssh.KeyAlgoECDSA256)
	if ed < 0 || ecdsa256 < 0 {
		t.Fatalf("recorded types missing: %v", algos)
	}
	// Neither recorded type may sit behind an unrecorded one.
	for _, unrecorded := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoECDSA384} {
		i := indexOf(algos, unrecorded)
		if i >= 0 && (i < ed || i < ecdsa256) {
			t.Errorf("unrecorded %s outranks a recorded type: %v", unrecorded, algos)
		}
	}
}

// TestKnownHostKeyAlgorithmsHashedEntry proves the derivation reuses
// knownhosts' own matcher rather than comparing hostnames itself: a hashed
// known_hosts (ssh-keyscan -H, and the default on many distributions) hides
// the hostname, so anything doing its own string match would find nothing.
func TestKnownHostKeyAlgorithmsHashedEntry(t *testing.T) {
	const addr = "hashed.example.com:22"
	key := testHostKey(t, ssh.KeyAlgoED25519)

	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(addr))}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	algos := knownHostKeyAlgorithms(path, addr)
	ed := indexOf(algos, ssh.KeyAlgoED25519)
	if ed < 0 {
		t.Fatalf("hashed ed25519 entry not found: %v", algos)
	}
	if i := indexOf(algos, ssh.KeyAlgoECDSA256); i >= 0 && i < ed {
		t.Errorf("ecdsa preferred over the recorded ed25519 despite a hashed entry: %v", algos)
	}
}

// TestKnownHostKeyAlgorithmsIPv6 covers the bracketed [addr]:port form
// known_hosts uses for IPv6, which the probe must feed through unchanged for
// knownhosts' own matcher to recognise it.
func TestKnownHostKeyAlgorithmsIPv6(t *testing.T) {
	const addr = "[2001:db8::1]:2222"
	path := writeKnownHosts(t, addr, testHostKey(t, ssh.KeyAlgoED25519))

	algos := knownHostKeyAlgorithms(path, addr)
	ed := indexOf(algos, ssh.KeyAlgoED25519)
	if ed < 0 {
		t.Fatalf("no ed25519 preference derived for an IPv6 target: %v", algos)
	}
	if i := indexOf(algos, ssh.KeyAlgoECDSA256); i >= 0 && i < ed {
		t.Errorf("ecdsa preferred over the recorded ed25519 for an IPv6 target: %v", algos)
	}
}
