package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyPolicy names the strictness levels for SSH host key verification.
type HostKeyPolicy string

const (
	// PolicyStrict verifies against known_hosts and rejects unknown hosts.
	PolicyStrict HostKeyPolicy = "strict"
	// PolicyAcceptNew verifies known hosts and appends unknown ones —
	// OpenSSH's StrictHostKeyChecking=accept-new. A *changed* key is still
	// always fatal.
	PolicyAcceptNew HostKeyPolicy = "accept-new"
	// PolicyInsecure skips verification entirely. Test rigs only.
	PolicyInsecure HostKeyPolicy = "insecure"
)

// DefaultKnownHostsPath returns ~/.ssh/known_hosts.
func DefaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

// HostKeyCallback builds the callback for a policy against a known_hosts
// file. An empty path uses the default location; the file (and ~/.ssh) is
// created on demand under accept-new.
func HostKeyCallback(policy HostKeyPolicy, path string) (ssh.HostKeyCallback, error) {
	switch policy {
	case PolicyStrict, PolicyAcceptNew:
	case PolicyInsecure:
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit opt-in
	default:
		// A security-posture flag must not degrade on a typo.
		return nil, fmt.Errorf("unknown host key policy %q (valid: %s, %s, %s)",
			policy, PolicyStrict, PolicyAcceptNew, PolicyInsecure)
	}
	if path == "" {
		var err error
		path, err = DefaultKnownHostsPath()
		if err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if policy == PolicyStrict {
			return nil, fmt.Errorf("known_hosts %s does not exist (use accept-new to create it)", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, err
		}
	}
	verify, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("known_hosts %s: %w", path, err)
	}
	if policy == PolicyStrict {
		return verify, nil
	}
	return acceptNew(verify, path), nil
}

// knownHostKeyAlgorithms returns a host key algorithm preference for addr
// ("host:port"), derived from the entries already recorded for it in the
// known_hosts file at path. Returns nil — meaning "leave the library's
// defaults alone" — when path is empty, unreadable, or holds no entry for
// addr, which is what keeps a first connection under accept-new free to
// record whatever the server offers.
//
// Without this, a host recorded only under one algorithm fails to verify for
// no good reason. x/crypto advertises a fixed preference with ssh-ed25519
// *last*, so a server offering several host keys is asked for whichever type
// that order reaches first, which may well be one the user has no line for;
// knownhosts then finds entries for the hostname but no matching key and
// reports a key mismatch — the same wording it uses for a real MITM. OpenSSH
// avoids this by preferring the algorithms it has already recorded, which is
// what this reproduces.
//
// The result keeps certificate algorithms ahead of every plain one, matching
// how x/crypto's own default is partitioned, and only then prefers the
// recorded types within each half. Hoisting a recorded plain algorithm above
// the remaining certificate algorithms is the obvious-looking simplification
// and it breaks @cert-authority hosts: knownhosts reports a CA line's key
// through the same KeyError.Want as a plain entry, with nothing to tell them
// apart, so a host whose certificate is of one type and whose plain key is of
// another would negotiate the plain key that no line covers, and fail with
// the very "key mismatch" this function exists to prevent.
func knownHostKeyAlgorithms(path, addr string) []string {
	if path == "" {
		return nil
	}
	// Deliberately the bare verifier, never the acceptNew wrapper: probing
	// through that would append the throwaway key below to known_hosts. A
	// file too malformed to parse yields nil here and is reported properly by
	// HostKeyCallback, which parses it too.
	verify, err := knownhosts.New(path)
	if err != nil {
		return nil
	}
	recorded := recordedHostKeyTypes(verify, addr)
	if len(recorded) == 0 {
		return nil
	}
	preferred := make(map[string]bool)
	for _, keyType := range recorded {
		for _, algo := range hostKeyAlgorithmsFor(keyType) {
			preferred[algo] = true
		}
	}
	if len(preferred) == 0 {
		return nil
	}
	var certKnown, certRest, plainKnown, plainRest []string
	for _, algo := range candidateHostKeyAlgorithms(preferred) {
		switch {
		case isCertAlgorithm(algo) && preferred[algo]:
			certKnown = append(certKnown, algo)
		case isCertAlgorithm(algo):
			certRest = append(certRest, algo)
		case preferred[algo]:
			plainKnown = append(plainKnown, algo)
		default:
			plainRest = append(plainRest, algo)
		}
	}
	return slices.Concat(certKnown, certRest, plainKnown, plainRest)
}

// candidateHostKeyAlgorithms is every algorithm the result may contain, in
// x/crypto's own preference order so that recorded types rank among
// themselves the way the library would rank them — a stale ssh-dss line must
// not outrank a recorded ssh-ed25519 one just for sitting higher in the file.
//
// The weak algorithms are included only when this host is actually recorded
// under one. Adding them unconditionally would widen the offer rather than
// reorder it: x/crypto prunes them from its default under GODEBUG=fips140,
// and reconstructing the list from the exported halves would put them back.
// Leaving them out of the tail costs nothing, since an unrecorded algorithm
// can only ever produce the key mismatch this exists to avoid. A host
// recorded under ssh-rsa or ssh-dss does still get it offered, FIPS or not —
// dropping that would break a connection that works today, which this must
// never do.
func candidateHostKeyAlgorithms(preferred map[string]bool) []string {
	out := ssh.SupportedAlgorithms().HostKeys
	for _, algo := range ssh.InsecureAlgorithms().HostKeys {
		if preferred[algo] {
			out = append(out, algo)
		}
	}
	return out
}

// certAlgoSuffix marks the OpenSSH host certificate algorithm names; every
// CertAlgo*v01 constant in x/crypto ends with it.
const certAlgoSuffix = "-cert-v01@openssh.com"

func isCertAlgorithm(algo string) bool { return strings.HasSuffix(algo, certAlgoSuffix) }

// probeAddr carries the target address into knownhosts' check as the remote
// net.Addr. The check splits host and port off whatever it is given before
// preferring the hostname argument, so it must parse, but its value is not
// otherwise consulted.
type probeAddr string

func (a probeAddr) Network() string { return "tcp" }
func (a probeAddr) String() string  { return string(a) }

// recordedHostKeyTypes asks a knownhosts verifier which key types it holds
// for addr, by offering a key that cannot match any of them: the mismatch
// error carries every entry the address matched. Nil when addr is unknown —
// which is what leaves a first connection under accept-new unconstrained.
func recordedHostKeyTypes(verify ssh.HostKeyCallback, addr string) []string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	unmatchable, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(verify(addr, probeAddr(addr), unmatchable), &keyErr) {
		return nil
	}
	var types []string
	for _, want := range keyErr.Want {
		if t := want.Key.Type(); !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	return types
}

// hostKeyAlgorithmsFor names every host key algorithm that yields a key of
// the given type as recorded in known_hosts. Feeds a set, so the order here
// carries no meaning — knownHostKeyAlgorithms decides that. known_hosts
// stores the key type, not the signature algorithm, so ssh-rsa covers the
// SHA-2 algorithms too, and must: advertising ssh-rsa alone would ask for the
// SHA-1 signature OpenSSH has disabled by default since 8.8.
func hostKeyAlgorithmsFor(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{
			ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01,
			ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA,
		}
	case ssh.KeyAlgoED25519:
		return []string{ssh.CertAlgoED25519v01, ssh.KeyAlgoED25519}
	case ssh.KeyAlgoECDSA256:
		return []string{ssh.CertAlgoECDSA256v01, ssh.KeyAlgoECDSA256}
	case ssh.KeyAlgoECDSA384:
		return []string{ssh.CertAlgoECDSA384v01, ssh.KeyAlgoECDSA384}
	case ssh.KeyAlgoECDSA521:
		return []string{ssh.CertAlgoECDSA521v01, ssh.KeyAlgoECDSA521}
	case ssh.InsecureKeyAlgoDSA: //nolint:staticcheck // matching a recorded entry, not endorsing it
		return []string{ssh.InsecureCertAlgoDSAv01, ssh.InsecureKeyAlgoDSA} //nolint:staticcheck
	default:
		// An algorithm this build does not know: let the defaults decide.
		return nil
	}
}

// acceptNew wraps a knownhosts verifier: unknown hosts are appended to the
// file and accepted; mismatched keys remain fatal.
func acceptNew(verify ssh.HostKeyCallback, path string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
			// Wrong key for a known host (or an unrelated failure): fatal.
			return err
		}
		f, ferr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if ferr != nil {
			return fmt.Errorf("append to known_hosts: %w", ferr)
		}
		defer f.Close()
		line := knownhosts.Normalize(hostname) + " " + key.Type() + " " +
			base64.StdEncoding.EncodeToString(key.Marshal()) + "\n"
		if _, ferr := f.WriteString(line); ferr != nil {
			return fmt.Errorf("append to known_hosts: %w", ferr)
		}
		// Show the fingerprint like OpenSSH's accept-new does, so the trust
		// decision is at least visible and verifiable out of band.
		fmt.Fprintf(os.Stderr, "gosh: permanently added %s (%s %s) to known hosts\r\n",
			hostname, key.Type(), ssh.FingerprintSHA256(key))
		return nil
	}
}
