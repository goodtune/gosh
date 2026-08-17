package bootstrap

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

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
