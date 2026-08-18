package bootstrap

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testMoshKey is a syntactically valid MOSH CONNECT session key.
const testMoshKey = "zr0jtuYVKJnfJHP/XOOsbQ"

// testSigner returns a fresh host key signer of the named type.
func testSigner(t *testing.T, keyType string) ssh.Signer {
	t.Helper()
	var key any
	switch keyType {
	case ssh.KeyAlgoED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = priv
	case ssh.KeyAlgoECDSA256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = priv
	default:
		t.Fatalf("unhandled key type %q", keyType)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startFakeSSHServer runs an sshd stand-in on localhost offering every given
// host key, accepting any password, and answering one exec request with a
// MOSH CONNECT line — enough for Run to complete. Returns its port.
//
// The point is the host key set: a real sshd offers several types at once,
// which is the situation where the client's algorithm preference decides
// which one the user is asked to verify.
func startFakeSSHServer(t *testing.T, signers ...ssh.Signer) int {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	for _, s := range signers {
		cfg.AddHostKey(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSSH(conn, cfg)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveFakeSSH(conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "session only") //nolint:errcheck
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range chReqs {
				if req.Type != "exec" {
					req.Reply(false, nil) //nolint:errcheck
					continue
				}
				req.Reply(true, nil)                                           //nolint:errcheck
				ch.Write([]byte("MOSH CONNECT 60001 " + testMoshKey + "\r\n")) //nolint:errcheck
				ch.SendRequest("exit-status", false,                           //nolint:errcheck
					ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}

// TestRunPrefersRecordedHostKeyAlgorithm is the end-to-end regression test
// for the reported failure, and covers the wiring that the unit tests around
// knownHostKeyAlgorithms cannot: that Run actually passes the derived
// preference into the client config.
//
// The server offers ECDSA and Ed25519, as a stock sshd does. known_hosts
// holds only the Ed25519 key — the ordinary result of `ssh-keyscan` or of a
// first connection recorded by OpenSSH. x/crypto's fixed preference puts
// ssh-ed25519 last, so without the fix the server is asked for its ECDSA key,
// known_hosts has no line for it, and the connection dies with a key mismatch
// even though the recorded key is present and correct.
func TestRunPrefersRecordedHostKeyAlgorithm(t *testing.T) {
	ed := testSigner(t, ssh.KeyAlgoED25519)
	port := startFakeSSHServer(t, testSigner(t, ssh.KeyAlgoECDSA256), ed)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// Only the Ed25519 key is recorded, exactly as ssh-keyscan would leave it.
	path := writeKnownHosts(t, addr, ed.PublicKey())
	verify, err := HostKeyCallback(PolicyStrict, path)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Run(Options{
		User:            "gosh",
		Host:            "127.0.0.1",
		SSHPort:         port,
		Auth:            []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: verify,
		KnownHostsPath:  path,
	})
	if err != nil {
		if strings.Contains(err.Error(), "key mismatch") {
			t.Fatalf("host known under ed25519 rejected as a key mismatch — the server was asked for an algorithm the user has no line for: %v", err)
		}
		t.Fatalf("Run: %v", err)
	}
	if res.Port != 60001 {
		t.Errorf("Port = %d, want 60001", res.Port)
	}
}

// TestRunUnknownHostStillAcceptsNew guards the other direction: deriving a
// preference must not disturb a first connection, where there is nothing
// recorded to prefer and accept-new has to be free to record whatever the
// server offers.
func TestRunUnknownHostStillAcceptsNew(t *testing.T) {
	port := startFakeSSHServer(t, testSigner(t, ssh.KeyAlgoECDSA256), testSigner(t, ssh.KeyAlgoED25519))

	path := writeKnownHosts(t, "unrelated.example.com:22", testHostKey(t, ssh.KeyAlgoED25519))
	verify, err := HostKeyCallback(PolicyAcceptNew, path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Run(Options{
		User:            "gosh",
		Host:            "127.0.0.1",
		SSHPort:         port,
		Auth:            []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: verify,
		KnownHostsPath:  path,
	}); err != nil {
		t.Fatalf("accept-new on an unknown host: %v", err)
	}

	// A nil error alone would also be satisfied by never verifying at all;
	// the recorded line is what proves accept-new ran.
	recorded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := knownhosts.Normalize(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); !strings.Contains(string(recorded), want) {
		t.Errorf("accept-new recorded no line for %s:\n%s", want, recorded)
	}
}

// hostCertSigner returns a signer presenting host as a certificate of
// signer's key, issued by ca.
func hostCertSigner(t *testing.T, ca, host ssh.Signer, principals ...string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             host.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "test-host",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return certSigner
}

// TestRunCertAuthorityHostStillVerifies is the regression test for the
// certs-before-plain partition. The server presents an ECDSA host
// *certificate* issued by an Ed25519 CA, and also holds a plain Ed25519 host
// key; known_hosts trusts only the CA, via a @cert-authority line.
//
// knownhosts surfaces that CA line's key through the same KeyError.Want as a
// plain entry, so the derivation sees "ed25519 is recorded" and cannot know
// it was a CA. Promoting plain ssh-ed25519 above the remaining certificate
// algorithms — the obvious simplification — makes the server hand over its
// plain Ed25519 key, which no line covers, and the connection dies with the
// same "key mismatch" this whole change exists to prevent. Keeping every
// certificate algorithm ahead of every plain one is what avoids that.
func TestRunCertAuthorityHostStillVerifies(t *testing.T) {
	ca := testSigner(t, ssh.KeyAlgoED25519)
	hostCert := hostCertSigner(t, ca, testSigner(t, ssh.KeyAlgoECDSA256), "127.0.0.1")
	// The plain Ed25519 key is the trap: it matches the CA's *type*, so a
	// derivation that ranks by type alone would steer the server to it.
	port := startFakeSSHServer(t, hostCert, testSigner(t, ssh.KeyAlgoED25519))
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	path := filepath.Join(t.TempDir(), "known_hosts")
	line := "@cert-authority " + knownhosts.Line([]string{addr}, ca.PublicKey())
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verify, err := HostKeyCallback(PolicyStrict, path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Run(Options{
		User:            "gosh",
		Host:            "127.0.0.1",
		SSHPort:         port,
		Auth:            []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: verify,
		KnownHostsPath:  path,
	}); err != nil {
		t.Fatalf("@cert-authority host rejected — a plain algorithm was preferred over the certificate ones: %v", err)
	}
}
