// Package crypto implements the mosh datagram sealing layer: a base64 session
// key from mosh-server, AES-128-OCB3 encryption, and the 12-byte nonce scheme
// (4 zero bytes + big-endian uint64 whose top bit is the direction and whose
// low 63 bits are the packet sequence number).
package crypto

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/goodtune/gosh/internal/ocb"
)

// AddedBytes is the per-datagram crypto overhead: the 16-byte OCB tag.
// (The 8-byte nonce tail is counted by the network layer.)
const AddedBytes = 16

// Base64Key is the 16-byte session key mosh-server prints after MOSH CONNECT,
// encoded as 22 base64 characters without padding.
type Base64Key [16]byte

// ParseBase64Key decodes the 22-character unpadded base64 key string.
func ParseBase64Key(s string) (Base64Key, error) {
	var k Base64Key
	if len(s) != 22 {
		return k, fmt.Errorf("key must be 22 base64 characters, got %d", len(s))
	}
	b, err := base64.StdEncoding.DecodeString(s + "==")
	if err != nil {
		return k, fmt.Errorf("invalid base64 key: %w", err)
	}
	copy(k[:], b)
	// Reject keys whose trailing padding bits are non-zero: they would
	// re-encode differently, which means the input wasn't a canonical key.
	if base64.StdEncoding.EncodeToString(k[:])[:22] != s {
		return k, errors.New("non-canonical base64 key")
	}
	return k, nil
}

// String re-encodes the key in mosh's unpadded form.
func (k Base64Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])[:22]
}

// Message is a sealed unit: an 8-byte nonce value (direction|seq) and the
// plaintext or ciphertext body.
type Message struct {
	NonceVal uint64
	Text     []byte
}

// Session seals and opens datagrams under one key. It is not safe for
// concurrent use; the client serializes all network I/O on one goroutine.
type Session struct {
	cipher *ocb.Cipher
}

// NewSession creates a session from a parsed key.
func NewSession(key Base64Key) (*Session, error) {
	c, err := ocb.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Session{cipher: c}, nil
}

func nonceBytes(val uint64) []byte {
	n := make([]byte, ocb.NonceLen)
	binary.BigEndian.PutUint64(n[4:], val)
	return n
}

// Encrypt seals a message: output is the 8-byte big-endian nonce value
// followed by the OCB ciphertext and tag.
func (s *Session) Encrypt(m Message) ([]byte, error) {
	n := nonceBytes(m.NonceVal)
	out := make([]byte, 8, 8+len(m.Text)+ocb.TagLen)
	copy(out, n[4:])
	return s.cipher.Seal(out, n, m.Text)
}

// ErrShortDatagram is returned for datagrams too short to carry a nonce+tag.
var ErrShortDatagram = errors.New("crypto: datagram too short")

// Decrypt opens a sealed datagram.
func (s *Session) Decrypt(b []byte) (Message, error) {
	if len(b) < 8+ocb.TagLen {
		return Message{}, ErrShortDatagram
	}
	var m Message
	m.NonceVal = binary.BigEndian.Uint64(b[:8])
	text, err := s.cipher.Open(nil, nonceBytes(m.NonceVal), b[8:])
	if err != nil {
		return Message{}, err
	}
	m.Text = text
	return m, nil
}
