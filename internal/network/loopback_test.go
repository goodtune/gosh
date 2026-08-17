package network

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/goodtune/gosh/internal/crypto"
)

// loopbackServer is a minimal mosh "server" datagram endpoint for tests: it
// decrypts client packets, surfaces payloads, and seals replies (including a
// deliberate replay for the stale-sequence test).
type loopbackServer struct {
	addr       string
	received   chan []byte
	reply      chan []byte
	replayLast chan struct{}
}

func newLoopbackServer(t *testing.T, key crypto.Base64Key) (*loopbackServer, error) {
	t.Helper()
	session, err := crypto.NewSession(key)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { sock.Close() })

	s := &loopbackServer{
		addr:       sock.LocalAddr().String(),
		received:   make(chan []byte, 16),
		reply:      make(chan []byte, 16),
		replayLast: make(chan struct{}, 1),
	}

	var seq uint64
	var lastWire []byte
	var mu sync.Mutex // guards clientAddr across the two goroutines
	var clientAddr net.Addr
	seal := func(payload []byte) []byte {
		text := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint16(text[0:2], 100)
		binary.BigEndian.PutUint16(text[2:4], 0xFFFF)
		copy(text[4:], payload)
		wire, err := session.Encrypt(crypto.Message{NonceVal: uint64(1)<<63 | seq, Text: text})
		if err != nil {
			t.Errorf("server seal: %v", err)
			return nil
		}
		seq++
		return wire
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := sock.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = from
			mu.Unlock()
			msg, err := session.Decrypt(buf[:n])
			if err != nil || len(msg.Text) < 4 {
				continue
			}
			s.received <- append([]byte(nil), msg.Text[4:]...)
		}
	}()
	go func() {
		for {
			select {
			case payload, ok := <-s.reply:
				if !ok {
					return
				}
				lastWire = seal(payload)
				mu.Lock()
				to := clientAddr
				mu.Unlock()
				if to != nil && lastWire != nil {
					sock.WriteTo(lastWire, to) //nolint:errcheck
				}
			case <-s.replayLast:
				mu.Lock()
				to := clientAddr
				mu.Unlock()
				if to != nil && lastWire != nil {
					sock.WriteTo(lastWire, to) //nolint:errcheck
				}
			}
		}
	}()
	return s, nil
}
