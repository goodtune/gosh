// Package network implements the client side of mosh's datagram layer: sealed
// UDP packets with sequence numbers, direction bits, timestamp echoes for RTT
// estimation, and replay protection.
package network

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goodtune/gosh/internal/crypto"
)

const (
	// DefaultSendMTU mirrors mosh's DEFAULT_SEND_MTU.
	DefaultSendMTU = 500
	// AddedBytes is the datagram overhead added by this layer: the 8-byte
	// nonce tail plus the two 16-bit timestamps.
	AddedBytes = 8 + 4

	receiveMTU = 2048

	minRTO = 50 * time.Millisecond
	maxRTO = 1000 * time.Millisecond
)

// ErrOldSequence marks a datagram dropped by replay protection; callers treat
// it as silence, not failure.
var ErrOldSequence = errors.New("network: stale sequence number")

// Connection is the client end of a mosh session: one UDP socket aimed at the
// server. Safe for the client's split of one sending goroutine (which also
// reads SRTT/Timeout via the transport sender) and one receiving goroutine:
// the shared link state is guarded by mu.
//
// The socket is redialed transparently on a send failure: on Windows, a
// connected UDP socket's cached route/interface goes stale across a network
// blip (Wi-Fi <-> Ethernet switch, sleep/resume) and every subsequent send
// fails with WSAEINVAL until the socket is recreated — POSIX sockets don't
// exhibit this, but redialing is a harmless no-op for them. sockMu is
// separate from mu so a redial never blocks Recv's SRTT/Timeout callers.
type Connection struct {
	raddr *net.UDPAddr

	sockMu sync.RWMutex // guards sock across the redial swap
	sock   *net.UDPConn

	closed atomic.Bool

	session *crypto.Session

	mu sync.Mutex // guards all mutable state below

	nextSeq             uint64
	expectedReceiverSeq uint64

	savedTimestamp           uint16
	savedTimestampReceivedAt time.Time
	haveSavedTimestamp       bool

	rttHit bool
	srtt   float64 // ms
	rttvar float64 // ms

	lastHeard time.Time
}

// Dial creates the connection. addr is the server's UDP address ("host:port").
func Dial(addr string, key crypto.Base64Key) (*Connection, error) {
	session, err := crypto.NewSession(key)
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", addr, err)
	}
	sock, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	return &Connection{
		raddr:   udpAddr,
		sock:    sock,
		session: session,
		srtt:    1000,
		rttvar:  500,
	}, nil
}

// Close releases the socket. Recv calls already in flight on a socket that
// redial subsequently replaced return their own net.ErrClosed; callers must
// use Closed, not that error, to tell intentional shutdown from a redial.
func (c *Connection) Close() error {
	c.closed.Store(true)
	return c.currentSock().Close()
}

// Closed reports whether Close has been called. Distinguishes an
// intentional shutdown from the transient net.ErrClosed a Recv call can
// observe when redial swaps out the socket it was reading from.
func (c *Connection) Closed() bool { return c.closed.Load() }

func (c *Connection) currentSock() *net.UDPConn {
	c.sockMu.RLock()
	defer c.sockMu.RUnlock()
	return c.sock
}

// redial replaces the socket with a freshly dialed one to the same remote
// address, closing the old one. Safe to call concurrently with Recv, which
// always reads c.sock through currentSock.
func (c *Connection) redial() error {
	newSock, err := net.DialUDP("udp", nil, c.raddr)
	if err != nil {
		return err
	}
	c.sockMu.Lock()
	old := c.sock
	c.sock = newSock
	c.sockMu.Unlock()
	old.Close()
	return nil
}

// Send seals and transmits one transport payload. Send and Close must only
// ever be called from the same single goroutine (the transport sender's, per
// package client) — redial's socket swap is unsynchronized against itself,
// only against the separate Recv goroutine's reads via sockMu.
func (c *Connection) Send(payload []byte) error {
	now := time.Now()
	c.mu.Lock()
	reply := tsMissing
	if c.haveSavedTimestamp && now.Sub(c.savedTimestampReceivedAt) < time.Second {
		// Echo the received timestamp advanced by our hold time.
		reply = c.savedTimestamp + uint16(now.Sub(c.savedTimestampReceivedAt).Milliseconds())
		if reply == tsMissing { // never collide with the "no reply" sentinel
			reply++
		}
		c.haveSavedTimestamp = false
	}
	p := Packet{
		Seq:            c.nextSeq,
		Direction:      ToServer,
		Timestamp:      timestamp16(now),
		TimestampReply: reply,
		Payload:        payload,
	}
	c.nextSeq++
	c.mu.Unlock()
	wire, err := c.session.Encrypt(p.toMessage())
	if err != nil {
		return err
	}
	_, err = c.currentSock().Write(wire)
	if err == nil || c.closed.Load() {
		return err
	}
	// Likely a stale cached route after a network blip (Windows: WSAEINVAL).
	// Redial and retry once before giving up.
	if rerr := c.redial(); rerr != nil {
		return errors.Join(err, rerr)
	}
	_, err = c.currentSock().Write(wire)
	return err
}

// Recv waits up to timeout for one datagram and returns its transport
// payload. Returns net timeout errors unchanged (callers poll), ErrOldSequence
// for replayed/reordered-stale packets, and crypto errors for forgeries —
// all of which the caller should treat as "nothing arrived".
func (c *Connection) Recv(timeout time.Duration) ([]byte, error) {
	sock := c.currentSock()
	if err := sock.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, receiveMTU)
	n, err := sock.Read(buf)
	if err != nil {
		return nil, err
	}
	msg, err := c.session.Decrypt(buf[:n])
	if err != nil {
		return nil, err
	}
	p, err := packetFromMessage(msg)
	if err != nil {
		return nil, err
	}
	if p.Direction != ToClient {
		return nil, errors.New("network: server sent client-direction packet")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.Seq < c.expectedReceiverSeq {
		// Replay or heavy reordering: drop, exactly like mosh.
		return nil, ErrOldSequence
	}
	c.expectedReceiverSeq = p.Seq + 1

	now := time.Now()
	c.lastHeard = now
	c.savedTimestamp = p.Timestamp
	c.savedTimestampReceivedAt = now
	c.haveSavedTimestamp = true

	if p.TimestampReply != tsMissing {
		r := float64(timestampDiff(timestamp16(now), p.TimestampReply))
		if !c.rttHit { // first measurement
			c.srtt = r
			c.rttvar = r / 2
			c.rttHit = true
		} else {
			const alpha, beta = 1.0 / 8.0, 1.0 / 4.0
			c.rttvar = (1-beta)*c.rttvar + beta*math.Abs(c.srtt-r)
			c.srtt = (1-alpha)*c.srtt + alpha*r
		}
	}
	return p.Payload, nil
}

// SRTT returns the smoothed round-trip estimate in milliseconds.
func (c *Connection) SRTT() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.srtt
}

// Timeout returns the retransmission timeout (RFC 6298 shape, mosh clamps).
func (c *Connection) Timeout() time.Duration {
	c.mu.Lock()
	rto := time.Duration(math.Ceil(c.srtt+4*c.rttvar)) * time.Millisecond
	c.mu.Unlock()
	if rto < minRTO {
		return minRTO
	}
	if rto > maxRTO {
		return maxRTO
	}
	return rto
}

// LastHeard reports when a valid server datagram last arrived (zero until the
// first one).
func (c *Connection) LastHeard() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHeard
}

// MTU returns the payload budget for the transport layer.
func (c *Connection) MTU() int {
	return DefaultSendMTU - AddedBytes - crypto.AddedBytes
}
