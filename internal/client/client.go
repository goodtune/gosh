// Package client runs an interactive mosh session: it pumps local input into
// the synchronized UserStream, applies server terminal diffs to stdout, and
// drives the transport timers until either side shuts down.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/goodtune/gosh/internal/crypto"
	"github.com/goodtune/gosh/internal/network"
	"github.com/goodtune/gosh/internal/osc52"
	"github.com/goodtune/gosh/internal/transport"
	"github.com/goodtune/gosh/internal/wire"
)

// escapeKey is mosh's default escape character, Ctrl-^ (0x1E). escapeKey
// followed by '.' ends the session; a doubled escapeKey sends it literally.
const escapeKey = 0x1E

// Config wires a Session.
type Config struct {
	// Addr is the server's UDP "host:port".
	Addr string
	// Key is the session key from the bootstrap.
	Key crypto.Base64Key

	// Input delivers local user input (stdin). EOF stops input processing
	// without ending the session — the remote side decides when it is over.
	Input io.Reader
	// Output receives terminal bytes from the server (stdout).
	Output io.Writer

	// Size reports the current terminal dimensions.
	Size func() (width, height int)
	// Resized signals that Size changed (SIGWINCH or poller); may be nil.
	Resized <-chan struct{}

	// DisableEscape turns off Ctrl-^ escape processing (scripted sessions).
	DisableEscape bool

	// Clipboard is the OSC 52 policy applied to terminal bytes from the
	// server. The zero value forwards clipboard writes and refuses clipboard
	// read queries.
	Clipboard osc52.Policy

	// ShutdownTimeout bounds the closing handshake (default 3s).
	ShutdownTimeout time.Duration
}

// Session is one running mosh connection.
type Session struct {
	cfg  Config
	conn *network.Connection
	tr   *transport.Transport

	// clip and out belong to the diff-applying path, which runs on the one
	// goroutine that calls transport.Transport.Recv; out is reused across
	// diffs so a filtered write costs no per-diff allocation.
	clip *osc52.Filter
	out  []byte
}

// New dials the server and prepares the session.
func New(cfg Config) (*Session, error) {
	if cfg.Size == nil {
		cfg.Size = func() (int, int) { return 80, 24 }
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 3 * time.Second
	}
	conn, err := network.Dial(cfg.Addr, cfg.Key)
	if err != nil {
		return nil, err
	}
	s := &Session{cfg: cfg, conn: conn, clip: osc52.New(cfg.Clipboard)}
	s.tr = transport.New(conn, s.apply)
	return s, nil
}

// apply renders one server diff: terminal bytes go to Output as they came
// (the diff language *is* the terminal's escape-sequence language) except for
// OSC 52 clipboard sequences, which the configured policy may rewrite or
// drop; resizes and echo acks are bookkeeping only.
func (s *Session) apply(diff []byte) error {
	events, err := wire.UnmarshalHostMessage(diff)
	if err != nil {
		return fmt.Errorf("client: bad host message: %w", err)
	}
	for _, ev := range events {
		if len(ev.Bytes) == 0 {
			continue
		}
		s.out = s.clip.Filter(s.out[:0], ev.Bytes)
		if len(s.out) == 0 {
			continue
		}
		if _, err := s.cfg.Output.Write(s.out); err != nil {
			return err
		}
	}
	return nil
}

// Run drives the session until shutdown (local escape, remote exit, or
// context cancellation). It always releases the socket.
func (s *Session) Run(ctx context.Context) error {
	defer s.conn.Close()

	// The first synchronized event must be the terminal size, so the server
	// lays out the session for the real window from frame one.
	w, h := s.cfg.Size()
	s.tr.UserStream().PushResize(w, h)

	// sessionDone unblocks the pump goroutines when Run returns.
	sessionDone := make(chan struct{})
	defer close(sessionDone)

	input := make(chan []byte, 32)
	if s.cfg.Input != nil {
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := s.cfg.Input.Read(buf)
				if n > 0 {
					select {
					case input <- append([]byte(nil), buf[:n]...):
					case <-sessionDone:
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}

	datagrams := make(chan []byte, 32)
	go func() {
		for {
			payload, err := s.conn.Recv(250 * time.Millisecond)
			if err != nil {
				if s.conn.Closed() {
					return
				}
				// Everything else — read timeouts, replayed sequence numbers,
				// forged or garbled datagrams — is noise on an open UDP port;
				// drop it and keep listening.
				continue
			}
			select {
			case datagrams <- payload:
			case <-sessionDone:
				return
			}
		}
	}()

	var (
		escapePending bool
		quitRequested bool
		shutdownFrom  time.Time
		fatal         error
	)

	timer := time.NewTimer(0)
	defer timer.Stop()

	// ctxDone is nilled once cancellation is handled, so the closed channel
	// doesn't win every subsequent select and busy-spin the shutdown loop.
	ctxDone := ctx.Done()

	for {
		// Let the sender do any due work, then sleep until its next deadline.
		//
		// Tick's only failure mode is network.Connection.Send (a UDP write),
		// which already retried once via a socket redial. A link that's down
		// for longer than that must not end the session: the sentStates
		// bookkeeping behind the failed send still advanced as if it went
		// out, so the sender's own retransmission timers retry the same
		// state on a later tick, exactly like a lost UDP packet — the same
		// "retry indefinitely" treatment as every other transient network
		// condition here.
		_ = s.tr.Sender.Tick()

		if s.tr.RemoteShutdown() && !s.tr.Sender.ShutdownInProgress() {
			s.tr.Sender.StartShutdown()
			shutdownFrom = time.Now()
		}
		if s.tr.Sender.ShutdownInProgress() {
			if s.tr.Sender.ShutdownAcknowledged() || s.tr.Sender.ShutdownAckTimedOut() ||
				time.Since(shutdownFrom) > s.cfg.ShutdownTimeout {
				return fatal
			}
		}

		wait := s.tr.Sender.WaitTime(time.Now())
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		if wait > 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		select {
		case <-ctxDone:
			ctxDone = nil
			quitRequested = true
			s.tr.Sender.StartShutdown()
			shutdownFrom = time.Now()
			fatal = ctx.Err()
		case b := <-input:
			keys := b
			if !s.cfg.DisableEscape {
				keys, quitRequested = s.processEscapes(b, &escapePending)
			}
			if len(keys) > 0 {
				s.tr.UserStream().PushKeys(keys)
			}
			if quitRequested && !s.tr.Sender.ShutdownInProgress() {
				s.tr.Sender.StartShutdown()
				shutdownFrom = time.Now()
			}
		case payload := <-datagrams:
			if err := s.tr.Recv(payload); err != nil {
				if errors.Is(err, transport.ErrVersionMismatch) {
					return err
				}
				// Any other decode failure is a malformed datagram; drop it.
			}
		case <-s.resized():
			w, h := s.cfg.Size()
			s.tr.UserStream().PushResize(w, h)
		case <-timer.C:
		}
	}
}

func (s *Session) resized() <-chan struct{} {
	if s.cfg.Resized != nil {
		return s.cfg.Resized
	}
	return nil
}

// processEscapes filters the escape sequence out of an input chunk. Returns
// the bytes to forward and whether a quit was requested.
func (s *Session) processEscapes(b []byte, pending *bool) (out []byte, quit bool) {
	out = make([]byte, 0, len(b))
	for _, c := range b {
		if *pending {
			*pending = false
			switch c {
			case '.':
				return out, true
			case escapeKey:
				out = append(out, escapeKey)
			default:
				out = append(out, escapeKey, c)
			}
			continue
		}
		if c == escapeKey {
			*pending = true
			continue
		}
		out = append(out, c)
	}
	return out, false
}
