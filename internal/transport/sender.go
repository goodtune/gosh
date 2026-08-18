package transport

import (
	"crypto/rand"
	"time"

	"github.com/goodtune/gosh/internal/statesync"
	"github.com/goodtune/gosh/internal/wire"
)

// Timing constants, milliseconds — mirrors transportsender.h.
const (
	sendIntervalMin = 20 * time.Millisecond
	sendIntervalMax = 250 * time.Millisecond
	ackInterval     = 3000 * time.Millisecond
	ackDelay        = 100 * time.Millisecond
	sendMindelay    = 8 * time.Millisecond
	shutdownRetries = 16

	// maxSendBurst bounds how long sendInFragments keeps attempting
	// fragments for one instruction. Tick runs synchronously on
	// client.Session.Run's single goroutine, the same one that reads local
	// keystrokes and the quit escape sequence, so a diff that fragments
	// into many pieces must not multiply each fragment's own worst-case
	// network latency (network.Connection.Send's dial/write timeouts) by
	// the fragment count. Fragments dropped by the deadline are retried
	// whole on the next scheduled retransmission — exactly like fragments
	// lost to the network already are, which the protocol already handles.
	maxSendBurst = 3 * time.Second
)

// ProtocolVersion is MOSH_PROTOCOL_VERSION (2, "bumped for echo-ack").
const ProtocolVersion = 2

// ShutdownNum is the state number that signals connection shutdown.
const ShutdownNum = ^uint64(0)

// timestampedState pairs a sent UserStream snapshot with its number and the
// time it was last transmitted.
type timestampedState struct {
	sentAt time.Time
	num    uint64
	state  *statesync.UserStream
}

// senderConn is the slice of Connection the sender needs; a seam for tests.
type senderConn interface {
	Send(payload []byte) error
	SRTT() float64
	Timeout() time.Duration
	MTU() int
	SetLastRoundtripSuccess(t time.Time)
}

// sender drives outgoing state synchronization: it decides when to send
// diffs, empty acks, and retransmissions, and prunes acknowledged states.
// A direct port of mosh's TransportSender<UserStream>.
type sender struct {
	conn         senderConn
	currentState *statesync.UserStream
	sentStates   []timestampedState // front = known-received state

	assumedReceiverStateIdx int

	fragmenter fragmenter

	nextAckTime  time.Time
	nextSendTime time.Time
	haveSendTime bool

	shutdownInProgress bool
	shutdownTries      int
	shutdownStart      time.Time

	ackNum         uint64
	pendingDataAck bool
	mindelayClock  time.Time
	haveMindelay   bool
}

func newSender(conn senderConn) *sender {
	initial := &statesync.UserStream{}
	return &sender{
		conn:         conn,
		currentState: initial.Clone(),
		sentStates:   []timestampedState{{sentAt: time.Now(), num: 0, state: initial}},
		nextAckTime:  time.Now(),
	}
}

// State returns the mutable current outgoing state.
func (s *sender) State() *statesync.UserStream { return s.currentState }

// RemoteHeard records when the remote last spoke (delays empty acks).
func (s *sender) RemoteHeard(t time.Time) { /* informational in this port */ }

// NoteRoundtripSuccess reports a confirmed end-to-end round trip to the
// connection layer, timestamped to when the now-acknowledged state was
// originally sent (sentStates[0], the known-received front, right after
// ProcessAcknowledgmentThrough) rather than "now" — mirrors mosh's
// sender.get_sent_state_acked_timestamp() fed to
// Connection::set_last_roundtrip_success in networktransport-impl.h's
// recv(). The caller (transport.Transport.Recv) calls this on every
// accepted instruction, matching mosh's placement right after
// process_acknowledgment_through.
func (s *sender) NoteRoundtripSuccess() {
	s.conn.SetLastRoundtripSuccess(s.sentStates[0].sentAt)
}

// SetAckNum records the newest remote state to acknowledge. Monotonic: an
// ack must never regress (mosh acks the back of its sorted receive queue;
// the transport's acceptance rule makes regressions impossible anyway, this
// guard keeps the invariant local).
func (s *sender) SetAckNum(n uint64) {
	if n > s.ackNum {
		s.ackNum = n
	}
}

// SetDataAck notes that we owe the server a prompt ack for real data.
func (s *sender) SetDataAck() { s.pendingDataAck = true }

func (s *sender) sendInterval() time.Duration {
	iv := time.Duration(s.conn.SRTT()/2+0.5) * time.Millisecond
	if iv < sendIntervalMin {
		return sendIntervalMin
	}
	if iv > sendIntervalMax {
		return sendIntervalMax
	}
	return iv
}

// updateAssumedReceiverState picks the newest sent state transmitted recently
// enough to give the benefit of the doubt.
func (s *sender) updateAssumedReceiverState(now time.Time) {
	s.assumedReceiverStateIdx = 0
	for i := 1; i < len(s.sentStates); i++ {
		if now.Sub(s.sentStates[i].sentAt) < s.conn.Timeout()+ackDelay {
			s.assumedReceiverStateIdx = i
		} else {
			return
		}
	}
}

// rationalizeStates cuts the known-received prefix out of every retained
// state so diffs stay small.
func (s *sender) rationalizeStates() {
	known := s.sentStates[0].state
	s.currentState.Subtract(known)
	for i := len(s.sentStates) - 1; i >= 0; i-- {
		s.sentStates[i].state.Subtract(known)
	}
}

func (s *sender) calculateTimers(now time.Time) {
	s.updateAssumedReceiverState(now)
	s.rationalizeStates()

	if s.pendingDataAck && s.nextAckTime.After(now.Add(ackDelay)) {
		s.nextAckTime = now.Add(ackDelay)
	}

	back := &s.sentStates[len(s.sentStates)-1]
	if !s.currentState.Equal(back.state) {
		if !s.haveMindelay {
			s.mindelayClock = now
			s.haveMindelay = true
		}
		target := s.mindelayClock.Add(sendMindelay)
		wait := back.sentAt.Add(s.sendInterval())
		if wait.After(target) {
			target = wait
		}
		s.nextSendTime = target
		s.haveSendTime = true
	} else if !s.currentState.Equal(s.sentStates[s.assumedReceiverStateIdx].state) {
		// Sent but not yet given up on: pace at the send interval.
		s.nextSendTime = back.sentAt.Add(s.sendInterval())
		s.haveSendTime = true
	} else if !s.currentState.Equal(s.sentStates[0].state) {
		// Everything sent recently, but the receiver hasn't acked: schedule
		// a retransmission once the RTO (plus ack delay) elapses.
		s.nextSendTime = back.sentAt.Add(s.conn.Timeout() + ackDelay)
		s.haveSendTime = true
	} else {
		s.haveSendTime = false
	}

	if s.shutdownInProgress || s.ackNum == ShutdownNum {
		s.nextAckTime = back.sentAt.Add(s.sendInterval())
	}
}

// WaitTime returns how long the caller may sleep before the next tick.
func (s *sender) WaitTime(now time.Time) time.Duration {
	s.calculateTimers(now)
	next := s.nextAckTime
	if s.haveSendTime && s.nextSendTime.Before(next) {
		next = s.nextSendTime
	}
	if next.After(now) {
		return next.Sub(now)
	}
	return 0
}

// Tick sends a diff or empty ack if one is due.
func (s *sender) Tick() error {
	now := time.Now()
	s.calculateTimers(now)

	if now.Before(s.nextAckTime) && (!s.haveSendTime || now.Before(s.nextSendTime)) {
		return nil
	}

	diff := s.currentState.DiffFrom(s.sentStates[s.assumedReceiverStateIdx].state)

	if len(diff) == 0 {
		if !now.Before(s.nextAckTime) {
			if err := s.sendEmptyAck(now); err != nil {
				return err
			}
			s.haveMindelay = false
		}
		if s.haveSendTime && !now.Before(s.nextSendTime) {
			s.haveSendTime = false
			s.haveMindelay = false
		}
		return nil
	}
	if err := s.sendToReceiver(now, diff); err != nil {
		return err
	}
	s.haveMindelay = false
	return nil
}

func (s *sender) sendEmptyAck(now time.Time) error {
	newNum := s.sentStates[len(s.sentStates)-1].num + 1
	if s.shutdownInProgress {
		newNum = ShutdownNum
	}
	if err := s.sendInFragments(nil, newNum); err != nil {
		// Don't record a sent state for an attempt that never left the
		// wire, and don't leave nextAckTime in the past: calculateTimers
		// only ever advances nextAckTime from here or from the success
		// path below, so skipping this on failure — as the pre-fix code
		// did — pins it due forever and Tick retries (and re-appends to
		// sentStates) on every call, as fast as the caller loops.
		s.nextAckTime = now.Add(s.sendInterval())
		return err
	}
	s.addSentState(now, newNum, s.currentState.Clone())
	s.nextAckTime = now.Add(ackInterval)
	s.haveSendTime = false
	return nil
}

func (s *sender) addSentState(now time.Time, num uint64, state *statesync.UserStream) {
	s.sentStates = append(s.sentStates, timestampedState{sentAt: now, num: num, state: state})
	if len(s.sentStates) > 32 {
		// Erase one state from the middle of the queue, like mosh: keep the
		// front (known-received) and the 15 most recent (mosh erases the
		// element 16 from the end).
		eraseIdx := len(s.sentStates) - 16
		s.sentStates = append(s.sentStates[:eraseIdx], s.sentStates[eraseIdx+1:]...)
		// The erase shifts later indices down; keep assumedReceiverStateIdx
		// pointing at a valid, no-newer element (it is recomputed every
		// calculateTimers, but sendInFragments may read it before then).
		if s.assumedReceiverStateIdx >= eraseIdx && s.assumedReceiverStateIdx > 0 {
			s.assumedReceiverStateIdx--
		}
	}
}

func (s *sender) sendToReceiver(now time.Time, diff []byte) error {
	back := &s.sentStates[len(s.sentStates)-1]
	var newNum uint64
	if s.currentState.Equal(back.state) { // previously sent state
		newNum = back.num
	} else {
		newNum = back.num + 1
	}
	if s.shutdownInProgress {
		newNum = ShutdownNum
	}
	if newNum == back.num {
		// Retransmitting a state we've already accounted for: bump its
		// timestamp before attempting so calculateTimers paces the next
		// retry off it correctly even if this send fails (this is what
		// keeps the retransmit path from hot-looping the way sendEmptyAck
		// used to — see there).
		back.sentAt = now
	}
	if err := s.sendInFragments(diff, newNum); err != nil {
		return err
	}
	if newNum != back.num {
		// Only mint a new state number once the send actually succeeded —
		// an attempt that never left the wire must not commit sentStates,
		// same reasoning as the sendEmptyAck fix.
		s.addSentState(now, newNum, s.currentState.Clone())
	}
	s.assumedReceiverStateIdx = len(s.sentStates) - 1
	s.nextAckTime = now.Add(ackInterval)
	s.haveSendTime = false
	return nil
}

func makeChaff() []byte {
	var lenByte [1]byte
	rand.Read(lenByte[:]) //nolint:errcheck // crypto/rand.Read cannot fail
	n := int(lenByte[0]) % 17
	chaff := make([]byte, n)
	rand.Read(chaff) //nolint:errcheck
	return chaff
}

func (s *sender) sendInFragments(diff []byte, newNum uint64) error {
	inst := &wire.Instruction{
		ProtocolVersion: ProtocolVersion,
		OldNum:          s.sentStates[s.assumedReceiverStateIdx].num,
		NewNum:          newNum,
		AckNum:          s.ackNum,
		ThrowawayNum:    s.sentStates[0].num,
		Diff:            diff,
		Chaff:           makeChaff(),
	}
	if newNum == ShutdownNum {
		s.shutdownTries++
	}
	deadline := time.Now().Add(maxSendBurst)
	for _, f := range s.fragmenter.makeFragments(inst.Marshal(), s.conn.MTU()) {
		if time.Now().After(deadline) {
			// Over budget: leave the rest for the next retransmission
			// rather than blocking this Tick call further.
			break
		}
		if err := s.conn.Send(f.marshal()); err != nil {
			return err
		}
	}
	s.pendingDataAck = false
	return nil
}

// ProcessAcknowledgmentThrough discards sent states the receiver has
// acknowledged, keeping the acked state as the new known-received front.
func (s *sender) ProcessAcknowledgmentThrough(ackNum uint64) {
	for i := range s.sentStates {
		if s.sentStates[i].num == ackNum {
			kept := s.sentStates[i:]
			s.sentStates = append([]timestampedState(nil), kept...)
			s.assumedReceiverStateIdx = 0
			break
		}
	}
}

// StartShutdown begins the shutdown handshake.
func (s *sender) StartShutdown() {
	if !s.shutdownInProgress {
		s.shutdownStart = time.Now()
		s.shutdownInProgress = true
	}
}

// ShutdownInProgress reports whether StartShutdown has been called.
func (s *sender) ShutdownInProgress() bool { return s.shutdownInProgress }

// ShutdownAcknowledged reports whether the peer acked our shutdown state.
func (s *sender) ShutdownAcknowledged() bool {
	return s.shutdownInProgress && s.sentStates[0].num == ShutdownNum
}

// ShutdownAckTimedOut reports whether we retried the shutdown long enough.
func (s *sender) ShutdownAckTimedOut() bool {
	return s.shutdownInProgress && s.shutdownTries >= shutdownRetries
}
