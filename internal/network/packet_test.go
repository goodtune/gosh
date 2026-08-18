package network

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/gosh/internal/crypto"
)

func TestPacketMessageRoundTrip(t *testing.T) {
	p := Packet{
		Seq:            42,
		Direction:      ToClient,
		Timestamp:      1234,
		TimestampReply: 777,
		Payload:        []byte("fragment bytes"),
	}
	got, err := packetFromMessage(p.toMessage())
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != p.Seq || got.Direction != p.Direction || got.Timestamp != p.Timestamp ||
		got.TimestampReply != p.TimestampReply || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("round trip: %+v vs %+v", got, p)
	}
}

func TestDirectionBitEncoding(t *testing.T) {
	server := Packet{Seq: 5, Direction: ToServer}
	if v := server.toMessage().NonceVal; v != 5 {
		t.Fatalf("ToServer nonce = %x, want 5", v)
	}
	client := Packet{Seq: 5, Direction: ToClient}
	if v := client.toMessage().NonceVal; v != 5|uint64(1)<<63 {
		t.Fatalf("ToClient nonce = %x", v)
	}
}

func TestShortMessageRejected(t *testing.T) {
	if _, err := packetFromMessage(crypto.Message{Text: []byte{1, 2, 3}}); err == nil {
		t.Fatal("3-byte message accepted")
	}
}

func TestTimestamp16AvoidsSentinel(t *testing.T) {
	// 0xFFFF means "no timestamp"; the clock value must never collide.
	at := time.UnixMilli(65535)
	if ts := timestamp16(at); ts == tsMissing {
		t.Fatal("timestamp16 produced the missing sentinel")
	}
	if d := timestampDiff(10, 0xFFF0); d != 26 {
		t.Fatalf("wraparound diff = %d, want 26", d)
	}
}

// TestLoopbackConnection exercises the sealed UDP path against a fake server
// implemented directly on a UDP socket with a second Session.
func TestLoopbackConnection(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.Send([]byte("hello server")); err != nil {
		t.Fatal(err)
	}
	got := <-server.received
	if string(got) != "hello server" {
		t.Fatalf("server got %q", got)
	}
	server.reply <- []byte("hello client")
	payload, err := conn.Recv(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "hello client" {
		t.Fatalf("client got %q", payload)
	}
	if conn.LastHeard().IsZero() {
		t.Fatal("LastHeard not updated")
	}

	// A replayed datagram (stale seq) must be dropped as ErrOldSequence.
	server.replayLast <- struct{}{}
	if _, err := conn.Recv(2 * time.Second); err != ErrOldSequence {
		t.Fatalf("replay: err = %v, want ErrOldSequence", err)
	}
}

// TestSendRedialsAfterSocketError reproduces the Windows network-blip bug: a
// connected UDP socket that starts failing every write (WSAEINVAL there,
// simulated here by closing the socket out from under Send) must not sink
// the session — Send should redial and keep going.
func TestSendRedialsAfterSocketError(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Simulate the stale-socket condition directly: close the live socket
	// without marking the Connection as intentionally closed.
	if err := conn.sock.Close(); err != nil {
		t.Fatal(err)
	}

	if err := conn.Send([]byte("still here")); err != nil {
		t.Fatalf("Send did not recover from a broken socket: %v", err)
	}
	if conn.Closed() {
		t.Fatal("redial must not mark the connection as closed")
	}

	select {
	case got := <-server.received:
		if string(got) != "still here" {
			t.Fatalf("server got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the redialed send")
	}
}

// TestSendHopsPortOnSilentBlackhole reproduces the reported unrecoverable
// case: writes never return an error (a route that blackholes rather than
// failing, which is what a Windows adapter can do after a network change),
// so the error-path redial in TestSendRedialsAfterSocketError never
// triggers. Send must still redial proactively once portHopInterval has
// passed with no confirmed round trip — mosh's PORT_HOP_INTERVAL — or the
// session is stuck forever.
func TestSendHopsPortOnSilentBlackhole(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	before := conn.currentSock().LocalAddr().String()

	// Backdate both timestamps past portHopInterval with no round trip ever
	// recorded (lastRoundtripSuccess stays zero, i.e. "never") — the exact
	// state a session reaches after a silent blackhole.
	conn.mu.Lock()
	conn.lastPortChoice = time.Now().Add(-portHopInterval - time.Second)
	conn.mu.Unlock()

	if err := conn.Send([]byte("probe")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	after := conn.currentSock().LocalAddr().String()
	if after == before {
		t.Fatalf("Send did not hop port after a silent blackhole: still on %s", before)
	}

	select {
	case got := <-server.received:
		if string(got) != "probe" {
			t.Fatalf("server got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the send from the hopped port")
	}
}

// TestSendDoesNotHopPortAfterRecentRoundtrip guards the other half of the
// AND condition: a stale lastPortChoice alone must not trigger a hop while
// round trips are still succeeding — otherwise a perfectly healthy,
// long-lived session would needlessly re-home its port every 10 seconds.
func TestSendDoesNotHopPortAfterRecentRoundtrip(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	before := conn.currentSock().LocalAddr().String()

	conn.mu.Lock()
	conn.lastPortChoice = time.Now().Add(-portHopInterval - time.Second)
	conn.lastRoundtripSuccess = time.Now()
	conn.mu.Unlock()

	if err := conn.Send([]byte("probe")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if after := conn.currentSock().LocalAddr().String(); after != before {
		t.Fatalf("Send hopped port despite a recent round trip: %s -> %s", before, after)
	}
}

// TestSendDoesNotHopPortRightAfterOwnHop covers the realistic state right
// after Dial (or a previous hop): lastPortChoice is recent but no round trip
// has confirmed the port yet (lastRoundtripSuccess still zero, "never").
// Only a stale lastPortChoice — not lastRoundtripSuccess alone — may trigger
// a hop, or a session would re-home its port every call until the first ack
// ever arrives.
func TestSendDoesNotHopPortRightAfterOwnHop(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	before := conn.currentSock().LocalAddr().String()
	// lastPortChoice is whatever Dial just set it to (recent); lastRoundtripSuccess
	// is still the zero value. Send should not hop.
	if err := conn.Send([]byte("probe")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if after := conn.currentSock().LocalAddr().String(); after != before {
		t.Fatalf("Send hopped port right after Dial, before lastPortChoice was even stale: %s -> %s", before, after)
	}
}

// TestSendDoesNotDoubleRedialAfterHopping is the regression test for the
// worst-case-latency finding on the port-hop fix: maybeHopPort's proactive
// redial and Send's error-path redial-and-retry must not both run in the
// same call, or Send's worst case doubles from ~2.5s to ~4s — over
// client.Config.ShutdownTimeout's 3s default (see dialTimeout's doc
// comment). Every dial in this test hands back an already-closed socket, so
// a write on it always fails; if Send redialed twice, rawDialUDP would be
// called twice.
func TestSendDoesNotDoubleRedialAfterHopping(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.mu.Lock()
	conn.lastPortChoice = time.Now().Add(-portHopInterval - time.Second)
	conn.mu.Unlock()

	var dials int32
	real := rawDialUDP
	rawDialUDP = func(raddr *net.UDPAddr) (*net.UDPConn, error) {
		atomic.AddInt32(&dials, 1)
		sock, err := real(raddr)
		if err != nil {
			return nil, err
		}
		sock.Close() // dead on arrival: every dial in this test yields an already-broken socket
		return sock, nil
	}
	t.Cleanup(func() { rawDialUDP = real })

	if err := conn.Send([]byte("probe")); err == nil {
		t.Fatal("Send succeeded despite every dial producing a dead socket")
	}
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("Send dialed %d times in one call after already hopping, want 1 (proactive hop and error-path redial must not both run)", got)
	}
}

// hangRawDialUDP replaces the package-level rawDialUDP with a fake that
// blocks until the test is done, then restores it. The restore in Cleanup
// only happens after the fake itself has returned (synchronized through
// fakeDone), so there is no unsynchronized access to the rawDialUDP
// variable across goroutines for -race to catch: dialUDP's background
// goroutine reads rawDialUDP exactly once, to obtain this fake, before ever
// blocking — nothing reads the variable again afterwards.
func hangRawDialUDP(t *testing.T) {
	t.Helper()
	unblock := make(chan struct{})
	fakeDone := make(chan struct{})
	real := rawDialUDP
	rawDialUDP = func(raddr *net.UDPAddr) (*net.UDPConn, error) {
		<-unblock
		defer close(fakeDone)
		return real(raddr)
	}
	t.Cleanup(func() {
		close(unblock)
		<-fakeDone
		rawDialUDP = real
	})
}

// TestDialUDPBoundsAHungRawDial guards the actual failure mode reported
// against a real Windows adapter: connect() blocking instead of erroring
// during a network transition. A non-routable destination address fails
// fast on every platform this suite runs on, so it can't exercise that path
// — instead this replaces rawDialUDP with a fake that blocks far longer
// than dialTimeout, the closest a portable test gets to a genuinely wedged
// syscall, and checks dialUDP still returns on schedule. Reverting dialUDP
// to call rawDialUDP directly (dropping the goroutine+select wrapper) would
// make this test hang until its own safety timeout and fail.
func TestDialUDPBoundsAHungRawDial(t *testing.T) {
	hangRawDialUDP(t)

	budget := dialTimeout + 2*time.Second
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := dialUDP(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); err == nil {
			t.Error("dialUDP against a hung raw dial returned no error")
		}
	}()
	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("dialUDP did not return within %s of a hung raw dial", budget)
	}
}

// TestSendRecoversWhenRedialItselfIsHung is the end-to-end version: with the
// same hung rawDialUDP, Send's redial-and-retry path must still return
// within its overall timeout budget rather than hanging the caller (in
// production, client.Session.Run's single input-handling goroutine).
func TestSendRecoversWhenRedialItselfIsHung(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.sock.Close(); err != nil {
		t.Fatal(err)
	}

	hangRawDialUDP(t)

	budget := dialTimeout + writeTimeout + 2*time.Second
	done := make(chan error, 1)
	go func() { done <- conn.Send([]byte("probe")) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Send succeeded despite a hung redial — unexpected but not a hang, investigate")
		}
	case <-time.After(budget):
		t.Fatalf("Send did not return within %s of a hung redial", budget)
	}
}

// TestRecvClosedDistinguishesRedialFromIntentionalClose pins the contract
// the client package's receive-pump goroutine relies on: when redial closes
// the socket a blocked Recv was reading, that Recv's error must not look
// like session shutdown (Closed() stays false, so the pump keeps looping),
// but a real Close must (Closed() flips true, so the pump exits).
func TestRecvClosedDistinguishesRedialFromIntentionalClose(t *testing.T) {
	key, _ := crypto.ParseBase64Key("zr0jtuYVKJnfJHP/XOOsbQ")
	server, err := newLoopbackServer(t, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(server.addr, key)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate redial closing the socket a Recv call was about to read from,
	// without going through Close.
	if err := conn.sock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Recv(time.Second); err == nil {
		t.Fatal("Recv on a closed socket returned no error")
	}
	if conn.Closed() {
		t.Fatal("a redial-style socket close must not mark the connection as closed")
	}

	// Give the connection a live socket again, exactly as a real redial
	// would, before exercising a genuine Close.
	if err := conn.redial(); err != nil {
		t.Fatal(err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !conn.Closed() {
		t.Fatal("Close must mark the connection as closed")
	}
	if _, err := conn.Recv(time.Second); err == nil {
		t.Fatal("Recv after Close returned no error")
	}
}
