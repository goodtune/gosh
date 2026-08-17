package network

import (
	"bytes"
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
