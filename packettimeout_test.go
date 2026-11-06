package sftp

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-filesystems/sftp/wire"
)

func TestPacketTimeoutResolution(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{{0, DefaultPacketTimeout}, {-1, 0}, {time.Second, time.Second}} {
		s, _ := New(newMemFS(), WithPacketTimeout(tc.in))
		if got := s.packetTimeout(); got != tc.want {
			t.Errorf("WithPacketTimeout(%v) -> %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A client that sends a packet length and stops loses its session within the
// timeout, and the server-wide budget it held comes back: with a budget of ONE,
// a second session is then served.
func TestAHalfSentPacketReleasesTheBudgetAndTheSession(t *testing.T) {
	srv, _ := New(newMemFS(), WithMaxInFlightTotal(1), WithPacketTimeout(200*time.Millisecond))
	a, b := net.Pipe()
	defer a.Close()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(b) }()
	var buf []byte
	buf, _ = wire.Send(a, wire.InitRequest{Version: wire.Version}, buf)
	if _, _, _, err := wire.ReadPacket(a, nil, 0); err != nil { // VERSION
		t.Fatal(err)
	}
	// A 100-byte packet, one byte of it, and then silence.
	if _, err := a.Write([]byte{0, 0, 0, 100, wire.FxpRealpath}); err != nil {
		t.Fatal(err)
	}
	c := serveOn(t, srv) // negotiated; its first request needs the one token
	got := make(chan struct{})
	go func() {
		c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: "/"})
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second session was served while the first held the whole budget")
	case <-time.After(60 * time.Millisecond):
	}
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("a half-sent packet kept its session past the timeout")
	}
	within(t, "the second session is served", got)
}

// A stream with no read deadline is closed instead; one that is neither is
// left alone (the bound cannot hold there, and nothing breaks).
type closeOnly struct {
	io.Reader
	io.Writer
	closed atomic.Bool
}

func (c *closeOnly) Close() error { c.closed.Store(true); return nil }

type bare struct {
	io.Reader
	io.Writer
}

func TestGivingUpUsesWhatTheStreamOffers(t *testing.T) {
	srv, _ := New(newMemFS())
	co := &closeOnly{}
	(&session{srv: srv, rw: co}).giveUp()
	if !co.closed.Load() {
		t.Error("a stream that can only be closed was not closed")
	}
	(&session{srv: srv, rw: bare{}}).giveUp() // nothing to do, and no panic
	a, b := net.Pipe()
	defer a.Close()
	(&session{srv: srv, rw: b}).giveUp()
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Error("the read deadline was not set")
	}
}

func TestADisabledPacketTimeoutArmsNothing(t *testing.T) {
	srv, _ := New(newMemFS(), WithPacketTimeout(-1))
	(&session{srv: srv}).armPacketTimer()()
}
