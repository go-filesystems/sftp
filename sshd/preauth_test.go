package sshd

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// dropped reports whether the server has closed c: a read returns EOF or a
// reset, not a deadline error, once the connection is gone. The server's own
// version line is read first.
func dropped(c net.Conn) bool {
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		return !errors.Is(err, os.ErrDeadlineExceeded)
	}
}

func dialN(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, 0, n)
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	return conns
}

// A peer that connects and sends nothing is dropped when the login grace time
// expires (audit 2026-11-22, finding 2: it used to be held for ever).
func TestSilentUnauthenticatedConnectionsDropped(t *testing.T) {
	addr, _, _, d := harness(t, tinyFS{files: map[string][]byte{}}, func(c *Config) {
		c.LoginGraceTime = 500 * time.Millisecond
	})
	conns := dialN(t, addr, 20)
	time.Sleep(1500 * time.Millisecond)
	for i, c := range conns {
		if !dropped(c) {
			t.Fatalf("silent connection %d still open after the grace time", i)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		d.mu.Lock()
		tracked := len(d.conns)
		d.mu.Unlock()
		if tracked == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server still tracks %d connections", tracked)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if d.gate.Held() != 0 {
		t.Fatalf("gate still holds %d slots", d.gate.Held())
	}
}

// Connections over MaxStartups are refused at once, and a slot is given back
// when its connection leaves.
func TestUnauthenticatedConnectionsCapped(t *testing.T) {
	addr, _, _, d := harness(t, tinyFS{files: map[string][]byte{}}, func(c *Config) {
		c.MaxStartups = 5
		c.MaxStartupsPerHost = -1
	})
	conns := dialN(t, addr, 5)
	waitHeld(t, d, 5)
	extra := dialN(t, addr, 1)
	if !dropped(extra[0]) {
		t.Fatal("a connection over the cap was not refused")
	}
	conns[0].Close()
	waitHeld(t, d, 4)
	again := dialN(t, addr, 1)
	if dropped(again[0]) {
		t.Fatal("a freed slot was not reusable")
	}
}

func TestUnauthenticatedConnectionsCappedPerHost(t *testing.T) {
	addr, _, _, d := harness(t, tinyFS{files: map[string][]byte{}}, func(c *Config) {
		c.MaxStartups = -1
		c.MaxStartupsPerHost = 3
	})
	dialN(t, addr, 3)
	waitHeld(t, d, 3)
	extra := dialN(t, addr, 1)
	if !dropped(extra[0]) {
		t.Fatal("a fourth connection from one address was not refused")
	}
}

func waitHeld(t *testing.T, d *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for d.gate.Held() != want {
		if time.Now().After(deadline) {
			t.Fatalf("gate holds %d, want %d", d.gate.Held(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStartupGateResolution(t *testing.T) {
	if startupGate(-1, -1) != nil {
		t.Fatal("both caps negative must mean no gate")
	}
	if startupGate(0, 0) == nil || startupGate(-1, 0) == nil || startupGate(4, -1) == nil {
		t.Fatal("a cap on either axis must make a gate")
	}
}

func TestSourceKey(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := sourceKey(a); got != "pipe" {
		t.Fatalf("pipe key = %q", got)
	}
	if got := sourceKey(&addrConn{Conn: a, addr: nil}); got != "" {
		t.Fatalf("nil address key = %q", got)
	}
	if got := sourceKey(&addrConn{Conn: a, addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 9}}); got != "192.0.2.7" {
		t.Fatalf("tcp key = %q", got)
	}
}

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.addr }
