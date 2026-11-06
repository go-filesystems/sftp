// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-filesystems/inflight"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// hookFS is a driver whose positional I/O calls a hook first, so a test can
// hold a request inside the driver and watch what else the server does.
type hookFS struct {
	writableFS
	hook func(op string, off int64)
	mu   sync.Mutex
	open []*memWritableFile
}

func (h *hookFS) OpenFile(path string) (filesystem.File, error) {
	f, err := h.writableFS.OpenFile(path)
	if err != nil {
		return nil, err
	}
	w := f.(*memWritableFile)
	h.mu.Lock()
	h.open = append(h.open, w)
	h.mu.Unlock()
	return &hookFile{WritableFile: w, hook: h.hook}, nil
}

func (h *hookFS) allClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range h.open {
		if !f.closed {
			return false
		}
	}
	return true
}

type hookFile struct {
	filesystem.WritableFile
	hook func(op string, off int64)
}

func (f *hookFile) ReadAt(p []byte, off int64) (int, error) {
	f.hook("read", off)
	return f.WritableFile.ReadAt(p, off)
}

func (f *hookFile) WriteAt(p []byte, off int64) (int, error) {
	f.hook("write", off)
	return f.WritableFile.WriteAt(p, off)
}

func newHookFS(data []byte, hook func(op string, off int64)) *hookFS {
	m := newMemFS().addFile("/f", data, 0o100644)
	if hook == nil {
		hook = func(string, int64) {}
	}
	return &hookFS{writableFS: writableFS{m}, hook: hook}
}

// replyID is the request id a reply answers.
func replyID(t *testing.T, payload []byte) uint32 {
	t.Helper()
	if len(payload) < 4 {
		t.Fatalf("reply too short: %d", len(payload))
	}
	return requestID(payload)
}

func (c *client) sendRead(id uint32, h string, off uint64, n uint32) {
	c.send(wire.ReadRequest{ID: id, Handle: h, Offset: off, Length: n})
}

func (c *client) sendWrite(id uint32, h string, off uint64, data []byte) {
	c.send(wire.WriteRequest{ID: id, Handle: h, Offset: off, Data: data})
}

func within(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out: %s", what)
	}
}

func notWithin(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("happened too early: %s", what)
	case <-time.After(150 * time.Millisecond):
	}
}

// The first read is held inside the driver and the second runs beside it, to
// completion; the replies still leave in the order the requests arrived. The
// draft would allow either (§6.1, §7), but OpenSSH's client refuses to resume
// a download whose replies came back reordered (sftp-client.c:1795, 1856).
func TestReadsRunTogetherAndReplyInOrder(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 20)
	release := make(chan struct{})
	secondIn := make(chan struct{})
	fsys := newHookFS(data, func(op string, off int64) {
		if off == 0 {
			<-release
		} else {
			close(secondIn)
		}
	})
	c := dial(t, fsys, ReadWrite())
	h := c.open("/f", wire.FxfRead)
	c.sendRead(100, h, 0, 10)
	c.sendRead(101, h, 50, 10)
	within(t, "second read in the driver beside the first", secondIn)
	got := make(chan struct{})
	var typ uint8
	var p []byte
	go func() { typ, p = c.recv(); close(got) }()
	notWithin(t, "a reply before the first request's", got)
	close(release)
	within(t, "first reply", got)
	if typ != wire.FxpData || replyID(t, p) != 100 {
		t.Fatalf("first reply = type %d id %d, want DATA for 100", typ, replyID(t, p))
	}
	if d, _ := wire.DecodeData(p); !bytes.Equal(d.Data, data[:10]) {
		t.Fatalf("reply 100 = %q", d.Data)
	}
	typ, p = c.recv()
	if typ != wire.FxpData || replyID(t, p) != 101 {
		t.Fatalf("second reply = type %d id %d, want DATA for 101", typ, replyID(t, p))
	}
	if d, _ := wire.DecodeData(p); !bytes.Equal(d.Data, data[50:60]) {
		t.Fatalf("reply 101 = %q", d.Data)
	}
	c.finish()
}

// A READ that overlaps a WRITE in progress waits for it; one that does not
// overlap runs beside a write that is held (its reply still follows the
// write's).
func TestOverlapWaitsDisjointDoesNot(t *testing.T) {
	enteredWrite := make(chan struct{})
	releaseWrite := make(chan struct{})
	readEntered := make(chan struct{})
	disjointIn := make(chan struct{})
	var wOnce, rOnce sync.Once
	fsys := newHookFS(make([]byte, 400), func(op string, off int64) {
		switch {
		case op == "write" && off == 0:
			wOnce.Do(func() { close(enteredWrite) })
			<-releaseWrite
		case op == "read" && off == 5:
			rOnce.Do(func() { close(readEntered) })
		case op == "read" && off == 200:
			close(disjointIn)
		}
	})
	c := dial(t, fsys, ReadWrite())
	h := c.open("/f", wire.FxfRead|wire.FxfWrite)
	c.sendWrite(1, h, 0, []byte("ABCDEFGHIJ"))
	within(t, "write enters the driver", enteredWrite)

	// Disjoint: a read at 200 reaches the driver while the write is held.
	c.sendRead(2, h, 200, 10)
	within(t, "disjoint read in the driver beside the write", disjointIn)

	// Overlapping: the read at 5 must not reach the driver yet. The client
	// send blocks on the synchronous pipe once the server stops reading, so
	// it runs on its own goroutine.
	sent := make(chan struct{})
	go func() { c.sendRead(3, h, 5, 10); close(sent) }()
	within(t, "overlapping read is read off the wire", sent)
	notWithin(t, "overlapping read reaching the driver", readEntered)
	close(releaseWrite)
	typ, p := c.recv()
	if typ != wire.FxpStatus || replyID(t, p) != 1 {
		t.Fatalf("first completion: type %d id %d, want status for 1", typ, replyID(t, p))
	}
	if typ, p = c.recv(); typ != wire.FxpData || replyID(t, p) != 2 {
		t.Fatalf("disjoint read: type %d id %d, want data for 2", typ, replyID(t, p))
	}
	typ, p = c.recv()
	if typ != wire.FxpData || replyID(t, p) != 3 {
		t.Fatalf("second completion: type %d id %d, want data for 3", typ, replyID(t, p))
	}
	if d, _ := wire.DecodeData(p); string(d.Data[:5]) != "FGHIJ" {
		t.Fatalf("read after overlapping write = %q, want the write's bytes", d.Data)
	}
	c.finish()
}

// Two writes to overlapping ranges apply in arrival order, across sessions.
func TestOverlappingWritesAcrossSessionsKeepOrder(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var order []byte
	var omu sync.Mutex
	fsys := newHookFS(make([]byte, 10), func(op string, off int64) {
		if op != "write" {
			return
		}
		once.Do(func() { close(entered); <-release })
		omu.Lock()
		order = append(order, byte(off))
		omu.Unlock()
	})
	srv, err := New(fsys, ReadWrite())
	if err != nil {
		t.Fatal(err)
	}
	a, b := serveOn(t, srv), serveOn(t, srv)
	ha := a.open("/f", wire.FxfRead|wire.FxfWrite)
	hb := b.open("/f", wire.FxfRead|wire.FxfWrite)
	a.sendWrite(1, ha, 0, []byte("aaaa"))
	within(t, "first write in the driver", entered)
	done := make(chan struct{})
	go func() {
		b.sendWrite(2, hb, 2, []byte("bbbb"))
		b.recv()
		close(done)
	}()
	notWithin(t, "overlapping write from the other session", done)
	close(release)
	a.recv()
	within(t, "second write answered", done)
	omu.Lock()
	defer omu.Unlock()
	if !bytes.Equal(order, []byte{0, 2}) {
		t.Fatalf("writes applied at %v, want [0 2]", order)
	}
}

// CLOSE is a barrier: it is answered after the READ pending on its handle,
// even though the READ is held in the driver when CLOSE arrives.
func TestCloseWaitsForPendingRequests(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fsys := newHookFS([]byte("hello world"), func(string, int64) {
		once.Do(func() { close(entered) })
		<-release
	})
	c := dial(t, fsys, ReadWrite())
	h := c.open("/f", wire.FxfRead)
	c.sendRead(10, h, 0, 5)
	within(t, "read in the driver", entered)
	sent := make(chan struct{})
	go func() {
		c.send(wire.HandleRequest{PacketType: wire.FxpClose, ID: 11, Handle: h})
		close(sent)
	}()
	within(t, "close is read", sent)
	time.Sleep(50 * time.Millisecond)
	close(release)
	typ, p := c.recv()
	if typ != wire.FxpData || replyID(t, p) != 10 {
		t.Fatalf("first reply type %d id %d, want data for 10", typ, replyID(t, p))
	}
	typ, p = c.recv()
	c.status(typ, p, wire.StatusOK)
	if replyID(t, p) != 11 {
		t.Fatalf("close reply id %d", replyID(t, p))
	}
	c.finish()
}

// The session cap is enforced before a request is read: with two in flight, a
// third is not taken off the wire, and never more than two are in the driver.
func TestInFlightCapIsBackpressure(t *testing.T) {
	release := make(chan struct{})
	var cur, peak atomic.Int32
	entered := make(chan struct{}, 8)
	fsys := newHookFS(make([]byte, 100), func(string, int64) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		cur.Add(-1)
	})
	c := dial(t, fsys, ReadWrite(), WithMaxInFlight(2))
	h := c.open("/f", wire.FxfRead)
	c.sendRead(1, h, 0, 1)
	c.sendRead(2, h, 1, 1)
	<-entered
	<-entered
	third := make(chan struct{})
	go func() { c.sendRead(3, h, 2, 1); close(third) }()
	// The bytes may sit in the session's read buffer (64 KiB at most), but
	// no request is begun: none reaches the driver while two are in flight.
	select {
	case <-entered:
		t.Fatal("a third request reached the driver at a cap of 2")
	case <-time.After(150 * time.Millisecond):
	}
	// The pipe has no buffer, so replies must be read for slots to free.
	replies := make(chan struct{})
	go func() {
		for range 3 {
			if typ, _ := c.recv(); typ != wire.FxpData {
				t.Errorf("reply type %d", typ)
			}
		}
		close(replies)
	}()
	close(release)
	within(t, "third request read once a slot frees", third)
	within(t, "three replies", replies)
	if p := peak.Load(); p != 2 {
		t.Fatalf("peak in the driver = %d, want 2", p)
	}
	c.finish()
}

// The client vanishes with requests pending: Serve waits for them, then
// releases every handle, and does not return an error for a clean EOF.
func TestSessionEndsWithRequestsPending(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fsys := newHookFS(make([]byte, 64), func(string, int64) {
		once.Do(func() { close(entered) })
		<-release
	})
	c := dial(t, fsys, ReadWrite())
	h := c.open("/f", wire.FxfRead)
	c.sendRead(1, h, 0, 8)
	within(t, "read in the driver", entered)
	c.conn.Close()
	select {
	case <-c.done:
		t.Fatal("Serve returned with a request still in the driver")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	within(t, "Serve returns", c.done)
	if !fsys.allClosed() {
		t.Fatal("a handle was left open")
	}
}

// A reply that cannot be written ends the session, once, with that error.
func TestReplyFailureEndsSession(t *testing.T) {
	srv, _ := New(newHookFS(make([]byte, 64), nil))
	toSrvR, toSrvW := io.Pipe()
	fromSrvR, fromSrvW := io.Pipe()
	rw := struct {
		io.Reader
		io.Writer
	}{toSrvR, &oneWrite{w: fromSrvW}}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(rw) }()
	var buf []byte
	buf, _ = wire.Send(toSrvW, wire.InitRequest{Version: wire.Version}, buf)
	if _, _, _, err := wire.ReadPacket(fromSrvR, nil, 0); err != nil { // VERSION
		t.Fatal(err)
	}
	// The reply to this cannot be written; the session ends at once.
	wire.Send(toSrvW, wire.PathRequest{PacketType: wire.FxpRealpath, ID: 1, Path: "/"}, buf)
	select {
	case err := <-errc:
		if !errors.Is(err, errBoom) {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no verdict")
	}
}

// failAfter lets n Writes through, then fails every one.
type failAfter struct {
	net.Conn
	ok atomic.Int32
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.ok.Add(-1) < 0 {
		return 0, errBoom
	}
	return f.Conn.Write(p)
}

// A reply that fails to write while the session is idle (waiting for the next
// packet, holding no slot) ends the session when that packet arrives, with the
// write's error, and without reading it.
func TestFailureWhileIdleEndsSessionAtTheNextPacket(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fsys := newHookFS(make([]byte, 64), func(string, int64) {
		once.Do(func() { close(entered) })
		<-release
	})
	srv, _ := New(fsys, ReadWrite())
	a, b := net.Pipe()
	fw := &failAfter{Conn: b}
	fw.ok.Store(2) // VERSION and the reply to OPEN
	c := &client{t: t, conn: a, done: make(chan struct{})}
	go func() { c.serveErr = srv.Serve(fw); close(c.done) }()
	t.Cleanup(func() { a.Close() })
	c.init()
	h := c.open("/f", wire.FxfRead)
	c.sendRead(1, h, 0, 8)
	within(t, "read in the driver", entered)
	close(release)
	time.Sleep(100 * time.Millisecond) // the reply's write fails; the session is in Peek
	c.sendRead(2, h, 0, 8)
	within(t, "Serve returns", c.done)
	if !errors.Is(c.serveErr, errBoom) {
		t.Fatalf("Serve = %v, want the write error", c.serveErr)
	}
}

// oneWrite lets exactly one Write through, then fails.
type oneWrite struct {
	w io.Writer
	n int
}

func (o *oneWrite) Write(p []byte) (int, error) {
	o.n++
	if o.n > 1 {
		return 0, errBoom
	}
	return o.w.Write(p)
}

var errBoom = errors.New("boom")

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errBoom }

// Offsets from the wire past what int64 holds are refused, not wrapped.
func TestHugeOffsets(t *testing.T) {
	c := dial(t, newHookFS(make([]byte, 8), nil), ReadWrite())
	h := c.open("/f", wire.FxfRead|wire.FxfWrite)
	typ, p := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: math.MaxUint64 - 3, Length: 100})
	c.status(typ, p, wire.StatusEOF)
	typ, p = c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: math.MaxUint64 - 3, Data: []byte("x")})
	c.status(typ, p, wire.StatusFailure)
	c.finish()
}

// A driver with no Opener takes the whole-file paths, which order against
// everything on the path and need no File.
func TestFallbackReadsAndWritesStayOrdered(t *testing.T) {
	m := newMemFS().addFile("/f", []byte("0123456789"), 0o100644)
	c := dial(t, bareFS{m}, ReadWrite())
	h := c.open("/f", wire.FxfRead|wire.FxfWrite)
	got := map[uint32][]byte{}
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for range 40 {
			typ, p := c.recv()
			if typ == wire.FxpData {
				d, _ := wire.DecodeData(p)
				got[replyID(t, p)] = d.Data
			}
		}
	}()
	for i := range 20 {
		c.sendWrite(uint32(100+i), h, uint64(i), []byte{byte('a' + i)})
		c.sendRead(uint32(200+i), h, 0, 64)
	}
	<-collected
	for i := range 20 {
		d := got[uint32(200+i)]
		if len(d) < i+1 || d[i] != byte('a'+i) {
			t.Fatalf("read %d after write %d = %q", i, i, d)
		}
	}
	c.finish()
}

// A transfer pipelined 64 deep, both ways, arrives byte for byte.
func TestPipelinedTransferSHA256(t *testing.T) {
	const size = 3<<20 + 12345
	src := make([]byte, size)
	rand.New(rand.NewSource(1)).Read(src)
	m := newMemFS().addFile("/get", src, 0o100644).addFile("/put", nil, 0o100644)
	c := dial(t, writableFS{m}, ReadWrite())
	const chunk = 32 << 10

	// put
	h := c.open("/put", wire.FxfWrite)
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for off := 0; off < size; off += chunk {
			c.sendWrite(uint32(off/chunk+1), h, uint64(off), src[off:min(off+chunk, size)])
		}
	}()
	for range (size + chunk - 1) / chunk {
		typ, p := c.recv()
		c.status(typ, p, wire.StatusOK)
	}
	<-sent
	c.closeHandle(h)
	if sha256.Sum256(m.nodes["/put"].data) != sha256.Sum256(src) {
		t.Fatal("put: digest differs")
	}

	// get, replies matched by id
	h = c.open("/get", wire.FxfRead)
	out := make([]byte, size)
	for off := 0; off < size; {
		batch := 0
		for ; batch < 64 && off+batch*chunk < size; batch++ {
			c.sendRead(uint32(batch+1), h, uint64(off+batch*chunk), chunk)
		}
		for range batch {
			typ, p := c.recv()
			if typ != wire.FxpData {
				t.Fatalf("get reply type %d", typ)
			}
			d, _ := wire.DecodeData(p)
			at := off + int(replyID(t, p)-1)*chunk
			copy(out[at:], d.Data)
		}
		off += batch * chunk
	}
	c.closeHandle(h)
	if sha256.Sum256(out) != sha256.Sum256(src) {
		t.Fatal("get: digest differs")
	}
	c.finish()
}

// With PathOpsConcurrent two Stat calls run in the driver together; without
// it they never do.
type statGate struct {
	*memFS
	in   atomic.Int32
	peak atomic.Int32
	wait time.Duration
}

func (g *statGate) Stat(p string) (filesystem.Stat, error) {
	if p == "/f" {
		n := g.in.Add(1)
		for p := g.peak.Load(); n > p && !g.peak.CompareAndSwap(p, n); p = g.peak.Load() {
		}
		// Wait for a second caller, if one is coming.
		for deadline := time.Now().Add(g.wait); g.peak.Load() < 2 && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		g.in.Add(-1)
	}
	return g.memFS.Stat(p)
}

func statTwice(t *testing.T, wait time.Duration, opts ...Option) int32 {
	g := &statGate{memFS: newMemFS().addFile("/f", nil, 0o100644), wait: wait}
	srv, err := New(g, opts...)
	if err != nil {
		t.Fatal(err)
	}
	a, b := serveOn(t, srv), serveOn(t, srv)
	var wg sync.WaitGroup
	for _, c := range []*client{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			typ, p := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: 1, Path: "/f"})
			if typ != wire.FxpAttrs {
				t.Errorf("stat reply %d (%v)", typ, p)
			}
		}()
	}
	wg.Wait()
	return g.peak.Load()
}

func TestPathOpsConcurrentOptIn(t *testing.T) {
	if p := statTwice(t, 100*time.Millisecond); p != 1 {
		t.Fatalf("default: %d Stat calls at once, want 1", p)
	}
	if p := statTwice(t, 10*time.Second, PathOpsConcurrent()); p != 2 {
		t.Fatalf("PathOpsConcurrent: %d Stat calls at once, want 2", p)
	}
}

func TestMaxInFlightOption(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{0, 0}, {-3, -3}, {5, 5}, {1 << 20, MaxInFlightLimit}} {
		s, _ := New(newMemFS(), WithMaxInFlight(tc.in))
		if s.maxInFlight != tc.want {
			t.Errorf("WithMaxInFlight(%d) = %d, want %d", tc.in, s.maxInFlight, tc.want)
		}
	}
	if s, _ := New(newMemFS()); s.maxTotal != DefaultMaxInFlightTotal || s.pool == nil {
		t.Errorf("default total = %d", s.maxTotal)
	}
	if s, _ := New(newMemFS(), WithMaxInFlightTotal(7)); s.maxTotal != 7 {
		t.Errorf("WithMaxInFlightTotal(7): %d", s.maxTotal)
	}
	// 1 is the serial mode of v0.7.0 and still transfers.
	m := newMemFS().addFile("/f", []byte("serial"), 0o100644)
	c := dial(t, openerFS{m}, WithMaxInFlight(1))
	h := c.open("/f", wire.FxfRead)
	if got := c.readAll(h, 4); string(got) != "serial" {
		t.Fatalf("serial read = %q", got)
	}
	c.finish()
}

// Sessions together stay under the server-wide bound: three sessions that
// could each have 64 requests in flight, a total of 4, and never more than 4
// requests reach the driver, however the sessions interleave.
func TestServerWideCapBoundsAllSessions(t *testing.T) {
	const total, sessions, perSession = 4, 3, 6
	release := make(chan struct{})
	entered := make(chan struct{}, 64)
	var cur, peak atomic.Int32
	fsys := newHookFS(make([]byte, 100), func(string, int64) {
		n := cur.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		entered <- struct{}{}
		<-release
		cur.Add(-1)
	})
	srv, err := New(fsys, ReadWrite(), WithMaxInFlightTotal(total))
	if err != nil {
		t.Fatal(err)
	}
	// Every session is open before any request is made: an open needs a token
	// too, and the first session's reads would hold them all.
	type conn struct {
		c *client
		h string
	}
	var conns []conn
	for range sessions {
		c := serveOn(t, srv)
		conns = append(conns, conn{c, c.open("/f", wire.FxfRead)})
	}
	var wg sync.WaitGroup
	for _, cn := range conns {
		c, h := cn.c, cn.h
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range perSession {
				c.sendRead(uint32(100+i), h, uint64(i), 1)
			}
		}()
		go func() {
			defer wg.Done()
			for i := range perSession {
				if typ, p := c.recv(); typ != wire.FxpData || replyID(t, p) != uint32(100+i) {
					t.Errorf("reply %d: type %d id %d", i, typ, replyID(t, p))
				}
			}
		}()
	}
	for range total {
		<-entered
	}
	time.Sleep(150 * time.Millisecond)
	if n := cur.Load(); n != total {
		t.Fatalf("%d requests in the driver, want exactly the global bound %d", n, total)
	}
	close(release)
	wg.Wait()
	if p := peak.Load(); p != total {
		t.Fatalf("peak in the driver = %d, want %d", p, total)
	}
}

// A read error between packets ends the session with that error.
func TestInputErrorBetweenPackets(t *testing.T) {
	srv, _ := New(newMemFS())
	var in bytes.Buffer
	wire.Send(&in, wire.InitRequest{Version: wire.Version}, nil)
	err := srv.Serve(struct {
		io.Reader
		io.Writer
	}{io.MultiReader(&in, errReader{}), io.Discard})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Serve = %v, want the read error", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A reply too large to frame ends the session instead of being dropped
// silently: the client would otherwise wait for it forever.
func TestUnframableReplyFailsTheSession(t *testing.T) {
	// frame hands the error to inflight, which ends the connection with it.
	if _, err := frame(&inflight.Slot{}, wire.DataReply{ID: 1, Data: make([]byte, wire.MaxPacket)}); !errors.Is(err, wire.ErrPacketTooLarge) {
		t.Fatalf("frame = %v, want ErrPacketTooLarge", err)
	}
}

func TestSaturatingAdd(t *testing.T) {
	if satAdd(1, 2) != 3 || satAdd(math.MaxUint64, 1) != math.MaxUint64 || satAdd(math.MaxUint64-1, 1) != math.MaxUint64 {
		t.Fatal("satAdd")
	}
}

// A nil stream cannot carry a session: Serve refuses it.
func TestServeRefusesANilStream(t *testing.T) {
	srv, _ := New(newMemFS())
	if err := srv.Serve(nil); !errors.Is(err, inflight.ErrWriter) {
		t.Fatalf("Serve(nil) = %v", err)
	}
}
