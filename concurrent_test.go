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
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// The first read is held inside the driver until the second has entered it:
// both are in the driver at once, and the replies leave in the other order,
// each carrying its own id and its own bytes (draft-ietf-secsh-filexfer-02
// §6.1: no restriction on the order of responses).
func TestReadsRunTogetherAndReplyOutOfOrder(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 20)
	// The first read stays in the driver until its successor has been
	// answered, so the order of the replies is not a race.
	release := make(chan struct{})
	fsys := newHookFS(data, func(op string, off int64) {
		if off == 0 {
			<-release
		}
	})
	c := dial(t, fsys, ReadWrite())
	h := c.open("/f", wire.FxfRead)
	c.sendRead(100, h, 0, 10)
	c.sendRead(101, h, 50, 10)
	typ, p := c.recv()
	if typ != wire.FxpData || replyID(t, p) != 101 {
		t.Fatalf("first reply = type %d id %d, want DATA for 101", typ, replyID(t, p))
	}
	if d, _ := wire.DecodeData(p); !bytes.Equal(d.Data, data[50:60]) {
		t.Fatalf("reply 101 = %q", d.Data)
	}
	close(release)
	typ, p = c.recv()
	if typ != wire.FxpData || replyID(t, p) != 100 {
		t.Fatalf("second reply = type %d id %d, want DATA for 100", typ, replyID(t, p))
	}
	if d, _ := wire.DecodeData(p); !bytes.Equal(d.Data, data[:10]) {
		t.Fatalf("reply 100 = %q", d.Data)
	}
	c.finish()
}

// A READ that overlaps a WRITE in progress waits for it; one that does not
// overlap goes ahead of a write that is held.
func TestOverlapWaitsDisjointDoesNot(t *testing.T) {
	enteredWrite := make(chan struct{})
	releaseWrite := make(chan struct{})
	readEntered := make(chan struct{})
	var wOnce, rOnce sync.Once
	fsys := newHookFS(make([]byte, 400), func(op string, off int64) {
		switch {
		case op == "write" && off == 0:
			wOnce.Do(func() { close(enteredWrite) })
			<-releaseWrite
		case op == "read" && off == 5:
			rOnce.Do(func() { close(readEntered) })
		}
	})
	c := dial(t, fsys, ReadWrite())
	h := c.open("/f", wire.FxfRead|wire.FxfWrite)
	c.sendWrite(1, h, 0, []byte("ABCDEFGHIJ"))
	within(t, "write enters the driver", enteredWrite)

	// Disjoint: a read at 200 is answered while the write is held.
	c.sendRead(2, h, 200, 10)
	if typ, p := c.recv(); typ != wire.FxpData || replyID(t, p) != 2 {
		t.Fatalf("disjoint read: type %d id %d", typ, replyID(t, p))
	}

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
	notWithin(t, "third request being read at the cap", third)
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

// Memory stays bounded however many requests are queued: a flood of reads
// creates no more slots than the cap.
func TestSlotsNeverExceedCap(t *testing.T) {
	p := newSlots(3)
	var got []*slot
	for range 3 {
		got = append(got, p.acquire())
	}
	done := make(chan *slot)
	go func() { done <- p.acquire() }()
	select {
	case <-done:
		t.Fatal("a fourth slot was handed out")
	case <-time.After(50 * time.Millisecond):
	}
	p.release(got[0])
	if s := <-done; s != got[0] {
		t.Fatal("the released slot was not reused")
	}
	if p.made != 3 {
		t.Fatalf("made %d slots, want 3", p.made)
	}
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

func TestReplyWriterRemembersFirstFailure(t *testing.T) {
	rw := &replyWriter{w: failWriter{}}
	if _, err := rw.Write([]byte("x")); !errors.Is(err, errBoom) {
		t.Fatalf("first write: %v", err)
	}
	if _, err := rw.Write([]byte("y")); !errors.Is(err, errBoom) {
		t.Fatalf("second write: %v", err)
	}
	rw.fail(errors.New("other"))
	if !errors.Is(rw.failure(), errBoom) {
		t.Fatalf("failure = %v, want the first", rw.failure())
	}
	fresh := &replyWriter{w: io.Discard}
	fresh.fail(ErrVersion)
	if fresh.failure() != ErrVersion {
		t.Fatal("fail did not record")
	}
}

func TestSaturatingAdd(t *testing.T) {
	if satAdd(1, 2) != 3 || satAdd(math.MaxUint64, 1) != math.MaxUint64 || satAdd(math.MaxUint64-1, 1) != math.MaxUint64 {
		t.Fatal("satAdd")
	}
}

func TestSpanConflicts(t *testing.T) {
	a := &span{path: "/f", lo: 0, hi: 10, write: true}
	for _, tc := range []struct {
		b    span
		want bool
	}{
		{span{path: "/f", lo: 5, hi: 6}, true},
		{span{path: "/f", lo: 10, hi: 20}, false},
		{span{path: "/g", lo: 5, hi: 6}, false},
		{span{path: "/f", lo: 5, hi: 6, write: true}, true},
	} {
		if got := a.conflicts(&tc.b); got != tc.want {
			t.Errorf("%+v: %v", tc.b, got)
		}
	}
	r1 := &span{path: "/f", lo: 0, hi: 10}
	r2 := &span{path: "/f", lo: 0, hi: 10}
	if r1.conflicts(r2) {
		t.Fatal("two reads conflict")
	}
}

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
	// 1 is the serial mode of v0.7.0 and still transfers.
	m := newMemFS().addFile("/f", []byte("serial"), 0o100644)
	c := dial(t, openerFS{m}, WithMaxInFlight(1))
	h := c.open("/f", wire.FxfRead)
	if got := c.readAll(h, 4); string(got) != "serial" {
		t.Fatalf("serial read = %q", got)
	}
	c.finish()
}
