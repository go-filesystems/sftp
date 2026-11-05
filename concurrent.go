// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"io"
	"math"
	"sync"

	"github.com/go-filesystems/sftp/wire"
)

// Concurrent dispatch.
//
// Bibliography (opened 2026-11-05):
//
//   - draft-ietf-secsh-filexfer-02 §6.1: "The protocol and implementations
//     MUST process requests relating to the same file in the order in which
//     they are received"; "overlapping reads and writes cannot be reordered
//     or parallelized"; "There are no restrictions on the order in which
//     responses to outstanding requests are delivered to the client". §7: a
//     server may answer in a different order than the requests were sent.
//   - OpenSSH sftp-server.c: process() runs one handler to completion per
//     call, so OpenSSH's own server is sequential; every reply echoes the
//     request's id.
//   - OpenSSH sftp-client.c: DEFAULT_NUM_REQUESTS 64; replies are matched by
//     id (request_find) and a reordered reply is tolerated (it only stops the
//     "highwater" mark advancing).
//
// What runs in parallel: SSH_FXP_READ and SSH_FXP_WRITE, the two requests a
// transfer is made of, subject to the §6.1 rule above: two requests whose
// byte ranges overlap on the same file (the same PATH, so two handles on one
// file count) with at least one a write run in arrival order. A write to a
// driver without WritableFile is a whole-file rewrite and orders against
// every other request on that path.
//
// What stays ordered: every other request is a BARRIER. The session waits
// for everything in flight to be answered, runs it alone, and only then reads
// the next packet. That covers OPEN, CLOSE (so a close follows every pending
// op on its handle), FSTAT, SETSTAT, READDIR and all path metadata. A barrier
// is stricter than §6.1 asks; it is also what makes handle-table and
// directory-cursor state need no lock, and a transfer (OPEN, 64 READs,
// CLOSE) loses nothing to it.

// replyWriter serialises replies from concurrent requests onto one stream:
// each reply is one Write (wire.WritePacket's guarantee), so holding the
// mutex around a Write keeps packets whole. A failed Write is remembered, and
// the session ends at its next packet.
type replyWriter struct {
	wmu sync.Mutex // held across a Write, which may block on a slow peer
	w   io.Writer

	emu sync.Mutex // guards err only, so failure() never waits on a Write
	err error
}

func (r *replyWriter) Write(p []byte) (int, error) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if err := r.failure(); err != nil {
		return 0, err
	}
	n, err := r.w.Write(p)
	if err != nil {
		r.fail(err)
	}
	return n, err
}

// fail records why the session cannot go on (a write error, or a reply too
// large to frame), keeping the first.
func (r *replyWriter) fail(err error) {
	r.emu.Lock()
	defer r.emu.Unlock()
	if r.err == nil {
		r.err = err
	}
}

func (r *replyWriter) failure() error {
	r.emu.Lock()
	defer r.emu.Unlock()
	return r.err
}

// slot is one request's buffers. A session owns at most maxInFlight of them,
// created on demand and reused for the life of the session, so a bulk
// transfer allocates nothing per packet in steady state.
type slot struct {
	in, out, data []byte
}

// slots is a session's pool of slots, and its cap on requests in flight.
type slots struct {
	free chan *slot
	made int
	max  int
}

func newSlots(n int) *slots { return &slots{free: make(chan *slot, n), max: n} }

// acquire returns a slot, blocking while all of them are in use. It is called
// BEFORE a packet is read, so at the cap the session stops reading and the
// client waits in the transport; nothing has been allocated for the request
// that is refused a slot. Only the session's reader calls it.
func (p *slots) acquire() *slot {
	select {
	case sl := <-p.free:
		return sl
	default:
	}
	if p.made < p.max {
		p.made++
		return &slot{}
	}
	return <-p.free
}

func (p *slots) release(sl *slot) { p.free <- sl }

// span is the part of a file one request touches.
type span struct {
	path   string
	lo, hi uint64 // [lo, hi)
	write  bool
}

func (a *span) conflicts(b *span) bool {
	return a.path == b.path && (a.write || b.write) && a.lo < b.hi && b.lo < a.hi
}

// satAdd is a+b, saturating: the offset comes off the wire.
func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// rangeSet is the set of spans being processed, across every session of a
// Server, and what makes overlapping I/O wait its turn. Two sessions writing
// one file overlap exactly as two requests of one session do.
type rangeSet struct {
	mu     sync.Mutex
	cv     *sync.Cond
	active []*span
}

// acquire blocks until sp conflicts with nothing in progress, then registers
// it. Callers are the sessions' readers, one packet at a time, which keeps a
// session's own requests in arrival order.
func (r *rangeSet) acquire(sp *span) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cv == nil {
		r.cv = sync.NewCond(&r.mu)
	}
	for r.blocked(sp) {
		r.cv.Wait()
	}
	r.active = append(r.active, sp)
}

func (r *rangeSet) blocked(sp *span) bool {
	for _, a := range r.active {
		if sp.conflicts(a) {
			return true
		}
	}
	return false
}

func (r *rangeSet) release(sp *span) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, a := range r.active {
		if a == sp {
			r.active = append(r.active[:i], r.active[i+1:]...)
			break
		}
	}
	r.cv.Broadcast()
}

// job is a request that may run beside others: where it touches, and how to
// answer it.
type job struct {
	span span
	run  func(*slot) wire.Message
}

// prepare decodes a READ or WRITE and checks everything that needs no driver.
// It returns a job to run concurrently, or the reply to send at once, or
// (nil, nil) for a request that is a barrier.
func (s *session) prepare(typ uint8, payload []byte) (*job, wire.Message) {
	switch typ {
	case wire.FxpRead:
		m, err := wire.DecodeRead(payload)
		if err != nil {
			return nil, badMessage(requestID(payload), err)
		}
		return s.readJob(m)
	case wire.FxpWrite:
		m, err := wire.DecodeWrite(payload)
		if err != nil {
			return nil, badMessage(requestID(payload), err)
		}
		return s.writeJob(m)
	}
	return nil, nil
}

// serveJob runs j and answers it; then frees everything it held.
func (s *session) serveJob(sl *slot, j *job) {
	s.reply(sl, j.run(sl))
	s.srv.ranges.release(&j.span)
	s.slots.release(sl)
	s.wg.Done()
}

// reply sends m on the shared stream, framed in sl's buffer.
func (s *session) reply(sl *slot, m wire.Message) {
	var err error
	if sl.out, err = wire.Send(s.w, m, sl.out); err != nil {
		s.w.fail(err)
	}
}
