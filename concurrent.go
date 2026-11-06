// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"io"
	"math"

	"github.com/go-filesystems/inflight"
	"github.com/go-filesystems/sftp/wire"
)

// Concurrent dispatch.
//
// The mechanism (bounds, range ordering, barriers, reply order) lives in
// [github.com/go-filesystems/inflight], extracted from this module's v0.9.0
// and shared with the NFS and SMB servers. What stays here is what is SFTP:
// which requests may overlap and what byte range each touches.
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
//
// Replies go out in the order the requests arrived (inflight.InOrder).
//
// Why in order: the draft allows any order (§6.1, §7), but OpenSSH's client
// treats a reordered reply as a reason to refuse to resume: sftp-client.c
// sets `reordered = 1` when a reply's offset is past the high-water mark
// (line 1795) and then fails "get -a" / "reget" with "server reordered
// requests" (lines 1856-1859); OpenSSH's own server never reorders
// (sftp-server.c process() runs one handler per call). So the work is
// concurrent and the replies are sequential.
//
// A slot, and the global token with it, is freed when its reply is written,
// so a peer that does not read keeps its requests' memory counted: the
// analogue of OpenSSH's sftp-server not reading input while its output queue
// cannot take a maximum-size message (sftp-server.c lines 2064-2066 and 2121).

// job is a request that may run beside others: where it touches, and how to
// answer it.
type job struct {
	span inflight.Span
	run  inflight.Run
}

// frame frames m as the reply in the slot's output buffer; nothing is written
// here (io.Discard). A reply too large to frame is an error that ends the
// session.
func frame(sl *inflight.Slot, m wire.Message) ([]byte, error) {
	var err error
	sl.Out, err = wire.Send(io.Discard, m, sl.Out)
	return sl.Out, err
}

// satAdd is a+b, saturating: the offset comes off the wire.
func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
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
