package sftp

import (
	"errors"
	"io"
	"time"

	"github.com/go-filesystems/inflight"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// ErrNilFilesystem reports [New] called with no filesystem.
//
// It is caught at construction because the alternative is a nil dereference
// on the first client request — long after the mistake, in a per-session
// goroutine, with no recover, taking down every other tenant the process is
// serving.
var ErrNilFilesystem = errors.New("sftp: nil filesystem")

// Server exports one [github.com/go-filesystems/interface.Filesystem] over
// SFTP version 3.
//
// One Server holds exactly one filesystem and no other capability. It has no
// listener, no goroutine and no global state until a session is handed to
// [Server.Serve], which is what makes running one per tenant — the shape this
// module is built for — cheap rather than aspirational.
//
// A Server is safe for concurrent use by any number of sessions.
type Server struct {
	fsys filesystem.Filesystem
	// opener is the driver's random-access capability, or nil. See
	// [openerFor]; nil when the driver cannot do random access.
	opener filesystem.Opener
	ro     bool
	// maxPacket caps one SFTP packet. Zero means [wire.MaxPacket].
	maxPacket int
	// start is the timestamp reported as atime and mtime for every file
	// until a driver can report a real one. See [TimeStat].
	start uint32

	// maxInFlight is how many requests one session may have in progress.
	maxInFlight int
	// maxTotal is the server-wide cap: one of pool's tokens is held by every
	// request from before its packet is read until its reply is written.
	maxTotal int
	// pathConcurrent is the embedder's assertion that the driver's
	// read-only path calls (Stat, ListDir, ReadFile, ReadLink) are safe
	// concurrently with each other and with File I/O. See [PathOpsConcurrent].
	pathConcurrent bool

	// pool holds what every session shares: the server-wide cap and the byte
	// ranges in progress, which order overlapping reads and writes across
	// sessions. See [github.com/go-filesystems/inflight].
	pool *inflight.Pool
	// fs is the filesystem lock, and the driver contract made executable:
	// File.ReadAt and File.WriteAt hold it shared (ranges permitting), every
	// other driver call exclusively, the read-only path calls shared with
	// [PathOpsConcurrent].
	fs *inflight.FSLock
}

// lock takes the filesystem lock exclusively: for path-based mutations,
// Truncate, Sync and Close.
func (s *Server) lock()   { s.fs.Lock() }
func (s *Server) unlock() { s.fs.Unlock() }

// rlock is for read-only path calls: shared only if the embedder asserted
// [PathOpsConcurrent], exclusive otherwise.
func (s *Server) rlock()   { s.fs.LockPath() }
func (s *Server) runlock() { s.fs.UnlockPath() }

// DefaultMaxInFlight is how many requests a session may have in progress at
// once unless [WithMaxInFlight] says otherwise: OpenSSH's sftp client keeps
// 64 outstanding (sftp-client.c, DEFAULT_NUM_REQUESTS).
const DefaultMaxInFlight = 64

// MaxInFlightLimit is the ceiling [WithMaxInFlight] is clamped to.
const MaxInFlightLimit = 1024

// WithMaxInFlight bounds how many requests one session processes at once.
//
// The bound is enforced BEFORE a request is read: the session takes one of n
// buffers first, and when none is free it stops reading, so a client that
// pipelines faster than the server answers waits in TCP's window instead of in
// this process's memory. Memory per session is at most n packets in and n
// replies out. 1 restores v0.7.0's one-request-at-a-time behaviour; a
// non-positive value means [DefaultMaxInFlight].
func WithMaxInFlight(n int) Option {
	return func(s *Server) { s.maxInFlight = min(n, MaxInFlightLimit) }
}

// DefaultMaxInFlightTotal is the server-wide ceiling on requests in flight
// across every session unless [WithMaxInFlightTotal] says otherwise.
const DefaultMaxInFlightTotal = 256

// WithMaxInFlightTotal bounds the requests in flight across ALL sessions of
// the server, the figure a host serving many clients sizes memory by: each
// request in flight holds up to one packet in, one reply out and one read
// buffer, so memory is at most 3 x n x the packet limit (about 200 MiB at the
// defaults), however many sessions there are. A session that would exceed it
// stops reading its input until another request is answered, as OpenSSH's
// sftp-server stops reading while its output queue cannot take a
// maximum-size message (sftp-server.c, process_requests). A peer that does
// not read its replies keeps its tokens: the same is true of knfsd's threads
// and Samba's `aio max threads`, and the answer there is the same, to close
// idle or stalled connections. A non-positive value means
// [DefaultMaxInFlightTotal].
func WithMaxInFlightTotal(n int) Option { return func(s *Server) { s.maxTotal = n } }

// PathOpsConcurrent asserts that the driver's read-only path calls (Stat,
// ListDir, ReadFile, ReadLink) may run concurrently with each other and with
// File I/O, which lets the server run them in parallel. The interface module
// does not promise it, so the embedder has to: it is right for a host
// directory (os calls), wrong for a driver with a shared cursor or cache.
func PathOpsConcurrent() Option { return func(s *Server) { s.pathConcurrent = true } }

// Option configures a [Server].
type Option func(*Server)

// ReadWrite makes the export writable.
//
// Exports are READ-ONLY BY DEFAULT, for two reasons that both point the same
// way. Most of what this module is pointed at is a forensic or build
// artefact, and an accidental write to one is unrecoverable. And until a
// driver's File implements [WritableFile], every write at a non-zero offset
// is a read-modify-write of the entire file — see the package documentation
// and the measurement in the README. Opting in should be a decision, not a
// default.
func ReadWrite() Option { return func(s *Server) { s.ro = false } }

// WithMaxPacket caps the size of a single SFTP packet, in bytes, counting the
// type byte and payload.
//
// The default, [wire.MaxPacket], accepts everything OpenSSH's client sends
// including its largest -B setting. Lowering it is how a host running many
// tenants bounds the memory any one session can make it hold. A non-positive
// value restores the default.
func WithMaxPacket(n int) Option { return func(s *Server) { s.maxPacket = n } }

// New returns a Server exporting fsys, read-only unless [ReadWrite] is given.
func New(fsys filesystem.Filesystem, opts ...Option) (*Server, error) {
	if fsys == nil {
		return nil, ErrNilFilesystem
	}
	s := &Server{
		fsys:   fsys,
		opener: openerFor(fsys),
		ro:     true,
		start:  uint32(time.Now().Unix()),
	}
	for _, o := range opts {
		o(s)
	}
	if s.maxTotal <= 0 {
		s.maxTotal = DefaultMaxInFlightTotal
	}
	// maxTotal is positive here, so NewPool cannot refuse it.
	s.pool, _ = inflight.NewPool(s.maxTotal)
	s.fs = inflight.NewFSLock(s.pathConcurrent)
	return s, nil
}

// ReadOnly reports whether the export refuses mutating operations.
func (s *Server) ReadOnly() bool { return s.ro }

// Serve runs one SFTP session over rw until the peer closes it or the stream
// fails, and returns nil on a clean close.
//
// rw is one client's SFTP channel: in the ordinary case the SSH subsystem
// channel opened by [github.com/go-filesystems/sftp/sshd], but deliberately
// only an io.ReadWriter, so a program that already runs an SSH server can
// hand this its own channel, and a test can hand it a pipe. Serve does not
// close rw — it did not open it.
//
// Every handle the session opened is released before Serve returns, including
// when the client vanishes mid-transfer, which is what killing an `sftp`
// process does.
func (s *Server) Serve(rw io.ReadWriter) error {
	n := s.maxInFlight
	if n <= 0 {
		n = DefaultMaxInFlight
	}
	conn, err := s.pool.NewConn(rw, inflight.InOrder, n)
	if err != nil {
		return err
	}
	sess := &session{srv: s, rw: rw, handles: newHandles(), conn: conn}
	// run returns only after every request in flight has been answered, so
	// closeAll never races a READ or WRITE still holding a driver file.
	defer sess.handles.closeAll()
	return sess.run()
}

// packetLimit returns the ceiling in force for this server.
func (s *Server) packetLimit() int {
	if s.maxPacket <= 0 {
		return wire.MaxPacket
	}
	return s.maxPacket
}
