package sftp

import (
	"errors"
	"io"
	"sync"
	"time"

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

	// mu serialises ALL access to the exported filesystem.
	//
	// A go-filesystems driver wraps a single *os.File and is not documented
	// as safe for concurrent use: two overlapping reads would interleave
	// seeks and hand each caller the other's bytes. That is not theoretical
	// here — OpenSSH's sftp client pipelines up to 64 requests at once by
	// default, which is the first thing a `get` of any real file does.
	//
	// One session already serialises itself (it answers each packet before
	// reading the next); this lock is what makes two SESSIONS against the
	// same Server safe. Correct and ordered beats fast and wrong, and a
	// driver that one day documents concurrency-safety can be given a
	// parallel path without any protocol change.
	mu sync.Mutex
}

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
	sess := &session{
		srv:     s,
		rw:      rw,
		handles: newHandles(),
	}
	defer sess.handles.closeAll()
	return sess.run()
}

// lock takes the filesystem lock. Every driver call in this package is made
// between lock and unlock; see [Server.mu].
func (s *Server) lock()   { s.mu.Lock() }
func (s *Server) unlock() { s.mu.Unlock() }

// packetLimit returns the ceiling in force for this server.
func (s *Server) packetLimit() int {
	if s.maxPacket <= 0 {
		return wire.MaxPacket
	}
	return s.maxPacket
}
