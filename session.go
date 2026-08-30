package sftp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"

	"github.com/go-filesystems/sftp/wire"
)

// ErrNoInit reports a peer whose first packet was not SSH_FXP_INIT.
//
// The session cannot continue: version negotiation is the only thing that
// establishes what the following bytes mean, so guessing would be worse than
// stopping.
var ErrNoInit = errors.New("sftp: first packet was not SSH_FXP_INIT")

// ErrVersion reports a peer demanding a protocol version this server cannot
// speak. See [wire.Version].
var ErrVersion = errors.New("sftp: unsupported client protocol version")

// session is one SFTP conversation over one stream.
//
// It handles packets strictly one at a time: read, dispatch, reply, read
// again. Clients pipeline heavily — OpenSSH keeps 64 requests outstanding —
// so this is a real serialisation, and it is the same choice
// [github.com/go-filesystems/nfs] makes for the same reason: the driver
// underneath is a single *os.File that is not documented as safe for
// concurrent use.
type session struct {
	srv     *Server
	rw      io.ReadWriter
	handles *handles

	// in and out are reused across packets so a bulk transfer does not
	// allocate once per 32 KiB chunk.
	in, out []byte
}

// run performs version negotiation and then the request loop.
func (s *session) run() error {
	br := bufio.NewReaderSize(s.rw, 64<<10)
	if err := s.negotiate(br); err != nil {
		return err
	}
	for {
		typ, payload, next, err := wire.ReadPacket(br, s.in, s.srv.packetLimit())
		s.in = next
		if err != nil {
			// A clean end of stream at a packet boundary is how a client
			// says goodbye; it is not a failure of anything.
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		msg := s.dispatch(typ, payload)
		if s.out, err = wire.Send(s.rw, msg, s.out); err != nil {
			return err
		}
	}
}

// negotiate exchanges INIT and VERSION.
func (s *session) negotiate(r io.Reader) error {
	typ, payload, next, err := wire.ReadPacket(r, s.in, s.srv.packetLimit())
	s.in = next
	if err != nil {
		return err
	}
	if typ != wire.FxpInit {
		return ErrNoInit
	}
	init, err := wire.DecodeInit(payload)
	if err != nil {
		return err
	}
	if init.Version < wire.Version {
		// Versions 1 and 2 differ from 3 in ways that are not
		// forward-compatible — most visibly, a status packet carries no
		// message — so agreeing to one would mean implementing it, not
		// merely tolerating it. Nothing sends them.
		return ErrVersion
	}
	// A client offering a HIGHER version is answered with 3 and is required
	// by the draft to drop to it. Every client does; this is the normal
	// path for the few that offer more.
	//
	// No extensions are advertised. Each one is an operation this server
	// would then have to implement — hardlink@openssh.com,
	// posix-rename@openssh.com, statvfs@openssh.com — and advertising one
	// that is not implemented is worse than silence, because a client stops
	// falling back. A client that sees none uses the base operations, which
	// is what this exports.
	s.out, err = wire.Send(s.rw, wire.VersionReply{Version: wire.Version}, s.out)
	return err
}

// requestID recovers the id from a payload whose decode failed.
//
// A status reply must echo the id of the request it answers, or the client
// cannot match it and waits forever. Every request except INIT begins with
// its id, so even a payload that is otherwise garbage usually still has one.
// A payload too short to hold one gets id 0 — the reply is then unmatchable,
// but the connection stays framed and the client's own timeout handles it,
// which is better than closing on a single bad packet.
func requestID(payload []byte) uint32 {
	if len(payload) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(payload[:4])
}

// status builds an SSH_FXP_STATUS reply.
func status(id uint32, code wire.Status, msg string) wire.StatusReply {
	return wire.StatusReply{ID: id, Code: code, Message: msg}
}

// dispatch decodes one request and produces its reply.
//
// Every branch returns a message; none returns an error. That is the
// invariant that keeps a session alive: a request the server cannot satisfy —
// malformed, unknown, refused — is answered, not escalated, because an SFTP
// client has no way to recover from a channel that simply stops.
func (s *session) dispatch(typ uint8, payload []byte) wire.Message {
	id := requestID(payload)
	switch typ {
	case wire.FxpOpen:
		m, err := wire.DecodeOpen(payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opOpen(m)

	case wire.FxpClose:
		m, err := wire.DecodeHandle(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opClose(m)

	case wire.FxpRead:
		m, err := wire.DecodeRead(payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opRead(m)

	case wire.FxpWrite:
		m, err := wire.DecodeWrite(payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opWrite(m)

	case wire.FxpLstat, wire.FxpStat:
		m, err := wire.DecodePath(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opStat(m)

	case wire.FxpFstat:
		m, err := wire.DecodeHandle(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opFstat(m)

	case wire.FxpSetstat:
		m, err := wire.DecodeSetstat(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opSetstat(m.ID, m.Path, m.Attrs)

	case wire.FxpFsetstat:
		m, err := wire.DecodeFsetstat(payload)
		if err != nil {
			return badMessage(id, err)
		}
		h, ok := s.handles.get(m.Handle)
		if !ok {
			return status(m.ID, wire.StatusFailure, "unknown handle")
		}
		return s.opSetstat(m.ID, h.path, m.Attrs)

	case wire.FxpOpendir:
		m, err := wire.DecodePath(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opOpendir(m)

	case wire.FxpReaddir:
		m, err := wire.DecodeHandle(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opReaddir(m)

	case wire.FxpRemove, wire.FxpRmdir:
		m, err := wire.DecodePath(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opRemove(m)

	case wire.FxpMkdir:
		m, err := wire.DecodeSetstat(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opMkdir(m)

	case wire.FxpRealpath:
		m, err := wire.DecodePath(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opRealpath(m)

	case wire.FxpRename:
		m, err := wire.DecodeRename(payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opRename(m)

	case wire.FxpReadlink:
		m, err := wire.DecodePath(typ, payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opReadlink(m)

	case wire.FxpSymlink:
		m, err := wire.DecodeSymlink(payload)
		if err != nil {
			return badMessage(id, err)
		}
		return s.opSymlink(m)

	case wire.FxpExtended:
		m, err := wire.DecodeExtended(payload)
		if err != nil {
			return badMessage(id, err)
		}
		// No extension is advertised, so a client asking for one is asking
		// for something it was told nothing about. Saying so lets it fall
		// back; inventing an answer would not.
		return status(m.ID, wire.StatusOpUnsupported, "unsupported extension: "+m.Name)

	default:
		// SSH_FXP_INIT arriving twice lands here too, which is right: the
		// session is already negotiated and a second one is a protocol
		// error, not a renegotiation.
		return status(id, wire.StatusOpUnsupported, "unsupported request type")
	}
}

// badMessage answers a request whose payload did not decode.
func badMessage(id uint32, err error) wire.StatusReply {
	return status(id, wire.StatusBadMessage, errText(err))
}
