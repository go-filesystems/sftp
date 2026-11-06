package sftp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/go-filesystems/inflight"
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
// One goroutine reads packets; READ and WRITE are answered on goroutines of
// their own, up to [WithMaxInFlight] at a time, and every other request is a
// barrier run alone. See concurrent.go for the rules and their sources.
// Replies go out in the order the requests arrived, whatever order the work
// finishes in (see [session.enqueue] for why).
type session struct {
	srv     *Server
	rw      io.ReadWriter
	handles *handles
	conn    *inflight.Conn

	// in and out serve negotiation; requests use their slot's buffers.
	in, out []byte
}

// run performs version negotiation and then the request loop.
func (s *session) run() error {
	br := bufio.NewReaderSize(s.rw, 64<<10)
	if err := s.negotiate(br); err != nil {
		return err
	}
	// Whatever ends the loop, requests in flight are answered (or fail on
	// the dead stream) before run returns and the handles are closed.
	defer s.conn.Wait()
	for {
		if err := s.conn.Err(); err != nil {
			return err
		}
		// Wait for the next packet to begin BEFORE taking a slot and a token:
		// an idle session must hold nothing of the server-wide budget.
		if _, err := br.Peek(1); err != nil {
			return endOfInput(err)
		}
		sl, err := s.conn.Begin()
		if err != nil {
			return err
		}
		// The slot and the token are held while the rest of the packet
		// arrives, so that time is bounded: a client that sends a length and
		// stops must not hold the server-wide budget.
		stop := s.armPacketTimer()
		typ, payload, next, err := wire.ReadPacket(br, sl.In, s.srv.packetLimit())
		stop()
		sl.In = next
		if err != nil {
			s.conn.Abandon(sl)
			return endOfInput(err)
		}
		j, early := s.prepare(typ, payload)
		switch {
		case j != nil:
			s.conn.Go(sl, j.span, j.run)
		case early != nil:
			s.conn.Barrier(sl, func(sl *inflight.Slot) ([]byte, error) { return frame(sl, early) })
		default:
			// A barrier: everything before it is answered first.
			s.conn.Barrier(sl, func(sl *inflight.Slot) ([]byte, error) { return frame(sl, s.dispatch(typ, payload)) })
		}
	}
}

// armPacketTimer starts the clock on the rest of a packet and returns what
// stops it. When it runs out the stream is given up: through SetReadDeadline
// if the stream has one (a net.Conn), by closing it otherwise (an SSH channel).
// A stream with neither cannot be interrupted, and the bound does not hold.
func (s *session) armPacketTimer() (stop func()) {
	d := s.srv.packetTimeout()
	if d <= 0 {
		return func() {}
	}
	t := time.AfterFunc(d, s.giveUp)
	return func() { t.Stop() }
}

func (s *session) giveUp() {
	switch c := s.rw.(type) {
	case interface{ SetReadDeadline(time.Time) error }:
		c.SetReadDeadline(time.Unix(1, 0))
	case io.Closer:
		c.Close()
	}
}

// endOfInput is what a failed read ends a session with. A clean end of stream
// at a packet boundary is how a client says goodbye; it is not a failure of
// anything.
func endOfInput(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
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
	// The extensions advertised are the ones answered: limits@openssh.com,
	// and copy-data where it can copy. Every other one -- hardlink@openssh.com,
	// posix-rename@openssh.com, statvfs@openssh.com -- is an operation this
	// server would then have to implement, and advertising one that is not
	// implemented is worse than silence, because a client stops falling back.
	s.out, err = wire.Send(s.rw, wire.VersionReply{Version: wire.Version,
		Extensions: s.srv.extensions()}, s.out)
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

	// READ and WRITE never arrive here: [session.prepare] takes them.

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
		switch m.Name {
		case limitsExtension:
			return s.limitsReply(m.ID)
		case copyDataExtension:
			return s.copyData(m.ID, m.Data)
		}
		// Any other extension is one this server did not advertise, so a
		// client asking for it is asking for something it was told nothing
		// about. Saying so lets it fall back; inventing an answer would not.
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
