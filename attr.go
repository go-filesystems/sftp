package sftp

import (
	"math"
	"strconv"
	"strings"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// TimeStat is the optional capability a driver's
// [github.com/go-filesystems/interface.Stat] may implement to report a real
// modification time.
//
// It is the older probe, kept for a Stat that carries its own time. A
// filesystem with [filesystem.TimesReader] (interface v0.6.0) takes precedence
// over it (see attrsAt), and a driver with neither carries the server's start
// time in atime and mtime for every file.
type TimeStat interface {
	ModTime() int64 // seconds since the Unix epoch
}

// attrsFromStat converts a driver Stat into an SFTP ATTRS structure.
//
// Every field it sets, it announces. Nothing is sent unflagged, because a
// flag that is not set means "the server did not say", which is a true and
// useful answer, whereas an unflagged zero is a lie a client will act on.
func (s *Server) attrsFromStat(st filesystem.Stat) wire.Attributes {
	a := wire.Attributes{
		Flags: wire.AttrSize | wire.AttrUIDGID | wire.AttrPermissions | wire.AttrACModTime,
		Size:  st.Size(),
	}

	mode := uint32(st.Mode())
	if mode&wire.ModeFmt == 0 {
		// A driver reporting permission bits only. Version 3 has no
		// separate file-type field, so leaving the type bits at zero would
		// give a client a listing in which nothing is a file OR a
		// directory. Regular file is the only guess that cannot make a
		// client try to enumerate something it must not.
		mode |= wire.ModeReg
	}
	a.Permissions = mode

	if s.ro {
		// Clearing the write bits on a read-only export makes the client's
		// own check agree with the SSH_FX_PERMISSION_DENIED it would
		// otherwise only discover after trying. Graphical clients grey out
		// rename and delete on the strength of this.
		a.Permissions &^= 0o222
	}

	a.Atime, a.Mtime = s.start, s.start
	if t, ok := st.(TimeStat); ok {
		m := uint32(t.ModTime())
		a.Atime, a.Mtime = m, m
	}
	return a
}

// attrsAt is attrsFromStat with the times the filesystem records for path, when
// it can say (filesystem.TimesReader); without the capability, or when its call
// fails, the result is attrsFromStat's.
//
// ATTRS version 3 carries atime and mtime as ONE flagged pair of uint32 seconds
// since 1970 (draft-ietf-secsh-filexfer-02 section 5, SSH_FILEXFER_ATTR_ACMODTIME):
// there is no way to flag one without the other, no sub-second part, no ctime and
// no birth time. So:
//
//   - mtime recorded: the pair is sent; a missing atime is the mtime.
//   - mtime not recorded: the flag is CLEARED, which is the protocol's own way
//     to say "the server did not say"; the format's atime alone is not worth a
//     mtime that would be invented.
//   - a time before 1970 clamps to 0 and one after 2106 to 2^32-1: the field is
//     unsigned and 32 bits wide.
func (s *Server) attrsAt(path string, st filesystem.Stat) wire.Attributes {
	a := s.attrsFromStat(st)
	tr, ok := s.fsys.(filesystem.TimesReader)
	if !ok {
		return a
	}
	ft, err := tr.Times(path)
	if err != nil {
		return a
	}
	mt, ok := seconds32(ft.Mtime)
	if !ok {
		a.Flags &^= wire.AttrACModTime
		a.Atime, a.Mtime = 0, 0
		return a
	}
	at, ok := seconds32(ft.Atime)
	if !ok {
		at = mt
	}
	a.Atime, a.Mtime = at, mt
	return a
}

// seconds32 returns a Timestamp as the unsigned 32-bit seconds ATTRS carries.
func seconds32(ts filesystem.Timestamp) (uint32, bool) {
	t, ok := ts.Get()
	if !ok {
		return 0, false
	}
	switch u := t.Unix(); {
	case u < 0:
		return 0, true
	case u > math.MaxUint32:
		return math.MaxUint32, true
	default:
		return uint32(u), true
	}
}

// longName renders one directory entry in `ls -l` form for the longname field
// of a NAME reply.
//
// Version 3 leaves this field's format completely unspecified, which has one
// consequence worth stating: no client may parse it, and every client
// displays it. It is presentation. The authoritative values are in the
// attributes beside it, and nothing here should ever be the only place a fact
// appears.
func longName(name string, a wire.Attributes) string {
	var b strings.Builder
	b.WriteString(modeString(a.Permissions))
	b.WriteString(" 1 ")
	b.WriteString(strconv.FormatUint(uint64(a.UID), 10))
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(uint64(a.GID), 10))
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(a.Size, 10))
	b.WriteByte(' ')
	if a.Flags&wire.AttrACModTime != 0 {
		b.WriteString(time.Unix(int64(a.Mtime), 0).UTC().Format("Jan _2 15:04"))
	} else {
		// No time was given: say so, rather than print 1970.
		b.WriteString("??? ?? ??:??")
	}
	b.WriteByte(' ')
	b.WriteString(name)
	return b.String()
}

// typeLetter is the first character of an `ls -l` mode string.
func typeLetter(mode uint32) byte {
	switch mode & wire.ModeFmt {
	case wire.ModeDir:
		return 'd'
	case wire.ModeLink:
		return 'l'
	case wire.ModeChar:
		return 'c'
	case wire.ModeBlock:
		return 'b'
	case wire.ModeFifo:
		return 'p'
	case wire.ModeSock:
		return 's'
	default:
		return '-'
	}
}

// modeString renders the ten-character mode field of `ls -l`.
func modeString(mode uint32) string {
	out := []byte("----------")
	out[0] = typeLetter(mode)
	const rwx = "rwxrwxrwx"
	for i := range 9 {
		if mode&(1<<(8-uint(i))) != 0 {
			out[i+1] = rwx[i]
		}
	}
	// setuid, setgid and sticky overwrite the execute position they
	// qualify, in the usual way: an uppercase letter means the bit is set
	// without the matching execute bit.
	setBit := func(pos int, bit uint32, set, unset byte) {
		if mode&bit == 0 {
			return
		}
		if out[pos] == 'x' {
			out[pos] = set
			return
		}
		out[pos] = unset
	}
	setBit(3, 0o4000, 's', 'S')
	setBit(6, 0o2000, 's', 'S')
	setBit(9, 0o1000, 't', 'T')
	return string(out)
}

// unixTime converts an SFTP 32-bit timestamp to a [time.Time].
//
// The 32-bit field is version 3's, not a choice made here; it stops working
// in 2106 and a later protocol version is the only thing that fixes it.
func unixTime(sec uint32) time.Time { return time.Unix(int64(sec), 0) }
