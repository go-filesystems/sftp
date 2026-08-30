package sftp

import (
	"errors"
	"io/fs"
	"strings"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// substringStatus maps a fragment of a driver's error text to a status.
//
// This is a wart, and it is worth being explicit about whose wart it is:
// [github.com/go-filesystems/interface] defines no error taxonomy, so drivers
// report "not found" however they like — iso9660 has typed sentinels that do
// not wrap [io/fs.ErrNotExist], fat32 uses a bare fmt.Errorf. A protocol
// server has to turn those into distinct wire codes, because a client behaves
// very differently on "no such file" than on a generic failure: `sftp get`
// retries one and gives up on the other.
//
// The mitigation is that this table is a LAST resort. Sentinel errors are
// tried first, and every operation that can afford to establishes existence
// and type with an explicit Stat rather than inferring them from a string.
// The real fix belongs upstream, in sentinel errors on the interface module
// that every driver wraps.
//
// It is the same table [github.com/go-filesystems/nfs] carries, for the same
// reason and against the same drivers; the right-hand column differs because
// version 3 has nine status codes where NFSv3 has thirty. Where SFTP cannot
// express the distinction, the text survives in the status message, which
// every client shows the user.
var substringStatus = []struct {
	frag   string
	status wire.Status
}{
	{"not found", wire.StatusNoSuchFile},
	{"no such", wire.StatusNoSuchFile},
	{"does not exist", wire.StatusNoSuchFile},
	{"not a directory", wire.StatusFailure},
	{"is a directory", wire.StatusFailure},
	{"not a regular file", wire.StatusFailure},
	{"not a symbolic link", wire.StatusFailure},
	{"not empty", wire.StatusFailure},
	{"read-only", wire.StatusPermissionDenied},
	{"permission", wire.StatusPermissionDenied},
	{"already exists", wire.StatusFailure},
	{"no space", wire.StatusFailure},
	{"not supported", wire.StatusOpUnsupported},
	{"unsupported", wire.StatusOpUnsupported},
}

// statusFor maps a driver error to a status code, using fallback when nothing
// matches.
func statusFor(err error, fallback wire.Status) wire.Status {
	if err == nil {
		return wire.StatusOK
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return wire.StatusNoSuchFile
	case errors.Is(err, fs.ErrPermission):
		return wire.StatusPermissionDenied
	case errors.Is(err, fs.ErrExist), errors.Is(err, fs.ErrInvalid):
		return wire.StatusFailure
	case errors.Is(err, filesystem.ErrShrinkUnsupported):
		return wire.StatusOpUnsupported
	}
	low := strings.ToLower(err.Error())
	for _, m := range substringStatus {
		if strings.Contains(low, m.frag) {
			return m.status
		}
	}
	return fallback
}

// errText renders a driver error for the status message field.
//
// A client displays this to a person, so it is the only channel through which
// a cause version 3's nine codes cannot express still arrives somewhere
// useful. It is truncated because the field is attacker-influenced in one
// direction — a driver could return a very long message about a very long
// path — and a reply should not become unbounded because of it.
func errText(err error) string {
	if err == nil {
		return ""
	}
	const max = 512
	s := err.Error()
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
