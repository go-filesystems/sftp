package sftp

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

func TestModeStringRendersEveryFileType(t *testing.T) {
	for _, tc := range []struct {
		mode uint32
		want string
	}{
		{wire.ModeReg | 0o644, "-rw-r--r--"},
		{wire.ModeDir | 0o755, "drwxr-xr-x"},
		{wire.ModeLink | 0o777, "lrwxrwxrwx"},
		{wire.ModeChar | 0o600, "crw-------"},
		{wire.ModeBlock | 0o660, "brw-rw----"},
		{wire.ModeFifo | 0o644, "prw-r--r--"},
		{wire.ModeSock | 0o755, "srwxr-xr-x"},
		{0o644, "-rw-r--r--"}, // no type bits at all
		// setuid, setgid and sticky, each with and without the execute bit
		// they qualify: lowercase means both, uppercase means the special
		// bit alone.
		{wire.ModeReg | 0o4755, "-rwsr-xr-x"},
		{wire.ModeReg | 0o4644, "-rwSr--r--"},
		{wire.ModeReg | 0o2755, "-rwxr-sr-x"},
		{wire.ModeReg | 0o2644, "-rw-r-Sr--"},
		{wire.ModeDir | 0o1777, "drwxrwxrwt"},
		{wire.ModeDir | 0o1666, "drw-rw-rwT"},
	} {
		if got := modeString(tc.mode); got != tc.want {
			t.Errorf("modeString(%o) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestLongNameLooksLikeLsMinusL(t *testing.T) {
	a := wire.Attributes{
		Flags: wire.AttrSize | wire.AttrPermissions | wire.AttrACModTime,
		Size:  1234, Permissions: wire.ModeReg | 0o644, Mtime: 1_700_000_000,
	}
	got := longName("file.txt", a)
	if !strings.HasPrefix(got, "-rw-r--r-- 1 0 0 1234 ") {
		t.Fatalf("longname = %q", got)
	}
	if !strings.HasSuffix(got, " file.txt") {
		t.Fatalf("longname = %q", got)
	}
}

// TestAttrsForADriverThatReportsPermissionsOnly covers a driver whose Stat
// carries no POSIX type bits. Version 3 has no separate file-type field, so
// leaving them at zero would give a client a listing in which nothing is a
// file OR a directory.
func TestAttrsForADriverThatReportsPermissionsOnly(t *testing.T) {
	srv, _ := New(newMemFS(), ReadWrite())
	a := srv.attrsFromStat(filesystem.NewStat(0o644, 10, 1))
	if a.Permissions&wire.ModeFmt != wire.ModeReg {
		t.Fatalf("permissions = %o, want the regular-file bits filled in", a.Permissions)
	}
}

func TestStatusForSentinelErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want wire.Status
	}{
		{nil, wire.StatusOK},
		{fs.ErrNotExist, wire.StatusNoSuchFile},
		{fs.ErrPermission, wire.StatusPermissionDenied},
		{fs.ErrExist, wire.StatusFailure},
		{fs.ErrInvalid, wire.StatusFailure},
		{filesystem.ErrShrinkUnsupported, wire.StatusOpUnsupported},
		{errors.New("file not found"), wire.StatusNoSuchFile},
		{errors.New("No Such file or directory"), wire.StatusNoSuchFile},
		{errors.New("filesystem is read-only"), wire.StatusPermissionDenied},
		{errors.New("operation not supported"), wire.StatusOpUnsupported},
		{errors.New("something nobody predicted"), wire.StatusFailure},
	} {
		if got := statusFor(tc.err, wire.StatusFailure); got != tc.want {
			t.Errorf("statusFor(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
	// A wrapped sentinel must still be found: drivers wrap.
	if got := statusFor(errWrap{fs.ErrNotExist}, wire.StatusFailure); got != wire.StatusNoSuchFile {
		t.Errorf("statusFor(wrapped ErrNotExist) = %v", got)
	}
}

type errWrap struct{ err error }

func (e errWrap) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

func TestErrTextIsBoundedAndTruthful(t *testing.T) {
	if got := errText(nil); got != "" {
		t.Fatalf("errText(nil) = %q", got)
	}
	if got := errText(errors.New("short")); got != "short" {
		t.Fatalf("errText = %q", got)
	}
	long := errors.New(strings.Repeat("x", 1000))
	got := errText(long)
	if len(got) > 600 {
		t.Fatalf("errText produced %d bytes; the field must stay bounded", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("a truncated message must say so: %q", got[len(got)-8:])
	}
}
