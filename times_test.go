package sftp

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

type timesFS struct {
	*memFS
	ft  filesystem.FileTimes
	err error
}

func (f timesFS) Times(string) (filesystem.FileTimes, error) { return f.ft, f.err }

func newTimesSrv(t *testing.T, ft filesystem.FileTimes, err error) *Server {
	t.Helper()
	srv, e := New(timesFS{memFS: fixture(), ft: ft, err: err})
	if e != nil {
		t.Fatal(e)
	}
	return srv
}

func TestAttrsAtUsesRecordedTimes(t *testing.T) {
	m := filesystem.NewTimestamp(time.Unix(1_700_000_000, 5), time.Nanosecond)
	at := filesystem.NewTimestamp(time.Unix(1_600_000_000, 0), 24*time.Hour)
	st := filesystem.NewStat(0o644, 3, 1)

	a := newTimesSrv(t, filesystem.FileTimes{Mtime: m, Atime: at}, nil).attrsAt("/x", st)
	if a.Flags&wire.AttrACModTime == 0 || a.Mtime != 1_700_000_000 || a.Atime != 1_600_000_000 {
		t.Errorf("both: %+v", a)
	}

	// atime missing: the flagged pair needs one, and it is the mtime.
	a = newTimesSrv(t, filesystem.FileTimes{Mtime: m}, nil).attrsAt("/x", st)
	if a.Flags&wire.AttrACModTime == 0 || a.Atime != 1_700_000_000 || a.Mtime != 1_700_000_000 {
		t.Errorf("no atime: %+v", a)
	}

	// mtime missing: the flag is cleared, nothing is invented -- even though
	// the format has an atime.
	a = newTimesSrv(t, filesystem.FileTimes{Atime: at}, nil).attrsAt("/x", st)
	if a.Flags&wire.AttrACModTime != 0 || a.Mtime != 0 || a.Atime != 0 {
		t.Errorf("no mtime: %+v", a)
	}
	if !strings.Contains(longName("x", a), "??? ?? ??:??") {
		t.Errorf("longname shows a date for no time: %q", longName("x", a))
	}

	// A failing Times call is the old behaviour: the server's start time.
	srv := newTimesSrv(t, filesystem.FileTimes{}, errors.New("boom"))
	a = srv.attrsAt("/x", st)
	if a.Flags&wire.AttrACModTime == 0 || a.Mtime != srv.start {
		t.Errorf("error: %+v, start %d", a, srv.start)
	}

	// No capability at all: unchanged.
	plain, _ := New(fixture())
	a = plain.attrsAt("/x", st)
	if a.Mtime != plain.start {
		t.Errorf("plain: %+v", a)
	}
}

func TestSeconds32(t *testing.T) {
	for _, tc := range []struct {
		name string
		ts   filesystem.Timestamp
		want uint32
		ok   bool
	}{
		{"absent", filesystem.Timestamp{}, 0, false},
		{"normal", filesystem.NewTimestamp(time.Unix(1234567890, 0), time.Second), 1234567890, true},
		{"before 1970", filesystem.NewTimestamp(time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), time.Second), 0, true},
		{"after 2106", filesystem.NewTimestamp(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), time.Second), math.MaxUint32, true},
	} {
		got, ok := seconds32(tc.ts)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: %d %v", tc.name, got, ok)
		}
	}
}

func TestReaddirCarriesRecordedTimes(t *testing.T) {
	m := filesystem.NewTimestamp(time.Date(2019, 3, 4, 5, 6, 8, 0, time.UTC), 2*time.Second)
	srv := newTimesSrv(t, filesystem.FileTimes{Mtime: m}, nil)
	s := &session{srv: srv}
	items := s.readdirBatch(&openFile{path: "/"}, []filesystem.DirEntry{filesystem.NewDirEntry(1, "hello.txt", 0)})
	if len(items) != 1 || !strings.Contains(items[0].Longname, "Mar  4 05:06 hello.txt") {
		t.Fatalf("items = %+v", items)
	}
}
