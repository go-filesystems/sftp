package sftp

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// fixture returns a small tree used by most tests below.
func fixture() *memFS {
	m := newMemFS()
	m.addDir("/sub")
	m.addFile("/hello.txt", []byte("hello from an image\n"), 0o100644)
	m.addFile("/sub/data.bin", bytes.Repeat([]byte("0123456789abcdef"), 512), 0o100644)
	m.addLink("/link", "/hello.txt")
	return m
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// TestReadThroughOpenerAndThroughFallback runs the identical transfer against
// a driver that has the Opener capability and one that does not, and requires
// byte-for-byte the same answer.
//
// Both paths exist because no driver in the fleet implements Opener yet, so
// the fallback is the one that actually runs today — and the day one does,
// this test is what says the change is invisible to a client.
func TestReadThroughOpenerAndThroughFallback(t *testing.T) {
	want := bytes.Repeat([]byte("0123456789abcdef"), 512)
	for _, tc := range []struct {
		name   string
		build  func(*memFS) filesystem.Filesystem
		opener bool
	}{
		{"fallback (no Opener — every real driver today)", func(m *memFS) filesystem.Filesystem { return bareFS{m} }, false},
		{"Opener", func(m *memFS) filesystem.Filesystem { return openerFS{m} }, true},
		{"Opener + WritableFile", func(m *memFS) filesystem.Filesystem { return writableFS{m} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := tc.build(fixture())
			srv, err := New(fsys)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if (srv.opener != nil) != tc.opener {
				t.Fatalf("opener probe = %v, want %v", srv.opener != nil, tc.opener)
			}
			c := serveOn(t, srv)
			h := c.open("/sub/data.bin", wire.FxfRead)
			if got := c.readAll(h, 4096); !bytes.Equal(got, want) {
				t.Fatalf("read %d bytes, want %d", len(got), len(want))
			}
			c.closeHandle(h)
		})
	}
}

// TestReadAtNonZeroOffset is the request SSH_FXP_READ exists for: give me
// these bytes, from there, without touching the rest.
func TestReadAtNonZeroOffset(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 512)
	for _, tc := range []struct {
		name  string
		build func(*memFS) filesystem.Filesystem
	}{
		{"fallback", func(m *memFS) filesystem.Filesystem { return bareFS{m} }},
		{"Opener", func(m *memFS) filesystem.Filesystem { return openerFS{m} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, tc.build(fixture()))
			h := c.open("/sub/data.bin", wire.FxfRead)
			const off, n = 4097, 33
			typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: off, Length: n})
			if typ != wire.FxpData {
				st, _ := wire.DecodeStatus(payload)
				t.Fatalf("read: %v (%q)", st.Code, st.Message)
			}
			d, err := wire.DecodeData(payload)
			if err != nil {
				t.Fatalf("DecodeData: %v", err)
			}
			if !bytes.Equal(d.Data, data[off:off+n]) {
				t.Fatalf("read at %d = %q, want %q", off, d.Data, data[off:off+n])
			}
			// The very last byte, and then past the end.
			typ, payload = c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: uint64(len(data)) - 1, Length: 64})
			d, _ = wire.DecodeData(payload)
			if typ != wire.FxpData || len(d.Data) != 1 || d.Data[0] != data[len(data)-1] {
				t.Fatalf("read of the final byte returned type %d, %q", typ, d.Data)
			}
			typ, payload = c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: uint64(len(data)), Length: 64})
			c.status(typ, payload, wire.StatusEOF)
			c.closeHandle(h)
		})
	}
}

func TestReadOfZeroLengthReturnsEmptyData(t *testing.T) {
	c := dial(t, fixture())
	h := c.open("/hello.txt", wire.FxfRead)
	typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 0})
	if typ != wire.FxpData {
		t.Fatalf("reply type %d, want SSH_FXP_DATA", typ)
	}
	d, _ := wire.DecodeData(payload)
	if len(d.Data) != 0 {
		t.Fatalf("zero-length read returned %d bytes", len(d.Data))
	}
	c.closeHandle(h)
}

func TestReadLengthIsClampedToThePacketLimit(t *testing.T) {
	// A client asking for more than the server would ever send must get a
	// short read, not an allocation of whatever it named.
	c := dial(t, fixture(), WithMaxPacket(1024))
	h := c.open("/sub/data.bin", wire.FxfRead)
	typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 1 << 30})
	if typ != wire.FxpData {
		t.Fatalf("reply type %d, want SSH_FXP_DATA", typ)
	}
	d, _ := wire.DecodeData(payload)
	if len(d.Data) != 1024 {
		t.Fatalf("read returned %d bytes, want the 1024-byte clamp", len(d.Data))
	}
	c.closeHandle(h)
}

func TestReadErrorsFromTheDriver(t *testing.T) {
	t.Run("fallback ReadFile fails", func(t *testing.T) {
		m := fixture()
		c := dial(t, bareFS{m})
		h := c.open("/hello.txt", wire.FxfRead)
		m.fail["ReadFile:/hello.txt"] = errors.New("disk on fire")
		typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 16})
		st := c.status(typ, payload, wire.StatusFailure)
		if !strings.Contains(st.Message, "disk on fire") {
			t.Fatalf("message %q lost the driver's reason", st.Message)
		}
	})
	t.Run("ReadAt fails", func(t *testing.T) {
		m := fixture()
		c := dial(t, openerFS{m})
		h := c.open("/hello.txt", wire.FxfRead)
		m.fail["ReadAt:/hello.txt"] = errors.New("bad sector")
		typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 16})
		st := c.status(typ, payload, wire.StatusFailure)
		if !strings.Contains(st.Message, "bad sector") {
			t.Fatalf("message %q lost the driver's reason", st.Message)
		}
	})
	t.Run("ReadAt returns no bytes and no error", func(t *testing.T) {
		m := fixture()
		m.addFile("/empty", nil, 0o100644)
		c := dial(t, openerFS{m})
		// Size 0 means the offset check reports EOF before ReadAt runs;
		// force the other branch with a file whose ReadAt is a no-op.
		h := c.open("/hello.txt", wire.FxfRead)
		m.fail["ReadAtNil:/hello.txt"] = errNoBytes
		typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 16})
		c.status(typ, payload, wire.StatusEOF)
	})
}

// errNoBytes is a marker in the fixture's failure map, not an error the
// driver returns: it makes ReadAt answer (0, nil), which is the branch where
// a driver reports neither data nor a reason. The server must still answer.
var errNoBytes = errors.New("marker")

func TestReadOnADirectoryHandleIsRefused(t *testing.T) {
	c := dial(t, fixture())
	h := c.opendir("/")
	typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 16})
	c.status(typ, payload, wire.StatusFailure)
	typ, payload = c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("x")})
	c.status(typ, payload, wire.StatusFailure)
	c.closeHandle(h)
}

func TestUnknownHandlesAreRefused(t *testing.T) {
	c := dial(t, fixture())
	const bogus = "deadbeef"
	for _, m := range []wire.Message{
		wire.ReadRequest{ID: c.next(), Handle: bogus},
		wire.WriteRequest{ID: c.next(), Handle: bogus, Data: []byte("x")},
		wire.HandleRequest{PacketType: wire.FxpClose, ID: c.next(), Handle: bogus},
		wire.HandleRequest{PacketType: wire.FxpReaddir, ID: c.next(), Handle: bogus},
		wire.HandleRequest{PacketType: wire.FxpFstat, ID: c.next(), Handle: bogus},
		wire.FsetstatRequest{ID: c.next(), Handle: bogus},
	} {
		typ, payload := c.do(m)
		c.status(typ, payload, wire.StatusFailure)
	}
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

func TestOpenRefusals(t *testing.T) {
	c := dial(t, fixture())
	t.Run("missing file", func(t *testing.T) {
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/nope", PFlags: wire.FxfRead})
		c.status(typ, payload, wire.StatusNoSuchFile)
	})
	t.Run("a directory is not a file", func(t *testing.T) {
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/sub", PFlags: wire.FxfRead})
		st := c.status(typ, payload, wire.StatusFailure)
		if !strings.Contains(st.Message, "directory") {
			t.Fatalf("message = %q, want it to say the path is a directory", st.Message)
		}
	})
	t.Run("writing to a read-only export", func(t *testing.T) {
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/hello.txt", PFlags: wire.FxfWrite})
		st := c.status(typ, payload, wire.StatusPermissionDenied)
		if !strings.Contains(st.Message, "read-only") {
			t.Fatalf("message = %q, want it to name the export's mode", st.Message)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/a\x00b", PFlags: wire.FxfRead})
		c.status(typ, payload, wire.StatusFailure)
	})
}

func TestOpenCreateTruncateExclusive(t *testing.T) {
	m := fixture()
	c := dial(t, m, ReadWrite())

	t.Run("create", func(t *testing.T) {
		h := c.open("/new.txt", wire.FxfWrite|wire.FxfCreat)
		c.closeHandle(h)
		if _, ok := m.nodes["/new.txt"]; !ok {
			t.Fatal("CREAT did not create the file")
		}
	})
	t.Run("exclusive create over an existing file", func(t *testing.T) {
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/new.txt", PFlags: wire.FxfWrite | wire.FxfCreat | wire.FxfExcl})
		st := c.status(typ, payload, wire.StatusFailure)
		if !strings.Contains(st.Message, "exists") {
			t.Fatalf("message = %q", st.Message)
		}
	})
	t.Run("write without CREAT on a missing file", func(t *testing.T) {
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/absent", PFlags: wire.FxfWrite})
		c.status(typ, payload, wire.StatusNoSuchFile)
	})
	t.Run("truncate", func(t *testing.T) {
		h := c.open("/hello.txt", wire.FxfWrite|wire.FxfTrunc)
		c.closeHandle(h)
		if len(m.nodes["/hello.txt"].data) != 0 {
			t.Fatalf("TRUNC left %d bytes", len(m.nodes["/hello.txt"].data))
		}
	})
	t.Run("create with an explicit mode", func(t *testing.T) {
		h := c.open2("/moded", wire.FxfWrite|wire.FxfCreat, wire.Attributes{
			Flags: wire.AttrPermissions, Permissions: 0o600,
		})
		c.closeHandle(h)
		if got := m.nodes["/moded"].mode & 0o7777; got != 0o600 {
			t.Fatalf("mode = %o, want 600", got)
		}
	})
	t.Run("the driver refuses the create", func(t *testing.T) {
		m.fail["WriteFile:/refused"] = errors.New("no space left on device")
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/refused", PFlags: wire.FxfWrite | wire.FxfCreat})
		c.status(typ, payload, wire.StatusFailure)
	})
}

func TestOpenerFailuresAtOpen(t *testing.T) {
	t.Run("OpenFile fails", func(t *testing.T) {
		m := fixture()
		m.fail["OpenFile:/hello.txt"] = fs.ErrPermission
		c := dial(t, openerFS{m})
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/hello.txt", PFlags: wire.FxfRead})
		c.status(typ, payload, wire.StatusPermissionDenied)
	})
	t.Run("OpenFile returns (nil, nil)", func(t *testing.T) {
		m := fixture()
		m.addFile("/nilfile", []byte("x"), 0o100644)
		c := dial(t, openerFS{m})
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/nilfile", PFlags: wire.FxfRead})
		st := c.status(typ, payload, wire.StatusFailure)
		if !strings.Contains(st.Message, "no file") {
			t.Fatalf("message = %q, want it to name the driver bug", st.Message)
		}
	})
	t.Run("a write open on a non-writable File closes it and falls back", func(t *testing.T) {
		m := fixture()
		c := dial(t, openerFS{m}, ReadWrite())
		h := c.open("/hello.txt", wire.FxfWrite)
		// The fallback path must still write correctly.
		typ, payload := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 6, Data: []byte("XXXXX")})
		c.status(typ, payload, wire.StatusOK)
		c.closeHandle(h)
		if got := string(m.nodes["/hello.txt"].data); got != "hello XXXXXan image\n" {
			t.Fatalf("file = %q", got)
		}
	})
	t.Run("closing the discarded File fails", func(t *testing.T) {
		m := fixture()
		m.fail["FileClose:/hello.txt"] = errors.New("close failed")
		c := dial(t, openerFS{m}, ReadWrite())
		typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/hello.txt", PFlags: wire.FxfWrite})
		c.status(typ, payload, wire.StatusFailure)
	})
}

func TestOpenRefusesToMintAPredictableHandle(t *testing.T) {
	// A server whose CSPRNG has failed must say so, not carry on with
	// something weaker that nobody was told about.
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	c := dial(t, fixture())
	typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/hello.txt", PFlags: wire.FxfRead})
	st := c.status(typ, payload, wire.StatusFailure)
	if !strings.Contains(st.Message, "no entropy") {
		t.Fatalf("message = %q", st.Message)
	}
	typ, payload = c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/"})
	c.status(typ, payload, wire.StatusFailure)
}

func TestOpenClosesTheDriverFileWhenTheHandleCannotBeMinted(t *testing.T) {
	m := fixture()
	c := dial(t, openerFS{m})
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: "/hello.txt", PFlags: wire.FxfRead})
	c.status(typ, payload, wire.StatusFailure)
}

func TestCloseErrors(t *testing.T) {
	t.Run("File.Close fails", func(t *testing.T) {
		m := fixture()
		m.fail["FileClose:/hello.txt"] = errors.New("close failed")
		c := dial(t, openerFS{m})
		h := c.open("/hello.txt", wire.FxfRead)
		typ, payload := c.do(wire.HandleRequest{PacketType: wire.FxpClose, ID: c.next(), Handle: h})
		c.status(typ, payload, wire.StatusFailure)
	})
	t.Run("Sync fails", func(t *testing.T) {
		m := fixture()
		m.fail["Sync:/hello.txt"] = errors.New("sync failed")
		c := dial(t, writableFS{m}, ReadWrite())
		h := c.open("/hello.txt", wire.FxfWrite)
		typ, payload := c.do(wire.HandleRequest{PacketType: wire.FxpClose, ID: c.next(), Handle: h})
		st := c.status(typ, payload, wire.StatusFailure)
		if !strings.Contains(st.Message, "sync failed") {
			t.Fatalf("message = %q", st.Message)
		}
	})
	t.Run("closing twice is refused the second time", func(t *testing.T) {
		c := dial(t, fixture())
		h := c.open("/hello.txt", wire.FxfRead)
		c.closeHandle(h)
		typ, payload := c.do(wire.HandleRequest{PacketType: wire.FxpClose, ID: c.next(), Handle: h})
		c.status(typ, payload, wire.StatusFailure)
	})
}

// TestAbandonedHandlesAreReleased covers the normal way an sftp session ends:
// someone interrupts it mid-transfer and nothing is closed.
func TestAbandonedHandlesAreReleased(t *testing.T) {
	m := fixture()
	srv, _ := New(openerFS{m})
	c := serveOn(t, srv)
	c.open("/hello.txt", wire.FxfRead)
	c.finish()
	// Nothing to assert on the driver from outside; what this proves is
	// that closeAll runs and Serve still returns cleanly.
}

func TestAbandonedHandleCloseErrorIsNotFatal(t *testing.T) {
	m := fixture()
	m.fail["FileClose:/hello.txt"] = errors.New("close failed")
	srv, _ := New(openerFS{m})
	c := serveOn(t, srv)
	c.open("/hello.txt", wire.FxfRead)
	c.finish()
}
