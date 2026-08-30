package sftp

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// TestWriteThroughBothPaths puts the same file through the read-modify-write
// fallback and through WritableFile, and requires an identical result.
//
// The two differ enormously in cost and not at all in outcome, which is the
// point: the wall is a performance property of the contract, not a
// correctness one, so a driver gaining WritableFile changes nothing a client
// can observe except the clock.
func TestWriteThroughBothPaths(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 1024) // 8 KiB
	for _, tc := range []struct {
		name     string
		build    func(*memFS) filesystem.Filesystem
		writable bool
	}{
		{"read-modify-write fallback", func(m *memFS) filesystem.Filesystem { return bareFS{m} }, false},
		{"WritableFile", func(m *memFS) filesystem.Filesystem { return writableFS{m} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMemFS()
			c := dial(t, tc.build(m), ReadWrite())
			h := c.open("/out.bin", wire.FxfWrite|wire.FxfCreat|wire.FxfTrunc)
			const chunk = 1024
			for off := 0; off < len(payload); off += chunk {
				end := min(off+chunk, len(payload))
				typ, p := c.do(wire.WriteRequest{
					ID: c.next(), Handle: h, Offset: uint64(off), Data: payload[off:end],
				})
				c.status(typ, p, wire.StatusOK)
			}
			c.closeHandle(h)
			if got := m.nodes["/out.bin"].data; !bytes.Equal(got, payload) {
				t.Fatalf("wrote %d bytes, image holds %d", len(payload), len(got))
			}
		})
	}
}

// TestWriteOutOfOrderLeavesAZeroHole covers a client that writes chunks in a
// different order from the one the file is laid out in — which the protocol
// permits and which the splice path has to get right, since it is the one
// that has to invent the gap.
func TestWriteOutOfOrderLeavesAZeroHole(t *testing.T) {
	m := newMemFS()
	c := dial(t, bareFS{m}, ReadWrite())
	h := c.open("/sparse", wire.FxfWrite|wire.FxfCreat)
	typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 8, Data: []byte("tail")})
	c.status(typ, p, wire.StatusOK)
	typ, p = c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("head")})
	c.status(typ, p, wire.StatusOK)
	c.closeHandle(h)
	want := append([]byte("head"), 0, 0, 0, 0)
	want = append(want, "tail"...)
	if got := m.nodes["/sparse"].data; !bytes.Equal(got, want) {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

func TestWriteRefusals(t *testing.T) {
	t.Run("read-only export", func(t *testing.T) {
		m := fixture()
		srv, _ := New(m, ReadWrite())
		c := serveOn(t, srv)
		h := c.open("/hello.txt", wire.FxfWrite)
		// Flip the export to read-only behind the handle: a write must be
		// refused on the export's mode, not only on the handle's.
		srv.ro = true
		typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("x")})
		c.status(typ, p, wire.StatusPermissionDenied)
	})
	t.Run("handle opened read-only", func(t *testing.T) {
		c := dial(t, fixture(), ReadWrite())
		h := c.open("/hello.txt", wire.FxfRead)
		typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("x")})
		st := c.status(typ, p, wire.StatusPermissionDenied)
		if !strings.Contains(st.Message, "not opened for writing") {
			t.Fatalf("message = %q", st.Message)
		}
	})
	t.Run("absurd offset is refused rather than allocated", func(t *testing.T) {
		m := newMemFS()
		c := dial(t, bareFS{m}, ReadWrite())
		h := c.open("/x", wire.FxfWrite|wire.FxfCreat)
		typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 1 << 62, Data: []byte("x")})
		st := c.status(typ, p, wire.StatusFailure)
		if !strings.Contains(st.Message, "maximum supported file size") {
			t.Fatalf("message = %q", st.Message)
		}
	})
	t.Run("driver read fails during splice", func(t *testing.T) {
		m := newMemFS()
		c := dial(t, bareFS{m}, ReadWrite())
		h := c.open("/x", wire.FxfWrite|wire.FxfCreat)
		m.fail["ReadFile:/x"] = errors.New("read failed")
		typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("x")})
		c.status(typ, p, wire.StatusFailure)
	})
	t.Run("driver write fails during splice", func(t *testing.T) {
		m := newMemFS()
		c := dial(t, bareFS{m}, ReadWrite())
		h := c.open("/x", wire.FxfWrite|wire.FxfCreat)
		m.fail["WriteFile:/x"] = errors.New("write failed")
		typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("x")})
		c.status(typ, p, wire.StatusFailure)
	})
	t.Run("WriteAt fails", func(t *testing.T) {
		m := fixture()
		c := dial(t, writableFS{m}, ReadWrite())
		h := c.open("/hello.txt", wire.FxfWrite)
		m.fail["WriteAt:/hello.txt"] = errors.New("device error")
		typ, p := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: []byte("x")})
		c.status(typ, p, wire.StatusFailure)
	})
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestStatLstatAndFstatAgree(t *testing.T) {
	c := dial(t, fixture())
	var attrs []wire.Attributes
	for _, typ := range []uint8{wire.FxpStat, wire.FxpLstat} {
		rt, p := c.do(wire.PathRequest{PacketType: typ, ID: c.next(), Path: "/hello.txt"})
		if rt != wire.FxpAttrs {
			t.Fatalf("reply type %d, want SSH_FXP_ATTRS", rt)
		}
		a, err := wire.DecodeAttrs(p)
		if err != nil {
			t.Fatalf("DecodeAttrs: %v", err)
		}
		attrs = append(attrs, a.Attrs)
	}
	h := c.open("/hello.txt", wire.FxfRead)
	rt, p := c.do(wire.HandleRequest{PacketType: wire.FxpFstat, ID: c.next(), Handle: h})
	if rt != wire.FxpAttrs {
		t.Fatalf("FSTAT reply type %d", rt)
	}
	a, _ := wire.DecodeAttrs(p)
	attrs = append(attrs, a.Attrs)
	c.closeHandle(h)

	for i, got := range attrs {
		if got.Size != uint64(len("hello from an image\n")) {
			t.Fatalf("attrs[%d].Size = %d", i, got.Size)
		}
		if got.Permissions&wire.ModeFmt != wire.ModeReg {
			t.Fatalf("attrs[%d] is not a regular file: mode %o", i, got.Permissions)
		}
		if got.Flags&(wire.AttrSize|wire.AttrPermissions|wire.AttrACModTime|wire.AttrUIDGID) == 0 {
			t.Fatalf("attrs[%d] announced nothing: flags %#x", i, got.Flags)
		}
	}
}

func TestReadOnlyExportClearsTheWriteBits(t *testing.T) {
	c := dial(t, fixture())
	_, p := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: "/hello.txt"})
	a, _ := wire.DecodeAttrs(p)
	if a.Attrs.Permissions&0o222 != 0 {
		t.Fatalf("read-only export reported mode %o with write bits set", a.Attrs.Permissions)
	}
	c2 := dial(t, fixture(), ReadWrite())
	_, p = c2.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c2.next(), Path: "/hello.txt"})
	a, _ = wire.DecodeAttrs(p)
	if a.Attrs.Permissions&0o200 == 0 {
		t.Fatalf("writable export reported mode %o with the owner write bit clear", a.Attrs.Permissions)
	}
}

func TestStatFailures(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		c := dial(t, fixture())
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: "/nope"})
		c.status(typ, p, wire.StatusNoSuchFile)
	})
	t.Run("a driver returning (nil, nil) does not crash the session", func(t *testing.T) {
		m := fixture()
		m.nilStat = "/hello.txt"
		c := dial(t, m)
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: "/hello.txt"})
		st := c.status(typ, p, wire.StatusFailure)
		if !strings.Contains(st.Message, "no stat") {
			t.Fatalf("message = %q", st.Message)
		}
		// The session must still be usable afterwards.
		typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: "/"})
		if typ != wire.FxpName {
			t.Fatalf("session died after the driver bug: type %d", typ)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		c := dial(t, fixture())
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: "\x00"})
		c.status(typ, p, wire.StatusFailure)
	})
}

func TestTimestampsComeFromTheDriverWhenItHasThem(t *testing.T) {
	c := dial(t, timeFS{fixture()})
	_, p := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: "/hello.txt"})
	a, _ := wire.DecodeAttrs(p)
	if a.Attrs.Mtime != 1_700_000_000 {
		t.Fatalf("mtime = %d, want the driver's 1700000000", a.Attrs.Mtime)
	}
}

func TestSetstat(t *testing.T) {
	t.Run("refused on a read-only export", func(t *testing.T) {
		c := dial(t, fixture())
		typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
			Attrs: wire.Attributes{Flags: wire.AttrPermissions, Permissions: 0o600}})
		c.status(typ, p, wire.StatusPermissionDenied)
	})
	t.Run("size goes through Truncater", func(t *testing.T) {
		m := fixture()
		c := dial(t, m, ReadWrite())
		typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
			Attrs: wire.Attributes{Flags: wire.AttrSize, Size: 5}})
		c.status(typ, p, wire.StatusOK)
		if got := string(m.nodes["/hello.txt"].data); got != "hello" {
			t.Fatalf("file = %q", got)
		}
	})
	t.Run("size on a driver with no Truncater is refused, not ignored", func(t *testing.T) {
		c := dial(t, bareFS{fixture()}, ReadWrite())
		typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
			Attrs: wire.Attributes{Flags: wire.AttrSize, Size: 5}})
		c.status(typ, p, wire.StatusOpUnsupported)
	})
	t.Run("Truncate failing is reported", func(t *testing.T) {
		m := fixture()
		m.fail["Truncate:/hello.txt"] = errors.New("cannot truncate")
		c := dial(t, m, ReadWrite())
		typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
			Attrs: wire.Attributes{Flags: wire.AttrSize, Size: 5}})
		c.status(typ, p, wire.StatusFailure)
	})
	t.Run("mode, owner and times go through MetadataSetter", func(t *testing.T) {
		m := &metaFS{memFS: fixture()}
		c := dial(t, m, ReadWrite())
		typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
			Attrs: wire.Attributes{
				Flags:       wire.AttrPermissions | wire.AttrUIDGID | wire.AttrACModTime,
				Permissions: 0o100600, UID: 501, GID: 20, Atime: 1, Mtime: 2,
			}})
		c.status(typ, p, wire.StatusOK)
		if m.chmodCalls != 1 || m.chownCalls != 1 || m.timeCalls != 1 {
			t.Fatalf("calls: chmod %d chown %d chtimes %d", m.chmodCalls, m.chownCalls, m.timeCalls)
		}
		if got := m.nodes["/hello.txt"].mode & 0o7777; got != 0o600 {
			t.Fatalf("mode = %o, want 600 — only the permission bits are the client's to set", got)
		}
	})
	t.Run("attributes a driver cannot set are ignored, not refused", func(t *testing.T) {
		// Refusing would break every `sftp put`: OpenSSH sets permissions
		// and times after each upload and treats a refusal as a failure.
		c := dial(t, bareFS{fixture()}, ReadWrite())
		typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
			Attrs: wire.Attributes{Flags: wire.AttrPermissions | wire.AttrACModTime, Permissions: 0o600}})
		c.status(typ, p, wire.StatusOK)
	})
	for _, call := range []string{"Chmod", "Chown", "Chtimes"} {
		t.Run(call+" failing is reported", func(t *testing.T) {
			m := &metaFS{memFS: fixture()}
			m.fail[call+":/hello.txt"] = errors.New("refused")
			c := dial(t, m, ReadWrite())
			typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/hello.txt",
				Attrs: wire.Attributes{
					Flags:       wire.AttrPermissions | wire.AttrUIDGID | wire.AttrACModTime,
					Permissions: 0o600,
				}})
			c.status(typ, p, wire.StatusFailure)
		})
	}
	t.Run("fsetstat applies to the handle's path", func(t *testing.T) {
		m := fixture()
		c := dial(t, m, ReadWrite())
		h := c.open("/hello.txt", wire.FxfWrite)
		typ, p := c.do(wire.FsetstatRequest{ID: c.next(), Handle: h,
			Attrs: wire.Attributes{Flags: wire.AttrSize, Size: 5}})
		c.status(typ, p, wire.StatusOK)
		if got := string(m.nodes["/hello.txt"].data); got != "hello" {
			t.Fatalf("file = %q", got)
		}
	})
}
