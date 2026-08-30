package sftp

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

func TestReaddirListsEverythingWithAttributes(t *testing.T) {
	c := dial(t, fixture())
	h := c.opendir("/")
	items := c.listAll(h)
	c.closeHandle(h)

	got := map[string]wire.NameItem{}
	for _, it := range items {
		got[it.Filename] = it
	}
	for _, want := range []string{"hello.txt", "sub", "link"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("listing %v is missing %q", items, want)
		}
	}
	if !got["sub"].Attrs.IsDir() {
		t.Fatalf("sub reported mode %o; a client cannot descend without the directory bits",
			got["sub"].Attrs.Permissions)
	}
	if got["hello.txt"].Attrs.Size != uint64(len("hello from an image\n")) {
		t.Fatalf("hello.txt size = %d", got["hello.txt"].Attrs.Size)
	}
	if !strings.HasSuffix(got["hello.txt"].Longname, " hello.txt") {
		t.Fatalf("longname %q does not end in the name", got["hello.txt"].Longname)
	}
	if !strings.HasPrefix(got["sub"].Longname, "d") {
		t.Fatalf("directory longname %q does not start with 'd'", got["sub"].Longname)
	}
}

// TestReaddirPagesAcrossBatches proves the pagination terminates and loses
// nothing: a directory bigger than one batch is the case where an off-by-one
// silently drops entries.
func TestReaddirPagesAcrossBatches(t *testing.T) {
	m := newMemFS()
	const n = readdirBatch*2 + 7
	for i := range n {
		m.addFile(fmt.Sprintf("/f%03d", i), []byte("x"), 0o100644)
	}
	c := dial(t, m)
	h := c.opendir("/")
	items := c.listAll(h)
	c.closeHandle(h)
	if len(items) != n {
		t.Fatalf("listed %d entries, want %d", len(items), n)
	}
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.Filename] {
			t.Fatalf("%q listed twice", it.Filename)
		}
		seen[it.Filename] = true
	}
}

func TestReaddirSkipsEntriesItCannotDescribe(t *testing.T) {
	// An entry that vanished between ListDir and Stat is skipped rather
	// than listed with invented attributes, because a client acts on a size.
	m := fixture()
	m.fail["Stat:/hello.txt"] = fs.ErrNotExist
	c := dial(t, m)
	h := c.opendir("/")
	for _, it := range c.listAll(h) {
		if it.Filename == "hello.txt" {
			t.Fatal("an unstattable entry was listed with invented attributes")
		}
	}
	c.closeHandle(h)
}

func TestReaddirWhereEveryEntryIsUnusableStillTerminates(t *testing.T) {
	m := newMemFS()
	m.addFile("/a", nil, 0o100644)
	m.addFile("/b", nil, 0o100644)
	m.fail["Stat:/a"] = fs.ErrNotExist
	m.fail["Stat:/b"] = fs.ErrNotExist
	c := dial(t, m)
	h := c.opendir("/")
	if items := c.listAll(h); len(items) != 0 {
		t.Fatalf("listed %v", items)
	}
	c.closeHandle(h)
}

func TestOpendirRefusals(t *testing.T) {
	c := dial(t, fixture())
	t.Run("not a directory", func(t *testing.T) {
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/hello.txt"})
		st := c.status(typ, p, wire.StatusFailure)
		if !strings.Contains(st.Message, "not a directory") {
			t.Fatalf("message = %q", st.Message)
		}
	})
	t.Run("missing", func(t *testing.T) {
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/nope"})
		c.status(typ, p, wire.StatusNoSuchFile)
	})
	t.Run("invalid path", func(t *testing.T) {
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "\x00"})
		c.status(typ, p, wire.StatusFailure)
	})
	t.Run("driver returns (nil, nil)", func(t *testing.T) {
		m := fixture()
		m.nilStat = "/sub"
		c := dial(t, m)
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/sub"})
		c.status(typ, p, wire.StatusFailure)
	})
	t.Run("ListDir fails", func(t *testing.T) {
		m := fixture()
		m.fail["ListDir:/sub"] = errors.New("directory unreadable")
		c := dial(t, m)
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/sub"})
		c.status(typ, p, wire.StatusFailure)
	})
	t.Run("readdir on a file handle", func(t *testing.T) {
		h := c.open("/hello.txt", wire.FxfRead)
		typ, p := c.do(wire.HandleRequest{PacketType: wire.FxpReaddir, ID: c.next(), Handle: h})
		c.status(typ, p, wire.StatusFailure)
		c.closeHandle(h)
	})
}

// TestReaddirSkipsNamesThatWouldNotResolveBack covers a driver reporting an
// entry name containing a slash: listing it would name something other than
// the entry.
func TestReaddirSkipsNamesThatWouldNotResolveBack(t *testing.T) {
	c := dial(t, slashNameFS{fixture()})
	h := c.opendir("/")
	for _, it := range c.listAll(h) {
		if strings.Contains(it.Filename, "/") {
			t.Fatalf("listed %q, which cannot resolve back to the entry", it.Filename)
		}
	}
	c.closeHandle(h)
}

type slashNameFS struct{ *memFS }

func (m slashNameFS) ListDir(path string) ([]filesystem.DirEntry, error) {
	out, err := m.memFS.ListDir(path)
	if err != nil {
		return nil, err
	}
	return append(out, filesystem.NewDirEntry(99, "a/b", 0)), nil
}

// ---------------------------------------------------------------------------
// Namespace operations
// ---------------------------------------------------------------------------

func TestRealpath(t *testing.T) {
	c := dial(t, fixture())
	for _, tc := range []struct{ in, want string }{
		{".", "/"},
		{"/", "/"},
		{"/sub/..", "/"},
		{"sub", "/sub"},
	} {
		typ, p := c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: tc.in})
		if typ != wire.FxpName {
			t.Fatalf("realpath(%q) type %d", tc.in, typ)
		}
		n, err := wire.DecodeName(p)
		if err != nil {
			t.Fatalf("DecodeName: %v", err)
		}
		if len(n.Items) != 1 || n.Items[0].Filename != tc.want {
			t.Fatalf("realpath(%q) = %v, want %q", tc.in, n.Items, tc.want)
		}
	}
	typ, p := c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: "\x00"})
	c.status(typ, p, wire.StatusFailure)
}

func TestMkdirRmdirRemove(t *testing.T) {
	m := fixture()
	c := dial(t, m, ReadWrite())

	typ, p := c.do(wire.SetstatRequest{PacketType: wire.FxpMkdir, ID: c.next(), Path: "/newdir",
		Attrs: wire.Attributes{Flags: wire.AttrPermissions, Permissions: 0o700}})
	c.status(typ, p, wire.StatusOK)
	if got := m.nodes["/newdir"].mode & 0o7777; got != 0o700 {
		t.Fatalf("mkdir mode = %o", got)
	}
	// Default mode when the client says nothing.
	typ, p = c.do(wire.SetstatRequest{PacketType: wire.FxpMkdir, ID: c.next(), Path: "/defdir"})
	c.status(typ, p, wire.StatusOK)
	if got := m.nodes["/defdir"].mode & 0o7777; got != 0o755 {
		t.Fatalf("default mkdir mode = %o, want 755", got)
	}
	typ, p = c.do(wire.SetstatRequest{PacketType: wire.FxpMkdir, ID: c.next(), Path: "/newdir"})
	c.status(typ, p, wire.StatusFailure)
	typ, p = c.do(wire.SetstatRequest{PacketType: wire.FxpMkdir, ID: c.next(), Path: "\x00"})
	c.status(typ, p, wire.StatusFailure)

	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRmdir, ID: c.next(), Path: "/newdir"})
	c.status(typ, p, wire.StatusOK)
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRemove, ID: c.next(), Path: "/hello.txt"})
	c.status(typ, p, wire.StatusOK)
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRemove, ID: c.next(), Path: "/hello.txt"})
	c.status(typ, p, wire.StatusNoSuchFile)
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRemove, ID: c.next(), Path: "\x00"})
	c.status(typ, p, wire.StatusFailure)
}

func TestMutationsRefusedOnAReadOnlyExport(t *testing.T) {
	c := dial(t, fixture())
	for _, m := range []wire.Message{
		wire.SetstatRequest{PacketType: wire.FxpMkdir, ID: c.next(), Path: "/d"},
		wire.PathRequest{PacketType: wire.FxpRemove, ID: c.next(), Path: "/hello.txt"},
		wire.PathRequest{PacketType: wire.FxpRmdir, ID: c.next(), Path: "/sub"},
		wire.RenameRequest{ID: c.next(), OldPath: "/hello.txt", NewPath: "/x"},
		wire.SymlinkRequest{ID: c.next(), TargetPath: "/hello.txt", LinkPath: "/l"},
	} {
		typ, p := c.do(m)
		st := c.status(typ, p, wire.StatusPermissionDenied)
		if !strings.Contains(st.Message, "read-only") {
			t.Fatalf("%T message = %q, want it to name the export's mode", m, st.Message)
		}
	}
}

func TestRename(t *testing.T) {
	m := fixture()
	c := dial(t, m, ReadWrite())
	typ, p := c.do(wire.RenameRequest{ID: c.next(), OldPath: "/hello.txt", NewPath: "/sub/moved.txt"})
	c.status(typ, p, wire.StatusOK)
	if _, ok := m.nodes["/sub/moved.txt"]; !ok {
		t.Fatal("rename did not move the node")
	}
	typ, p = c.do(wire.RenameRequest{ID: c.next(), OldPath: "/nope", NewPath: "/x"})
	c.status(typ, p, wire.StatusNoSuchFile)
	typ, p = c.do(wire.RenameRequest{ID: c.next(), OldPath: "\x00", NewPath: "/x"})
	c.status(typ, p, wire.StatusFailure)
	typ, p = c.do(wire.RenameRequest{ID: c.next(), OldPath: "/sub", NewPath: "\x00"})
	c.status(typ, p, wire.StatusFailure)
}

func TestReadlink(t *testing.T) {
	c := dial(t, fixture())
	typ, p := c.do(wire.PathRequest{PacketType: wire.FxpReadlink, ID: c.next(), Path: "/link"})
	if typ != wire.FxpName {
		t.Fatalf("readlink type %d", typ)
	}
	n, _ := wire.DecodeName(p)
	if n.Items[0].Filename != "/hello.txt" {
		t.Fatalf("readlink = %q", n.Items[0].Filename)
	}
	// A path that exists but is not a link: the driver's own words, mapped
	// through the substring table because the contract has no sentinel.
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpReadlink, ID: c.next(), Path: "/hello.txt"})
	c.status(typ, p, wire.StatusFailure)
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpReadlink, ID: c.next(), Path: "/nope"})
	c.status(typ, p, wire.StatusNoSuchFile)
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpReadlink, ID: c.next(), Path: "\x00"})
	c.status(typ, p, wire.StatusFailure)
}

func TestSymlink(t *testing.T) {
	m := fixture()
	c := dial(t, m, ReadWrite())
	typ, p := c.do(wire.SymlinkRequest{ID: c.next(), TargetPath: "../outside/target", LinkPath: "/l"})
	c.status(typ, p, wire.StatusOK)
	// The target is stored VERBATIM: it is data, not a path this server
	// resolves. Normalising it would change what the user asked for.
	if got := m.nodes["/l"].target; got != "../outside/target" {
		t.Fatalf("stored target = %q, want it verbatim", got)
	}
	typ, p = c.do(wire.SymlinkRequest{ID: c.next(), TargetPath: "/x", LinkPath: "\x00"})
	c.status(typ, p, wire.StatusFailure)

	m2 := fixture()
	m2.fail["Symlink:/l"] = errors.New("cannot link")
	c2 := dial(t, m2, ReadWrite())
	typ, p = c2.do(wire.SymlinkRequest{ID: c2.next(), TargetPath: "/x", LinkPath: "/l"})
	c2.status(typ, p, wire.StatusFailure)

	c3 := dial(t, bareFS{fixture()}, ReadWrite())
	typ, p = c3.do(wire.SymlinkRequest{ID: c3.next(), TargetPath: "/x", LinkPath: "/l"})
	c3.status(typ, p, wire.StatusOpUnsupported)
}

// ---------------------------------------------------------------------------
// Protocol edges
// ---------------------------------------------------------------------------

func TestExtendedRequestsAreRefusedByName(t *testing.T) {
	c := dial(t, fixture())
	typ, p := c.do(wire.ExtendedRequest{ID: c.next(), Name: "statvfs@openssh.com", Data: []byte("/")})
	st := c.status(typ, p, wire.StatusOpUnsupported)
	if !strings.Contains(st.Message, "statvfs@openssh.com") {
		t.Fatalf("message = %q, want it to name the extension", st.Message)
	}
}

func TestUnknownRequestTypeIsAnsweredNotFatal(t *testing.T) {
	c := dial(t, fixture())
	typ, p := c.raw(99, []byte{0, 0, 0, 7})
	st := c.status(typ, p, wire.StatusOpUnsupported)
	if st.ID != 7 {
		t.Fatalf("status echoed id %d, want 7", st.ID)
	}
	// The session must survive it.
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: "/"})
	if typ != wire.FxpName {
		t.Fatalf("session died after an unknown request type")
	}
}

// TestMalformedPayloadsAreAnsweredNotFatal walks every request type with a
// payload that cannot decode.
//
// The invariant under test is that a session survives all of them: an SFTP
// client has no way to recover from a channel that simply stops, so a
// request the server cannot parse must be ANSWERED.
func TestMalformedPayloadsAreAnsweredNotFatal(t *testing.T) {
	c := dial(t, fixture())
	types := []uint8{
		wire.FxpOpen, wire.FxpClose, wire.FxpRead, wire.FxpWrite,
		wire.FxpLstat, wire.FxpFstat, wire.FxpSetstat, wire.FxpFsetstat,
		wire.FxpOpendir, wire.FxpReaddir, wire.FxpRemove, wire.FxpMkdir,
		wire.FxpRmdir, wire.FxpRealpath, wire.FxpStat, wire.FxpRename,
		wire.FxpReadlink, wire.FxpSymlink, wire.FxpExtended,
	}
	// A four-byte payload holds an id and nothing else, so every decoder
	// gets past the id and then runs out — which is the branch that has to
	// answer rather than close.
	for _, ty := range types {
		typ, p := c.raw(ty, []byte{0, 0, 0, 42})
		st := c.status(typ, p, wire.StatusBadMessage)
		if st.ID != 42 {
			t.Fatalf("type %d: status echoed id %d, want 42", ty, st.ID)
		}
	}
	// And a payload too short even to hold an id.
	typ, p := c.raw(wire.FxpStat, []byte{1})
	st := c.status(typ, p, wire.StatusBadMessage)
	if st.ID != 0 {
		t.Fatalf("unmatchable request answered with id %d, want 0", st.ID)
	}
	typ, p = c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: "/"})
	if typ != wire.FxpName {
		t.Fatal("session did not survive the malformed packets")
	}
}

func TestFsetstatOnAnUnknownHandle(t *testing.T) {
	c := dial(t, fixture(), ReadWrite())
	typ, p := c.do(wire.FsetstatRequest{ID: c.next(), Handle: "nope"})
	c.status(typ, p, wire.StatusFailure)
}

func TestOversizedPacketEndsTheSession(t *testing.T) {
	// A length prefix over the ceiling misframes the stream, so the only
	// safe answer is to stop: replying would put a packet into a stream the
	// peer is no longer aligned with.
	srv, _ := New(fixture(), WithMaxPacket(64))
	c := serveOn(t, srv)
	c.conn.Write([]byte{0, 0, 0x10, 0}) // 4096, over the 64-byte ceiling
	select {
	case <-c.done:
		if !errors.Is(c.serveErr, wire.ErrPacketTooLarge) {
			t.Fatalf("Serve = %v, want wire.ErrPacketTooLarge", c.serveErr)
		}
	case <-timeoutChan():
		t.Fatal("server did not stop on an oversized packet")
	}
}

func TestWriteFailureEndsTheSession(t *testing.T) {
	srv, _ := New(fixture())
	c := serveOn(t, srv)
	// Ask a question and vanish before the answer can be written.
	c.send(wire.PathRequest{PacketType: wire.FxpRealpath, ID: 1, Path: "/"})
	c.conn.Close()
	select {
	case <-c.done:
		if c.serveErr == nil {
			t.Fatal("Serve returned nil after the reply could not be written")
		}
	case <-timeoutChan():
		t.Fatal("server did not stop after a write failure")
	}
}
