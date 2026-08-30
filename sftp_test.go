package sftp

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/go-filesystems/sftp/wire"
)

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewRejectsNilFilesystem(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrNilFilesystem) {
		t.Fatalf("New(nil) = %v, want ErrNilFilesystem", err)
	}
}

func TestExportsAreReadOnlyByDefault(t *testing.T) {
	srv, err := New(newMemFS())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !srv.ReadOnly() {
		t.Fatal("a new export is writable; it must be read-only until ReadWrite() is given")
	}
	srv, err = New(newMemFS(), ReadWrite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.ReadOnly() {
		t.Fatal("ReadWrite() did not make the export writable")
	}
}

func TestWithMaxPacket(t *testing.T) {
	srv, _ := New(newMemFS())
	if got := srv.packetLimit(); got != wire.MaxPacket {
		t.Fatalf("default packet limit = %d, want %d", got, wire.MaxPacket)
	}
	srv, _ = New(newMemFS(), WithMaxPacket(4096))
	if got := srv.packetLimit(); got != 4096 {
		t.Fatalf("packet limit = %d, want 4096", got)
	}
	srv, _ = New(newMemFS(), WithMaxPacket(-1))
	if got := srv.packetLimit(); got != wire.MaxPacket {
		t.Fatalf("a non-positive limit must restore the default, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

func TestFirstPacketMustBeInit(t *testing.T) {
	srv, _ := New(newMemFS())
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(b) }()
	var buf []byte
	buf, _ = wire.Send(a, wire.PathRequest{PacketType: wire.FxpStat, ID: 1, Path: "/"}, buf)
	if err := <-done; !errors.Is(err, ErrNoInit) {
		t.Fatalf("Serve = %v, want ErrNoInit", err)
	}
	a.Close()
}

func TestInitBelowVersionThreeIsRefused(t *testing.T) {
	srv, _ := New(newMemFS())
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(b) }()
	var buf []byte
	buf, _ = wire.Send(a, wire.InitRequest{Version: 2}, buf)
	if err := <-done; !errors.Is(err, ErrVersion) {
		t.Fatalf("Serve = %v, want ErrVersion", err)
	}
	a.Close()
}

func TestInitAboveVersionThreeNegotiatesDownToThree(t *testing.T) {
	srv, _ := New(newMemFS())
	a, b := net.Pipe()
	go func() { srv.Serve(b) }()
	defer a.Close()
	var buf []byte
	buf, _ = wire.Send(a, wire.InitRequest{Version: 6}, buf)
	typ, payload, _, err := wire.ReadPacket(a, nil, 0)
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if typ != wire.FxpVersion {
		t.Fatalf("reply type %d, want SSH_FXP_VERSION", typ)
	}
	v, err := wire.DecodeVersion(payload)
	if err != nil {
		t.Fatalf("DecodeVersion: %v", err)
	}
	if v.Version != 3 {
		t.Fatalf("negotiated %d, want 3", v.Version)
	}
	if len(v.Extensions) != 0 {
		t.Fatalf("advertised extensions %v; none are implemented so none must be advertised", v.Extensions)
	}
}

func TestInitMalformedEndsTheSession(t *testing.T) {
	srv, _ := New(newMemFS())
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(b) }()
	var buf []byte
	buf, _ = wire.WritePacket(a, wire.FxpInit, []byte{1, 2}, buf) // truncated version
	if err := <-done; !errors.Is(err, wire.ErrShort) {
		t.Fatalf("Serve = %v, want wire.ErrShort", err)
	}
	a.Close()
}

func TestNegotiationReadFailureEndsTheSession(t *testing.T) {
	srv, _ := New(newMemFS())
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(b) }()
	a.Close()
	if err := <-done; err == nil {
		t.Fatal("Serve returned nil after the peer vanished before INIT")
	}
}

func TestSecondInitIsRefusedNotRenegotiated(t *testing.T) {
	c := dial(t, newMemFS())
	typ, payload := c.do(wire.InitRequest{Version: 3})
	c.status(typ, payload, wire.StatusOpUnsupported)
}

// ---------------------------------------------------------------------------
// Containment — the property the whole isolation model rests on
// ---------------------------------------------------------------------------

// TestNoPathEscapesTheExport is the security test of this module.
//
// A server is given ONE filesystem and must never be able to name anything
// else. Every string below is a way a client might try to leave: parent
// traversal, absolute host paths, doubled slashes, a mix. Each must resolve
// INSIDE the export — and the proof is not that the request fails, but that
// it succeeds against the file the export actually contains at the clamped
// path, which is a much stronger statement than "an error came back".
func TestNoPathEscapesTheExport(t *testing.T) {
	// The export holds /etc/passwd. The HOST also has one. If any of the
	// escapes below reached the host, this file's contents would not be
	// what came back.
	fsys := newMemFS()
	fsys.addDir("/etc")
	fsys.addFile("/etc/passwd", []byte("in-the-image\n"), 0o100644)
	c := dial(t, fsys)

	for _, attempt := range []string{
		"/../../../../etc/passwd",
		"../../../../../../etc/passwd",
		"/etc/../etc/passwd",
		"//etc//passwd",
		"/etc/./passwd",
		"/../etc/passwd",
		"..//../etc/passwd",
		"/etc/passwd/../passwd",
	} {
		h := c.open(attempt, wire.FxfRead)
		got := c.readAll(h, 4096)
		c.closeHandle(h)
		if string(got) != "in-the-image\n" {
			t.Fatalf("%q read %q; it must resolve inside the export", attempt, got)
		}
	}

	// And ".." at the root is a no-op, not a step above it.
	typ, payload := c.do(wire.PathRequest{PacketType: wire.FxpRealpath, ID: c.next(), Path: "/../../.."})
	if typ != wire.FxpName {
		t.Fatalf("realpath reply type %d, want SSH_FXP_NAME", typ)
	}
	n, err := wire.DecodeName(payload)
	if err != nil {
		t.Fatalf("DecodeName: %v", err)
	}
	if n.Items[0].Filename != "/" {
		t.Fatalf("realpath(%q) = %q, want %q", "/../../..", n.Items[0].Filename, "/")
	}
	c.finish()
}

// TestNoSymlinkEscapesTheExport is the second half of the containment proof.
//
// Path traversal is the obvious escape and TestNoPathEscapesTheExport covers
// it. A symlink is the subtle one: the image itself contains a pointer at the
// host, so the escape is DATA the server was handed rather than a string a
// client invented. If the server resolved links, a link reading "/etc/passwd"
// or "../../../../etc/passwd" would be a straight read of the host's file.
//
// This server never resolves a symlink. READLINK hands the target back
// verbatim — lying about what the image stores would be its own bug — and the
// client then re-sends that target as an ordinary path, where [clean] clamps
// it exactly as it clamps anything else. The proof below runs that full
// round trip: read the link, then follow it the way a client would, and show
// the bytes come from inside the image.
func TestNoSymlinkEscapesTheExport(t *testing.T) {
	fsys := newMemFS()
	fsys.addDir("/etc")
	// The decoy. The HOST also has /etc/passwd; if a link ever escaped, the
	// contents would differ and this test would say so.
	fsys.addFile("/etc/passwd", []byte("in-the-image\n"), 0o100644)
	fsys.addLink("/absolute", "/etc/passwd")
	fsys.addLink("/relative", "../../../../etc/passwd")
	fsys.addLink("/mixed", "/../..//etc/./passwd")

	c := dial(t, fsys)
	for _, link := range []string{"/absolute", "/relative", "/mixed"} {
		// 1. READLINK returns the target unmodified: the server does not
		//    rewrite what the image holds.
		typ, payload := c.do(wire.PathRequest{
			PacketType: wire.FxpReadlink, ID: c.next(), Path: link,
		})
		if typ != wire.FxpName {
			t.Fatalf("readlink(%q) reply type %d, want SSH_FXP_NAME", link, typ)
		}
		n, err := wire.DecodeName(payload)
		if err != nil {
			t.Fatalf("DecodeName: %v", err)
		}
		target := n.Items[0].Filename

		// 2. Follow it the way a client does — send the target back as a
		//    path. This is where containment has to hold, and it is the
		//    step an attacker actually performs.
		h := c.open(target, wire.FxfRead)
		got := c.readAll(h, 4096)
		c.closeHandle(h)
		if string(got) != "in-the-image\n" {
			t.Fatalf("following %q (target %q) read %q; it must resolve inside the export",
				link, target, got)
		}
	}
	c.finish()
}

func TestPathsWithNULAreRefused(t *testing.T) {
	c := dial(t, newMemFS())
	typ, payload := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: "/a\x00b"})
	st := c.status(typ, payload, wire.StatusFailure)
	if !strings.Contains(st.Message, "invalid path") {
		t.Fatalf("message = %q, want it to name the invalid path", st.Message)
	}
}

func TestOverlongPathsAreRefused(t *testing.T) {
	c := dial(t, newMemFS())
	long := "/" + strings.Repeat("a", maxPath+1)
	typ, payload := c.do(wire.PathRequest{PacketType: wire.FxpStat, ID: c.next(), Path: long})
	c.status(typ, payload, wire.StatusFailure)
}

func TestCleanAndJoinUnits(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "/"},
		{".", "/"},
		{"/", "/"},
		{"a/b", "/a/b"},
		{"/a/b/", "/a/b"},
		{"/a//b", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/../b", "/b"},
		{"/../..", "/"},
	} {
		got, ok := clean(tc.in)
		if !ok || got != tc.want {
			t.Errorf("clean(%q) = %q,%v; want %q,true", tc.in, got, ok, tc.want)
		}
	}
	if _, ok := clean("a\x00b"); ok {
		t.Error("clean accepted a NUL")
	}
	if got := parent("/a/b"); got != "/a" {
		t.Errorf("parent(/a/b) = %q", got)
	}
	if got := parent("/a"); got != "/" {
		t.Errorf("parent(/a) = %q", got)
	}
	if got := base("/"); got != "/" {
		t.Errorf("base(/) = %q", got)
	}
	if got := base("/a/b"); got != "b" {
		t.Errorf("base(/a/b) = %q", got)
	}
	if p, ok := join("/", "x"); !ok || p != "/x" {
		t.Errorf("join(/, x) = %q,%v", p, ok)
	}
	if p, ok := join("/a", "x"); !ok || p != "/a/x" {
		t.Errorf("join(/a, x) = %q,%v", p, ok)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if _, ok := join("/d", bad); ok {
			t.Errorf("join accepted %q as an entry name", bad)
		}
	}
	if _, ok := join("/"+strings.Repeat("a", maxPath), "b"); ok {
		t.Error("join accepted a path over the ceiling")
	}
}
