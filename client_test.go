package sftp

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// The tests in this package drive the server THROUGH THE WIRE, not through
// its Go API.
//
// That is not ceremony. An in-process call cannot catch a field written in
// the wrong order, a length prefix that counts the wrong bytes, a missing
// request id, or a reply whose type byte disagrees with its payload — and
// those are exactly the defects that make a real client fail while every
// unit test passes. Encoding and decoding the actual packets is the only way
// a test failure and a client failure are the same event.

// client is a minimal SFTP client for the tests, speaking the same [wire]
// codec the server does — which is also a proof that the codec is symmetric,
// since the client half is only ever exercised here.
type client struct {
	t    *testing.T
	conn net.Conn
	id   uint32
	buf  []byte
	in   []byte
	// done is CLOSED when Serve returns, and serveErr holds its verdict.
	// A closed channel can be waited on any number of times, which matters
	// because both an explicit finish() and the test cleanup wait on it.
	done     chan struct{}
	serveErr error
}

// dial starts a server over a synchronous in-memory pipe and negotiates.
func dial(t *testing.T, fsys filesystem.Filesystem, opts ...Option) *client {
	t.Helper()
	srv, err := New(fsys, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return serveOn(t, srv)
}

// serveOn attaches a client to an existing server, for the tests that need
// two sessions against one server.
func serveOn(t *testing.T, srv *Server) *client {
	t.Helper()
	a, b := net.Pipe()
	c := &client{t: t, conn: a, done: make(chan struct{})}
	go func() {
		c.serveErr = srv.Serve(b)
		close(c.done)
	}()
	t.Cleanup(func() {
		a.Close()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop within 5s")
		}
	})
	c.init()
	return c
}

// init performs version negotiation.
func (c *client) init() {
	c.t.Helper()
	c.send(wire.InitRequest{Version: wire.Version})
	typ, payload := c.recv()
	if typ != wire.FxpVersion {
		c.t.Fatalf("first reply = type %d, want SSH_FXP_VERSION", typ)
	}
	v, err := wire.DecodeVersion(payload)
	if err != nil {
		c.t.Fatalf("DecodeVersion: %v", err)
	}
	if v.Version != wire.Version {
		c.t.Fatalf("negotiated version %d, want %d", v.Version, wire.Version)
	}
}

// next returns a fresh request id. Ids are distinct so that a reply carrying
// the wrong one is a test failure rather than an accident that passes.
func (c *client) next() uint32 { c.id++; return c.id }

func (c *client) send(m wire.Message) {
	c.t.Helper()
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	var err error
	if c.buf, err = wire.Send(c.conn, m, c.buf); err != nil {
		c.t.Fatalf("send %T: %v", m, err)
	}
}

func (c *client) recv() (uint8, []byte) {
	c.t.Helper()
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	typ, payload, next, err := wire.ReadPacket(c.conn, c.in, 0)
	c.in = next
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	// The payload aliases the read buffer, which the next call reuses.
	return typ, append([]byte(nil), payload...)
}

// do sends one request and returns the reply.
func (c *client) do(m wire.Message) (uint8, []byte) {
	c.t.Helper()
	c.send(m)
	return c.recv()
}

// raw sends a hand-built packet, for the malformed-input tests that no
// message type can express.
func (c *client) raw(typ uint8, payload []byte) (uint8, []byte) {
	c.t.Helper()
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	var err error
	if c.buf, err = wire.WritePacket(c.conn, typ, payload, c.buf); err != nil {
		c.t.Fatalf("raw write: %v", err)
	}
	return c.recv()
}

// status asserts the reply is a status with the expected code and returns it.
func (c *client) status(typ uint8, payload []byte, want wire.Status) wire.StatusReply {
	c.t.Helper()
	if typ != wire.FxpStatus {
		c.t.Fatalf("reply type %d, want SSH_FXP_STATUS", typ)
	}
	st, err := wire.DecodeStatus(payload)
	if err != nil {
		c.t.Fatalf("DecodeStatus: %v", err)
	}
	if st.Code != want {
		c.t.Fatalf("status = %v (%q), want %v", st.Code, st.Message, want)
	}
	return st
}

// open opens path and returns its handle, failing the test if it cannot.
func (c *client) open(path string, pflags uint32) string {
	c.t.Helper()
	typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: path, PFlags: pflags})
	if typ != wire.FxpHandle {
		st, _ := wire.DecodeStatus(payload)
		c.t.Fatalf("open %q: %v (%q)", path, st.Code, st.Message)
	}
	h, err := wire.DecodeHandleReply(payload)
	if err != nil {
		c.t.Fatalf("DecodeHandleReply: %v", err)
	}
	return h.Handle
}

// open2 opens with explicit attributes, for the create-with-mode cases.
func (c *client) open2(path string, pflags uint32, a wire.Attributes) string {
	c.t.Helper()
	typ, payload := c.do(wire.OpenRequest{ID: c.next(), Path: path, PFlags: pflags, Attrs: a})
	if typ != wire.FxpHandle {
		st, _ := wire.DecodeStatus(payload)
		c.t.Fatalf("open %q: %v (%q)", path, st.Code, st.Message)
	}
	h, err := wire.DecodeHandleReply(payload)
	if err != nil {
		c.t.Fatalf("DecodeHandleReply: %v", err)
	}
	return h.Handle
}

// opendir opens a directory and returns its handle.
func (c *client) opendir(path string) string {
	c.t.Helper()
	typ, payload := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: path})
	if typ != wire.FxpHandle {
		st, _ := wire.DecodeStatus(payload)
		c.t.Fatalf("opendir %q: %v (%q)", path, st.Code, st.Message)
	}
	h, err := wire.DecodeHandleReply(payload)
	if err != nil {
		c.t.Fatalf("DecodeHandleReply: %v", err)
	}
	return h.Handle
}

// readAll reads a whole file the way a client does: fixed-size reads until
// SSH_FX_EOF. It is the operation the module exists to serve, so it is the
// one the tests use rather than a single convenient read.
func (c *client) readAll(handle string, chunk int) []byte {
	c.t.Helper()
	var out []byte
	for off := uint64(0); ; {
		typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: handle, Offset: off, Length: uint32(chunk)})
		if typ == wire.FxpStatus {
			st, err := wire.DecodeStatus(payload)
			if err != nil {
				c.t.Fatalf("DecodeStatus: %v", err)
			}
			if st.Code == wire.StatusEOF {
				return out
			}
			c.t.Fatalf("read at %d: %v (%q)", off, st.Code, st.Message)
		}
		d, err := wire.DecodeData(payload)
		if err != nil {
			c.t.Fatalf("DecodeData: %v", err)
		}
		if len(d.Data) == 0 {
			c.t.Fatalf("read at %d returned no data and no EOF", off)
		}
		out = append(out, d.Data...)
		off += uint64(len(d.Data))
	}
}

// listAll pages a directory to exhaustion.
func (c *client) listAll(handle string) []wire.NameItem {
	c.t.Helper()
	var out []wire.NameItem
	for {
		typ, payload := c.do(wire.HandleRequest{PacketType: wire.FxpReaddir, ID: c.next(), Handle: handle})
		if typ == wire.FxpStatus {
			c.status(typ, payload, wire.StatusEOF)
			return out
		}
		n, err := wire.DecodeName(payload)
		if err != nil {
			c.t.Fatalf("DecodeName: %v", err)
		}
		out = append(out, n.Items...)
	}
}

// closeHandle closes a handle and asserts success.
func (c *client) closeHandle(h string) {
	c.t.Helper()
	typ, payload := c.do(wire.HandleRequest{PacketType: wire.FxpClose, ID: c.next(), Handle: h})
	c.status(typ, payload, wire.StatusOK)
}

// finish closes the client side and waits for the server's verdict, which
// must be a clean nil: a session ending because the peer went away is not a
// failure of anything.
func (c *client) finish() {
	c.t.Helper()
	c.conn.Close()
	select {
	case <-c.done:
		if err := c.serveErr; err != nil && !errors.Is(err, io.ErrClosedPipe) {
			c.t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		c.t.Fatal("server did not stop within 5s")
	}
}

// timeoutChan is the deadline every "the server must stop" assertion waits on.
func timeoutChan() <-chan time.Time { return time.After(5 * time.Second) }
