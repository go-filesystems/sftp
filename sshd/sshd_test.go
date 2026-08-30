package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/sftp/wire"
	"golang.org/x/crypto/ssh"
)

// No key in this file is ever written to disk. Every one is generated in
// memory, for one test, and is unreachable once it returns — which is the
// same rule the module states for production: keys come from the caller and
// this package neither reads nor writes them.

// tinyFS is the smallest Filesystem that lets a real client fetch a real file.
type tinyFS struct{ files map[string][]byte }

func (t tinyFS) Close() error { return nil }
func (t tinyFS) ReadFile(p string) ([]byte, error) {
	b, ok := t.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}
func (t tinyFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	if p != "/" {
		return nil, fs.ErrNotExist
	}
	var out []filesystem.DirEntry
	for name := range t.files {
		out = append(out, filesystem.NewDirEntry(1, strings.TrimPrefix(name, "/"), 0))
	}
	return out, nil
}
func (t tinyFS) Stat(p string) (filesystem.Stat, error) {
	if p == "/" {
		return filesystem.NewStat(0o040755, 0, 1), nil
	}
	b, ok := t.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return filesystem.NewStat(0o100644, uint64(len(b)), 2), nil
}
func (t tinyFS) WriteFile(string, []byte, os.FileMode) error { return errors.New("read-only") }
func (t tinyFS) ReadLink(string) (string, error)             { return "", errors.New("not a symbolic link") }
func (t tinyFS) MkDir(string, os.FileMode) error             { return errors.New("read-only") }
func (t tinyFS) DeleteFile(string) error                     { return errors.New("read-only") }
func (t tinyFS) DeleteDir(string) error                      { return errors.New("read-only") }
func (t tinyFS) Rename(string, string) error                 { return errors.New("read-only") }

// clientKey returns a fresh in-memory Ed25519 client key pair.
func clientKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return s, p
}

// harness starts a server on loopback and returns its address plus the client
// signer that is authorised on it.
func harness(t *testing.T, fsys filesystem.Filesystem, extra ...func(*Config)) (string, ssh.Signer, ssh.PublicKey, *Server) {
	t.Helper()
	srv, err := sftp.New(fsys)
	if err != nil {
		t.Fatalf("sftp.New: %v", err)
	}
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey: %v", err)
	}
	signer, pub := clientKey(t)
	cfg := Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}}
	for _, f := range extra {
		f(&cfg)
	}
	d, err := New(srv, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Serve(ln) }()
	t.Cleanup(func() {
		d.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ErrServerClosed) {
				t.Errorf("Serve = %v, want ErrServerClosed", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop within 5s")
		}
	})
	return ln.Addr().String(), signer, hostKey.PublicKey(), d
}

// sftpChannel authenticates, opens a session and requests the sftp subsystem.
func sftpChannel(t *testing.T, addr string, signer ssh.Signer, hostPub ssh.PublicKey) (io.ReadWriter, func()) {
	t.Helper()
	cc := &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", addr, cc)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	w, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	r, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("RequestSubsystem: %v", err)
	}
	return rw{r: r, w: w}, func() { sess.Close(); conn.Close() }
}

type rw struct {
	r io.Reader
	w io.Writer
}

func (x rw) Read(p []byte) (int, error)  { return x.r.Read(p) }
func (x rw) Write(p []byte) (int, error) { return x.w.Write(p) }

// TestEndToEndOverRealSSH is the whole module in one test: a real SSH
// handshake, a real public-key authentication, a real subsystem request, and
// a real file coming back over it.
func TestEndToEndOverRealSSH(t *testing.T) {
	want := bytes.Repeat([]byte("go-filesystems"), 1000)
	fsys := tinyFS{files: map[string][]byte{"/data.bin": want}}
	addr, signer, hostPub, _ := harness(t, fsys)
	ch, closeFn := sftpChannel(t, addr, signer, hostPub)
	defer closeFn()

	var out []byte
	var in []byte
	send := func(m wire.Message) {
		var err error
		out, err = wire.Send(ch, m, out)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	recv := func() (uint8, []byte) {
		typ, payload, next, err := wire.ReadPacket(ch, in, 0)
		in = next
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		return typ, append([]byte(nil), payload...)
	}

	send(wire.InitRequest{Version: 3})
	if typ, _ := recv(); typ != wire.FxpVersion {
		t.Fatalf("first reply type %d, want VERSION", typ)
	}
	send(wire.OpenRequest{ID: 1, Path: "/data.bin", PFlags: wire.FxfRead})
	typ, payload := recv()
	if typ != wire.FxpHandle {
		st, _ := wire.DecodeStatus(payload)
		t.Fatalf("open: %v (%q)", st.Code, st.Message)
	}
	h, _ := wire.DecodeHandleReply(payload)

	var got []byte
	for off := uint64(0); ; {
		send(wire.ReadRequest{ID: 2, Handle: h.Handle, Offset: off, Length: 4096})
		typ, payload := recv()
		if typ == wire.FxpStatus {
			st, _ := wire.DecodeStatus(payload)
			if st.Code != wire.StatusEOF {
				t.Fatalf("read: %v (%q)", st.Code, st.Message)
			}
			break
		}
		d, _ := wire.DecodeData(payload)
		got = append(got, d.Data...)
		off += uint64(len(d.Data))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read %d bytes over SSH, want %d", len(got), len(want))
	}
}

func TestNewValidatesItsConfig(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	hostKey, _ := GenerateHostKey()
	_, pub := clientKey(t)

	if _, err := New(nil, Config{}); !errors.Is(err, ErrNilServer) {
		t.Errorf("New(nil) = %v", err)
	}
	if _, err := New(srv, Config{AuthorizedKeys: []ssh.PublicKey{pub}}); !errors.Is(err, ErrNoHostKey) {
		t.Errorf("New with no host key = %v", err)
	}
	if _, err := New(srv, Config{HostKeys: []ssh.Signer{hostKey}}); !errors.Is(err, ErrNoAuthorizedKeys) {
		t.Errorf("New with no authorized keys = %v; it must refuse rather than allow everyone", err)
	}
	if _, err := New(srv, Config{
		HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}, Banner: "hello",
	}); err != nil {
		t.Errorf("New with a banner = %v", err)
	}
}

func TestUnauthorizedKeyIsRefused(t *testing.T) {
	addr, _, hostPub, _ := harness(t, tinyFS{files: map[string][]byte{}})
	other, _ := clientKey(t)
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(other)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		t.Fatal("a key that is not in AuthorizedKeys was accepted")
	}
}

func TestBannerReachesTheClient(t *testing.T) {
	var seen string
	addr, signer, hostPub, _ := harness(t, tinyFS{files: map[string][]byte{}},
		func(c *Config) { c.Banner = "one image, one tenant\n" })
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		BannerCallback:  func(m string) error { seen = m; return nil },
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if !strings.Contains(seen, "one image, one tenant") {
		t.Fatalf("banner = %q", seen)
	}
}

func TestOnlySftpSessionsAreServed(t *testing.T) {
	addr, signer, hostPub, _ := harness(t, tinyFS{files: map[string][]byte{}})
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	t.Run("a forwarding channel is refused by name", func(t *testing.T) {
		// direct-tcpip is a proxy. Serving it would turn a file server into
		// a network relay, which is the thing this must never become.
		_, _, err := conn.OpenChannel("direct-tcpip", nil)
		if err == nil {
			t.Fatal("direct-tcpip was accepted")
		}
		var oce *ssh.OpenChannelError
		if !errors.As(err, &oce) || oce.Reason != ssh.UnknownChannelType {
			t.Fatalf("err = %v, want UnknownChannelType", err)
		}
	})
	t.Run("shell and exec are refused", func(t *testing.T) {
		sess, err := conn.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer sess.Close()
		if err := sess.Shell(); err == nil {
			t.Fatal("a shell was granted; there is no shell here to give")
		}
	})
	t.Run("another subsystem is refused", func(t *testing.T) {
		sess, err := conn.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer sess.Close()
		if err := sess.RequestSubsystem("netconf"); err == nil {
			t.Fatal("an unknown subsystem was granted")
		}
	})
	t.Run("a subsystem request with a malformed payload is refused", func(t *testing.T) {
		ch, reqs, err := conn.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("OpenChannel: %v", err)
		}
		defer ch.Close()
		go ssh.DiscardRequests(reqs)
		ok, err := ch.SendRequest("subsystem", true, []byte{0xff})
		if err != nil {
			t.Fatalf("SendRequest: %v", err)
		}
		if ok {
			t.Fatal("a malformed subsystem payload was accepted")
		}
	})
}

func TestParseAuthorizedKeys(t *testing.T) {
	_, pub1 := clientKey(t)
	_, pub2 := clientKey(t)
	data := append(ssh.MarshalAuthorizedKey(pub1), ssh.MarshalAuthorizedKey(pub2)...)
	keys, err := ParseAuthorizedKeys(data)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(keys))
	}
	if !bytes.Equal(keys[0].Marshal(), pub1.Marshal()) {
		t.Fatal("first key does not round-trip")
	}
	// Comments and blank lines.
	withNoise := append([]byte("# a comment\n\n  \n"), data...)
	if keys, err = ParseAuthorizedKeys(withNoise); err != nil || len(keys) != 2 {
		t.Fatalf("ParseAuthorizedKeys with noise = %d keys, %v", len(keys), err)
	}
	// Trailing whitespace after the last key must not be an error.
	if keys, err = ParseAuthorizedKeys(append(data, ' ', '\n', '\t')); err != nil || len(keys) != 2 {
		t.Fatalf("ParseAuthorizedKeys with a trailing blank = %d keys, %v", len(keys), err)
	}
	// Empty input yields nothing and no error.
	if keys, err = ParseAuthorizedKeys(nil); err != nil || len(keys) != 0 {
		t.Fatalf("ParseAuthorizedKeys(nil) = %d keys, %v", len(keys), err)
	}
	// A malformed line is an error, not a silent skip: skipping is how a
	// server ends up denying the one person it was configured for.
	if _, err = ParseAuthorizedKeys([]byte("ssh-ed25519 not-base64 nobody\n")); err == nil {
		t.Fatal("a malformed authorized_keys line parsed without error")
	}
}

func TestParseHostKey(t *testing.T) {
	// Generated here, in memory, and never written anywhere.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pem, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	signer, err := ParseHostKey(encodePEM(pem))
	if err != nil {
		t.Fatalf("ParseHostKey: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %q", signer.PublicKey().Type())
	}
	if _, err := ParseHostKey([]byte("not a key")); err == nil {
		t.Fatal("ParseHostKey accepted rubbish")
	}
}

func TestListenAndServeAndClose(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	hostKey, _ := GenerateHostKey()
	_, pub := clientKey(t)
	d, err := New(srv, Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- d.ListenAndServe("127.0.0.1:0") }()
	// Give the listener a moment, then stop it. Close is idempotent.
	for range 100 {
		d.mu.Lock()
		up := d.ln != nil
		d.mu.Unlock()
		if up {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrServerClosed) {
		t.Fatalf("ListenAndServe = %v, want ErrServerClosed", err)
	}
	// Serving again after Close must refuse rather than accept silently.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := d.Serve(ln); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Close = %v", err)
	}
}

func TestListenAndServeReportsABadAddress(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	hostKey, _ := GenerateHostKey()
	_, pub := clientKey(t)
	d, _ := New(srv, Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}})
	if err := d.ListenAndServe("127.0.0.1:not-a-port"); err == nil {
		t.Fatal("ListenAndServe accepted a bad address")
	}
}

func TestServeReportsAnAcceptFailure(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	hostKey, _ := GenerateHostKey()
	_, pub := clientKey(t)
	d, _ := New(srv, Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ln.Close() // Accept now fails, and the server was never Closed.
	if err := d.Serve(ln); err == nil || errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve = %v, want the accept error", err)
	}
}

func TestHandleConnRejectsANonSSHPeer(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	hostKey, _ := GenerateHostKey()
	_, pub := clientKey(t)
	d, _ := New(srv, Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}})
	// A real socket, not net.Pipe: the SSH handshake writes its version
	// banner before reading anything, and an unbuffered pipe with nobody
	// reading would deadlock instead of failing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		c.Close()
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := d.HandleConn(conn); err == nil {
		t.Fatal("HandleConn accepted a peer that is not speaking SSH")
	}
}

// TestConnectionArrivingDuringCloseIsNotLeaked covers the race between accept
// and Close: a connection tracked after Close must be dropped, since nothing
// will come back for it.
func TestConnectionArrivingDuringCloseIsNotLeaked(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	hostKey, _ := GenerateHostKey()
	_, pub := clientKey(t)
	d, _ := New(srv, Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}})
	d.Close()
	a, b := net.Pipe()
	defer a.Close()
	d.track(b, true)
	if len(d.conns) != 0 {
		t.Fatal("a connection arriving after Close was tracked")
	}
	// It must also have been closed.
	b.SetDeadline(time.Now().Add(time.Second))
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("the connection was left open")
	}
}

// encodePEM renders a *pem.Block, which is what ssh.MarshalPrivateKey returns.
func encodePEM(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

func TestGenerateHostKeyReportsAFailedCSPRNG(t *testing.T) {
	orig := keyRand
	t.Cleanup(func() { keyRand = orig })
	keyRand = failingReader{}
	if _, err := GenerateHostKey(); err == nil {
		t.Fatal("GenerateHostKey returned a key from a failed CSPRNG")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestAChannelThatCannotBeAcceptedEndsTheConnection(t *testing.T) {
	orig := acceptChannel
	t.Cleanup(func() { acceptChannel = orig })
	boom := errors.New("connection died mid-request")
	acceptChannel = func(ssh.NewChannel) (ssh.Channel, <-chan *ssh.Request, error) {
		return nil, nil, boom
	}
	addr, signer, hostPub, _ := harness(t, tinyFS{files: map[string][]byte{}})
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "anyone",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.NewSession(); err == nil {
		t.Fatal("a session was granted although the channel could not be accepted")
	}
}
