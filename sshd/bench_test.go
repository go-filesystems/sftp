// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/sftp/wire"
	"github.com/go-filesystems/ssh"
)

// BenchmarkGetOverSSH fetches a file through a real SSH handshake on loopback
// with `depth` 32 KiB READs outstanding, and reports how many Write calls (one
// write(2) each) the server's TCP connection received per MiB sent. It uses
// only the public API, so it can be copied into a clean clone of an earlier tag
// to measure it:
//
//	go test -c -o new.test ./sshd && ./new.test -test.run xxx -test.bench GetOverSSH -test.benchmem
//
// Timings are valid only when the machine's 1-minute load is at most 8; the
// Write counts and the allocation counts are exact at any load.
func BenchmarkGetOverSSH(b *testing.B) {
	const size = 32 << 20
	data := make([]byte, size)
	for _, sessions := range []int{1, 4} {
		b.Run(map[int]string{1: "1session", 4: "4sessions"}[sessions], func(b *testing.B) {
			benchOverSSH(b, data, sessions)
		})
	}
}

func benchOverSSH(b *testing.B, data []byte, sessions int) {
	srv, err := sftp.New(benchFS{data}, benchOptions()...)
	if err != nil {
		b.Fatal(err)
	}
	hostKey, _ := GenerateHostKey()
	signer, pub := benchClientKey(b)
	d, err := New(srv, Config{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeys: []ssh.PublicKey{pub}})
	if err != nil {
		b.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Skip("no loopback")
	}
	ln := &countingListener{Listener: inner}
	go d.Serve(ln)
	defer d.Close()
	cc := &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey())}

	// One SSH connection per session, made once: the handshake is not measured.
	type sess struct {
		rw    io.ReadWriter
		close func()
	}
	var ss []sess
	for range sessions {
		conn, err := ssh.Dial("tcp", inner.Addr().String(), cc)
		if err != nil {
			b.Fatal(err)
		}
		s, _ := conn.NewSession()
		w, _ := s.StdinPipe()
		r, _ := s.StdoutPipe()
		if err := s.RequestSubsystem("sftp"); err != nil {
			b.Fatal(err)
		}
		ss = append(ss, sess{struct {
			io.Reader
			io.Writer
		}{r, w}, func() { s.Close(); conn.Close() }})
	}
	defer func() {
		for _, s := range ss {
			s.close()
		}
	}()
	for _, s := range ss {
		negotiate(b, s.rw)
	}

	b.SetBytes(int64(len(data) * sessions))
	b.ReportAllocs()
	ln.writes.Store(0)
	b.ResetTimer()
	for range b.N {
		var wg sync.WaitGroup
		for _, s := range ss {
			wg.Add(1)
			go func() { defer wg.Done(); fetch(b, s.rw, len(data), 64) }()
		}
		wg.Wait()
	}
	b.StopTimer()
	mib := float64(b.N) * float64(len(data)*sessions) / (1 << 20)
	b.ReportMetric(float64(ln.writes.Load())/mib, "writes/MiB")
}

func negotiate(b *testing.B, rw io.ReadWriter) {
	if _, err := wire.Send(rw, wire.InitRequest{Version: wire.Version}, nil); err != nil {
		b.Fatal(err)
	}
	if _, _, _, err := wire.ReadPacket(rw, nil, 0); err != nil {
		b.Fatal(err)
	}
}

// fetch opens /f, reads size bytes with depth READs outstanding, closes it.
func fetch(b *testing.B, rw io.ReadWriter, size, depth int) {
	const chunk = 32 << 10
	var buf, in []byte
	send := func(m wire.Message) {
		var err error
		if buf, err = wire.Send(rw, m, buf); err != nil {
			b.Error(err)
		}
	}
	recv := func() (uint8, []byte) {
		typ, p, next, err := wire.ReadPacket(rw, in, 0)
		in = next
		if err != nil {
			b.Error(err)
		}
		return typ, p
	}
	send(wire.OpenRequest{ID: 1, Path: "/f", PFlags: wire.FxfRead})
	_, p := recv()
	h, _ := wire.DecodeHandleReply(p)
	reqs := make(chan struct{}, depth)
	go func() {
		for off := 0; off < size; off += chunk {
			reqs <- struct{}{}
			send(wire.ReadRequest{ID: uint32(off/chunk + 2), Handle: h.Handle, Offset: uint64(off), Length: uint32(chunk)})
		}
		close(reqs)
	}()
	for got := 0; got < size; {
		typ, p := recv()
		if typ != wire.FxpData {
			b.Errorf("reply type %d", typ)
			return
		}
		d, _ := wire.DecodeData(p)
		got += len(d.Data)
		<-reqs
	}
	// The request goroutine is the only sender and has finished (reqs closed
	// and drained), so this send does not race it.
	send(wire.HandleRequest{PacketType: wire.FxpClose, ID: 1 << 30, Handle: h.Handle})
	recv()
}

// countingListener counts the Write calls the server makes on its connections.
type countingListener struct {
	net.Listener
	writes atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, n: &l.writes}, nil
}

type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) { c.n.Add(1); return c.Conn.Write(p) }

func benchClientKey(b *testing.B) (ssh.Signer, ssh.PublicKey) {
	b.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		b.Fatal(err)
	}
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		b.Fatal(err)
	}
	return s, p
}

// benchFS serves one in-memory file, /f, through the Opener capability.
type benchFS struct{ data []byte }

func (b benchFS) Close() error                                { return nil }
func (b benchFS) ReadFile(string) ([]byte, error)             { return b.data, nil }
func (b benchFS) WriteFile(string, []byte, os.FileMode) error { return fs.ErrPermission }
func (b benchFS) ReadLink(string) (string, error)             { return "", fs.ErrInvalid }
func (b benchFS) MkDir(string, os.FileMode) error             { return fs.ErrPermission }
func (b benchFS) DeleteFile(string) error                     { return fs.ErrPermission }
func (b benchFS) DeleteDir(string) error                      { return fs.ErrPermission }
func (b benchFS) Rename(string, string) error                 { return fs.ErrPermission }
func (b benchFS) ListDir(string) ([]filesystem.DirEntry, error) {
	return nil, nil
}
func (b benchFS) Stat(p string) (filesystem.Stat, error) {
	if p == "/" {
		return filesystem.NewStat(0o040755, 0, 1), nil
	}
	return filesystem.NewStat(0o100644, uint64(len(b.data)), 2), nil
}
func (b benchFS) OpenFile(string) (filesystem.File, error) { return benchFile(b), nil }

type benchFile struct{ data []byte }

func (f benchFile) Size() int64  { return int64(len(f.data)) }
func (f benchFile) Close() error { return nil }
func (f benchFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
