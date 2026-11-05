// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// This file uses only the public API and the wire package, so it can be
// copied unchanged into a clean clone of an earlier tag to measure it
// (v0.7.0 is the serial baseline; the default here is DefaultMaxInFlight).
//
//	go test -run xxx -bench BenchmarkGet -benchmem -count 6
//
// Timings are valid only when the machine's 1-minute load is at most 8;
// allocation counts are exact at any load.

// benchFS serves one in-memory file through the Opener capability.
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

// benchGet fetches the file over `sessions` sessions at once, each keeping
// `depth` 32 KiB READs outstanding, the way OpenSSH's sftp client does.
func benchGet(b *testing.B, dial dialer, path string, size, sessions, depth int) {
	const chunk = 32 << 10
	b.SetBytes(int64(size * sessions))
	b.ReportAllocs()
	for range b.N {
		var wg sync.WaitGroup
		for range sessions {
			wg.Add(1)
			go func() {
				defer wg.Done()
				getOnce(b, dial, path, size, depth, chunk)
			}()
		}
		wg.Wait()
	}
}

// A dialer starts one session and returns its stream and how to end it.
type dialer func() (io.ReadWriter, func())

// inProcess serves sessions of srv over in-memory pipes.
func inProcess(srv *Server) dialer {
	return func() (io.ReadWriter, func()) {
		a, c := net.Pipe()
		done := make(chan struct{})
		go func() { srv.Serve(c); close(done) }()
		return a, func() { a.Close(); <-done }
	}
}

// sftpServerBinary is OpenSSH's sftp-server, the reference.
func sftpServerBinary() string {
	for _, p := range []string{"/usr/libexec/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// openSSHServer starts OpenSSH's sftp-server on stdin and stdout, one process
// per session, the way sshd does.
func openSSHServer(bin string) dialer {
	return func() (io.ReadWriter, func()) {
		cmd := exec.Command(bin)
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		cmd.Start()
		return struct {
			io.Reader
			io.Writer
		}{out, in}, func() {
			in.Close()
			cmd.Wait()
		}
	}
}

func getOnce(b *testing.B, dial dialer, path string, size, depth, chunk int) {
	a, end := dial()
	defer end()
	var buf, in []byte
	send := func(m wire.Message) {
		var err error
		if buf, err = wire.Send(a, m, buf); err != nil {
			b.Error(err)
		}
	}
	recv := func() (uint8, []byte) {
		typ, p, next, err := wire.ReadPacket(a, in, 0)
		in = next
		if err != nil {
			b.Error(err)
		}
		return typ, p
	}
	send(wire.InitRequest{Version: wire.Version})
	recv()
	send(wire.OpenRequest{ID: 1, Path: path, PFlags: wire.FxfRead})
	_, p := recv()
	h, _ := wire.DecodeHandleReply(p)
	handle := h.Handle
	got := 0
	// Sends run on their own goroutine: the pipe is synchronous.
	reqs := make(chan struct{}, depth)
	go func() {
		for off := 0; off < size; off += chunk {
			reqs <- struct{}{}
			send(wire.ReadRequest{ID: uint32(off/chunk + 2), Handle: handle, Offset: uint64(off), Length: uint32(chunk)})
		}
		close(reqs)
	}()
	for got < size {
		typ, p := recv()
		if typ != wire.FxpData {
			b.Errorf("reply type %d", typ)
			return
		}
		d, _ := wire.DecodeData(p)
		got += len(d.Data)
		<-reqs
	}
}

func BenchmarkGet(b *testing.B) {
	const size = 16 << 20
	data := make([]byte, size)
	for _, tc := range []struct {
		name            string
		sessions, depth int
	}{
		{"1session", 1, 64},
		{"2sessions", 2, 64},
	} {
		srv, _ := New(benchFS{data})
		b.Run(tc.name, func(b *testing.B) { benchGet(b, inProcess(srv), "/f", size, tc.sessions, tc.depth) })
	}
}

// BenchmarkGetOpenSSH is the same transfer against OpenSSH's own sftp-server,
// the reference, where it is installed.
func BenchmarkGetOpenSSH(b *testing.B) {
	bin := sftpServerBinary()
	if bin == "" {
		b.Skip("no OpenSSH sftp-server here")
	}
	const size = 16 << 20
	path := filepath.Join(b.TempDir(), "f")
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		sessions int
	}{{"1session", 1}, {"2sessions", 2}} {
		b.Run(tc.name, func(b *testing.B) { benchGet(b, openSSHServer(bin), path, size, tc.sessions, 64) })
	}
}
