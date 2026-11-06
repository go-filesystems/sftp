// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// ramFS is a writable in-memory Filesystem whose Files read and write at an
// offset, so the server takes its concurrent path.
type ramFS struct {
	mu    sync.RWMutex
	files map[string][]byte
	// slow makes every third 32 KiB block of a read slow, so that a server
	// answering as work completes would send replies out of order.
	slow time.Duration
}

func (r *ramFS) Close() error { return nil }
func (r *ramFS) ReadFile(p string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (r *ramFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []filesystem.DirEntry
	for name := range r.files {
		out = append(out, filesystem.NewDirEntry(1, strings.TrimPrefix(name, "/"), 0))
	}
	return out, nil
}
func (r *ramFS) Stat(p string) (filesystem.Stat, error) {
	if p == "/" {
		return filesystem.NewStat(0o040755, 0, 1), nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return filesystem.NewStat(0o100644, uint64(len(b)), 2), nil
}
func (r *ramFS) WriteFile(p string, data []byte, _ os.FileMode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[p] = append([]byte(nil), data...)
	return nil
}
func (r *ramFS) ReadLink(string) (string, error)  { return "", errors.New("not a symbolic link") }
func (r *ramFS) MkDir(string, os.FileMode) error  { return errors.New("unsupported") }
func (r *ramFS) DeleteFile(string) error          { return errors.New("unsupported") }
func (r *ramFS) DeleteDir(string) error           { return errors.New("unsupported") }
func (r *ramFS) Rename(string, string) error      { return errors.New("unsupported") }
func (r *ramFS) Truncate(p string, n int64) error { return r.WriteFile(p, make([]byte, n), 0) }
func (r *ramFS) OpenFile(p string) (filesystem.File, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.files[p]; !ok {
		return nil, fs.ErrNotExist
	}
	return &ramFile{r, p}, nil
}

type ramFile struct {
	r *ramFS
	p string
}

func (f *ramFile) Size() int64 {
	f.r.mu.RLock()
	defer f.r.mu.RUnlock()
	return int64(len(f.r.files[f.p]))
}
func (f *ramFile) Close() error { return nil }
func (f *ramFile) ReadAt(p []byte, off int64) (int, error) {
	if f.r.slow > 0 && (off>>15)%3 == 0 {
		time.Sleep(f.r.slow)
	}
	f.r.mu.RLock()
	defer f.r.mu.RUnlock()
	b := f.r.files[f.p]
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *ramFile) WriteAt(p []byte, off int64) (int, error) {
	if f.r.slow > 0 && (off>>15)%3 == 0 {
		time.Sleep(f.r.slow)
	}
	f.r.mu.Lock()
	defer f.r.mu.Unlock()
	b := f.r.files[f.p]
	if end := int(off) + len(p); end > len(b) {
		b = append(b, make([]byte, end-len(b))...)
	}
	copy(b[off:], p)
	f.r.files[f.p] = b
	return len(p), nil
}
func (f *ramFile) Truncate(n int64) error { return f.r.Truncate(f.p, n) }
func (f *ramFile) Sync() error            { return nil }

// OpenSSH's own sftp client, pipelining 64 requests (and then more, with
// larger blocks), puts and gets files of 24 MiB through the concurrent server
// and gets every byte back: SHA-256 of the file on each side is equal.
func TestOpenSSHLargeTransfersConcurrent(t *testing.T) {
	sftpBin, err := exec.LookPath("sftp")
	if err != nil {
		if os.Getenv("SFTP_REQUIRE_OPENSSH") != "" {
			t.Fatal("OpenSSH's sftp is required here")
		}
		t.Skip("OpenSSH is not installed")
	}
	const size = 24<<20 + 777
	src := make([]byte, size)
	rand.Read(src)
	ram := &ramFS{files: map[string][]byte{"/get.bin": src}}
	srv, err := sftp.New(ram, sftp.ReadWrite())
	if err != nil {
		t.Fatal(err)
	}
	// The OpenSSH client needs its key in a file: a throwaway key for a
	// loopback server, in the test's own temporary directory.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	addr, _, _, _ := harnessFor(t, Config{
		AuthorizedKeys: []ssh.PublicKey{sshPub},
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := strings.Cut(addr, ":")
	up := filepath.Join(dir, "up.bin")
	if err := os.WriteFile(up, src, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{{}, {"-R", "128", "-B", "131072"}} {
		down := filepath.Join(dir, "down.bin")
		os.Remove(down)
		args := append([]string{"-b", "-", "-P", port, "-i", key,
			"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"}, flags...)
		cmd := exec.Command(sftpBin, append(args, "alice@"+host)...)
		cmd.Stdin = strings.NewReader("get /get.bin " + down + "\nput " + up + " /put.bin\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sftp %v: %v\n%s", flags, err, out)
		}
		got, err := os.ReadFile(down)
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(got) != sha256.Sum256(src) {
			t.Fatalf("flags %v: get: SHA-256 differs (%d bytes)", flags, len(got))
		}
		ram.mu.RLock()
		put := ram.files["/put.bin"]
		ram.mu.RUnlock()
		if sha256.Sum256(put) != sha256.Sum256(src) {
			t.Fatalf("flags %v: put: SHA-256 differs (%d bytes)", flags, len(put))
		}
		ram.mu.Lock()
		delete(ram.files, "/put.bin")
		ram.mu.Unlock()
	}
}

// OpenSSH's client refuses to resume a download whose replies came back out
// of order ("server reordered requests", sftp-client.c:1856), so a server that
// answers concurrently must still reply in order. `get -a` of a half-fetched
// file must finish it, byte for byte.
func TestOpenSSHResumeAgainstConcurrentServer(t *testing.T) {
	sftpBin, err := exec.LookPath("sftp")
	if err != nil {
		if os.Getenv("SFTP_REQUIRE_OPENSSH") != "" {
			t.Fatal("OpenSSH's sftp is required here")
		}
		t.Skip("OpenSSH is not installed")
	}
	const size = 16<<20 + 321
	src := make([]byte, size)
	rand.Read(src)
	srv, err := sftp.New(&ramFS{files: map[string][]byte{"/get.bin": src}, slow: 3 * time.Millisecond}, sftp.ReadWrite())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	addr, _, _, _ := harnessFor(t, Config{
		AuthorizedKeys: []ssh.PublicKey{sshPub},
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	if err := os.WriteFile(key, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(dir, "part.bin")
	if err := os.WriteFile(part, src[:9<<20], 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := strings.Cut(addr, ":")
	cmd := exec.Command(sftpBin, "-b", "-", "-P", port, "-i", key,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "alice@"+host)
	cmd.Stdin = strings.NewReader("get -a /get.bin " + part + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("get -a: %v\n%s", err, out)
	}
	got, err := os.ReadFile(part)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(src) {
		t.Fatalf("resumed file differs (%d bytes, want %d)", len(got), size)
	}
}

// OpenSSH's client logs "server reordered ACKs" (sftp-client.c:2224, debug3,
// so `-vvv`) when a WRITE status comes back past an earlier one, and a
// download or upload interrupted after that cannot be resumed (lines
// 1856-1859). Slow every third block in the driver, so that a server
// answering as the work completes would reorder, and put a file: the
// message must not appear.
func TestOpenSSHRepliesStayInOrder(t *testing.T) {
	sftpBin, err := exec.LookPath("sftp")
	if err != nil {
		if os.Getenv("SFTP_REQUIRE_OPENSSH") != "" {
			t.Fatal("OpenSSH's sftp is required here")
		}
		t.Skip("OpenSSH is not installed")
	}
	const size = 8 << 20
	src := make([]byte, size)
	rand.Read(src)
	ram := &ramFS{files: map[string][]byte{}, slow: 3 * time.Millisecond}
	srv, err := sftp.New(ram, sftp.ReadWrite())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	addr, _, _, _ := harnessFor(t, Config{
		AuthorizedKeys: []ssh.PublicKey{sshPub},
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	if err := os.WriteFile(key, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	up := filepath.Join(dir, "up.bin")
	if err := os.WriteFile(up, src, 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := strings.Cut(addr, ":")
	cmd := exec.Command(sftpBin, "-vvv", "-b", "-", "-P", port, "-i", key,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "alice@"+host)
	cmd.Stdin = strings.NewReader("put " + up + " /put.bin\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("put: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "server reordered ACKs") {
		t.Fatal("OpenSSH's client saw the server's replies out of order")
	}
	ram.mu.RLock()
	defer ram.mu.RUnlock()
	if sha256.Sum256(ram.files["/put.bin"]) != sha256.Sum256(src) {
		t.Fatal("put: SHA-256 differs")
	}
}
