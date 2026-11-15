// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"errors"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// pathFS is a driver that can sync by path, and records which paths it was asked
// about; a path in fail is one whose volume has failed.
type pathFS struct {
	filesystem.Filesystem
	paths []string
	fail  map[string]error
}

func (p *pathFS) SyncPath(path string) error {
	p.paths = append(p.paths, path)
	return p.fail[path]
}

// pathAndWholeFS can also be synced as a whole: the path is preferred.
type pathAndWholeFS struct {
	pathFS
	whole int
}

func (p *pathAndWholeFS) Sync() error { p.whole++; return nil }

func advertisesFsync(t *testing.T, c *client) bool {
	t.Helper()
	for _, n := range versionExtensions(t, c) {
		if n == "fsync@openssh.com" {
			return true
		}
	}
	return false
}

// A driver that can sync by path is offered fsync@openssh.com and is asked about
// the handle's path, never the whole filesystem; its failure for one path is the
// client's error for a handle there only.
func TestFsyncSyncsByPath(t *testing.T) {
	boom := errors.New("EIO")
	fs := &pathFS{Filesystem: fixture(), fail: map[string]error{"/bad.bin": boom}}
	c := dial(t, fs, ReadWrite())
	if !advertisesFsync(t, c) {
		t.Fatal("fsync@openssh.com is not advertised for a driver with SyncPath")
	}
	good := c.open("/good.bin", wire.FxfWrite|wire.FxfCreat)
	bad := c.open("/bad.bin", wire.FxfWrite|wire.FxfCreat)
	if code, msg := c.fsync(good); code != wire.StatusOK {
		t.Fatalf("fsync on a healthy path: %v %q", code, msg)
	}
	if code, _ := c.fsync(bad); code != wire.StatusFailure {
		t.Errorf("fsync on the failed path answered %v, want a failure", code)
	}
	if code, _ := c.fsync(good); code != wire.StatusOK {
		t.Errorf("a failed path made the healthy one fail: %v", code)
	}
	want := []string{"/good.bin", "/bad.bin", "/good.bin"}
	if len(fs.paths) != len(want) {
		t.Fatalf("SyncPath asked about %v, want %v", fs.paths, want)
	}
	for i := range want {
		if fs.paths[i] != want[i] {
			t.Errorf("SyncPath call %d was %q, want %q", i, fs.paths[i], want[i])
		}
	}
}

// With both, the path wins: Sync of the whole is not used.
func TestFsyncPrefersThePath(t *testing.T) {
	fs := &pathAndWholeFS{pathFS: pathFS{Filesystem: fixture()}}
	c := dial(t, fs, ReadWrite())
	h := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	if code, msg := c.fsync(h); code != wire.StatusOK {
		t.Fatalf("fsync: %v %q", code, msg)
	}
	if len(fs.paths) != 1 || fs.whole != 0 {
		t.Errorf("SyncPath %v, Sync %d times; want one path and no whole sync", fs.paths, fs.whole)
	}
}
