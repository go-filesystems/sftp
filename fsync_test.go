// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"errors"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// syncFS is a driver with no positional files (the embedded interface hides
// the fixture's) and a filesystem-level Sync, as (*hfsplus.Volume) is.
type syncFS struct {
	filesystem.Filesystem
	syncs int
	err   error
}

func (s *syncFS) Sync() error { s.syncs++; return s.err }

func (c *client) fsync(handle string) (wire.Status, string) {
	c.t.Helper()
	e := wire.NewEncoder(nil)
	e.String(handle)
	typ, payload := c.do(wire.ExtendedRequest{ID: c.next(), Name: "fsync@openssh.com", Data: e.Bytes()})
	if typ != wire.FxpStatus {
		c.t.Fatalf("fsync: reply type %d, want SSH_FXP_STATUS", typ)
	}
	st, _ := wire.DecodeStatus(payload)
	return st.Code, st.Message
}

// fsync@openssh.com is offered on a writable export whose driver can be synced,
// and reaches the filesystem's Sync for a handle opened for writing; a failure
// is the client's error, never a success.
func TestFsyncSyncsTheFilesystem(t *testing.T) {
	fs := &syncFS{Filesystem: fixture()}
	c := dial(t, fs, ReadWrite())
	var offered bool
	for _, n := range versionExtensions(t, c) {
		offered = offered || n == "fsync@openssh.com"
	}
	if !offered {
		t.Fatalf("fsync@openssh.com is not advertised: %v", versionExtensions(t, c))
	}
	w := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	if code, msg := c.fsync(w); code != wire.StatusOK || fs.syncs != 1 {
		t.Fatalf("fsync: %v %q, syncs %d, want OK and 1", code, msg, fs.syncs)
	}
	fs.err = errors.New("disk gone")
	if code, _ := c.fsync(w); code != wire.StatusFailure {
		t.Errorf("fsync with a failing Sync answered %v, want a failure", code)
	}
	fs.err = nil
	if code, _ := c.fsync("nope"); code != wire.StatusFailure {
		t.Errorf("an unknown handle answered %v", code)
	}
	r := c.open("/hello.txt", wire.FxfRead)
	before := fs.syncs
	if code, _ := c.fsync(r); code != wire.StatusOK || fs.syncs != before {
		t.Errorf("a read-only handle: %v, synced %d times", code, fs.syncs-before)
	}

	// Read-only, or a driver that cannot be synced: not offered.
	for name, c := range map[string]*client{
		"read-only": dial(t, &syncFS{Filesystem: fixture()}),
		"no Syncer": dial(t, fixture(), ReadWrite()),
	} {
		for _, n := range versionExtensions(t, c) {
			if n == "fsync@openssh.com" {
				t.Errorf("%s: fsync@openssh.com advertised", name)
			}
		}
	}
}
