// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"testing"

	"github.com/go-filesystems/sftp/wire"
)

// A request the server cannot honour is refused with a status that says why,
// each in its own words: a body that is not a handle, an export that did not
// advertise the extension, a directory handle.
func TestFsyncRefusals(t *testing.T) {
	fs := &syncFS{Filesystem: fixture()}
	c := dial(t, fs, ReadWrite())
	typ, payload := c.do(wire.ExtendedRequest{ID: c.next(), Name: "fsync@openssh.com", Data: []byte{0}})
	if st, _ := wire.DecodeStatus(payload); typ != wire.FxpStatus || st.Code != wire.StatusBadMessage {
		t.Errorf("a short body: type %d, %v; want StatusBadMessage", typ, st.Code)
	}
	if code, _ := c.fsync(c.opendir("/sub")); code != wire.StatusFailure {
		t.Errorf("a directory handle answered %v, want a failure", code)
	}
	if fs.syncs != 0 {
		t.Errorf("a refused request synced %d times", fs.syncs)
	}

	// An export whose driver cannot be synced never advertised it, and refuses
	// a client that asks anyway.
	plain := dial(t, fixture(), ReadWrite())
	h := plain.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	if code, msg := plain.fsync(h); code != wire.StatusOpUnsupported {
		t.Errorf("an export that cannot sync answered %v %q, want StatusOpUnsupported", code, msg)
	}
}

// writableSyncFS is a driver with positional files AND a filesystem-level Sync:
// the handle's own Sync is the one used, and the filesystem's is not.
type writableSyncFS struct {
	writableFS
	syncs int
}

func (s *writableSyncFS) Sync() error { s.syncs++; return nil }

func TestFsyncUsesTheHandlesOwnSync(t *testing.T) {
	fs := &writableSyncFS{writableFS: writableFS{fixture()}}
	c := dial(t, fs, ReadWrite())
	h := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	if code, msg := c.fsync(h); code != wire.StatusOK {
		t.Fatalf("fsync on a writable handle: %v %q", code, msg)
	}
	if fs.syncs != 0 {
		t.Errorf("the filesystem was synced %d times; the handle's own Sync serves a WritableFile", fs.syncs)
	}
}
