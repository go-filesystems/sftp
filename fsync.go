// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"github.com/go-filesystems/sftp/wire"
)

// fsyncExtension is OpenSSH's fsync@openssh.com (PROTOCOL §4.9): the client's
// fsync(2) on an open handle. The request is one string, the handle; the answer
// is a status.
const fsyncExtension = "fsync@openssh.com"

// volumeSyncer is a Filesystem that can be asked to put everything it has
// accepted on its backing store: (*hfsplus.Volume).Sync is one.
type volumeSyncer interface{ Sync() error }

// pathSyncer is a Filesystem that can sync the part of itself a path lives in:
// a tree of several volumes (fileshare's per-person tree) syncs only the one
// under the path, so one failing or slow volume does not fail or delay an fsync
// of a file on another. It is preferred over volumeSyncer, and gets the handle's
// path: the cleaned, absolute path the handle was opened with. A rename moves a
// file within its volume at most (a tree that refuses to rename across volumes
// keeps the path's volume the same), so the volume under the path is the
// handle's.
type pathSyncer interface{ SyncPath(path string) error }

// syncs reports whether fsync@openssh.com is offered: on a writable export whose
// driver can be synced, as a whole or by path. A driver whose files have a Sync of
// their own (WritableFile) is already synced by CLOSE and needs nothing
// advertised.
func (s *Server) syncs() bool {
	_, byPath := s.fsys.(pathSyncer)
	_, whole := s.fsys.(volumeSyncer)
	return (byPath || whole) && !s.ro
}

// syncFS syncs the filesystem for a handle at path: by path when the driver can,
// else as a whole. The caller has checked syncs().
func (s *Server) syncFS(path string) error {
	if p, ok := s.fsys.(pathSyncer); ok {
		return p.SyncPath(path)
	}
	return s.fsys.(volumeSyncer).Sync()
}

// fsync answers fsync@openssh.com. A handle with a WritableFile is synced
// through it; otherwise the filesystem is, so what a driver that rewrites whole
// files accepted (hfsplus at mounted or lazy durability) is on the medium before
// the client is told it is. A failure is the client's error, not a success.
func (s *session) fsync(id uint32, data []byte) wire.Message {
	handle, err := wire.NewDecoder(data).String()
	if err != nil {
		return status(id, wire.StatusBadMessage, "fsync: "+err.Error())
	}
	if !s.srv.syncs() {
		return status(id, wire.StatusOpUnsupported, "unsupported extension: "+fsyncExtension)
	}
	h, ok := s.handles.get(handle)
	if !ok {
		return status(id, wire.StatusFailure, "unknown handle")
	}
	if h.dir {
		return status(id, wire.StatusFailure, "handle is a directory")
	}
	if !h.write {
		// Nothing was written through this handle; OpenSSH answers OK too.
		return status(id, wire.StatusOK, "")
	}
	s.srv.lock()
	defer s.srv.unlock()
	var serr error
	if h.writable != nil {
		serr = h.writable.Sync()
	} else {
		serr = s.srv.syncFS(h.path)
	}
	if serr != nil {
		return status(id, statusFor(serr, wire.StatusFailure), errText(serr))
	}
	return status(id, wire.StatusOK, "")
}
