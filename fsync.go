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

// syncs reports whether fsync@openssh.com is offered: on a writable export whose
// driver can be synced as a whole. A driver whose files have a Sync of their
// own (WritableFile) is already synced by CLOSE and needs nothing advertised.
func (s *Server) syncs() bool {
	_, ok := s.fsys.(volumeSyncer)
	return ok && !s.ro
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
		serr = s.srv.fsys.(volumeSyncer).Sync()
	}
	if serr != nil {
		return status(id, statusFor(serr, wire.StatusFailure), errText(serr))
	}
	return status(id, wire.StatusOK, "")
}
