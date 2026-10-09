// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	filesystem "github.com/go-filesystems/interface"

	"github.com/go-filesystems/hostcopy"
	"github.com/go-filesystems/sftp/wire"
)

// copyDataExtension is server-side copy (draft-ietf-secsh-filexfer-
// extensions-00 §7; OpenSSH PROTOCOL §4.10), what OpenSSH 9.0's sftp sends
// for its "cp" command: from one open handle into another, without the bytes
// crossing the network twice.
const copyDataExtension = "copy-data"

// copiesData reports whether copy-data is offered: it copies between files
// the driver opens, into a writable export.
func (s *Server) copiesData() bool {
	_, ok := s.fsys.(filesystem.Opener)
	return ok && !s.ro
}

// extensions is what VERSION advertises: only what is answered.
func (s *Server) extensions() []wire.ExtendedPair {
	ext := []wire.ExtendedPair{{Type: limitsExtension, Data: "1"}}
	if s.copiesData() {
		ext = append(ext, wire.ExtendedPair{Type: copyDataExtension, Data: "1"})
	}
	return ext
}

// copyData answers copy-data:
//
//	string read-from-handle, uint64 read-from-offset, uint64 read-data-length,
//	string write-to-handle, uint64 write-to-offset
//
// with a status. A length of 0 copies to the end of the source. The copy is
// go-filesystems/hostcopy's: a megabyte at a time, or copy_file_range(2) in
// the kernel between two files of the host, which shares blocks on btrfs and
// XFS.
func (s *session) copyData(id uint32, data []byte) wire.Message {
	d := wire.NewDecoder(data)
	from, err1 := d.String()
	fromOff, err2 := d.Uint64()
	length, err3 := d.Uint64()
	to, err4 := d.String()
	toOff, err5 := d.Uint64()
	for _, err := range []error{err1, err2, err3, err4, err5} {
		if err != nil {
			return status(id, wire.StatusBadMessage, "copy-data: "+err.Error())
		}
	}
	if !s.srv.copiesData() {
		return status(id, wire.StatusOpUnsupported, "unsupported extension: "+copyDataExtension)
	}
	src, ok := s.handles.get(from)
	dst, ok2 := s.handles.get(to)
	if !ok || !ok2 {
		return status(id, wire.StatusFailure, "unknown handle")
	}
	if src.dir || dst.dir {
		return status(id, wire.StatusFailure, "handle is a directory")
	}
	// One file read and written at once is refused, as OpenSSH does for the
	// same handle and, since 10.4, the same inode: an overlapping copy
	// within a file overwrites what it has yet to read.
	if src.path == dst.path {
		return status(id, wire.StatusFailure, "copy-data within one file")
	}
	if !dst.write {
		return status(id, wire.StatusPermissionDenied, "write-to handle was not opened for writing")
	}
	if src.file == nil || dst.writable == nil {
		return status(id, wire.StatusOpUnsupported, "copy-data needs files the driver opens and writes in place")
	}
	if fromOff > 1<<62 || length > 1<<62 || toOff > 1<<62 {
		return status(id, wire.StatusFailure, "copy-data: offset or length out of range")
	}

	s.srv.lock()
	defer s.srv.unlock()
	n := int64(length)
	if size := src.file.Size(); length == 0 || int64(fromOff)+n > size {
		n = max(size-int64(fromOff), 0)
	}
	// The destination's final length first: a driver whose WriteAt cannot
	// extend a file grows it only through Truncate.
	if end := int64(toOff) + n; end > dst.writable.Size() {
		if err := dst.writable.Truncate(end); err != nil {
			return status(id, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	if _, err := hostcopy.Range(dst.writable, src.file, int64(toOff), int64(fromOff), n); err != nil {
		return status(id, statusFor(err, wire.StatusFailure), errText(err))
	}
	return status(id, wire.StatusOK, "")
}
