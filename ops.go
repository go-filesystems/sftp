package sftp

import (
	"errors"
	"io"
	"os"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// readdirBatch is how many entries one SSH_FXP_READDIR reply carries.
//
// The draft leaves this to the server. Each entry costs a driver Stat — SFTP
// version 3 has no attribute-less listing, so the attributes are mandatory,
// not an optimisation a server may skip — so the batch is the unit of work
// that holds the filesystem lock. 64 keeps a reply comfortably inside one
// packet for any plausible name length while keeping the lock hold bounded on
// a directory with thousands of entries. OpenSSH's own server uses 100.
const readdirBatch = 64

// errReadOnly is the message a read-only export answers mutating requests
// with. Naming the export's mode is what tells a person the refusal is a
// configuration choice and not a broken image.
const errReadOnly = "export is read-only"

// resolve turns a client path into a cleaned absolute path inside the export.
func resolve(id uint32, p string) (string, wire.Message) {
	c, ok := clean(p)
	if !ok {
		return "", status(id, wire.StatusFailure, "invalid path")
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// opStat answers SSH_FXP_STAT and SSH_FXP_LSTAT.
//
// Both are answered identically, and the reason is a gap in the contract
// rather than a shortcut: [github.com/go-filesystems/interface.Filesystem] has
// one Stat and no lstat, so there is no way from here to ask a driver for
// "the link itself, not its target". Whether the answer describes the link or
// what it points at is therefore whatever the driver decided. Answering LSTAT
// with a fabricated symlink attribute would be worse — a client would then
// call READLINK on things that are not links.
func (s *session) opStat(m wire.PathRequest) wire.Message {
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	s.srv.lock()
	defer s.srv.unlock()
	st, err := s.srv.fsys.Stat(path)
	if err != nil {
		return status(m.ID, statusFor(err, wire.StatusNoSuchFile), errText(err))
	}
	if st == nil {
		// A driver returning (nil, nil) is a bug, but it is THIS process
		// that would take the nil dereference, in a per-session goroutine
		// with no recover — one bad driver would end every other tenant's
		// session in the same process. It is answered as a failure instead.
		return status(m.ID, wire.StatusFailure, "driver returned no stat")
	}
	return wire.AttrsReply{ID: m.ID, Attrs: s.srv.attrsFromStat(st)}
}

// opFstat answers SSH_FXP_FSTAT: the same question against an open handle.
func (s *session) opFstat(m wire.HandleRequest) wire.Message {
	h, ok := s.handles.get(m.Handle)
	if !ok {
		return status(m.ID, wire.StatusFailure, "unknown handle")
	}
	return s.opStat(wire.PathRequest{ID: m.ID, Path: h.path})
}

// opSetstat applies SSH_FXP_SETSTAT and SSH_FXP_FSETSTAT.
//
// Attributes the driver cannot set are IGNORED rather than refused, with one
// exception: size. Silently ignoring a truncate would let a client believe a
// file is empty when it is not, which is data loss in the direction that
// matters. Ignoring an unsettable mode or timestamp merely means the client's
// next STAT shows the old value, which it can see for itself — and refusing
// those instead would break every `sftp put`, since OpenSSH's client sets
// permissions and times after every upload and treats a refusal as a failed
// transfer.
func (s *session) opSetstat(id uint32, path string, a wire.Attributes) wire.Message {
	if s.srv.ro {
		return status(id, wire.StatusPermissionDenied, errReadOnly)
	}
	s.srv.lock()
	defer s.srv.unlock()

	if a.Flags&wire.AttrSize != 0 {
		t, ok := s.srv.fsys.(filesystem.Truncater)
		if !ok {
			return status(id, wire.StatusOpUnsupported, "driver cannot truncate")
		}
		if err := t.Truncate(path, int64(a.Size)); err != nil {
			return status(id, statusFor(err, wire.StatusFailure), errText(err))
		}
	}

	ms, ok := s.srv.fsys.(filesystem.MetadataSetter)
	if !ok {
		return status(id, wire.StatusOK, "")
	}
	if a.Flags&wire.AttrPermissions != 0 {
		// Only the permission bits are settable; the type bits in the same
		// field describe what the object IS and are not a client's to change.
		if err := ms.Chmod(path, os.FileMode(a.Permissions&wire.ModePerm)); err != nil {
			return status(id, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	if a.Flags&wire.AttrUIDGID != 0 {
		if err := ms.Chown(path, a.UID, a.GID); err != nil {
			return status(id, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	if a.Flags&wire.AttrACModTime != 0 {
		if err := ms.Chtimes(path, unixTime(a.Atime), unixTime(a.Mtime)); err != nil {
			return status(id, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	return status(id, wire.StatusOK, "")
}

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

// opOpendir answers SSH_FXP_OPENDIR.
//
// The listing is taken here, once, and paged out by READDIR. The contract has
// no streaming ListDir, so there is no alternative — and the snapshot is what
// a client wants anyway: a directory mutating underneath a paginated read is
// how entries come to be listed twice or skipped.
func (s *session) opOpendir(m wire.PathRequest) wire.Message {
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	s.srv.lock()
	defer s.srv.unlock()

	// Establishing the type explicitly, rather than inferring it from
	// whatever error ListDir returns on a regular file, is what keeps the
	// substring table in errors.go a last resort instead of the mechanism.
	st, err := s.srv.fsys.Stat(path)
	if err != nil {
		return status(m.ID, statusFor(err, wire.StatusNoSuchFile), errText(err))
	}
	if st == nil {
		return status(m.ID, wire.StatusFailure, "driver returned no stat")
	}
	if uint32(st.Mode())&wire.ModeFmt != wire.ModeDir {
		return status(m.ID, wire.StatusFailure, "not a directory")
	}
	entries, err := s.srv.fsys.ListDir(path)
	if err != nil {
		return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
	}
	tok, err := s.handles.add(&openFile{path: path, dir: true, entries: entries})
	if err != nil {
		return status(m.ID, wire.StatusFailure, errText(err))
	}
	return wire.HandleReply{ID: m.ID, Handle: tok}
}

// opReaddir answers SSH_FXP_READDIR with the next batch, or SSH_FX_EOF when
// the snapshot is exhausted. EOF is not an error here: it is the only way the
// client's loop terminates.
func (s *session) opReaddir(m wire.HandleRequest) wire.Message {
	h, ok := s.handles.get(m.Handle)
	if !ok {
		return status(m.ID, wire.StatusFailure, "unknown handle")
	}
	if !h.dir {
		return status(m.ID, wire.StatusFailure, "handle is not a directory")
	}
	if h.pos >= len(h.entries) {
		return status(m.ID, wire.StatusEOF, "")
	}
	end := min(h.pos+readdirBatch, len(h.entries))
	batch := h.entries[h.pos:end]
	h.pos = end

	s.srv.lock()
	defer s.srv.unlock()
	items := make([]wire.NameItem, 0, len(batch))
	for _, e := range batch {
		name := e.Name()
		full, ok := join(h.path, name)
		if !ok {
			// "." and ".." are synthesised by the client, and a driver
			// reporting a name with a slash in it would produce a path
			// that does not resolve back to the entry. Skipping is the
			// only honest answer: listing it would name something else.
			continue
		}
		st, err := s.srv.fsys.Stat(full)
		if err != nil || st == nil {
			// An entry that vanished between ListDir and Stat, or one the
			// driver cannot stat, is skipped rather than reported with
			// invented attributes. A client seeing a name with a fabricated
			// size will act on the size.
			continue
		}
		a := s.srv.attrsFromStat(st)
		items = append(items, wire.NameItem{
			Filename: name,
			Longname: longName(name, a),
			Attrs:    a,
		})
	}
	if len(items) == 0 {
		// Every entry in this batch was unusable. Returning an empty NAME
		// would end some clients' loops early, so recurse onto the next
		// batch; h.pos has already advanced, so this terminates.
		return s.opReaddir(m)
	}
	return wire.NameReply{ID: m.ID, Items: items}
}

// opRealpath answers SSH_FXP_REALPATH.
//
// This is the first request an OpenSSH client sends (for "."), and its answer
// establishes where the session starts. The canonical form is produced by the
// same [clean] that guards every other path, so the containment property and
// the answer the user sees are the same computation — they cannot drift apart.
//
// Symbolic links are NOT resolved. Version 3 says a server should canonicalise
// them, but the contract offers only ReadLink, and following links from here
// would mean writing a resolver — with its own loop detection and its own
// containment argument — that duplicates what each driver already does
// internally. A client that needs the target asks READLINK.
func (s *session) opRealpath(m wire.PathRequest) wire.Message {
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	return wire.NameReply{ID: m.ID, Items: []wire.NameItem{{
		Filename: path,
		Longname: path,
	}}}
}

// opMkdir answers SSH_FXP_MKDIR.
func (s *session) opMkdir(m wire.SetstatRequest) wire.Message {
	if s.srv.ro {
		return status(m.ID, wire.StatusPermissionDenied, errReadOnly)
	}
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	perm := os.FileMode(0o755)
	if m.Attrs.Flags&wire.AttrPermissions != 0 {
		perm = os.FileMode(m.Attrs.Permissions & wire.ModePerm)
	}
	s.srv.lock()
	defer s.srv.unlock()
	if err := s.srv.fsys.MkDir(path, perm); err != nil {
		return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
	}
	return status(m.ID, wire.StatusOK, "")
}

// opRemove answers SSH_FXP_REMOVE and SSH_FXP_RMDIR, which differ only in
// which driver call they make — and the distinction is real: deleting a
// directory with the file call, or vice versa, is exactly the confusion the
// two request numbers exist to prevent.
func (s *session) opRemove(m wire.PathRequest) wire.Message {
	if s.srv.ro {
		return status(m.ID, wire.StatusPermissionDenied, errReadOnly)
	}
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	s.srv.lock()
	defer s.srv.unlock()
	var err error
	if m.PacketType == wire.FxpRmdir {
		err = s.srv.fsys.DeleteDir(path)
	} else {
		err = s.srv.fsys.DeleteFile(path)
	}
	if err != nil {
		return status(m.ID, statusFor(err, wire.StatusNoSuchFile), errText(err))
	}
	return status(m.ID, wire.StatusOK, "")
}

// opRename answers SSH_FXP_RENAME.
//
// Version 3 does not say whether an existing destination is replaced, and
// implementations disagree; this one passes the question to the driver rather
// than deciding it, because the driver is where the answer can be atomic.
func (s *session) opRename(m wire.RenameRequest) wire.Message {
	if s.srv.ro {
		return status(m.ID, wire.StatusPermissionDenied, errReadOnly)
	}
	oldPath, bad := resolve(m.ID, m.OldPath)
	if bad != nil {
		return bad
	}
	newPath, bad := resolve(m.ID, m.NewPath)
	if bad != nil {
		return bad
	}
	s.srv.lock()
	defer s.srv.unlock()
	if err := s.srv.fsys.Rename(oldPath, newPath); err != nil {
		return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
	}
	return status(m.ID, wire.StatusOK, "")
}

// opReadlink answers SSH_FXP_READLINK.
//
// The target is returned exactly as the driver stored it, absolute or
// relative, without being resolved or rewritten. Rewriting it would be a lie
// about what the image contains, and the client resolving it does so against
// this same export, where [clean] clamps it.
func (s *session) opReadlink(m wire.PathRequest) wire.Message {
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	s.srv.lock()
	defer s.srv.unlock()
	target, err := s.srv.fsys.ReadLink(path)
	if err != nil {
		return status(m.ID, statusFor(err, wire.StatusNoSuchFile), errText(err))
	}
	return wire.NameReply{ID: m.ID, Items: []wire.NameItem{{
		Filename: target,
		Longname: target,
	}}}
}

// opSymlink answers SSH_FXP_SYMLINK.
//
// The target is NOT cleaned. A symlink target is data — the literal string
// the image will store — not a path this server is about to resolve, and
// normalising it would silently change what the user asked for. Containment
// is unaffected: whatever the target says, resolving it later goes through
// [clean] like every other path, and the driver resolves it inside the image.
func (s *session) opSymlink(m wire.SymlinkRequest) wire.Message {
	if s.srv.ro {
		return status(m.ID, wire.StatusPermissionDenied, errReadOnly)
	}
	linkPath, bad := resolve(m.ID, m.LinkPath)
	if bad != nil {
		return bad
	}
	sl, ok := s.srv.fsys.(filesystem.Symlinker)
	if !ok {
		return status(m.ID, wire.StatusOpUnsupported, "driver cannot create symlinks")
	}
	s.srv.lock()
	defer s.srv.unlock()
	if err := sl.Symlink(m.TargetPath, linkPath); err != nil {
		return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
	}
	return status(m.ID, wire.StatusOK, "")
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

// wantsWrite reports whether an OPEN's pflags ask for any mutation.
func wantsWrite(pflags uint32) bool {
	return pflags&(wire.FxfWrite|wire.FxfAppend|wire.FxfCreat|wire.FxfTrunc|wire.FxfExcl) != 0
}

// opOpen answers SSH_FXP_OPEN.
func (s *session) opOpen(m wire.OpenRequest) wire.Message {
	path, bad := resolve(m.ID, m.Path)
	if bad != nil {
		return bad
	}
	write := wantsWrite(m.PFlags)
	if write && s.srv.ro {
		return status(m.ID, wire.StatusPermissionDenied, errReadOnly)
	}

	s.srv.lock()
	defer s.srv.unlock()

	st, statErr := s.srv.fsys.Stat(path)
	exists := statErr == nil && st != nil
	if exists && uint32(st.Mode())&wire.ModeFmt == wire.ModeDir {
		// OPEN on a directory must fail, and must fail HERE: a client that
		// gets a handle back will read from it, and answering those reads
		// with the directory's raw on-disk bytes would hand out filesystem
		// metadata as file content.
		return status(m.ID, wire.StatusFailure, "is a directory")
	}

	if !write {
		if !exists {
			return status(m.ID, statusFor(statErr, wire.StatusNoSuchFile), errText(statErr))
		}
		return s.finishOpen(m.ID, path, false)
	}

	perm := os.FileMode(0o644)
	if m.Attrs.Flags&wire.AttrPermissions != 0 {
		perm = os.FileMode(m.Attrs.Permissions & wire.ModePerm)
	}
	switch {
	case exists && m.PFlags&wire.FxfExcl != 0:
		return status(m.ID, wire.StatusFailure, "file already exists")
	case !exists && m.PFlags&wire.FxfCreat == 0:
		return status(m.ID, statusFor(statErr, wire.StatusNoSuchFile), errText(statErr))
	case !exists, m.PFlags&wire.FxfTrunc != 0:
		// Creating and truncating are the same driver call: WriteFile with
		// no data. The contract has no create-without-write, so an
		// exclusive create is not atomic against a concurrent one — the
		// check above and this call are two steps. Nothing in the contract
		// can make it one, and pretending otherwise would be worse than
		// saying so.
		if err := s.srv.fsys.WriteFile(path, nil, perm); err != nil {
			return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	return s.finishOpen(m.ID, path, true)
}

// finishOpen registers a handle, wiring up the driver's random-access
// capabilities when it has them.
//
// The caller must hold the filesystem lock.
func (s *session) finishOpen(id uint32, path string, write bool) wire.Message {
	h := &openFile{path: path, write: write}

	if s.srv.opener != nil {
		f, err := s.srv.opener.OpenFile(path)
		if err != nil {
			return status(id, statusFor(err, wire.StatusFailure), errText(err))
		}
		if f == nil {
			// A driver returning (nil, nil) from OpenFile is a bug that
			// would otherwise become a nil dereference on the first READ.
			return status(id, wire.StatusFailure, "driver returned no file")
		}
		wf, writable := f.(WritableFile)
		switch {
		case !write:
			h.file = f
		case writable:
			h.file, h.writable = f, wf
		default:
			// Opened for writing, but the driver's File cannot write at an
			// offset. Keeping it open for the read side and doing writes
			// through WriteFile would be actively wrong, not merely slow:
			// interface.File is documented as a SNAPSHOT with a fixed size,
			// so after the first read-modify-write it would serve stale
			// bytes and a stale length. Close it and use the path for both.
			if err := f.Close(); err != nil {
				return status(id, statusFor(err, wire.StatusFailure), errText(err))
			}
		}
	}

	tok, err := s.handles.add(h)
	if err != nil {
		if h.file != nil {
			h.file.Close()
		}
		return status(id, wire.StatusFailure, errText(err))
	}
	return wire.HandleReply{ID: id, Handle: tok}
}

// opClose answers SSH_FXP_CLOSE.
//
// Sync is called here for a writable handle because version 3 has no fsync of
// its own: CLOSE is the last moment at which a driver's buffering failure can
// still be reported to the client, rather than discovered by whoever opens
// the image next.
func (s *session) opClose(m wire.HandleRequest) wire.Message {
	h, ok := s.handles.remove(m.Handle)
	if !ok {
		return status(m.ID, wire.StatusFailure, "unknown handle")
	}
	s.srv.lock()
	defer s.srv.unlock()
	if h.writable != nil {
		if err := h.writable.Sync(); err != nil {
			h.file.Close()
			return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	if h.file != nil {
		if err := h.file.Close(); err != nil {
			return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
		}
	}
	return status(m.ID, wire.StatusOK, "")
}

// opRead answers SSH_FXP_READ.
func (s *session) opRead(m wire.ReadRequest) wire.Message {
	h, ok := s.handles.get(m.Handle)
	if !ok {
		return status(m.ID, wire.StatusFailure, "unknown handle")
	}
	if h.dir {
		return status(m.ID, wire.StatusFailure, "handle is a directory")
	}
	if m.Length == 0 {
		return wire.DataReply{ID: m.ID, Data: nil}
	}
	// The length is a uint32 straight off the wire and is about to size a
	// buffer, so it is clamped to what this server would ever agree to
	// send. A client asking for more gets a short read, which io.ReaderAt's
	// contract and every SFTP client both handle.
	n := min(int(m.Length), s.srv.packetLimit())

	s.srv.lock()
	defer s.srv.unlock()

	if h.file != nil {
		return s.readAt(m.ID, h.file, m.Offset, n)
	}
	return s.readWhole(m.ID, h.path, m.Offset, n)
}

// readAt serves a READ from an open [github.com/go-filesystems/interface.File].
// This is the path SSH_FXP_READ was made for: one ReadAt, no more bytes
// touched than were asked for.
func (s *session) readAt(id uint32, f filesystem.File, off uint64, n int) wire.Message {
	if off >= uint64(f.Size()) {
		return status(id, wire.StatusEOF, "")
	}
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, int64(off))
	if got > 0 {
		// io.ReaderAt may return data together with io.EOF. Sending the
		// data and letting the NEXT read report EOF is what every client
		// expects; reporting EOF now would drop the last bytes of the file.
		return wire.DataReply{ID: id, Data: buf[:got]}
	}
	if err == nil || errors.Is(err, io.EOF) {
		return status(id, wire.StatusEOF, "")
	}
	return status(id, statusFor(err, wire.StatusFailure), errText(err))
}

// readWhole serves a READ from a driver with no Opener, by reading the entire
// file and slicing it.
//
// This is the fallback for a driver with no Opener. It costs one full-file
// read PER REQUEST: an OpenSSH client reads in 32 KiB chunks, so fetching an
// n-byte file reads n²/32768 bytes in total. The README measures it.
//
// fat32 v0.3.0 implements Opener, so the fleet's reference driver takes the
// linear path above; formats that cannot answer a byte range without decoding
// everything before it (whole-file compression) land here and should.
//
// Reading the file once at OPEN and serving from that copy would make it
// linear, and is deliberately not done: it converts a time cost into a
// resident-memory cost of the whole file, in a server designed to run once
// per tenant on one machine. The fix is a driver implementing Opener.
func (s *session) readWhole(id uint32, path string, off uint64, n int) wire.Message {
	data, err := s.srv.fsys.ReadFile(path)
	if err != nil {
		return status(id, statusFor(err, wire.StatusFailure), errText(err))
	}
	if off >= uint64(len(data)) {
		return status(id, wire.StatusEOF, "")
	}
	end := min(off+uint64(n), uint64(len(data)))
	return wire.DataReply{ID: id, Data: data[off:end]}
}

// opWrite answers SSH_FXP_WRITE.
func (s *session) opWrite(m wire.WriteRequest) wire.Message {
	h, ok := s.handles.get(m.Handle)
	if !ok {
		return status(m.ID, wire.StatusFailure, "unknown handle")
	}
	if h.dir {
		return status(m.ID, wire.StatusFailure, "handle is a directory")
	}
	if s.srv.ro {
		return status(m.ID, wire.StatusPermissionDenied, errReadOnly)
	}
	if !h.write {
		// The handle was opened read-only. Refusing here rather than
		// writing is the whole value of recording the open mode: a client
		// that opened for reading and then wrote has a bug, and performing
		// the write would hide it inside someone's image.
		return status(m.ID, wire.StatusPermissionDenied, "handle not opened for writing")
	}

	s.srv.lock()
	defer s.srv.unlock()

	if h.writable != nil {
		if _, err := h.writable.WriteAt(m.Data, int64(m.Offset)); err != nil {
			return status(m.ID, statusFor(err, wire.StatusFailure), errText(err))
		}
		return status(m.ID, wire.StatusOK, "")
	}
	return s.writeSplice(m.ID, h.path, m.Offset, m.Data)
}

// writeSplice performs a write at an offset on a driver that has no
// [WritableFile]: read the whole file, splice, write the whole file back.
//
// This is the wall. It is O(filesize) per request, so a client streaming a
// file in fixed-size chunks makes it O(filesize²) overall, and the constant is
// a real disk. [github.com/go-filesystems/nfs] measured the identical
// construction at 90 kB/s; the README has this module's number.
//
// It is not hidden behind a write-back cache, and that is a deliberate
// refusal rather than an omission. Buffering the writes and flushing on CLOSE
// would make the benchmark look fine while changing what "the server
// acknowledged this write" means: an acknowledged write that is still only in
// this process's memory is a durability claim the server cannot honour if it
// dies. The slow, honest version keeps the pressure where the fix belongs —
// on [WritableFile] in the drivers.
func (s *session) writeSplice(id uint32, path string, off uint64, data []byte) wire.Message {
	old, err := s.srv.fsys.ReadFile(path)
	if err != nil {
		return status(id, statusFor(err, wire.StatusFailure), errText(err))
	}
	end := off + uint64(len(data))
	if end > uint64(maxFileSplice) {
		// The offset is a uint64 from the wire and this is about to size a
		// buffer with it. A client writing one byte at offset 2^63 would
		// otherwise ask the server to materialise eight exabytes.
		return status(id, wire.StatusFailure, "write beyond the maximum supported file size")
	}
	buf := old
	if end > uint64(len(old)) {
		// Growing: the gap between the old end and the new offset is a
		// hole, and it is zero-filled because make() zeroes. A client
		// writing chunks out of order relies on that.
		buf = make([]byte, end)
		copy(buf, old)
	}
	copy(buf[off:], data)
	if err := s.srv.fsys.WriteFile(path, buf, 0o644); err != nil {
		return status(id, statusFor(err, wire.StatusFailure), errText(err))
	}
	return status(id, wire.StatusOK, "")
}

// maxFileSplice bounds what the read-modify-write path will materialise in
// memory. It is generous — larger than any image the fleet's drivers open —
// and exists only to make a hostile offset a refusal rather than an
// allocation failure.
const maxFileSplice = 1 << 40
