package sftp

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// memFS is an in-memory Filesystem for the tests.
//
// It exists so the server can be driven against a driver whose behaviour the
// test controls completely: which optional capabilities it has, and which
// call fails with what. Running the tests against a real image would prove
// less, not more — a real driver has exactly one set of capabilities and one
// set of errors, and the branches this server has for the others would never
// execute.
type memFS struct {
	mu    sync.Mutex
	nodes map[string]*memNode

	// fail injects an error into the named method for the named path. The
	// key is "method:path"; "method:*" matches any path.
	fail map[string]error

	// nilStat makes Stat return (nil, nil) for this path, which is the
	// driver bug the server has to survive rather than dereference.
	nilStat string

	closed bool
}

type memNode struct {
	mode   uint16
	data   []byte
	target string
	inode  uint64
}

func newMemFS() *memFS {
	m := &memFS{nodes: map[string]*memNode{}, fail: map[string]error{}}
	m.nodes["/"] = &memNode{mode: 0o040755, inode: 1}
	return m
}

// errFor returns the injected error for a call, if any.
func (m *memFS) errFor(method, path string) error {
	if e, ok := m.fail[method+":"+path]; ok {
		return e
	}
	return m.fail[method+":*"]
}

func (m *memFS) addFile(path string, data []byte, mode uint16) *memFS {
	m.nodes[path] = &memNode{mode: mode, data: data, inode: uint64(len(m.nodes) + 1)}
	return m
}

func (m *memFS) addDir(path string) *memFS {
	m.nodes[path] = &memNode{mode: 0o040755, inode: uint64(len(m.nodes) + 1)}
	return m
}

func (m *memFS) addLink(path, target string) *memFS {
	m.nodes[path] = &memNode{mode: 0o120777, target: target, inode: uint64(len(m.nodes) + 1)}
	return m
}

func (m *memFS) Close() error { m.closed = true; return m.errFor("Close", "*") }

func (m *memFS) Stat(path string) (filesystem.Stat, error) {
	if err := m.errFor("Stat", path); err != nil {
		return nil, err
	}
	if path == m.nilStat {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return filesystem.NewStat(n.mode, uint64(len(n.data)), n.inode), nil
}

func (m *memFS) ReadFile(path string) ([]byte, error) {
	if err := m.errFor("ReadFile", path); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), n.data...), nil
}

func (m *memFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := m.errFor("WriteFile", path); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.nodes[path]; ok {
		n.data = append([]byte(nil), data...)
		return nil
	}
	m.nodes[path] = &memNode{mode: 0o100000 | uint16(perm&0o7777), data: append([]byte(nil), data...), inode: uint64(len(m.nodes) + 1)}
	return nil
}

func (m *memFS) ListDir(path string) ([]filesystem.DirEntry, error) {
	if err := m.errFor("ListDir", path); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[path]; !ok {
		return nil, fs.ErrNotExist
	}
	prefix := path
	if prefix != "/" {
		prefix += "/"
	}
	var names []string
	for p := range m.nodes {
		if p == path || !strings.HasPrefix(p, prefix) {
			continue
		}
		if strings.Contains(p[len(prefix):], "/") {
			continue
		}
		names = append(names, p[len(prefix):])
	}
	sort.Strings(names)
	out := make([]filesystem.DirEntry, 0, len(names))
	for _, n := range names {
		full := prefix + n
		out = append(out, filesystem.NewDirEntry(m.nodes[full].inode, n, 0))
	}
	return out, nil
}

func (m *memFS) ReadLink(path string) (string, error) {
	if err := m.errFor("ReadLink", path); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path]
	if !ok {
		return "", fs.ErrNotExist
	}
	if n.mode&0o170000 != 0o120000 {
		return "", errors.New("not a symbolic link")
	}
	return n.target, nil
}

func (m *memFS) MkDir(path string, perm os.FileMode) error {
	if err := m.errFor("MkDir", path); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[path]; ok {
		return errors.New("already exists")
	}
	m.nodes[path] = &memNode{mode: 0o040000 | uint16(perm&0o7777), inode: uint64(len(m.nodes) + 1)}
	return nil
}

func (m *memFS) DeleteFile(path string) error {
	if err := m.errFor("DeleteFile", path); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[path]; !ok {
		return fs.ErrNotExist
	}
	delete(m.nodes, path)
	return nil
}

func (m *memFS) DeleteDir(path string) error {
	if err := m.errFor("DeleteDir", path); err != nil {
		return err
	}
	return m.DeleteFile(path)
}

func (m *memFS) Rename(oldPath, newPath string) error {
	if err := m.errFor("Rename", oldPath); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[oldPath]
	if !ok {
		return fs.ErrNotExist
	}
	delete(m.nodes, oldPath)
	m.nodes[newPath] = n
	return nil
}

// --- optional capabilities -------------------------------------------------

func (m *memFS) Symlink(target, linkPath string) error {
	if err := m.errFor("Symlink", linkPath); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[linkPath] = &memNode{mode: 0o120777, target: target, inode: uint64(len(m.nodes) + 1)}
	return nil
}

func (m *memFS) Truncate(path string, newSize int64) error {
	if err := m.errFor("Truncate", path); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path]
	if !ok {
		return fs.ErrNotExist
	}
	if int64(len(n.data)) > newSize {
		n.data = n.data[:newSize]
		return nil
	}
	n.data = append(n.data, make([]byte, newSize-int64(len(n.data)))...)
	return nil
}

// metaFS adds the MetadataSetter capability. It is separate so that a test can
// export a filesystem WITHOUT it and reach the branch where SETSTAT silently
// ignores what the driver cannot do.
type metaFS struct {
	*memFS
	chmodCalls, chownCalls, timeCalls int
}

func (m *metaFS) Chmod(path string, perm os.FileMode) error {
	if err := m.errFor("Chmod", path); err != nil {
		return err
	}
	m.chmodCalls++
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.nodes[path]; ok {
		n.mode = n.mode&0o170000 | uint16(perm&0o7777)
	}
	return nil
}

func (m *metaFS) Chown(path string, uid, gid uint32) error {
	if err := m.errFor("Chown", path); err != nil {
		return err
	}
	m.chownCalls++
	return nil
}

func (m *metaFS) Chtimes(path string, atime, mtime time.Time) error {
	if err := m.errFor("Chtimes", path); err != nil {
		return err
	}
	m.timeCalls++
	return nil
}

// --- Opener and WritableFile ----------------------------------------------

// openerFS is a memFS that implements filesystem.Opener with a read-only
// File: the capability every driver in the fleet is still missing.
type openerFS struct{ *memFS }

func (m openerFS) OpenFile(path string) (filesystem.File, error) {
	if err := m.errFor("OpenFile", path); err != nil {
		return nil, err
	}
	if path == "/nilfile" {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &memFile{fs: m.memFS, path: path, node: n}, nil
}

// writableFS returns a File that also satisfies [WritableFile]: the capability
// that removes the write wall.
type writableFS struct{ *memFS }

func (m writableFS) OpenFile(path string) (filesystem.File, error) {
	if err := m.errFor("OpenFile", path); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &memWritableFile{memFile{fs: m.memFS, path: path, node: n}}, nil
}

type memFile struct {
	fs     *memFS
	path   string
	node   *memNode
	closed bool
}

func (f *memFile) Size() int64 {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	return int64(len(f.node.data))
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	if err := f.fs.errFor("ReadAt", f.path); err != nil {
		return 0, err
	}
	if _, ok := f.fs.fail["ReadAtNil:"+f.path]; ok {
		// (0, nil): a driver that reports neither data nor a reason. The
		// server must still answer, not spin.
		return 0, nil
	}
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *memFile) Close() error {
	f.closed = true
	return f.fs.errFor("FileClose", f.path)
}

type memWritableFile struct{ memFile }

func (f *memWritableFile) WriteAt(p []byte, off int64) (int, error) {
	if err := f.fs.errFor("WriteAt", f.path); err != nil {
		return 0, err
	}
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	end := off + int64(len(p))
	if end > int64(len(f.node.data)) {
		f.node.data = append(f.node.data, make([]byte, end-int64(len(f.node.data)))...)
	}
	copy(f.node.data[off:], p)
	return len(p), nil
}

func (f *memWritableFile) Truncate(size int64) error {
	return f.fs.Truncate(f.path, size)
}

func (f *memWritableFile) Sync() error { return f.fs.errFor("Sync", f.path) }

// timeStat wraps a Stat so it also reports a modification time, which is the
// TimeStat capability no driver has yet.
type timeStat struct {
	filesystem.Stat
	mtime int64
}

func (t timeStat) ModTime() int64 { return t.mtime }

// timeFS reports real timestamps, exercising the TimeStat probe.
type timeFS struct{ *memFS }

func (m timeFS) Stat(path string) (filesystem.Stat, error) {
	st, err := m.memFS.Stat(path)
	if err != nil {
		return nil, err
	}
	return timeStat{Stat: st, mtime: 1_700_000_000}, nil
}

// bareFS implements ONLY the base Filesystem contract: no Symlinker, no
// Truncater, no MetadataSetter, no Opener.
//
// The wrapped memFS is a NAMED field rather than an embedded one, and that is
// load-bearing: embedding would promote Truncate and Symlink into bareFS's
// method set, so a type assertion for those capabilities would succeed and the
// branches that answer SSH_FX_OP_UNSUPPORTED would never run. A fixture meant
// to lack a capability has to actually lack it.
type bareFS struct{ m *memFS }

func (b bareFS) Close() error                      { return b.m.Close() }
func (b bareFS) ReadFile(p string) ([]byte, error) { return b.m.ReadFile(p) }
func (b bareFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	return b.m.ListDir(p)
}
func (b bareFS) Stat(p string) (filesystem.Stat, error) { return b.m.Stat(p) }
func (b bareFS) WriteFile(p string, d []byte, perm os.FileMode) error {
	return b.m.WriteFile(p, d, perm)
}
func (b bareFS) ReadLink(p string) (string, error)      { return b.m.ReadLink(p) }
func (b bareFS) MkDir(p string, perm os.FileMode) error { return b.m.MkDir(p, perm) }
func (b bareFS) DeleteFile(p string) error              { return b.m.DeleteFile(p) }
func (b bareFS) DeleteDir(p string) error               { return b.m.DeleteDir(p) }
func (b bareFS) Rename(o, n string) error               { return b.m.Rename(o, n) }

// compile-time proof that the fixtures really do carry the capabilities the
// tests assume, so a fixture losing one fails to build instead of quietly
// making a test assert nothing.
var (
	_ filesystem.Filesystem     = (*memFS)(nil)
	_ filesystem.Symlinker      = (*memFS)(nil)
	_ filesystem.Truncater      = (*memFS)(nil)
	_ filesystem.MetadataSetter = (*metaFS)(nil)
	_ filesystem.Opener         = openerFS{}
	_ filesystem.Opener         = writableFS{}
	_ filesystem.Filesystem     = bareFS{}
	_ WritableFile              = (*memWritableFile)(nil)
	_ TimeStat                  = timeStat{}
	_ wire.Message              = wire.StatusReply{}
)
