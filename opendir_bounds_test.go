package sftp

import (
	"runtime"
	"strconv"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// OPENDIR keeps the whole listing in the handle, so handles bounded only by
// count let one session hold 1024 copies of a large directory (audit
// 2026-11-22, finding 5: 256 handles of 20000 entries retained 236 MiB). The
// session now has a budget of retained entries.
func TestOpendirRetainedEntriesBounded(t *testing.T) {
	fsys := newMemFS().addDir("/d")
	const files = 20000
	for i := 0; i < files; i++ {
		fsys.addFile("/d/f"+strconv.Itoa(i), nil, 0o100644)
	}
	c := dial(t, fsys)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const n = 256
	opened := 0
	for i := 0; i < n; i++ {
		typ, _ := c.do(wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/d"})
		if typ == wire.FxpHandle {
			opened++
		}
	}
	if opened < 1 || opened > maxRetainedEntries/files+1 {
		t.Fatalf("%d OPENDIRs accepted of %d, want between 1 and %d", opened, n, maxRetainedEntries/files+1)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	const bound = 16 << 20
	if retained > bound {
		t.Fatalf("one idle session retains %d MiB in directory handles; bound %d MiB", retained>>20, bound>>20)
	}
	runtime.KeepAlive(fsys)
}

func TestHandlesDirBudget(t *testing.T) {
	h := newHandles()
	if h.dirFull(maxRetainedEntries * 4) {
		t.Fatal("the first listing must be allowed whatever its size")
	}
	big := make([]*openFile, 0, 2)
	for _, n := range []int{maxRetainedEntries / 2, maxRetainedEntries / 2} {
		f := &openFile{dir: true, entries: make([]filesystem.DirEntry, n)}
		tok, err := h.add(f)
		if err != nil {
			t.Fatal(err)
		}
		_ = tok
		big = append(big, f)
	}
	if !h.dirFull(1) {
		t.Fatal("a listing past the budget must be refused")
	}
	for tok, f := range h.m {
		if f == big[0] {
			h.remove(tok)
		}
	}
	if h.dirFull(1) {
		t.Fatal("closing a directory must give its entries back")
	}
}
