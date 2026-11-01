package sftp

import (
	"runtime"
	"testing"

	"github.com/go-filesystems/sftp/wire"
)

func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// memFS has no WritableFile, so a WRITE goes through writeSplice, which
// materialises the whole file at its new end. Before these bounds the only
// limit was 1 TiB: one 1-byte WRITE at offset 2^39 asked make() for 512 GiB.
func TestTheWholeFileSpliceRefusesWhatAClientCannotHave(t *testing.T) {
	c := dial(t, fixture(), ReadWrite())
	h := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	write := func(off uint64, n int) (wire.Status, string) {
		typ, payload := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: off, Data: make([]byte, n)})
		st, err := wire.DecodeStatus(payload)
		if typ != wire.FxpStatus || err != nil {
			t.Fatalf("WRITE at %d: reply type %d, %v", off, typ, err)
		}
		return st.Code, st.Message
	}
	for _, off := range []uint64{1 << 39, 1 << 63, ^uint64(0)} {
		var code wire.Status
		grew := allocated(func() { code, _ = write(off, 1) })
		if code != wire.StatusFailure {
			t.Errorf("WRITE at %#x answered %d, want FAILURE", off, code)
		}
		if grew > 1<<20 {
			t.Errorf("WRITE at %#x allocated %d bytes before refusing", off, grew)
		}
	}
	// The growth bound is exact: a write ending maxSpliceGrowth past the end
	// is served, one byte further is not.
	if code, msg := write(maxSpliceGrowth-1, 1); code != wire.StatusOK {
		t.Fatalf("a write ending exactly maxSpliceGrowth past the end: %d %q", code, msg)
	}
	if code, _ := write(2*maxSpliceGrowth, 1); code != wire.StatusFailure {
		t.Fatalf("a write ending one byte past the growth bound was served: %d", code)
	}
	// Writing inside the file is never refused, however far in.
	if code, msg := write(10, 4); code != wire.StatusOK {
		t.Fatalf("an in-place write was refused: %d %q", code, msg)
	}
	c.closeHandle(h)
}

// A SETSTAT size above 2^63-1 used to reach the driver as a negative int64;
// the test driver, like a real in-memory one, panics slicing with it.
func TestASetstatSizePastInt64IsRefused(t *testing.T) {
	c := dial(t, fixture(), ReadWrite())
	h := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	c.closeHandle(h)
	typ, payload := c.do(wire.SetstatRequest{PacketType: wire.FxpSetstat, ID: c.next(), Path: "/new.bin",
		Attrs: wire.Attributes{Flags: wire.AttrSize, Size: 1 << 63}})
	st, err := wire.DecodeStatus(payload)
	if typ != wire.FxpStatus || err != nil || st.Code != wire.StatusFailure {
		t.Fatalf("SETSTAT size 2^63: type %d, %+v, %v", typ, st, err)
	}
}
