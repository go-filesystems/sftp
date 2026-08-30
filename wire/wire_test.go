package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

func TestEncoderDecoderRoundTrip(t *testing.T) {
	e := NewEncoder(nil)
	e.Byte(0x42)
	e.Uint32(0xDEADBEEF)
	e.Uint64(0x0102030405060708)
	e.Int64(-3)
	e.String("héllo")
	e.Blob([]byte{1, 2, 3})
	if e.Len() != len(e.Bytes()) {
		t.Fatalf("Len = %d, Bytes = %d", e.Len(), len(e.Bytes()))
	}

	d := NewDecoder(e.Bytes())
	if b, err := d.Byte(); err != nil || b != 0x42 {
		t.Fatalf("Byte = %v,%v", b, err)
	}
	if v, err := d.Uint32(); err != nil || v != 0xDEADBEEF {
		t.Fatalf("Uint32 = %v,%v", v, err)
	}
	if v, err := d.Uint64(); err != nil || v != 0x0102030405060708 {
		t.Fatalf("Uint64 = %v,%v", v, err)
	}
	if v, err := d.Int64(); err != nil || v != -3 {
		t.Fatalf("Int64 = %v,%v", v, err)
	}
	if s, err := d.String(); err != nil || s != "héllo" {
		t.Fatalf("String = %q,%v", s, err)
	}
	if b, err := d.Blob(); err != nil || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Fatalf("Blob = %v,%v", b, err)
	}
	if err := d.End(); err != nil {
		t.Fatalf("End = %v", err)
	}
}

func TestDecoderRefusesToRunPastTheEnd(t *testing.T) {
	empty := NewDecoder(nil)
	if _, err := empty.Byte(); !errors.Is(err, ErrShort) {
		t.Errorf("Byte on empty = %v", err)
	}
	if _, err := empty.Uint32(); !errors.Is(err, ErrShort) {
		t.Errorf("Uint32 on empty = %v", err)
	}
	if _, err := empty.Uint64(); !errors.Is(err, ErrShort) {
		t.Errorf("Uint64 on empty = %v", err)
	}
	if _, err := empty.Int64(); !errors.Is(err, ErrShort) {
		t.Errorf("Int64 on empty = %v", err)
	}
	if _, err := empty.Blob(); !errors.Is(err, ErrShort) {
		t.Errorf("Blob on empty = %v", err)
	}
	if _, err := empty.String(); !errors.Is(err, ErrShort) {
		t.Errorf("String on empty = %v", err)
	}
	// A length prefix that promises more than is there.
	short := NewDecoder([]byte{0, 0, 0, 8, 1, 2})
	if _, err := short.Blob(); !errors.Is(err, ErrShort) {
		t.Errorf("Blob with a lying prefix = %v", err)
	}
}

// TestAbsurdLengthCostsAComparisonNotMemory is the hostile-input property:
// four bytes of 0xFF must be rejected before anything is allocated.
func TestAbsurdLengthCostsAComparisonNotMemory(t *testing.T) {
	d := NewDecoder([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if _, err := d.Blob(); !errors.Is(err, ErrLimit) {
		t.Fatalf("Blob with a 4 GiB prefix = %v, want ErrLimit", err)
	}
}

func TestSetLimit(t *testing.T) {
	buf := NewEncoder(nil)
	buf.String("abcdefgh")
	d := NewDecoder(buf.Bytes())
	d.SetLimit(4)
	if _, err := d.String(); !errors.Is(err, ErrLimit) {
		t.Fatalf("String over the limit = %v", err)
	}
	d = NewDecoder(buf.Bytes())
	d.SetLimit(-1) // restores the default
	if s, err := d.String(); err != nil || s != "abcdefgh" {
		t.Fatalf("String after restoring the default = %q,%v", s, err)
	}
	if d.cap() != DefaultLimit {
		t.Fatalf("cap = %d, want DefaultLimit", d.cap())
	}
}

func TestEndReportsTrailingBytes(t *testing.T) {
	d := NewDecoder([]byte{1, 2, 3})
	if err := d.End(); !errors.Is(err, ErrTrailing) {
		t.Fatalf("End with 3 bytes left = %v", err)
	}
	if d.Remaining() != 3 {
		t.Fatalf("Remaining = %d", d.Remaining())
	}
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

func TestPacketRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	out, err := WritePacket(&buf, FxpStat, []byte("body"), nil)
	if err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("WritePacket returned no buffer to reuse")
	}
	typ, payload, next, err := ReadPacket(&buf, nil, 0)
	if err != nil || typ != FxpStat || string(payload) != "body" {
		t.Fatalf("ReadPacket = %d,%q,%v", typ, payload, err)
	}
	// The returned buffer must be reusable, and reuse must not corrupt.
	buf.Reset()
	WritePacket(&buf, FxpData, []byte("second"), out)
	typ, payload, _, err = ReadPacket(&buf, next, 0)
	if err != nil || typ != FxpData || string(payload) != "second" {
		t.Fatalf("reused ReadPacket = %d,%q,%v", typ, payload, err)
	}
}

func TestPacketFramingRefusals(t *testing.T) {
	t.Run("zero length leaves no room for the type byte", func(t *testing.T) {
		_, _, _, err := ReadPacket(bytes.NewReader([]byte{0, 0, 0, 0}), nil, 0)
		if !errors.Is(err, ErrPacketEmpty) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("over the ceiling", func(t *testing.T) {
		_, _, _, err := ReadPacket(bytes.NewReader([]byte{0, 0, 0x10, 0}), nil, 64)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("clean end of stream at a boundary is io.EOF", func(t *testing.T) {
		_, _, _, err := ReadPacket(bytes.NewReader(nil), nil, 0)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want io.EOF", err)
		}
	})
	t.Run("a stream ending inside a packet is not a clean close", func(t *testing.T) {
		// One-byte body promised, none delivered: io.ReadFull would report
		// plain io.EOF here, which a caller would read as a clean goodbye.
		_, _, _, err := ReadPacket(bytes.NewReader([]byte{0, 0, 0, 1}), nil, 0)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
		_, _, _, err = ReadPacket(bytes.NewReader([]byte{0, 0, 0, 8, 1, 2}), nil, 0)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("writing more than the ceiling", func(t *testing.T) {
		_, err := WritePacket(io.Discard, FxpData, make([]byte, MaxPacket+1), nil)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a write failure is reported", func(t *testing.T) {
		if _, err := WritePacket(errWriter{}, FxpData, []byte("x"), nil); err == nil {
			t.Fatal("a failing writer produced no error")
		}
	})
	t.Run("a header read failure is reported", func(t *testing.T) {
		if _, _, _, err := ReadPacket(errReader{}, nil, 0); err == nil {
			t.Fatal("a failing reader produced no error")
		}
	})
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestSendFramesAMessage(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Send(&buf, StatusReply{ID: 9, Code: StatusEOF}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	typ, payload, _, err := ReadPacket(&buf, nil, 0)
	if err != nil || typ != FxpStatus {
		t.Fatalf("ReadPacket = %d,%v", typ, err)
	}
	st, err := DecodeStatus(payload)
	if err != nil || st.ID != 9 || st.Code != StatusEOF {
		t.Fatalf("DecodeStatus = %+v,%v", st, err)
	}
}
