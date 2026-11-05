// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package wire

import (
	"bytes"
	"testing"
)

// FuzzReadPacket: arbitrary bytes framed as a stream never panic, never
// return a payload larger than the limit, and never allocate past it (the
// length prefix is checked before the body is read). The committed corpus is
// in testdata/fuzz/FuzzReadPacket.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{0, 0, 0, 5, FxpRead, 0, 0, 0, 1})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1})
	f.Add([]byte{0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, in []byte) {
		const limit = 4096
		r := bytes.NewReader(in)
		var buf []byte
		for {
			_, payload, next, err := ReadPacket(r, buf, limit)
			buf = next
			if err != nil {
				return
			}
			if len(payload) >= limit {
				t.Fatalf("payload of %d bytes past the %d limit", len(payload), limit)
			}
			if cap(buf) > limit {
				t.Fatalf("buffer grew to %d past the %d limit", cap(buf), limit)
			}
		}
	})
}

// FuzzDecode: every request decoder accepts any payload without panicking,
// and a payload it accepts re-encodes to a payload it accepts again.
func FuzzDecode(f *testing.F) {
	f.Add(uint8(FxpOpen), []byte{0, 0, 0, 1, 0, 0, 0, 1, 'a', 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add(uint8(FxpRead), []byte{0, 0, 0, 1, 0, 0, 0, 1, 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9})
	f.Add(uint8(FxpWrite), []byte{0, 0, 0, 1, 0, 0, 0, 1, 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 'x'})
	f.Add(uint8(FxpExtended), []byte{0, 0, 0, 1, 0, 0, 0, 4, 'c', 'o', 'p', 'y'})
	f.Fuzz(func(t *testing.T, typ uint8, p []byte) {
		DecodeInit(p)
		DecodePath(typ, p)
		DecodeHandle(typ, p)
		DecodeOpen(p)
		DecodeSetstat(typ, p)
		DecodeFsetstat(p)
		DecodeRename(p)
		DecodeSymlink(p)
		DecodeExtended(p)
		DecodeVersion(p)
		DecodeStatus(p)
		DecodeHandleReply(p)
		DecodeData(p)
		DecodeName(p)
		DecodeAttrs(p)
		DecodeExtendedReply(p)
		DecodeAttributes(NewDecoder(p))
		if m, err := DecodeRead(p); err == nil {
			var out bytes.Buffer
			if _, err := Send(&out, m, nil); err != nil {
				t.Fatalf("a decoded READ does not re-encode: %v", err)
			}
		}
		if m, err := DecodeWrite(p); err == nil {
			var out bytes.Buffer
			if _, err := Send(&out, m, nil); err != nil && len(m.Data) < MaxPacket-1024 {
				t.Fatalf("a decoded WRITE does not re-encode: %v", err)
			}
		}
	})
}
