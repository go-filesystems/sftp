// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp/wire"
)

// limits@openssh.com is answered with the four numbers PROTOCOL §4.8 names.
func TestLimitsAreAnswered(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		opts                       []Option
		packet, read, write, handl uint64
	}{
		{"default", nil, wire.MaxPacket, maxReadLength, maxReadLength, maxOpenHandles},
		{"a small packet limit", []Option{WithMaxPacket(1024)}, 1024, 1024, 1024 - writeOverhead, maxOpenHandles},
	} {
		c := dial(t, fixture(), tc.opts...)
		typ, payload := c.do(wire.ExtendedRequest{ID: c.next(), Name: "limits@openssh.com"})
		if typ != wire.FxpExtendedReply {
			t.Fatalf("%s: reply type %d, want SSH_FXP_EXTENDED_REPLY", tc.name, typ)
		}
		r, err := wire.DecodeExtendedReply(payload)
		if err != nil || len(r.Data) != 32 {
			t.Fatalf("%s: %d bytes of limits, %v", tc.name, len(r.Data), err)
		}
		got := [4]uint64{}
		for i := range got {
			got[i] = binary.BigEndian.Uint64(r.Data[8*i:])
		}
		if want := [4]uint64{tc.packet, tc.read, tc.write, tc.handl}; got != want {
			t.Errorf("%s: limits %v, want %v", tc.name, got, want)
		}
	}
	if maxReadLength+13 > 256<<10 {
		t.Errorf("a %d-byte DATA reply is over OpenSSH's 256 KiB message limit", maxReadLength+13)
	}
}

// A READ asking for everything gets at most maxReadLength, so its reply
// stays under the 256 KiB an OpenSSH client accepts.
func TestAReadStaysUnderOpenSSHsMessageLimit(t *testing.T) {
	m := fixture()
	m.addFile("/big.bin", bytes.Repeat([]byte{7}, 300<<10), 0o100644)
	c := dial(t, openerFS{m})
	h := c.open("/big.bin", wire.FxfRead)
	typ, payload := c.do(wire.ReadRequest{ID: c.next(), Handle: h, Offset: 0, Length: 1 << 30})
	if typ != wire.FxpData {
		t.Fatalf("reply type %d, want SSH_FXP_DATA", typ)
	}
	if d, _ := wire.DecodeData(payload); len(d.Data) != maxReadLength {
		t.Fatalf("read returned %d bytes, want %d", len(d.Data), maxReadLength)
	}
	c.closeHandle(h)
}

// A WRITE of the advertised length fits the packet limit.
func TestAWriteOfTheAdvertisedLengthFits(t *testing.T) {
	c := dial(t, writableFS{fixture()}, ReadWrite(), WithMaxPacket(4096))
	h := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	n := (&Server{maxPacket: 4096}).writeLength()
	typ, payload := c.do(wire.WriteRequest{ID: c.next(), Handle: h, Offset: 0, Data: bytes.Repeat([]byte{1}, n)})
	if st, _ := wire.DecodeStatus(payload); typ != wire.FxpStatus || st.Code != wire.StatusOK {
		t.Fatalf("a %d-byte write under a 4096-byte packet limit: %v (%q)", n, st.Code, st.Message)
	}
	c.closeHandle(h)
}

// countingFS counts what its driver opens.
type countingFS struct {
	openerFS
	opens *atomic.Int64
}

func (c countingFS) OpenFile(path string) (filesystem.File, error) {
	c.opens.Add(1)
	return c.openerFS.OpenFile(path)
}

// A session holds at most maxOpenHandles, and the one refused is refused
// before the driver opens anything: on a host directory, a descriptor.
func TestOpenHandlesAreBounded(t *testing.T) {
	var opens atomic.Int64
	c := dial(t, countingFS{openerFS{fixture()}, &opens})
	var hs []string
	for range maxOpenHandles - 1 {
		hs = append(hs, c.open("/sub/data.bin", wire.FxfRead))
	}
	hs = append(hs, c.opendir("/sub"))
	before := opens.Load()
	for _, req := range []wire.Message{
		wire.OpenRequest{ID: c.next(), Path: "/sub/data.bin", PFlags: wire.FxfRead},
		wire.PathRequest{PacketType: wire.FxpOpendir, ID: c.next(), Path: "/sub"},
	} {
		typ, payload := c.do(req)
		st, _ := wire.DecodeStatus(payload)
		if typ != wire.FxpStatus || st.Code != wire.StatusFailure || st.Message != errTooManyHandles.Error() {
			t.Fatalf("open %d: type %d, %v (%q); want FAILURE, too many open handles", maxOpenHandles+1, typ, st.Code, st.Message)
		}
	}
	if opens.Load() != before {
		t.Fatalf("the refused open still opened %d file(s) in the driver", opens.Load()-before)
	}
	c.closeHandle(hs[0])
	c.closeHandle(c.open("/sub/data.bin", wire.FxfRead))
}
