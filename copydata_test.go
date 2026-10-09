// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-filesystems/sftp/wire"
)

// copyRequest encodes a copy-data request's body.
func copyRequest(from string, fromOff, length uint64, to string, toOff uint64) []byte {
	e := wire.NewEncoder(nil)
	e.String(from)
	e.Uint64(fromOff)
	e.Uint64(length)
	e.String(to)
	e.Uint64(toOff)
	return e.Bytes()
}

func (c *client) copyData(body []byte) (wire.Status, string) {
	c.t.Helper()
	typ, payload := c.do(wire.ExtendedRequest{ID: c.next(), Name: "copy-data", Data: body})
	if typ != wire.FxpStatus {
		c.t.Fatalf("copy-data: reply type %d, want SSH_FXP_STATUS", typ)
	}
	st, _ := wire.DecodeStatus(payload)
	return st.Code, st.Message
}

func versionExtensions(t *testing.T, c *client) []string {
	t.Helper()
	var names []string
	for _, e := range c.version.Extensions {
		names = append(names, e.Type)
	}
	return names
}

// copy-data is advertised where it can copy: a writable export whose driver
// opens files.
func TestCopyDataIsAdvertisedWhereItCanCopy(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    *client
		want int
	}{
		{"read-only", dial(t, writableFS{fixture()}), 1},
		{"no Opener", dial(t, fixture(), ReadWrite()), 1},
		{"writable, Opener", dial(t, writableFS{fixture()}, ReadWrite()), 2},
	} {
		if got := versionExtensions(t, tc.c); len(got) != tc.want || got[0] != "limits@openssh.com" || (tc.want == 2 && got[1] != "copy-data") {
			t.Errorf("%s: extensions %v", tc.name, got)
		}
	}
}

func TestCopyDataCopies(t *testing.T) {
	m := fixture()
	src := bytes.Repeat([]byte("0123456789abcdef"), 1<<16+3)
	m.addFile("/src.bin", src, 0o100644)
	c := dial(t, writableFS{m}, ReadWrite())
	from := c.open("/src.bin", wire.FxfRead)

	// The whole file, as OpenSSH's sftp "cp" asks: 0, 0 -> 0.
	to := c.open("/dst.bin", wire.FxfWrite|wire.FxfCreat|wire.FxfTrunc)
	if code, msg := c.copyData(copyRequest(from, 0, 0, to, 0)); code != wire.StatusOK {
		t.Fatalf("whole copy: %v %q", code, msg)
	}
	if got := m.nodes["/dst.bin"].data; !bytes.Equal(got, src) {
		t.Fatalf("whole copy: %d bytes, want %d", len(got), len(src))
	}

	// A range into the middle of another file, and a length past the end.
	to2 := c.open("/part.bin", wire.FxfWrite|wire.FxfCreat|wire.FxfTrunc)
	if code, msg := c.copyData(copyRequest(from, 16, 32, to2, 4)); code != wire.StatusOK {
		t.Fatalf("range copy: %v %q", code, msg)
	}
	if got := m.nodes["/part.bin"].data; !bytes.Equal(got[4:], src[16:48]) || len(got) != 36 {
		t.Fatalf("range copy: % x", got)
	}
	if code, _ := c.copyData(copyRequest(from, uint64(len(src))-5, 1<<20, to2, 0)); code != wire.StatusOK {
		t.Fatal("a length past the end must copy to the end")
	}
	if got := m.nodes["/part.bin"].data; !bytes.Equal(got[:5], src[len(src)-5:]) {
		t.Fatalf("past-the-end copy: % x", got[:5])
	}
	c.closeHandle(from)
	c.closeHandle(to)
	c.closeHandle(to2)
}

func TestCopyDataRefusals(t *testing.T) {
	m := fixture()
	c := dial(t, writableFS{m}, ReadWrite())
	src := c.open("/sub/data.bin", wire.FxfRead)
	dst := c.open("/new.bin", wire.FxfWrite|wire.FxfCreat)
	ro := c.open("/hello.txt", wire.FxfRead)
	dir := c.opendir("/sub")
	for _, tc := range []struct {
		name string
		body []byte
		want wire.Status
	}{
		{"a short body", []byte{0, 0}, wire.StatusBadMessage},
		{"an unknown handle", copyRequest("nope", 0, 0, dst, 0), wire.StatusFailure},
		{"a directory", copyRequest(dir, 0, 0, dst, 0), wire.StatusFailure},
		{"one file both ways", copyRequest(src, 0, 0, c.open("/sub/data.bin", wire.FxfWrite), 0), wire.StatusFailure},
		{"a read-only destination", copyRequest(src, 0, 0, ro, 0), wire.StatusPermissionDenied},
		{"an absurd offset", copyRequest(src, 1<<63, 0, dst, 0), wire.StatusFailure},
	} {
		if code, msg := c.copyData(tc.body); code != tc.want {
			t.Errorf("%s: %v %q, want %v", tc.name, code, msg, tc.want)
		}
	}

	// A destination the driver cannot write in place.
	co := dial(t, openerFS{fixture()}, ReadWrite())
	s2 := co.open("/sub/data.bin", wire.FxfRead)
	d2 := co.open("/hello.txt", wire.FxfWrite)
	if code, _ := co.copyData(copyRequest(s2, 0, 0, d2, 0)); code != wire.StatusOpUnsupported {
		t.Errorf("no in-place writes: %v, want OP_UNSUPPORTED", code)
	}

	// Asked of a server that does not offer it.
	cr := dial(t, writableFS{fixture()})
	s3 := cr.open("/sub/data.bin", wire.FxfRead)
	if code, _ := cr.copyData(copyRequest(s3, 0, 0, s3, 0)); code != wire.StatusOpUnsupported {
		t.Errorf("read-only server: %v, want OP_UNSUPPORTED", code)
	}

	// Driver failures come back as statuses.
	boom := errors.New("media error")
	for _, method := range []string{"Truncate", "ReadAt"} {
		mf := fixture()
		cf := dial(t, writableFS{mf}, ReadWrite())
		s := cf.open("/sub/data.bin", wire.FxfRead)
		d := cf.open("/out.bin", wire.FxfWrite|wire.FxfCreat)
		path := "/out.bin"
		if method == "ReadAt" {
			path = "/sub/data.bin"
		}
		mf.fail = map[string]error{method + ":" + path: boom}
		if code, _ := cf.copyData(copyRequest(s, 0, 0, d, 0)); code == wire.StatusOK {
			t.Errorf("%s failing: the copy reported OK", method)
		}
	}
}
