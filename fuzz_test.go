// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"io"
	"testing"

	"github.com/go-filesystems/sftp/wire"
)

// FuzzSession feeds a whole session an arbitrary byte stream after a valid
// INIT, against a driver with every capability, writable, with a small
// in-flight cap so the slot and range machinery is exercised. The session
// must end (never hang, never panic) and release its handles. The committed
// corpus is in testdata/fuzz/FuzzSession.
func FuzzSession(f *testing.F) {
	pkt := func(m wire.Message) []byte {
		var b bytes.Buffer
		wire.Send(&b, m, nil)
		return b.Bytes()
	}
	f.Add(pkt(wire.PathRequest{PacketType: wire.FxpStat, ID: 1, Path: "/f"}))
	f.Add(append(pkt(wire.OpenRequest{ID: 1, Path: "/f", PFlags: wire.FxfRead | wire.FxfWrite}),
		pkt(wire.ReadRequest{ID: 2, Handle: "nope", Length: 10})...))
	f.Add(pkt(wire.WriteRequest{ID: 3, Handle: "nope", Data: []byte("x")}))
	f.Add([]byte{0, 0, 0, 9, wire.FxpExtended, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, stream []byte) {
		m := newMemFS().addFile("/f", []byte("0123456789"), 0o100644).addDir("/d")
		srv, err := New(writableFS{m}, ReadWrite(), WithMaxInFlight(4), WithMaxPacket(1<<14))
		if err != nil {
			t.Fatal(err)
		}
		var in bytes.Buffer
		wire.Send(&in, wire.InitRequest{Version: wire.Version}, nil)
		in.Write(stream)
		srv.Serve(struct {
			io.Reader
			io.Writer
		}{&in, io.Discard})
	})
}
