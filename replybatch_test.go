// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"testing"

	"github.com/go-filesystems/sftp/wire"
)

func TestReplyBatchOption(t *testing.T) {
	for _, c := range []struct {
		opt  int
		want int
	}{{0, DefaultReplyBatch}, {-1, 0}, {-100, 0}, {4096, 4096}} {
		s := &Server{}
		WithReplyBatch(c.opt)(s)
		if got := s.replyBatchBytes(); got != c.want {
			t.Errorf("WithReplyBatch(%d) -> %d, want %d", c.opt, got, c.want)
		}
	}
}

// Whatever the batch bound, pipelined READs come back complete, intact and in
// request order: a batch is only a different way to write the same bytes.
func TestPipelinedReadsAreTheSameWithAndWithoutBatching(t *testing.T) {
	data := make([]byte, 40*(32<<10)+123)
	for i := range data {
		data[i] = byte(i * 7)
	}
	for name, opt := range map[string]Option{
		"default": WithReplyBatch(0),
		"tiny":    WithReplyBatch(1),
		"small":   WithReplyBatch(100 << 10),
		"off":     WithReplyBatch(-1),
	} {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			m.addFile("/f", data, 0o100644)
			c := dial(t, openerFS{m}, opt)
			h := c.open("/f", wire.FxfRead)
			const chunk = 32 << 10
			n := (len(data) + chunk - 1) / chunk
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				for i := range n {
					c.send(wire.ReadRequest{ID: uint32(1000 + i), Handle: h, Offset: uint64(i * chunk), Length: chunk})
				}
			}()
			var got []byte
			for i := range n {
				typ, p := c.recv()
				d, err := wire.DecodeData(p)
				if typ != wire.FxpData || err != nil || d.ID != uint32(1000+i) {
					t.Fatalf("reply %d: type %d id %d err %v", i, typ, d.ID, err)
				}
				got = append(got, d.Data...)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("read back %d bytes, differing from the %d written", len(got), len(data))
			}
			<-sent
			c.closeHandle(h)
		})
	}
}
