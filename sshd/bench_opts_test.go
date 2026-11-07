// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sshd

import (
	"flag"

	"github.com/go-filesystems/sftp"
)

var benchBatch = flag.String("sftp.batch", "on", "BenchmarkGetOverSSH: \"off\" disables reply batching")

// benchOptions is what BenchmarkGetOverSSH builds its server with. This file is
// the only one that differs from the copy dropped into a clean clone of an
// earlier tag (where it returns nothing): -sftp.batch=off measures the current
// code with reply batching disabled, to separate it from the rest.
func benchOptions() []sftp.Option {
	if *benchBatch == "off" {
		return []sftp.Option{sftp.WithReplyBatch(-1)}
	}
	return nil
}
