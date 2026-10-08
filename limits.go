// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"encoding/binary"
	"errors"

	"github.com/go-filesystems/sftp/wire"
)

// limitsExtension is OpenSSH's limits@openssh.com (PROTOCOL §4.8, OpenSSH
// 8.6): the client asks what the server accepts, and sizes its reads and
// writes to it. Without the answer, OpenSSH's sftp reads and writes 32 KiB
// at a time; with it, up to maxReadLength.
const limitsExtension = "limits@openssh.com"

const (
	// maxReadLength is the most one SSH_FXP_READ is answered with, and the
	// most one SSH_FXP_WRITE is expected to carry. It is OpenSSH's own
	// sftp-server value, SFTP_MAX_MSG_LENGTH less 1024: OpenSSH's client
	// refuses a message over 256 KiB, and a DATA reply is the data plus its
	// header, so a read of the whole 260 KiB this server accepts would
	// produce a reply that client drops.
	maxReadLength = 256<<10 - 1024

	// maxOpenHandles is how many files and directories one session may hold
	// open at once. A handle on a host directory is a host descriptor, and
	// without a bound one authenticated user could spend every descriptor
	// the server process has, for every other user too.
	maxOpenHandles = 1024
)

var errTooManyHandles = errors.New("too many open handles")

// readLength is what one READ is answered with at most.
func (s *Server) readLength() int { return min(maxReadLength, s.packetLimit()) }

// writeOverhead is what an SSH_FXP_WRITE carries besides its data: length,
// type, id, the handle as a string, offset, and the data's own length.
const writeOverhead = 4 + 1 + 4 + (4 + 2*handleBytes) + 8 + 4

// writeLength is the most data one WRITE can carry and still fit the
// packet limit this server enforces on what it receives.
func (s *Server) writeLength() int {
	return max(min(maxReadLength, s.packetLimit()-writeOverhead), 1)
}

// limitsReply answers limits@openssh.com: max-packet-length,
// max-read-length, max-write-length and max-open-handles, each a uint64.
func (s *session) limitsReply(id uint32) wire.Message {
	data := make([]byte, 0, 32)
	data = binary.BigEndian.AppendUint64(data, uint64(s.srv.packetLimit()))
	data = binary.BigEndian.AppendUint64(data, uint64(s.srv.readLength()))
	data = binary.BigEndian.AppendUint64(data, uint64(s.srv.writeLength()))
	data = binary.BigEndian.AppendUint64(data, maxOpenHandles)
	return wire.ExtendedReply{ID: id, Data: data}
}
