package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxPacket is the largest SFTP packet this codec will read or write,
// counting the type byte and the payload but not the 4-byte length prefix.
//
// The value is not arbitrary. OpenSSH's sftp client sends SSH_FXP_WRITE
// payloads of 32 KiB by default and can be pushed to 256 KiB with -B; the
// prefix and the fixed fields around the data add well under 4 KiB. 260 KiB
// therefore accepts everything a real client sends and rejects everything
// else before allocating for it.
const MaxPacket = 260 << 10

// ErrPacketTooLarge reports a length prefix above the ceiling in force.
//
// It is checked before the body is read, so a hostile 4 GiB prefix costs one
// comparison rather than 4 GiB of buffer and a stalled connection. The
// connection is not recoverable afterwards — the stream is now misframed —
// so a server that sees this must close, not reply.
var ErrPacketTooLarge = errors.New("wire: packet too large")

// ErrPacketEmpty reports a packet whose length prefix is zero, which leaves
// no room for the mandatory type byte.
var ErrPacketEmpty = errors.New("wire: empty packet")

// ReadPacket reads one packet from r, reusing buf when it is large enough.
//
// It returns the packet type, the payload (which aliases buf and is valid
// only until the next call), and the possibly-grown buffer for the caller to
// pass back in. Reusing the buffer is what keeps a bulk transfer from
// allocating once per 32 KiB chunk.
//
// max caps the packet; a non-positive value means [MaxPacket].
//
// io.EOF is returned unwrapped when the stream ends cleanly at a packet
// boundary, which is how a client says goodbye; a stream that ends *inside* a
// packet yields io.ErrUnexpectedEOF, and the difference is exactly the one a
// caller needs to decide whether to log an error.
func ReadPacket(r io.Reader, buf []byte, max int) (typ uint8, payload, next []byte, err error) {
	if max <= 0 {
		max = MaxPacket
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, buf, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return 0, nil, buf, ErrPacketEmpty
	}
	if uint64(n) > uint64(max) {
		return 0, nil, buf, ErrPacketTooLarge
	}
	if cap(buf) < int(n) {
		buf = make([]byte, n)
	}
	body := buf[:n]
	if _, err := io.ReadFull(r, body); err != nil {
		// ReadFull turns a truncated body into ErrUnexpectedEOF already
		// for n > 1; for n == 1 it reports io.EOF, which would be read by
		// the caller as a clean close in the middle of a packet. Normalise.
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, buf, err
	}
	return body[0], body[1:], buf, nil
}

// WritePacket frames payload as a packet of the given type and writes it to w
// in a single Write call.
//
// The single call matters: SFTP runs inside an SSH channel, and splitting a
// packet across two writes turns into two SSH_MSG_CHANNEL_DATA messages, each
// with its own MAC and its own round of framing. It is also what makes the
// writer safe to reason about when a caller serialises access with one mutex.
//
// out is a scratch buffer; the possibly-grown buffer is returned for reuse.
func WritePacket(w io.Writer, typ uint8, payload []byte, out []byte) ([]byte, error) {
	total := 1 + len(payload)
	if uint64(total) > uint64(MaxPacket) {
		return out, ErrPacketTooLarge
	}
	need := 4 + total
	if cap(out) < need {
		out = make([]byte, need)
	}
	out = out[:need]
	binary.BigEndian.PutUint32(out[0:4], uint32(total))
	out[4] = typ
	copy(out[5:], payload)
	_, err := w.Write(out)
	return out, err
}
