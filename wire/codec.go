package wire

import (
	"encoding/binary"
	"errors"
)

// Errors returned by a [Decoder].
//
// They are deliberately few: a server turns any of them into the single wire
// answer SSH_FX_BAD_MESSAGE, so splitting "ran out of bytes" from "length
// prefix is absurd" buys a caller nothing and costs a reader a branch to
// think about. They are distinct types only so a *test* can tell which
// rejection it provoked.
var (
	// ErrShort reports that the buffer ended in the middle of an item.
	ErrShort = errors.New("wire: buffer too short")
	// ErrLimit reports a length prefix larger than the ceiling in force.
	// It is returned *before* any allocation, which is the entire point:
	// an attacker's 4 GiB length prefix must cost a comparison, not 4 GiB.
	ErrLimit = errors.New("wire: length exceeds limit")
	// ErrTrailing reports bytes left over after a message decoded. A
	// well-formed peer sends none, and accepting them would let two
	// implementations disagree about what they just exchanged while both
	// believe they succeeded.
	ErrTrailing = errors.New("wire: trailing bytes after message")
)

// DefaultLimit is the ceiling applied to a single variable-length item when a
// [Decoder] has no explicit one.
//
// 256 KiB is comfortably above the largest thing version 3 legitimately
// carries: OpenSSH's client reads and writes in 32 KiB chunks and its largest
// is 256 KiB, and a path cannot sensibly approach either. Anything larger is
// malformed or hostile.
const DefaultLimit = 256 << 10

// Encoder accumulates SSH-encoded values in a buffer.
//
// No method returns an error, and that is a design choice with a consequence
// worth stating: every input is already a valid Go value of a type the
// encoding can represent, and the buffer grows, so encoding genuinely cannot
// fail. Reply-building code is therefore free of error checks on a path where
// nothing can go wrong, which is what keeps the message constructors readable.
type Encoder struct {
	buf []byte
}

// NewEncoder returns an Encoder appending to buf, whose existing contents are
// discarded. Passing a recycled buffer with spare capacity avoids an
// allocation per reply.
func NewEncoder(buf []byte) *Encoder { return &Encoder{buf: buf[:0]} }

// Bytes returns the encoded message. The slice aliases the Encoder's buffer
// and stays valid only until the next write.
func (e *Encoder) Bytes() []byte { return e.buf }

// Len reports how many bytes have been encoded so far.
func (e *Encoder) Len() int { return len(e.buf) }

// Byte encodes a single byte. Packet types and nothing else use this.
func (e *Encoder) Byte(v uint8) { e.buf = append(e.buf, v) }

// Uint32 encodes a 32-bit unsigned integer.
func (e *Encoder) Uint32(v uint32) { e.buf = binary.BigEndian.AppendUint32(e.buf, v) }

// Uint64 encodes a 64-bit unsigned integer.
func (e *Encoder) Uint64(v uint64) { e.buf = binary.BigEndian.AppendUint64(e.buf, v) }

// Int64 encodes a signed 64-bit integer. SFTP's signed and unsigned 64-bit
// values share a representation, so this is a two's-complement reinterpret.
func (e *Encoder) Int64(v int64) { e.Uint64(uint64(v)) }

// Bytes writes a variable-length string: a 4-byte length, then the bytes.
// There is no padding — this is SSH's encoding, not XDR's.
func (e *Encoder) Blob(b []byte) {
	e.Uint32(uint32(len(b)))
	e.buf = append(e.buf, b...)
}

// String writes an SFTP string, which is wire-identical to [Encoder.Blob].
//
// Version 3 says nothing about the character set of a filename, and this
// encoder imposes none: names go out exactly as the filesystem reported them.
// Guessing at UTF-8 here would corrupt names on the images this is pointed at,
// where a FAT32 short name is CP437 and an ISO 9660 name is US-ASCII.
func (e *Encoder) String(s string) {
	e.Uint32(uint32(len(s)))
	e.buf = append(e.buf, s...)
}

// Decoder reads SSH-encoded values from a byte slice.
//
// Every method returns an error rather than panicking: the bytes come from
// the network, and a panic in a per-connection goroutine would take down every
// other session the process is serving.
type Decoder struct {
	buf   []byte
	off   int
	limit int
}

// NewDecoder returns a Decoder reading buf with [DefaultLimit].
func NewDecoder(buf []byte) *Decoder { return &Decoder{buf: buf} }

// SetLimit caps the accepted length of any single variable-length item. A
// non-positive value restores [DefaultLimit].
func (d *Decoder) SetLimit(n int) { d.limit = n }

// cap returns the ceiling in force.
func (d *Decoder) cap() int {
	if d.limit <= 0 {
		return DefaultLimit
	}
	return d.limit
}

// Remaining reports how many undecoded bytes are left.
func (d *Decoder) Remaining() int { return len(d.buf) - d.off }

// End reports ErrTrailing if anything is left undecoded, and nil otherwise.
// Message decoders call it last so that a peer sending extra bytes is caught
// rather than silently tolerated.
func (d *Decoder) End() error {
	if d.Remaining() != 0 {
		return ErrTrailing
	}
	return nil
}

// Byte decodes a single byte.
func (d *Decoder) Byte() (uint8, error) {
	if d.Remaining() < 1 {
		return 0, ErrShort
	}
	v := d.buf[d.off]
	d.off++
	return v, nil
}

// Uint32 decodes a 32-bit unsigned integer.
func (d *Decoder) Uint32() (uint32, error) {
	if d.Remaining() < 4 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v, nil
}

// Uint64 decodes a 64-bit unsigned integer.
func (d *Decoder) Uint64() (uint64, error) {
	if d.Remaining() < 8 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v, nil
}

// Int64 decodes a signed 64-bit integer.
func (d *Decoder) Int64() (int64, error) {
	v, err := d.Uint64()
	return int64(v), err
}

// Blob decodes a variable-length string as bytes.
//
// The result is a copy. The Decoder's buffer is a reusable per-connection read
// buffer, so handing out an alias would let the next request rewrite data the
// caller is still holding — a bug that shows up as one client's filename
// appearing in another's reply, long after the code that caused it.
func (d *Decoder) Blob() ([]byte, error) {
	n, err := d.Uint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(d.cap()) {
		return nil, ErrLimit
	}
	if d.Remaining() < int(n) {
		return nil, ErrShort
	}
	out := make([]byte, n)
	copy(out, d.buf[d.off:d.off+int(n)])
	d.off += int(n)
	return out, nil
}

// String decodes a variable-length string.
//
// The bytes are returned as-is, with no validation of UTF-8 or of path syntax.
// That is deliberate: this layer's job is framing. Whether a filename may
// contain a slash is an SFTP question, answered once, in the server's path
// code — answering it here would silently change what the layer above thinks
// it received.
func (d *Decoder) String() (string, error) {
	b, err := d.Blob()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
