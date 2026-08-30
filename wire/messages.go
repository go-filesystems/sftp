package wire

import "io"

// This file holds one Go type per SFTP version 3 message, each able to encode
// itself and decode itself.
//
// The symmetry is the point. A server decodes requests and encodes replies; a
// client does exactly the reverse. Writing only the server's half would make
// this package useful to one caller and force the next one to reimplement the
// same bytes — which is the outcome the split into a codec package exists to
// prevent. Every type below is therefore complete in both directions and
// exercised in both directions by the tests.
//
// Several message types share a shape (an id and a path; an id and a handle),
// and they share a Go type accordingly: PathRequest covers seven request
// numbers. The alternative — seven identical structs — would be seven places
// to get the same encoding wrong.

// Message is anything that can be sent as an SFTP packet: it knows its own
// packet type and how to write its payload.
type Message interface {
	// Type returns the SSH_FXP_* number this message is sent as. For the
	// shared shapes (PathRequest, HandleRequest) it is a field, because the
	// wire format cannot tell you which of the seven it was.
	Type() uint8
	// EncodePayload writes everything after the type byte.
	EncodePayload(e *Encoder)
}

// Send frames m and writes it to w, reusing and returning buf.
func Send(w io.Writer, m Message, buf []byte) ([]byte, error) {
	e := NewEncoder(make([]byte, 0, 64))
	m.EncodePayload(e)
	return WritePacket(w, m.Type(), e.Bytes(), buf)
}

// ---------------------------------------------------------------------------
// Session start
// ---------------------------------------------------------------------------

// InitRequest is SSH_FXP_INIT, the first packet a client sends. It has no
// request id: nothing has been established yet for an id to refer to.
type InitRequest struct {
	Version    uint32
	Extensions []ExtendedPair
}

// Type implements [Message].
func (InitRequest) Type() uint8 { return FxpInit }

// EncodePayload implements [Message].
func (m InitRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.Version)
	for _, p := range m.Extensions {
		e.String(p.Type)
		e.String(p.Data)
	}
}

// DecodeInit reads an SSH_FXP_INIT payload.
//
// Trailing extension pairs are read until the payload is exhausted; unlike
// every other message there is no count, so "ran out" is the terminator and a
// half-pair is an error rather than a silent truncation.
func DecodeInit(payload []byte) (InitRequest, error) {
	d := NewDecoder(payload)
	var m InitRequest
	var err error
	if m.Version, err = d.Uint32(); err != nil {
		return m, err
	}
	for d.Remaining() > 0 {
		if len(m.Extensions) >= maxExtendedPairs {
			return m, ErrLimit
		}
		t, err := d.String()
		if err != nil {
			return m, err
		}
		v, err := d.String()
		if err != nil {
			return m, err
		}
		m.Extensions = append(m.Extensions, ExtendedPair{Type: t, Data: v})
	}
	return m, nil
}

// VersionReply is SSH_FXP_VERSION, the server's answer to INIT. It too has no
// request id.
type VersionReply struct {
	Version    uint32
	Extensions []ExtendedPair
}

// Type implements [Message].
func (VersionReply) Type() uint8 { return FxpVersion }

// EncodePayload implements [Message].
func (m VersionReply) EncodePayload(e *Encoder) {
	e.Uint32(m.Version)
	for _, p := range m.Extensions {
		e.String(p.Type)
		e.String(p.Data)
	}
}

// DecodeVersion reads an SSH_FXP_VERSION payload. It shares INIT's shape, so
// it shares its decoder.
func DecodeVersion(payload []byte) (VersionReply, error) {
	m, err := DecodeInit(payload)
	return VersionReply(m), err
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

// PathRequest is any request that is an id and a single path: SSH_FXP_LSTAT,
// SSH_FXP_STAT, SSH_FXP_OPENDIR, SSH_FXP_REMOVE, SSH_FXP_RMDIR,
// SSH_FXP_REALPATH and SSH_FXP_READLINK.
//
// PacketType carries which one, because the payload cannot say.
type PathRequest struct {
	PacketType uint8
	ID         uint32
	Path       string
}

// Type implements [Message].
func (m PathRequest) Type() uint8 { return m.PacketType }

// EncodePayload implements [Message].
func (m PathRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Path)
}

// DecodePath reads the payload of any [PathRequest]-shaped message.
func DecodePath(typ uint8, payload []byte) (PathRequest, error) {
	d := NewDecoder(payload)
	m := PathRequest{PacketType: typ}
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Path, err = d.String(); err != nil {
		return m, err
	}
	return m, d.End()
}

// HandleRequest is any request that is an id and a handle: SSH_FXP_CLOSE,
// SSH_FXP_READDIR and SSH_FXP_FSTAT.
type HandleRequest struct {
	PacketType uint8
	ID         uint32
	Handle     string
}

// Type implements [Message].
func (m HandleRequest) Type() uint8 { return m.PacketType }

// EncodePayload implements [Message].
func (m HandleRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Handle)
}

// DecodeHandle reads the payload of any [HandleRequest]-shaped message.
func DecodeHandle(typ uint8, payload []byte) (HandleRequest, error) {
	d := NewDecoder(payload)
	m := HandleRequest{PacketType: typ}
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Handle, err = d.String(); err != nil {
		return m, err
	}
	return m, d.End()
}

// OpenRequest is SSH_FXP_OPEN.
type OpenRequest struct {
	ID     uint32
	Path   string
	PFlags uint32
	Attrs  Attributes
}

// Type implements [Message].
func (OpenRequest) Type() uint8 { return FxpOpen }

// EncodePayload implements [Message].
func (m OpenRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Path)
	e.Uint32(m.PFlags)
	m.Attrs.Encode(e)
}

// DecodeOpen reads an SSH_FXP_OPEN payload.
func DecodeOpen(payload []byte) (OpenRequest, error) {
	d := NewDecoder(payload)
	var m OpenRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Path, err = d.String(); err != nil {
		return m, err
	}
	if m.PFlags, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Attrs, err = DecodeAttributes(d); err != nil {
		return m, err
	}
	return m, d.End()
}

// ReadRequest is SSH_FXP_READ: read Length bytes at Offset.
//
// This is the request that maps exactly onto
// [github.com/go-filesystems/interface.File.ReadAt], which is why a driver
// implementing the optional Opener capability can serve it without reading
// anything it was not asked for.
type ReadRequest struct {
	ID     uint32
	Handle string
	Offset uint64
	Length uint32
}

// Type implements [Message].
func (ReadRequest) Type() uint8 { return FxpRead }

// EncodePayload implements [Message].
func (m ReadRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Handle)
	e.Uint64(m.Offset)
	e.Uint32(m.Length)
}

// DecodeRead reads an SSH_FXP_READ payload.
func DecodeRead(payload []byte) (ReadRequest, error) {
	d := NewDecoder(payload)
	var m ReadRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Handle, err = d.String(); err != nil {
		return m, err
	}
	if m.Offset, err = d.Uint64(); err != nil {
		return m, err
	}
	if m.Length, err = d.Uint32(); err != nil {
		return m, err
	}
	return m, d.End()
}

// WriteRequest is SSH_FXP_WRITE: put Data at Offset.
//
// The offset is the hard part of serving this over the current
// [github.com/go-filesystems/interface] contract; see the server package's
// documentation for the cost and its measurement.
type WriteRequest struct {
	ID     uint32
	Handle string
	Offset uint64
	Data   []byte
}

// Type implements [Message].
func (WriteRequest) Type() uint8 { return FxpWrite }

// EncodePayload implements [Message].
func (m WriteRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Handle)
	e.Uint64(m.Offset)
	e.Blob(m.Data)
}

// DecodeWrite reads an SSH_FXP_WRITE payload.
func DecodeWrite(payload []byte) (WriteRequest, error) {
	d := NewDecoder(payload)
	var m WriteRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Handle, err = d.String(); err != nil {
		return m, err
	}
	if m.Offset, err = d.Uint64(); err != nil {
		return m, err
	}
	if m.Data, err = d.Blob(); err != nil {
		return m, err
	}
	return m, d.End()
}

// SetstatRequest is SSH_FXP_SETSTAT (by path) or SSH_FXP_MKDIR, both of which
// are an id, a path and an ATTRS.
type SetstatRequest struct {
	PacketType uint8
	ID         uint32
	Path       string
	Attrs      Attributes
}

// Type implements [Message].
func (m SetstatRequest) Type() uint8 { return m.PacketType }

// EncodePayload implements [Message].
func (m SetstatRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Path)
	m.Attrs.Encode(e)
}

// DecodeSetstat reads an SSH_FXP_SETSTAT or SSH_FXP_MKDIR payload.
func DecodeSetstat(typ uint8, payload []byte) (SetstatRequest, error) {
	d := NewDecoder(payload)
	m := SetstatRequest{PacketType: typ}
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Path, err = d.String(); err != nil {
		return m, err
	}
	if m.Attrs, err = DecodeAttributes(d); err != nil {
		return m, err
	}
	return m, d.End()
}

// FsetstatRequest is SSH_FXP_FSETSTAT: SETSTAT against an open handle.
type FsetstatRequest struct {
	ID     uint32
	Handle string
	Attrs  Attributes
}

// Type implements [Message].
func (FsetstatRequest) Type() uint8 { return FxpFsetstat }

// EncodePayload implements [Message].
func (m FsetstatRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Handle)
	m.Attrs.Encode(e)
}

// DecodeFsetstat reads an SSH_FXP_FSETSTAT payload.
func DecodeFsetstat(payload []byte) (FsetstatRequest, error) {
	d := NewDecoder(payload)
	var m FsetstatRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Handle, err = d.String(); err != nil {
		return m, err
	}
	if m.Attrs, err = DecodeAttributes(d); err != nil {
		return m, err
	}
	return m, d.End()
}

// RenameRequest is SSH_FXP_RENAME.
type RenameRequest struct {
	ID               uint32
	OldPath, NewPath string
}

// Type implements [Message].
func (RenameRequest) Type() uint8 { return FxpRename }

// EncodePayload implements [Message].
func (m RenameRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.OldPath)
	e.String(m.NewPath)
}

// DecodeRename reads an SSH_FXP_RENAME payload.
func DecodeRename(payload []byte) (RenameRequest, error) {
	d := NewDecoder(payload)
	var m RenameRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.OldPath, err = d.String(); err != nil {
		return m, err
	}
	if m.NewPath, err = d.String(); err != nil {
		return m, err
	}
	return m, d.End()
}

// SymlinkRequest is SSH_FXP_SYMLINK.
//
// The field order on the wire is target-then-link, which is the REVERSE of
// what draft-ietf-secsh-filexfer-02 §6.10 says. That is not a mistake here:
// OpenSSH's server shipped with the arguments swapped, the error was not
// noticed until it was deployed everywhere, and every client now sends the
// swapped order. OpenSSH documents the discrepancy in its own PROTOCOL file,
// §4.1. Following the draft instead of the deployed reality would create
// symlinks pointing the wrong way for every real client — the field names
// below are the truth on the wire, and the order they are written in is why.
type SymlinkRequest struct {
	ID                   uint32
	TargetPath, LinkPath string
}

// Type implements [Message].
func (SymlinkRequest) Type() uint8 { return FxpSymlink }

// EncodePayload implements [Message].
func (m SymlinkRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.TargetPath)
	e.String(m.LinkPath)
}

// DecodeSymlink reads an SSH_FXP_SYMLINK payload.
func DecodeSymlink(payload []byte) (SymlinkRequest, error) {
	d := NewDecoder(payload)
	var m SymlinkRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.TargetPath, err = d.String(); err != nil {
		return m, err
	}
	if m.LinkPath, err = d.String(); err != nil {
		return m, err
	}
	return m, d.End()
}

// ExtendedRequest is SSH_FXP_EXTENDED, the escape hatch by which vendors add
// operations. Data is left uninterpreted: what it means depends entirely on
// Name, and this codec does not pretend to know every vendor's.
type ExtendedRequest struct {
	ID   uint32
	Name string
	Data []byte
}

// Type implements [Message].
func (ExtendedRequest) Type() uint8 { return FxpExtended }

// EncodePayload implements [Message].
func (m ExtendedRequest) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Name)
	e.buf = append(e.buf, m.Data...)
}

// DecodeExtended reads an SSH_FXP_EXTENDED payload. The remainder after the
// name is returned raw, since its shape is the extension's business.
func DecodeExtended(payload []byte) (ExtendedRequest, error) {
	d := NewDecoder(payload)
	var m ExtendedRequest
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Name, err = d.String(); err != nil {
		return m, err
	}
	m.Data = append([]byte(nil), d.buf[d.off:]...)
	return m, nil
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

// StatusReply is SSH_FXP_STATUS.
//
// Message is shown to the user by every client worth using, so it is the one
// place a cause that version 3's nine status codes cannot express still
// reaches a person. Lang is an RFC 1766 tag and is universally empty.
type StatusReply struct {
	ID      uint32
	Code    Status
	Message string
	Lang    string
}

// Type implements [Message].
func (StatusReply) Type() uint8 { return FxpStatus }

// EncodePayload implements [Message].
func (m StatusReply) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.Uint32(uint32(m.Code))
	e.String(m.Message)
	e.String(m.Lang)
}

// DecodeStatus reads an SSH_FXP_STATUS payload.
//
// The message and language fields were added in version 3 and some version-2
// era peers omit them, so a payload that ends after the code decodes as a
// status with an empty message rather than as a protocol error.
func DecodeStatus(payload []byte) (StatusReply, error) {
	d := NewDecoder(payload)
	var m StatusReply
	id, err := d.Uint32()
	if err != nil {
		return m, err
	}
	m.ID = id
	code, err := d.Uint32()
	if err != nil {
		return m, err
	}
	m.Code = Status(code)
	if d.Remaining() == 0 {
		return m, nil
	}
	if m.Message, err = d.String(); err != nil {
		return m, err
	}
	if d.Remaining() == 0 {
		return m, nil
	}
	if m.Lang, err = d.String(); err != nil {
		return m, err
	}
	return m, d.End()
}

// HandleReply is SSH_FXP_HANDLE: the opaque token a client presents for every
// subsequent operation on what it just opened.
type HandleReply struct {
	ID     uint32
	Handle string
}

// Type implements [Message].
func (HandleReply) Type() uint8 { return FxpHandle }

// EncodePayload implements [Message].
func (m HandleReply) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.String(m.Handle)
}

// DecodeHandleReply reads an SSH_FXP_HANDLE payload.
func DecodeHandleReply(payload []byte) (HandleReply, error) {
	d := NewDecoder(payload)
	var m HandleReply
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Handle, err = d.String(); err != nil {
		return m, err
	}
	return m, d.End()
}

// DataReply is SSH_FXP_DATA, the answer to READ.
type DataReply struct {
	ID   uint32
	Data []byte
}

// Type implements [Message].
func (DataReply) Type() uint8 { return FxpData }

// EncodePayload implements [Message].
func (m DataReply) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.Blob(m.Data)
}

// DecodeData reads an SSH_FXP_DATA payload.
func DecodeData(payload []byte) (DataReply, error) {
	d := NewDecoder(payload)
	var m DataReply
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Data, err = d.Blob(); err != nil {
		return m, err
	}
	return m, d.End()
}

// NameItem is one entry of a NAME reply.
type NameItem struct {
	// Filename is the bare name for a READDIR entry, or the resolved path
	// for a REALPATH answer.
	Filename string
	// Longname is a human-readable line in `ls -l` form. Version 3 leaves
	// its format entirely unspecified, which means no client may parse it
	// and every client displays it — so it is presentation, and the
	// authoritative values are in Attrs.
	Longname string
	Attrs    Attributes
}

// NameReply is SSH_FXP_NAME: the answer to READDIR and to REALPATH.
type NameReply struct {
	ID    uint32
	Items []NameItem
}

// Type implements [Message].
func (NameReply) Type() uint8 { return FxpName }

// EncodePayload implements [Message].
func (m NameReply) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.Uint32(uint32(len(m.Items)))
	for _, it := range m.Items {
		e.String(it.Filename)
		e.String(it.Longname)
		it.Attrs.Encode(e)
	}
}

// maxNameItems caps the entry count a peer may claim in a NAME reply, for the
// same reason [maxExtendedPairs] exists: the count is sized off the wire.
// OpenSSH sends at most 100 entries per READDIR round; 64 Ki is far past any
// real reply and still bounds the allocation.
const maxNameItems = 1 << 16

// DecodeName reads an SSH_FXP_NAME payload.
func DecodeName(payload []byte) (NameReply, error) {
	d := NewDecoder(payload)
	var m NameReply
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	n, err := d.Uint32()
	if err != nil {
		return m, err
	}
	if n > maxNameItems {
		return m, ErrLimit
	}
	m.Items = make([]NameItem, 0, n)
	for range n {
		var it NameItem
		if it.Filename, err = d.String(); err != nil {
			return m, err
		}
		if it.Longname, err = d.String(); err != nil {
			return m, err
		}
		if it.Attrs, err = DecodeAttributes(d); err != nil {
			return m, err
		}
		m.Items = append(m.Items, it)
	}
	return m, d.End()
}

// AttrsReply is SSH_FXP_ATTRS: the answer to STAT, LSTAT and FSTAT.
type AttrsReply struct {
	ID    uint32
	Attrs Attributes
}

// Type implements [Message].
func (AttrsReply) Type() uint8 { return FxpAttrs }

// EncodePayload implements [Message].
func (m AttrsReply) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	m.Attrs.Encode(e)
}

// DecodeAttrs reads an SSH_FXP_ATTRS payload.
func DecodeAttrs(payload []byte) (AttrsReply, error) {
	d := NewDecoder(payload)
	var m AttrsReply
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	if m.Attrs, err = DecodeAttributes(d); err != nil {
		return m, err
	}
	return m, d.End()
}

// ExtendedReply is SSH_FXP_EXTENDED_REPLY. Like [ExtendedRequest], its body
// is opaque here.
type ExtendedReply struct {
	ID   uint32
	Data []byte
}

// Type implements [Message].
func (ExtendedReply) Type() uint8 { return FxpExtendedReply }

// EncodePayload implements [Message].
func (m ExtendedReply) EncodePayload(e *Encoder) {
	e.Uint32(m.ID)
	e.buf = append(e.buf, m.Data...)
}

// DecodeExtendedReply reads an SSH_FXP_EXTENDED_REPLY payload.
func DecodeExtendedReply(payload []byte) (ExtendedReply, error) {
	d := NewDecoder(payload)
	var m ExtendedReply
	var err error
	if m.ID, err = d.Uint32(); err != nil {
		return m, err
	}
	m.Data = append([]byte(nil), d.buf[d.off:]...)
	return m, nil
}
