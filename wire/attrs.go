package wire

// Attributes is an SFTP version 3 ATTRS structure
// (draft-ietf-secsh-filexfer-02 §5).
//
// Every field is optional and its presence is announced in Flags. That is why
// this is not a plain struct of values: "size 0" and "size not stated" are
// different answers, and a decoder that conflates them tells a client a file
// is empty when the server never claimed anything of the sort. Read a field
// only after checking its flag; write one only together with setting it.
type Attributes struct {
	// Flags is the bitmask of ATTR_* constants saying which fields below
	// carry meaning.
	Flags uint32
	// Size is the file length in bytes. Valid when AttrSize is set.
	Size uint64
	// UID and GID are the numeric owner ids. Valid when AttrUIDGID is set.
	UID, GID uint32
	// Permissions carries both the POSIX type bits and the mode bits.
	// Version 3 has no separate file-type field, so the type bits here are
	// the *only* way a client learns that something is a directory. Valid
	// when AttrPermissions is set.
	Permissions uint32
	// Atime and Mtime are seconds since the Unix epoch. Version 3 states
	// them as 32-bit, which runs out in 2106; later drafts widened the
	// field, and this codec does not get to fix that on its own.
	// Valid when AttrACModTime is set.
	Atime, Mtime uint32
	// Extended carries vendor extensions as (type, data) pairs. Valid when
	// AttrExtended is set. Nothing here produces any; they are decoded
	// rather than dropped so that a request carrying one round-trips
	// truthfully instead of being silently truncated.
	Extended []ExtendedPair
}

// ExtendedPair is one vendor-extension attribute.
type ExtendedPair struct {
	Type, Data string
}

// IsDir reports whether the permissions say directory. It answers false when
// permissions were not stated at all, which is the safe direction: a client
// that wrongly believes something is a directory will try to enumerate it.
func (a Attributes) IsDir() bool {
	return a.Flags&AttrPermissions != 0 && a.Permissions&ModeFmt == ModeDir
}

// IsLink reports whether the permissions say symbolic link, on the same terms
// as [Attributes.IsDir].
func (a Attributes) IsLink() bool {
	return a.Flags&AttrPermissions != 0 && a.Permissions&ModeFmt == ModeLink
}

// Encode writes the ATTRS structure.
func (a Attributes) Encode(e *Encoder) {
	e.Uint32(a.Flags)
	if a.Flags&AttrSize != 0 {
		e.Uint64(a.Size)
	}
	if a.Flags&AttrUIDGID != 0 {
		e.Uint32(a.UID)
		e.Uint32(a.GID)
	}
	if a.Flags&AttrPermissions != 0 {
		e.Uint32(a.Permissions)
	}
	if a.Flags&AttrACModTime != 0 {
		e.Uint32(a.Atime)
		e.Uint32(a.Mtime)
	}
	if a.Flags&AttrExtended != 0 {
		e.Uint32(uint32(len(a.Extended)))
		for _, p := range a.Extended {
			e.String(p.Type)
			e.String(p.Data)
		}
	}
}

// maxExtendedPairs caps the extension count a peer may claim.
//
// The count is a uint32 read straight off the wire and immediately used to
// size a slice, which is the classic shape of a one-packet memory exhaustion:
// four bytes of 0xFF ask for four billion two-string structs. Nothing sends
// more than a handful, so the ceiling is generous at 64 and still bounds the
// allocation to something a connection can afford.
const maxExtendedPairs = 64

// DecodeAttributes reads an ATTRS structure.
func DecodeAttributes(d *Decoder) (Attributes, error) {
	var a Attributes
	var err error
	if a.Flags, err = d.Uint32(); err != nil {
		return a, err
	}
	if a.Flags&AttrSize != 0 {
		if a.Size, err = d.Uint64(); err != nil {
			return a, err
		}
	}
	if a.Flags&AttrUIDGID != 0 {
		if a.UID, err = d.Uint32(); err != nil {
			return a, err
		}
		if a.GID, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.Flags&AttrPermissions != 0 {
		if a.Permissions, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.Flags&AttrACModTime != 0 {
		if a.Atime, err = d.Uint32(); err != nil {
			return a, err
		}
		if a.Mtime, err = d.Uint32(); err != nil {
			return a, err
		}
	}
	if a.Flags&AttrExtended != 0 {
		n, err := d.Uint32()
		if err != nil {
			return a, err
		}
		if n > maxExtendedPairs {
			return a, ErrLimit
		}
		a.Extended = make([]ExtendedPair, 0, n)
		for range n {
			t, err := d.String()
			if err != nil {
				return a, err
			}
			v, err := d.String()
			if err != nil {
				return a, err
			}
			a.Extended = append(a.Extended, ExtendedPair{Type: t, Data: v})
		}
	}
	return a, nil
}
