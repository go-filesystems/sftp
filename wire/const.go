package wire

// Version is the SFTP protocol version this codec implements:
// draft-ietf-secsh-filexfer-02. See the package documentation for why 3 and
// not a later draft.
const Version uint32 = 3

// Packet types (draft-ietf-secsh-filexfer-02 §3, §4).
//
// The numbering has a shape worth knowing when reading a hex dump: 1..20 are
// requests, 101..105 are replies, and 200/201 are the extension escape hatch.
const (
	FxpInit     uint8 = 1
	FxpVersion  uint8 = 2
	FxpOpen     uint8 = 3
	FxpClose    uint8 = 4
	FxpRead     uint8 = 5
	FxpWrite    uint8 = 6
	FxpLstat    uint8 = 7
	FxpFstat    uint8 = 8
	FxpSetstat  uint8 = 9
	FxpFsetstat uint8 = 10
	FxpOpendir  uint8 = 11
	FxpReaddir  uint8 = 12
	FxpRemove   uint8 = 13
	FxpMkdir    uint8 = 14
	FxpRmdir    uint8 = 15
	FxpRealpath uint8 = 16
	FxpStat     uint8 = 17
	FxpRename   uint8 = 18
	FxpReadlink uint8 = 19
	FxpSymlink  uint8 = 20

	FxpStatus uint8 = 101
	FxpHandle uint8 = 102
	FxpData   uint8 = 103
	FxpName   uint8 = 104
	FxpAttrs  uint8 = 105

	FxpExtended      uint8 = 200
	FxpExtendedReply uint8 = 201
)

// Status is an SSH_FX_* code: the answer carried by an SSH_FXP_STATUS packet.
//
// Version 3 defines exactly the nine below. Later drafts add finer codes
// (SSH_FX_NO_SUCH_PATH, SSH_FX_DIR_NOT_EMPTY, ...) and it is tempting to send
// them anyway, but a version-3 client is entitled to treat any code it does
// not know as a hard failure, and some do. The finer distinction goes in the
// human-readable message instead, where it costs nothing and reaches the user.
type Status uint32

// The version 3 status codes.
const (
	// StatusOK means the operation completed. It is also what a
	// write-shaped request returns on success, since there is nothing else
	// to send back.
	StatusOK Status = 0
	// StatusEOF ends a READ or a READDIR. It is not an error: it is the
	// only way either of those two loops terminates.
	StatusEOF Status = 1
	// StatusNoSuchFile is ENOENT.
	StatusNoSuchFile Status = 2
	// StatusPermissionDenied is EACCES/EPERM, and is what a read-only
	// export answers to every mutating request.
	StatusPermissionDenied Status = 3
	// StatusFailure is the catch-all. A client shows its message to the
	// user, so the message is the only place the real cause can go.
	StatusFailure Status = 4
	// StatusBadMessage reports a packet that did not decode. It is the
	// codec's verdict, not the filesystem's.
	StatusBadMessage Status = 5
	// StatusNoConnection and StatusConnectionLost are client-side codes in
	// practice; they are defined for completeness of the enum.
	StatusNoConnection   Status = 6
	StatusConnectionLost Status = 7
	// StatusOpUnsupported reports an operation the server will not do.
	// Answering it honestly is what lets a client fall back instead of
	// hanging or believing a lie.
	StatusOpUnsupported Status = 8
)

// String renders a status as its SSH_FX_ name, for logs and test failures.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "SSH_FX_OK"
	case StatusEOF:
		return "SSH_FX_EOF"
	case StatusNoSuchFile:
		return "SSH_FX_NO_SUCH_FILE"
	case StatusPermissionDenied:
		return "SSH_FX_PERMISSION_DENIED"
	case StatusFailure:
		return "SSH_FX_FAILURE"
	case StatusBadMessage:
		return "SSH_FX_BAD_MESSAGE"
	case StatusNoConnection:
		return "SSH_FX_NO_CONNECTION"
	case StatusConnectionLost:
		return "SSH_FX_CONNECTION_LOST"
	case StatusOpUnsupported:
		return "SSH_FX_OP_UNSUPPORTED"
	default:
		return "SSH_FX_UNKNOWN"
	}
}

// Open flags (SSH_FXF_*), the pflags field of SSH_FXP_OPEN.
const (
	FxfRead   uint32 = 0x00000001
	FxfWrite  uint32 = 0x00000002
	FxfAppend uint32 = 0x00000004
	FxfCreat  uint32 = 0x00000008
	FxfTrunc  uint32 = 0x00000010
	FxfExcl   uint32 = 0x00000020
)

// Attribute presence flags (SSH_FILEXFER_ATTR_*).
//
// Every field of an ATTRS structure is optional and announced by one of
// these. That is the whole reason [Attributes] carries a Flags field rather
// than being a plain struct of values: "size 0" and "size not stated" are
// different answers, and conflating them is how a client comes to believe a
// file is empty.
const (
	AttrSize        uint32 = 0x00000001
	AttrUIDGID      uint32 = 0x00000002
	AttrPermissions uint32 = 0x00000004
	AttrACModTime   uint32 = 0x00000008
	AttrExtended    uint32 = 0x80000000
)

// POSIX file-type bits, as they appear in the permissions field of an ATTRS
// structure.
//
// SFTP version 3 has no separate file-type field: a client learns that
// something is a directory by masking these out of the permissions, which is
// why a server that sends permissions without type bits produces a listing
// where nothing is a directory.
const (
	ModeFmt   uint32 = 0o170000
	ModeFifo  uint32 = 0o010000
	ModeChar  uint32 = 0o020000
	ModeDir   uint32 = 0o040000
	ModeBlock uint32 = 0o060000
	ModeReg   uint32 = 0o100000
	ModeLink  uint32 = 0o120000
	ModeSock  uint32 = 0o140000

	// ModePerm masks the permission and setuid/setgid/sticky bits.
	ModePerm uint32 = 0o7777
)
