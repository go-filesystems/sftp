package wire

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// fullAttrs exercises every optional field of an ATTRS structure at once, so
// that a decoder skipping one is caught by the round trip rather than by a
// client months later.
var fullAttrs = Attributes{
	Flags:       AttrSize | AttrUIDGID | AttrPermissions | AttrACModTime | AttrExtended,
	Size:        1 << 40,
	UID:         501,
	GID:         20,
	Permissions: ModeReg | 0o644,
	Atime:       1_700_000_000,
	Mtime:       1_700_000_001,
	Extended:    []ExtendedPair{{Type: "x@example.com", Data: "v"}},
}

// message is one round-trip case.
type message struct {
	name string
	msg  Message
	// decode turns a payload back into a value comparable with msg.
	decode func(typ uint8, payload []byte) (any, error)
	// want is what decode must produce; nil means msg itself.
	want any
	// minLen is the shortest payload the decoder legitimately accepts.
	// Truncations at or above it are not required to fail — see
	// DecodeStatus, which tolerates a version-2 era peer that omits the
	// message and language fields.
	minLen int
}

func cases() []message {
	return []message{
		{
			name: "INIT",
			msg:  InitRequest{Version: 3, Extensions: []ExtendedPair{{Type: "a", Data: "b"}}},
			decode: func(_ uint8, p []byte) (any, error) {
				m, err := DecodeInit(p)
				return m, err
			},
			minLen: 4,
		},
		{
			name: "VERSION",
			msg:  VersionReply{Version: 3, Extensions: []ExtendedPair{{Type: "a", Data: "b"}}},
			decode: func(_ uint8, p []byte) (any, error) {
				m, err := DecodeVersion(p)
				return m, err
			},
			minLen: 4,
		},
		{
			name:   "OPEN",
			msg:    OpenRequest{ID: 1, Path: "/a", PFlags: FxfRead | FxfWrite, Attrs: fullAttrs},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeOpen(p) },
		},
		{
			name:   "CLOSE",
			msg:    HandleRequest{PacketType: FxpClose, ID: 2, Handle: "h"},
			decode: func(ty uint8, p []byte) (any, error) { return DecodeHandle(ty, p) },
		},
		{
			name:   "READDIR",
			msg:    HandleRequest{PacketType: FxpReaddir, ID: 3, Handle: "h"},
			decode: func(ty uint8, p []byte) (any, error) { return DecodeHandle(ty, p) },
		},
		{
			name:   "READ",
			msg:    ReadRequest{ID: 4, Handle: "h", Offset: 1 << 33, Length: 32768},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeRead(p) },
		},
		{
			name:   "WRITE",
			msg:    WriteRequest{ID: 5, Handle: "h", Offset: 1 << 33, Data: []byte("payload")},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeWrite(p) },
		},
		{
			name:   "STAT",
			msg:    PathRequest{PacketType: FxpStat, ID: 6, Path: "/a/b"},
			decode: func(ty uint8, p []byte) (any, error) { return DecodePath(ty, p) },
		},
		{
			name:   "SETSTAT",
			msg:    SetstatRequest{PacketType: FxpSetstat, ID: 7, Path: "/a", Attrs: fullAttrs},
			decode: func(ty uint8, p []byte) (any, error) { return DecodeSetstat(ty, p) },
		},
		{
			name:   "FSETSTAT",
			msg:    FsetstatRequest{ID: 8, Handle: "h", Attrs: fullAttrs},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeFsetstat(p) },
		},
		{
			name:   "RENAME",
			msg:    RenameRequest{ID: 9, OldPath: "/a", NewPath: "/b"},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeRename(p) },
		},
		{
			name:   "SYMLINK",
			msg:    SymlinkRequest{ID: 10, TargetPath: "/t", LinkPath: "/l"},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeSymlink(p) },
		},
		{
			name:   "EXTENDED",
			msg:    ExtendedRequest{ID: 11, Name: "statvfs@openssh.com", Data: []byte("/")},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeExtended(p) },
			minLen: 4,
		},
		{
			name:   "STATUS",
			msg:    StatusReply{ID: 12, Code: StatusNoSuchFile, Message: "gone", Lang: "en"},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeStatus(p) },
			minLen: 8,
		},
		{
			name:   "HANDLE",
			msg:    HandleReply{ID: 13, Handle: "abc"},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeHandleReply(p) },
		},
		{
			name:   "DATA",
			msg:    DataReply{ID: 14, Data: []byte("bytes")},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeData(p) },
		},
		{
			name: "NAME",
			msg: NameReply{ID: 15, Items: []NameItem{
				{Filename: "a", Longname: "-rw-r--r-- 1 0 0 1 Jan  1 00:00 a", Attrs: fullAttrs},
				{Filename: "b", Longname: "b", Attrs: Attributes{}},
			}},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeName(p) },
		},
		{
			name:   "ATTRS",
			msg:    AttrsReply{ID: 16, Attrs: fullAttrs},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeAttrs(p) },
		},
		{
			name:   "EXTENDED_REPLY",
			msg:    ExtendedReply{ID: 17, Data: []byte("body")},
			decode: func(_ uint8, p []byte) (any, error) { return DecodeExtendedReply(p) },
			minLen: 4,
		},
	}
}

// encode returns a message's payload.
func encode(m Message) []byte {
	e := NewEncoder(nil)
	m.EncodePayload(e)
	return append([]byte(nil), e.Bytes()...)
}

// TestMessagesRoundTrip encodes every message type and decodes it back.
//
// Both directions are exercised because both are published: the server uses
// one half and a client would use the other, and a codec that has only ever
// been driven from one side is a codec whose other side has never been run.
func TestMessagesRoundTrip(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			payload := encode(tc.msg)
			got, err := tc.decode(tc.msg.Type(), payload)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			want := tc.want
			if want == nil {
				want = tc.msg
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip:\n got %#v\nwant %#v", got, want)
			}
		})
	}
}

// TestTruncatedMessagesAreRejected cuts every message at every length and
// requires an error.
//
// This is the sweep that reaches the error branch of every field decode. A
// hand-written test per field would be the same assertions written nineteen
// times, and would still miss the field somebody adds next year.
func TestTruncatedMessagesAreRejected(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			payload := encode(tc.msg)
			for i := range len(payload) {
				if i >= tc.minLen && tc.minLen > 0 {
					continue
				}
				if _, err := tc.decode(tc.msg.Type(), payload[:i]); err == nil {
					t.Fatalf("a %d-byte prefix of a %d-byte payload decoded without error",
						i, len(payload))
				}
			}
		})
	}
}

// TestTrailingBytesAreRejected appends a byte to every message that claims a
// definite length, and requires the decoder to notice.
func TestTrailingBytesAreRejected(t *testing.T) {
	for _, tc := range cases() {
		switch tc.name {
		case "INIT", "VERSION", "EXTENDED", "EXTENDED_REPLY":
			// These three legitimately consume whatever is left: INIT and
			// VERSION carry an uncounted extension list, and the two
			// EXTENDED messages carry an opaque body.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			payload := append(encode(tc.msg), 0)
			if _, err := tc.decode(tc.msg.Type(), payload); !errors.Is(err, ErrTrailing) {
				t.Fatalf("decode with a trailing byte = %v, want ErrTrailing", err)
			}
		})
	}
}

func TestInitRejectsAHalfExtensionPair(t *testing.T) {
	e := NewEncoder(nil)
	e.Uint32(3)
	e.String("only-a-type")
	if _, err := DecodeInit(e.Bytes()); err == nil {
		t.Fatal("a half extension pair decoded without error")
	}
}

func TestInitRejectsTooManyExtensions(t *testing.T) {
	e := NewEncoder(nil)
	e.Uint32(3)
	for range maxExtendedPairs + 1 {
		e.String("t")
		e.String("v")
	}
	if _, err := DecodeInit(e.Bytes()); !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

func TestAttributesRejectAbsurdCounts(t *testing.T) {
	t.Run("extension count", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Uint32(AttrExtended)
		e.Uint32(1 << 20)
		if _, err := DecodeAttributes(NewDecoder(e.Bytes())); !errors.Is(err, ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
	})
	t.Run("name item count", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Uint32(1)
		e.Uint32(1 << 20)
		if _, err := DecodeName(e.Bytes()); !errors.Is(err, ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
	})
	t.Run("a half extension pair inside ATTRS", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Uint32(AttrExtended)
		e.Uint32(1)
		e.String("type-only")
		if _, err := DecodeAttributes(NewDecoder(e.Bytes())); err == nil {
			t.Fatal("a half pair decoded without error")
		}
	})
}

func TestStatusToleratesAVersionTwoEraPeer(t *testing.T) {
	// A status with no message at all, and one with a message but no
	// language: both are seen in the wild and neither is a protocol error.
	e := NewEncoder(nil)
	e.Uint32(7)
	e.Uint32(uint32(StatusEOF))
	st, err := DecodeStatus(e.Bytes())
	if err != nil || st.ID != 7 || st.Code != StatusEOF || st.Message != "" {
		t.Fatalf("DecodeStatus = %+v,%v", st, err)
	}
	e = NewEncoder(nil)
	e.Uint32(7)
	e.Uint32(uint32(StatusEOF))
	e.String("done")
	st, err = DecodeStatus(e.Bytes())
	if err != nil || st.Message != "done" || st.Lang != "" {
		t.Fatalf("DecodeStatus = %+v,%v", st, err)
	}
}

func TestAttributesPresenceIsWhatIsAsserted(t *testing.T) {
	// An ATTRS with no flags carries no fields, and every accessor must say
	// "not stated" rather than "zero".
	e := NewEncoder(nil)
	Attributes{}.Encode(e)
	a, err := DecodeAttributes(NewDecoder(e.Bytes()))
	if err != nil {
		t.Fatalf("DecodeAttributes: %v", err)
	}
	if a.IsDir() || a.IsLink() {
		t.Fatal("an ATTRS stating no permissions claimed a file type")
	}
	if len(e.Bytes()) != 4 {
		t.Fatalf("an empty ATTRS encoded %d bytes, want 4", len(e.Bytes()))
	}

	dir := Attributes{Flags: AttrPermissions, Permissions: ModeDir | 0o755}
	if !dir.IsDir() || dir.IsLink() {
		t.Fatal("a directory ATTRS is not reported as one")
	}
	lnk := Attributes{Flags: AttrPermissions, Permissions: ModeLink | 0o777}
	if !lnk.IsLink() || lnk.IsDir() {
		t.Fatal("a symlink ATTRS is not reported as one")
	}
}

func TestStatusStrings(t *testing.T) {
	for code, want := range map[Status]string{
		StatusOK:               "SSH_FX_OK",
		StatusEOF:              "SSH_FX_EOF",
		StatusNoSuchFile:       "SSH_FX_NO_SUCH_FILE",
		StatusPermissionDenied: "SSH_FX_PERMISSION_DENIED",
		StatusFailure:          "SSH_FX_FAILURE",
		StatusBadMessage:       "SSH_FX_BAD_MESSAGE",
		StatusNoConnection:     "SSH_FX_NO_CONNECTION",
		StatusConnectionLost:   "SSH_FX_CONNECTION_LOST",
		StatusOpUnsupported:    "SSH_FX_OP_UNSUPPORTED",
		Status(99):             "SSH_FX_UNKNOWN",
	} {
		if got := code.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", code, got, want)
		}
	}
}

// TestSymlinkFieldOrderMatchesOpenSSH pins the reversal.
//
// draft-ietf-secsh-filexfer-02 §6.10 says linkpath then targetpath. OpenSSH
// shipped it the other way round, the mistake was found only after universal
// deployment, and every client now sends target first. Following the draft
// here would create links pointing the wrong way for every real client, so
// the order is asserted on the bytes rather than left to a comment.
func TestSymlinkFieldOrderMatchesOpenSSH(t *testing.T) {
	payload := encode(SymlinkRequest{ID: 1, TargetPath: "TARGET", LinkPath: "LINK"})
	d := NewDecoder(payload)
	d.Uint32()
	first, _ := d.String()
	second, _ := d.String()
	if first != "TARGET" || second != "LINK" {
		t.Fatalf("wire order is %q then %q; OpenSSH sends target first", first, second)
	}
}

func TestMessageTypesAreTheProtocolNumbers(t *testing.T) {
	for _, tc := range []struct {
		m    Message
		want uint8
	}{
		{InitRequest{}, FxpInit},
		{VersionReply{}, FxpVersion},
		{OpenRequest{}, FxpOpen},
		{PathRequest{PacketType: FxpStat}, FxpStat},
		{HandleRequest{PacketType: FxpClose}, FxpClose},
		{ReadRequest{}, FxpRead},
		{WriteRequest{}, FxpWrite},
		{SetstatRequest{PacketType: FxpMkdir}, FxpMkdir},
		{FsetstatRequest{}, FxpFsetstat},
		{RenameRequest{}, FxpRename},
		{SymlinkRequest{}, FxpSymlink},
		{ExtendedRequest{}, FxpExtended},
		{StatusReply{}, FxpStatus},
		{HandleReply{}, FxpHandle},
		{DataReply{}, FxpData},
		{NameReply{}, FxpName},
		{AttrsReply{}, FxpAttrs},
		{ExtendedReply{}, FxpExtendedReply},
	} {
		if got := tc.m.Type(); got != tc.want {
			t.Errorf("%T.Type() = %d, want %d", tc.m, got, tc.want)
		}
	}
}

func TestDataReplyCopiesRatherThanAliases(t *testing.T) {
	// The decoder's buffer is a reusable connection read buffer. Handing
	// out an alias would let the next request rewrite data a caller still
	// holds — a defect that surfaces as one client's bytes in another's
	// reply, long after the code that caused it.
	payload := encode(DataReply{ID: 1, Data: []byte("original")})
	d, err := DecodeData(payload)
	if err != nil {
		t.Fatalf("DecodeData: %v", err)
	}
	for i := range payload {
		payload[i] = 'X'
	}
	if !bytes.Equal(d.Data, []byte("original")) {
		t.Fatalf("decoded data aliases the buffer: %q", d.Data)
	}
}

func TestInitAndStatusPartialFieldFailures(t *testing.T) {
	t.Run("INIT with a truncated extension type", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Uint32(3)
		e.Uint32(16) // a length prefix promising 16 bytes that are not there
		if _, err := DecodeInit(e.Bytes()); !errors.Is(err, ErrShort) {
			t.Fatalf("err = %v, want ErrShort", err)
		}
	})
	t.Run("STATUS with a truncated message", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Uint32(1)
		e.Uint32(uint32(StatusFailure))
		e.Uint32(16)
		if _, err := DecodeStatus(e.Bytes()); !errors.Is(err, ErrShort) {
			t.Fatalf("err = %v, want ErrShort", err)
		}
	})
	t.Run("STATUS with a truncated language", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Uint32(1)
		e.Uint32(uint32(StatusFailure))
		e.String("msg")
		e.Uint32(16)
		if _, err := DecodeStatus(e.Bytes()); !errors.Is(err, ErrShort) {
			t.Fatalf("err = %v, want ErrShort", err)
		}
	})
}
