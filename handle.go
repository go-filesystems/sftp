package sftp

import (
	"crypto/rand"
	"encoding/hex"

	filesystem "github.com/go-filesystems/interface"
)

// A file handle is the hardest design question in an NFS server, and it is
// worth recording why it is nearly a non-question here — because the reason
// is the single biggest difference between the two protocols, and it explains
// several other choices in this package.
//
// NFSv3 is stateless. Its handle is 64 opaque bytes that a client stores,
// hands back hours later, possibly to a different server process, with
// nothing in the protocol to say the server ever restarted. Making that safe
// costs [github.com/go-filesystems/nfs] a 60-byte structure with a magic
// number, an export id, a random per-process epoch, a dense slot index and an
// HMAC-SHA256 over all of it — because the slot is an index the server will
// dereference, and without the MAC a client could walk it to enumerate every
// path the server had ever resolved.
//
// SFTP is stateful and its handles are session-scoped. A handle is created by
// OPEN or OPENDIR inside an authenticated session, is meaningless outside it,
// and dies with it. There is no cross-process lifetime to defend and no
// enumeration to prevent: everything in this session's table was opened by
// this same client, so guessing another entry gains it access to something it
// already has. The MAC would defend against nothing.
//
// What survives from that design, because it is not about lifetime, is: never
// dereference wire bytes as an index. The table is a map keyed by the token,
// so an unknown token is a miss rather than an out-of-range read, and the
// token itself is 16 random bytes rather than a counter — not because a
// counter would be exploitable, but because a counter would make two
// sessions' handles look interchangeable in a packet capture and invite
// exactly the confusion this comment exists to prevent.

// handleBytes is the length of the random part of a handle. Version 3 caps a
// handle at 256 bytes; 16 random bytes is 128 bits, which is past any
// collision concern for a table that lives as long as one TCP connection.
const handleBytes = 16

// randRead is crypto/rand.Read, indirected so a test can prove that a server
// whose CSPRNG has failed refuses to open a file rather than minting a
// predictable handle. There is no other way to reach that branch, and it is
// the one branch where the wrong behaviour would be silent.
var randRead = rand.Read

// openFile is what one SSH_FXP_HANDLE refers to.
//
// A handle is either a file or a directory, never both, and the zero value of
// the unused half is never consulted — dir is the discriminant and every
// operation checks it before touching anything else.
type openFile struct {
	// path is the cleaned absolute path inside the export. It is retained
	// for the fallback read and write paths, which have no open file to
	// work with and must name the file to the driver on every request.
	path string

	// dir marks a handle opened by OPENDIR.
	dir bool

	// entries is the directory listing, taken once at OPENDIR.
	//
	// The contract has no streaming ListDir, so the whole listing is read
	// up front and READDIR pages through it. That also makes the listing a
	// snapshot, which is the behaviour a client wants: a directory changing
	// underneath a paginated read is how entries get seen twice or missed.
	entries []filesystem.DirEntry
	// pos is how far READDIR has got through entries.
	pos int

	// file is the driver's random-access reader when it implements
	// [github.com/go-filesystems/interface.Opener], and nil otherwise. When
	// it is nil, reads fall back to ReadFile per request; see the package
	// documentation for what that costs.
	file filesystem.File
	// writable is file again when it also satisfies [WritableFile], and nil
	// otherwise. When it is nil, writes fall back to read-modify-write.
	writable WritableFile

	// write records that the handle was opened for writing, so that a WRITE
	// against a handle opened read-only is refused rather than performed.
	write bool
}

// handles is one session's handle table.
//
// It needs no mutex: a session reads its packets one at a time from a single
// stream and answers each before reading the next, so exactly one goroutine
// ever touches it. That serialisation is not incidental — see [Server] for
// why the driver requires it — and the absence of a lock here is a
// consequence of it rather than an oversight.
type handles struct {
	m map[string]*openFile
}

// newHandles returns an empty table.
func newHandles() *handles { return &handles{m: make(map[string]*openFile)} }

// add stores h under a fresh random token and returns the token.
//
// It returns an error rather than falling back to something predictable when
// the CSPRNG fails, for the same reason the NFS server refuses to start in
// that case: a server that cannot generate randomness must say so, not carry
// on with a weaker substitute nobody was told about.
func (t *handles) add(h *openFile) (string, error) {
	var b [handleBytes]byte
	if _, err := randRead(b[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b[:])
	t.m[tok] = h
	return tok, nil
}

// get resolves a token. A miss is a miss — there is no index to bound-check
// and nothing to dereference.
func (t *handles) get(tok string) (*openFile, bool) {
	h, ok := t.m[tok]
	return h, ok
}

// remove drops a token and returns what it named, so CLOSE can release the
// driver's file exactly once even if a confused client closes twice.
func (t *handles) remove(tok string) (*openFile, bool) {
	h, ok := t.m[tok]
	if ok {
		delete(t.m, tok)
	}
	return h, ok
}

// closeAll releases every still-open handle and returns the first error.
//
// A client that drops its connection without closing its handles is normal —
// killing an `sftp` session with Ctrl-C does exactly that — so this runs at
// the end of every session, not only clean ones. Without it a driver's
// per-file state would leak once per abandoned transfer.
func (t *handles) closeAll() error {
	var first error
	for tok, h := range t.m {
		if h.file != nil {
			if err := h.file.Close(); err != nil && first == nil {
				first = err
			}
		}
		delete(t.m, tok)
	}
	return first
}
