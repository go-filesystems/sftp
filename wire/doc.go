// Package wire is the SFTP version 3 codec: packet framing, message types,
// and the SSH binary encoding they are built from.
//
// # Why this is its own package
//
// It knows nothing about filesystems, servers, or SSH transports. It depends
// on nothing but the standard library. That is deliberate and it is a
// structural commitment, not a stylistic one: an SFTP *client* speaks exactly
// these bytes, and a client belongs somewhere else entirely (a `sftp://`
// source for a downloader, say). Keeping the codec free of any reference to
// [github.com/go-filesystems/interface] or to the server package means moving
// it is a move, not a rewrite.
//
// The same split is why [github.com/go-filesystems/nfs] keeps `xdr` and `rpc`
// out of its server package.
//
// # The encoding
//
// SFTP is layered on the SSH binary encoding of RFC 4251 §5, not on XDR, and
// the difference matters in exactly one place: a string is a 4-byte
// big-endian length followed by that many bytes with *no padding*. Everything
// is big-endian. There are no alignment rules, so there is no padding to
// validate — the one XDR hazard this codec does not have.
//
// # The protocol version
//
// This implements draft-ietf-secsh-filexfer-02, "SFTP version 3". Later
// drafts exist (4 through 6, and the version 6 draft is what the IETF stopped
// at) but essentially nothing speaks them: OpenSSH's client and server,
// FileZilla, WinSCP, Cyberduck, libssh, JSch, paramiko and Go's own
// github.com/pkg/sftp all negotiate 3. Implementing a version nobody speaks
// would be a way to be correct and unreachable at the same time.
//
// # Hostile input
//
// Every byte a [Decoder] reads came off a network. The decoder therefore
// never allocates on a length it has not first compared against a ceiling —
// a 4 GiB length prefix on a 40-byte packet costs one comparison — and every
// method returns an error rather than panicking, because a panic in a
// per-connection goroutine takes down every other session in the process.
package wire
