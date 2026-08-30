package sftp

import (
	"io"

	filesystem "github.com/go-filesystems/interface"
)

// WritableFile is the capability that removes this module's write wall.
//
// It is an open file that can be written AT AN OFFSET, which is what
// SSH_FXP_WRITE asks for and what the base
// [github.com/go-filesystems/interface.Filesystem] contract cannot express:
// that contract has WriteFile, which replaces a file whole, so serving a
// 32 KiB write into the middle of a 100 MiB file means reading 100 MiB,
// splicing, and writing 100 MiB back. See the package documentation for the
// measurement.
//
// The interface is declared HERE, structurally, rather than imported. That is
// not a fork of the contract, it is how the transition works: the shape below
// is the one being added to the interface module as filesystem.WritableFile,
// every method takes and returns none but builtin types, and Go matches
// method sets structurally in that case — so a driver whose File implements
// the real filesystem.WritableFile satisfies this one automatically, today,
// with no version pin and no reflection. (This is exactly the problem
// [github.com/go-filesystems/nfs] had to solve with a reflective probe,
// because filesystem.File's own return type appeared in the signature. Here
// it does not.)
//
// This module does not implement it for any driver. It probes for it, uses it
// when present, and falls back with a documented cost when absent.
type WritableFile interface {
	filesystem.File
	io.WriterAt

	// Truncate resizes the open file. SSH_FXP_OPEN with SSH_FXF_TRUNC and
	// SSH_FXP_FSETSTAT with a size attribute both need it.
	Truncate(size int64) error

	// Sync flushes the driver's buffers for this file. SFTP has no
	// fsync in version 3, so this is called on CLOSE — which is the last
	// moment at which a failure can still be reported to the client rather
	// than discovered by whoever opens the image next.
	Sync() error
}

// openerFor returns the driver's random-access opener, or nil when it has
// none.
//
// A plain type assertion is enough because the capability is published in
// [github.com/go-filesystems/interface] v0.2.0 and this module requires that
// version. At the time of writing no driver in the fleet implements it, so
// this returns nil for every real filesystem and the fallback path in
// [Server] is the one that actually runs — which is precisely why the
// fallback's cost is measured rather than assumed.
func openerFor(fsys filesystem.Filesystem) filesystem.Opener {
	o, ok := fsys.(filesystem.Opener)
	if !ok {
		return nil
	}
	return o
}
