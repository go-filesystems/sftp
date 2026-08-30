package sftp

import (
	filesystem "github.com/go-filesystems/interface"
)

// WritableFile is the capability that removes this module's write wall.
//
// It is an open file that can be written AT AN OFFSET, which is exactly what
// SSH_FXP_WRITE(handle, offset, data) asks for, and exactly what the base
// [github.com/go-filesystems/interface.Filesystem] contract cannot express:
// that contract's only write is WriteFile, which replaces a file WHOLE. So
// serving a 32 KiB write into the middle of a 100 MiB file without this
// capability means reading 100 MiB, splicing 32 KiB in, and writing 100 MiB
// back — per request. See [writeSplice] and the README for the measurement of
// both paths.
//
// It is an alias for [github.com/go-filesystems/interface.WritableFile],
// published in interface v0.3.0, rather than a local redeclaration. The alias
// exists purely so that this package's own documentation has somewhere to
// explain what the capability means TO AN SFTP SERVER — which is not the same
// question as what it means to the interface module — while the type itself
// stays the fleet's one canonical definition. A driver satisfies it or does
// not; there is no second contract here to drift out of sync.
//
// This module never implements it. It probes for it on the File returned by
// [github.com/go-filesystems/interface.Opener], uses it when present, and
// falls back to read-modify-write with a documented cost when absent.
type WritableFile = filesystem.WritableFile

// openerFor returns the driver's random-access opener, or nil when it has none.
//
// A plain type assertion is enough — no reflection. This is worth contrasting
// with [github.com/go-filesystems/nfs], which needs a reflective shape probe
// for the same capability: that module deliberately does not depend on the
// interface module version that declares Opener, so it declares its own
// structural twin, and Go matches method sets by TYPE IDENTITY, meaning a
// driver returning filesystem.File would not satisfy a locally declared
// Opener. This module takes the dependency instead (interface v0.3.0), so the
// assertion is the real one and costs nothing.
//
// A driver with no Opener is not an error: the caller falls back to ReadFile
// and slices, which is correct and quadratic. [Server] documents the cost.
func openerFor(fsys filesystem.Filesystem) filesystem.Opener {
	o, ok := fsys.(filesystem.Opener)
	if !ok {
		return nil
	}
	return o
}
