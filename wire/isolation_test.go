package wire_test

import (
	"go/build"
	"strings"
	"testing"
)

// TestCodecHasNoDependencies enforces the split this package exists for.
//
// The whole reason the codec is its own package is that an sftp:// CLIENT
// transport may one day live in go-streamkit and would share this encoding.
// That extraction is a move rather than a rewrite only for as long as this
// package depends on nothing but the standard library — not on the filesystem
// interface, not on the server, not on golang.org/x/crypto. The moment one of
// those edges appears, the move becomes a rewrite, and nobody notices until
// they try it. go-filesystems/nfs made the same split with xdr/ and rpc/.
//
// So the property is checked rather than intended. This is a test and not a
// comment because a comment does not fail the build.
func TestCodecHasNoDependencies(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}
	// Imports covers the package proper; the in-package test file's own
	// imports are deliberately not consulted, since a test may use whatever
	// it likes without affecting what a consumer inherits.
	for _, imp := range pkg.Imports {
		// A standard-library path has no dot in its first element; every
		// module path does, because it starts with a hostname.
		first, _, _ := strings.Cut(imp, "/")
		if strings.Contains(first, ".") {
			t.Errorf("wire imports %q; this package must depend on the standard "+
				"library alone, so that an sftp:// client transport can adopt it "+
				"by moving the directory rather than rewriting it", imp)
		}
	}
	t.Logf("wire imports only: %v", pkg.Imports)
}
