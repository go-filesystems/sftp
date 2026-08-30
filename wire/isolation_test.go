package wire_test

import (
	"go/build"
	"os"
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
// those edges appears the move becomes a rewrite, and nobody notices until
// they try it. go-filesystems/nfs made the same split with xdr/ and rpc/.
//
// So the property is checked rather than intended. This is a test and not a
// comment because a comment does not fail the build.
//
// # Why it can skip
//
// It reads the package's SOURCE, so it needs the source tree beside it. The
// emulated CI arches cross-compile the test binaries and run them under QEMU
// in a bare directory, where there is nothing to read — the skip below is that
// case and only that case. It is safe because this is a property of the source
// and not of the target architecture: every native job runs it, so no change
// can land without it having been checked. A skip that could hide a real
// failure would not be worth having.
func TestCodecHasNoDependencies(t *testing.T) {
	if _, err := os.Stat("codec.go"); err != nil {
		t.Skip("source tree not present (cross-compiled binary run elsewhere); " +
			"this check runs on every native job")
	}
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}
	// Imports covers the package proper. The test files' own imports are
	// deliberately not consulted: a test may use whatever it likes without
	// affecting what a consumer of the package inherits.
	for _, imp := range pkg.Imports {
		// A standard-library import path has no dot in its first element;
		// every module path does, because it begins with a hostname.
		first, _, _ := strings.Cut(imp, "/")
		if strings.Contains(first, ".") {
			t.Errorf("wire imports %q; this package must depend on the standard "+
				"library alone, so that an sftp:// client transport can adopt it "+
				"by moving the directory rather than rewriting it", imp)
		}
	}
	t.Logf("wire imports only: %v", pkg.Imports)
}
