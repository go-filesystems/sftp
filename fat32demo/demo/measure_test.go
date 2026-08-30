package demo

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/sftp/sshd"
	"golang.org/x/crypto/ssh"
)

// This file measures the two write paths against each other on a REAL image,
// through the REAL client, because the difference between them is the single
// most consequential performance fact about this module and it should not be
// asserted from the shape of the code.
//
//   - With [github.com/go-filesystems/interface.WritableFile],
//     SSH_FXP_WRITE(handle, offset, data) is one positional write. Cost is
//     O(len(data)) per request, so O(n) to stream a file.
//   - Without it, the only write the base Filesystem contract offers is
//     WriteFile(path, data, perm), which replaces the file WHOLE. Serving a
//     write at an offset therefore means read-all, splice, write-all: O(n) per
//     request, and so O(n²) to stream a file in fixed-size chunks.
//     go-filesystems/nfs measured the identical construction at 90 kB/s, with
//     a soft-mounted client giving up with EIO partway through.
//
// The measurement is deliberately NOT a Go benchmark. A benchmark would time
// the server's internals; what matters is how long `put` takes, which includes
// the client's own 32 KiB chunking and round-trip behaviour. So this times the
// real client and reports kB/s.
//
// It runs as a normal test, and it asserts only the ORDER of the two results,
// never an absolute threshold. An absolute number would be a machine-speed
// assertion that fails on a loaded CI runner and teaches everyone to ignore
// it; the ordering is the claim the design actually makes.

// baseOnly hides every optional capability of the filesystem it wraps.
//
// Embedding the INTERFACE, not the concrete driver, is what makes this work,
// and it is load-bearing: filesystem.Filesystem has no OpenFile, so the
// embedded method set is exactly the base contract and a type assertion to
// filesystem.Opener fails. Embedding the concrete driver type would promote
// OpenFile and quietly measure the fast path twice.
type baseOnly struct{ filesystem.Filesystem }

// serveFS runs an SSH front-end for an already-open filesystem on an
// ephemeral loopback port.
func serveFS(t *testing.T, fsys filesystem.Filesystem, authorized string) string {
	t.Helper()
	ak, err := os.ReadFile(authorized)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	keys, err := sshd.ParseAuthorizedKeys(ak)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	hk, err := sshd.GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey: %v", err)
	}
	srv, err := sftp.New(fsys, sftp.ReadWrite())
	if err != nil {
		t.Fatalf("sftp.New: %v", err)
	}
	d, err := sshd.New(srv, sshd.Config{
		HostKeys:       []ssh.Signer{hk},
		AuthorizedKeys: keys,
	})
	if err != nil {
		t.Fatalf("sshd.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Serve(ln) }()
	t.Cleanup(func() { _ = d.Close(); <-done })
	return ln.Addr().String()
}

// measurePut times a `put` through the real client.
func measurePut(t *testing.T, addr, priv, dir, remote string, payload []byte) time.Duration {
	t.Helper()
	src := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	start := time.Now()
	runSFTP(t, addr, priv, fmt.Sprintf("put payload.bin %s\n", remote), dir)
	return time.Since(start)
}

// rate formats a throughput.
func rate(n int, d time.Duration) string {
	return fmt.Sprintf("%.0f kB/s", (float64(n)/1024)/d.Seconds())
}

// TestMeasureBothWritePaths is the measurement the README quotes.
func TestMeasureBothWritePaths(t *testing.T) {
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skip("no OpenSSH sftp client on this machine")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	// 2 MiB, matching the size go-filesystems/nfs used for its own 90 kB/s
	// figure so the two numbers are comparable.
	const size = 2 << 20
	payload := bytes.Repeat([]byte("0123456789abcdef"), size/16)

	dir := t.TempDir()
	priv, authorized := genClientKey(t, dir)

	// --- Path A: WritableFile, the positional write -------------------
	imgA := filepath.Join(dir, "fast.img")
	fsA, err := fat32.Format(imgA, 64<<20, fat32.FormatConfig{Label: "FAST"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if _, ok := fsA.(filesystem.Opener); !ok {
		t.Skip("this fat32 build has no Opener; nothing to compare")
	}
	addrA := serveFS(t, fsA, authorized)
	fast := measurePut(t, addrA, priv, dir, "/FAST.BIN", payload)
	if err := fsA.Close(); err != nil {
		t.Fatalf("close fast image: %v", err)
	}

	// --- Path B: the same driver, capability hidden -------------------
	imgB := filepath.Join(dir, "slow.img")
	fsB, err := fat32.Format(imgB, 64<<20, fat32.FormatConfig{Label: "SLOW"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	wrapped := baseOnly{fsB}
	if _, ok := filesystem.Filesystem(wrapped).(filesystem.Opener); ok {
		t.Fatal("baseOnly still exposes Opener; the comparison would be meaningless")
	}
	addrB := serveFS(t, wrapped, authorized)
	slow := measurePut(t, addrB, priv, dir, "/SLOW.BIN", payload)
	if err := fsB.Close(); err != nil {
		t.Fatalf("close slow image: %v", err)
	}

	t.Logf("write %d bytes in 32 KiB client chunks:", size)
	t.Logf("  WritableFile (positional)   : %8s  %s", fast.Round(time.Millisecond), rate(size, fast))
	t.Logf("  WriteFile fallback (splice) : %8s  %s", slow.Round(time.Millisecond), rate(size, slow))
	t.Logf("  ratio                       : %.1fx", float64(slow)/float64(fast))

	// The only assertion: the positional path must be the faster one. A
	// threshold on the ratio would be a claim about this machine, not about
	// the design.
	if slow <= fast {
		t.Errorf("read-modify-write (%v) was not slower than positional write (%v); "+
			"the capability probe is probably not selecting the path it claims", slow, fast)
	}

	// And both must have produced the identical file, because a fast path
	// that is fast by being wrong is the failure this whole comparison
	// would otherwise invite.
	for _, tc := range []struct{ img, name string }{{imgA, "/FAST.BIN"}, {imgB, "/SLOW.BIN"}} {
		fsys, err := fat32.Open(tc.img, -1)
		if err != nil {
			t.Fatalf("reopen %s: %v", tc.img, err)
		}
		got, err := fsys.ReadFile(tc.name)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", tc.name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("%s: image holds %d bytes, want %d identical", tc.name, len(got), len(payload))
		}
		fsys.Close()
	}
}

// TestFallbackIsQuadratic measures the SHAPE of the fallback's cost, not just
// that it is slower.
//
// "Slower" is a weak claim and the wrong one. The fallback is slower by a
// factor that GROWS WITH THE FILE, because each of the n/32Ki requests rewrites
// the whole file: doubling the size doubles the number of requests and doubles
// the cost of each, so the total quadruples. That is the property that makes it
// unusable on a real image rather than merely unfortunate, and it is the reason
// the module documents the fallback as a wall instead of a slow path.
//
// It is measured rather than deduced. The assertion is that doubling the size
// costs MORE than doubling the time — a linear path would land at 2.0x, and
// anything meaningfully above that is the quadratic term showing up. The bound
// is deliberately loose (>2.4x) because the constant is a real disk on a shared
// runner; the point is the trend, not a number.
func TestFallbackIsQuadratic(t *testing.T) {
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skip("no OpenSSH sftp client on this machine")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	dir := t.TempDir()
	priv, authorized := genClientKey(t, dir)

	sizes := []int{1 << 20, 2 << 20, 4 << 20}
	took := make([]time.Duration, len(sizes))
	for i, size := range sizes {
		img := filepath.Join(dir, fmt.Sprintf("q%d.img", i))
		fsys, err := fat32.Format(img, 64<<20, fat32.FormatConfig{Label: "QUAD"})
		if err != nil {
			t.Fatalf("Format: %v", err)
		}
		addr := serveFS(t, baseOnly{fsys}, authorized)
		took[i] = measurePut(t, addr, priv, dir, "/Q.BIN",
			bytes.Repeat([]byte("0123456789abcdef"), size/16))
		if err := fsys.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		t.Logf("splice fallback, %4d KiB: %8s  %s",
			size/1024, took[i].Round(time.Millisecond), rate(size, took[i]))
	}

	for i := 1; i < len(sizes); i++ {
		ratio := float64(took[i]) / float64(took[i-1])
		t.Logf("  %d KiB -> %d KiB: %.2fx the time for 2x the data",
			sizes[i-1]/1024, sizes[i]/1024, ratio)
		if ratio < 2.4 {
			t.Errorf("doubling the data cost only %.2fx the time; that is linear, "+
				"so the fallback is not doing the whole-file rewrite it claims", ratio)
		}
	}
}
