package demo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	fat32 "github.com/go-filesystems/fat32"
)

// This file is the end-to-end verification, and it is the reason this module
// exists. Everything in the parent module's test suite proves the server
// agrees with ITSELF: its own client helper speaks its own codec. That is
// necessary and it is not sufficient. Nothing there would catch a byte order
// this repository is simply consistently wrong about, or a packet OpenSSH
// rejects for a reason the protocol document does not spell out.
//
// So this drives the `sftp` binary that ships with OpenSSH, against an image
// that the fat32 driver actually formatted, and compares what comes back with
// what the driver returns through ReadFile. The comparison is on CONTENT —
// sha256 of a megabyte, and the exact bytes at a non-zero offset — not on the
// client's exit status, because a client can exit 0 having fetched nothing.
//
// # Keys
//
// Every key is generated into t.TempDir(), which is outside every repository
// and is removed when the test ends. That is the right default HERE, where
// the artefact is a throwaway credential that must not outlive the test —
// as opposed to a diagnostic artefact someone needs to open afterwards.
// No key is written into this repository, and none is generated at a fixed
// path.

// keyBits is the payload used to make a file whose content is unmistakable if
// an offset is off by even one byte: every 16-byte group differs from its
// neighbours.
func keyBits(n int) []byte {
	b := make([]byte, 0, n*16)
	for i := range n {
		b = append(b, fmt.Sprintf("%015d\n", i)...)
	}
	return b
}

// buildImage formats a real FAT32 image and returns its path plus the content
// written to it.
func buildImage(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	img := filepath.Join(dir, "disk.img")
	fsys, err := fat32.Format(img, 64<<20, fat32.FormatConfig{Label: "LIVE"})
	if err != nil {
		t.Fatalf("fat32.Format: %v", err)
	}
	big := keyBits(65536) // 1 MiB, and every line names its own offset
	if err := fsys.WriteFile("/HELLO.TXT", []byte("hello from a real image\n"), 0o644); err != nil {
		t.Fatalf("WriteFile HELLO.TXT: %v", err)
	}
	if err := fsys.MkDir("/SUB", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := fsys.WriteFile("/SUB/BIG.BIN", big, 0o644); err != nil {
		t.Fatalf("WriteFile BIG.BIN: %v", err)
	}
	if err := fsys.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return img, big
}

// genClientKey writes an ed25519 keypair into dir with ssh-keygen and returns
// the private key path and the authorized_keys path.
//
// ssh-keygen rather than this module's own generator because the point is to
// exercise the format a real client presents, produced by the real tool.
func genClientKey(t *testing.T, dir string) (priv, authorized string) {
	t.Helper()
	priv = filepath.Join(dir, "id_ed25519")
	// -N "" is an empty passphrase on the command line. It is not a secret:
	// it is the absence of one, for a key that exists for the duration of
	// this test and is generated fresh every run.
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sftp-live-test", "-f", priv)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return priv, priv + ".pub"
}

// serve starts the demo server on an ephemeral loopback port and returns the
// address. Everything is torn down through t.Cleanup, so no process, listener
// or open image outlives the test even if it fails.
func serve(t *testing.T, img, authorized string) string {
	t.Helper()
	d, closeFS, err := Build(Options{
		Image:          img,
		AuthorizedKeys: authorized,
		ReadWrite:      true,
		Partition:      -1,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeFS()
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Serve(ln) }()
	t.Cleanup(func() {
		_ = d.Close()
		<-done
		_ = closeFS()
	})
	return ln.Addr().String()
}

// runSFTP drives the real OpenSSH client over a batch file.
func runSFTP(t *testing.T, addr, priv string, script string, workdir string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	batch := filepath.Join(workdir, "batch.txt")
	if err := os.WriteFile(batch, []byte(script), 0o600); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	cmd := exec.Command("sftp",
		"-b", batch,
		"-i", priv,
		"-P", port,
		"-o", "StrictHostKeyChecking=no",
		// The host key is ephemeral, so there is nothing to remember and
		// nothing that should be written into the developer's known_hosts.
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=10",
		"tester@"+host,
	)
	cmd.Dir = workdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sftp failed: %v\n--- output ---\n%s", err, out)
	}
	return string(out)
}

// TestLiveOpenSSHClient is the proof.
func TestLiveOpenSSHClient(t *testing.T) {
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skip("no OpenSSH sftp client on this machine")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	dir := t.TempDir()
	img, big := buildImage(t, dir)
	priv, authorized := genClientKey(t, dir)
	addr := serve(t, img, authorized)

	// ------------------------------------------------------------------
	// ls, and a whole-file get
	// ------------------------------------------------------------------
	out := runSFTP(t, addr, priv, strings.Join([]string{
		"ls -l /",
		"ls -l /SUB",
		"get /HELLO.TXT hello.got",
		"get /SUB/BIG.BIN big.got",
		"",
	}, "\n"), dir)

	for _, want := range []string{"HELLO.TXT", "SUB", "BIG.BIN"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls output does not mention %q:\n%s", want, out)
		}
	}

	gotHello, err := os.ReadFile(filepath.Join(dir, "hello.got"))
	if err != nil {
		t.Fatalf("read fetched HELLO.TXT: %v", err)
	}
	if string(gotHello) != "hello from a real image\n" {
		t.Fatalf("HELLO.TXT over SFTP = %q", gotHello)
	}

	gotBig, err := os.ReadFile(filepath.Join(dir, "big.got"))
	if err != nil {
		t.Fatalf("read fetched BIG.BIN: %v", err)
	}

	// The comparison that matters: the sha256 the client received against
	// the sha256 of what the DRIVER returns from the same image, read
	// directly. Not against the bytes this test wrote — that would only
	// prove the test is self-consistent.
	fsys, err := fat32.Open(img, -1)
	if err != nil {
		t.Fatalf("reopen image: %v", err)
	}
	defer fsys.Close()
	direct, err := fsys.ReadFile("/SUB/BIG.BIN")
	if err != nil {
		t.Fatalf("driver ReadFile: %v", err)
	}
	overSFTP := sha256.Sum256(gotBig)
	fromDriver := sha256.Sum256(direct)
	t.Logf("sha256 over SFTP    : %s (%d bytes)", hex.EncodeToString(overSFTP[:]), len(gotBig))
	t.Logf("sha256 from ReadFile: %s (%d bytes)", hex.EncodeToString(fromDriver[:]), len(direct))
	if overSFTP != fromDriver {
		t.Fatalf("SFTP bytes differ from what the driver returns")
	}
	if !bytes.Equal(direct, big) {
		t.Fatalf("driver does not return what was written")
	}

	// ------------------------------------------------------------------
	// A read at a NON-ZERO offset. `get` starts at zero, so a server that
	// ignored the offset entirely would still pass everything above; this
	// is what catches it. reget resumes into an existing partial file,
	// which makes the client issue reads starting at that file's length.
	// ------------------------------------------------------------------
	const prefix = 700_000
	partial := filepath.Join(dir, "resume.got")
	if err := os.WriteFile(partial, direct[:prefix], 0o644); err != nil {
		t.Fatalf("seed partial: %v", err)
	}
	runSFTP(t, addr, priv, "reget /SUB/BIG.BIN resume.got\n", dir)
	resumed, err := os.ReadFile(partial)
	if err != nil {
		t.Fatalf("read resumed: %v", err)
	}
	if !bytes.Equal(resumed, direct) {
		t.Fatalf("reget from offset %d produced %d bytes, want %d identical",
			prefix, len(resumed), len(direct))
	}
	t.Logf("reget resumed from offset %d and reassembled the file exactly", prefix)

	// ------------------------------------------------------------------
	// A write, through the client, landing in the image.
	// ------------------------------------------------------------------
	payload := keyBits(4096) // 64 KiB, several SFTP write packets
	src := filepath.Join(dir, "upload.bin")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatalf("write upload source: %v", err)
	}
	runSFTP(t, addr, priv, "put upload.bin /UP.BIN\n", dir)

	// Read it back through the driver, from a fresh open of the image, so
	// the assertion is about what reached the medium and not about any
	// state the live server still holds.
	fresh, err := fat32.Open(img, -1)
	if err != nil {
		t.Fatalf("reopen after put: %v", err)
	}
	defer fresh.Close()
	stored, err := fresh.ReadFile("/UP.BIN")
	if err != nil {
		t.Fatalf("ReadFile /UP.BIN after put: %v", err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("uploaded %d bytes, image holds %d and they differ", len(payload), len(stored))
	}
	up := sha256.Sum256(stored)
	t.Logf("uploaded %d bytes; sha256 in the image: %s", len(stored), hex.EncodeToString(up[:]))
}

// TestLiveReadOnlyRefusesAWrite proves the read-only default is enforced
// against a real client, not merely against this repository's own.
func TestLiveReadOnlyRefusesAWrite(t *testing.T) {
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skip("no OpenSSH sftp client on this machine")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	dir := t.TempDir()
	img, _ := buildImage(t, dir)
	priv, authorized := genClientKey(t, dir)

	d, closeFS, err := Build(Options{Image: img, AuthorizedKeys: authorized, Partition: -1})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeFS()
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Serve(ln) }()
	t.Cleanup(func() { _ = d.Close(); <-done; _ = closeFS() })

	src := filepath.Join(dir, "nope.bin")
	if err := os.WriteFile(src, []byte("must not land"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	batch := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(batch, []byte("put nope.bin /NOPE.BIN\n"), 0o600); err != nil {
		t.Fatalf("batch: %v", err)
	}
	cmd := exec.Command("sftp", "-b", batch, "-i", priv, "-P", port,
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
		"tester@127.0.0.1")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("put succeeded against a read-only export:\n%s", out)
	}
	t.Logf("read-only export refused the put, as it must: %s", strings.TrimSpace(string(out)))

	// And the image must not contain it.
	fresh, err := fat32.Open(img, -1)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer fresh.Close()
	if _, err := fresh.ReadFile("/NOPE.BIN"); err == nil {
		t.Fatal("/NOPE.BIN exists in the image; the read-only export let a write through")
	}
}
