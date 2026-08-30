package demo

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// These are the unit tests for the command's own surface: argument parsing,
// key loading, and the failure paths of Build. The live tests next door prove
// the happy path end to end with a real client; what is left is every way a
// person can invoke this wrongly, because those are the paths that decide
// whether a mistake is reported or swallowed.

func TestParseArgs(t *testing.T) {
	var out bytes.Buffer
	o, err := ParseArgs([]string{
		"-image", "/tmp/x.img",
		"-authorized-keys", "/tmp/ak",
		"-addr", "127.0.0.1:9",
		"-host-key", "/tmp/hk",
		"-rw",
		"-partition", "2",
	}, &out)
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if o.Image != "/tmp/x.img" || o.AuthorizedKeys != "/tmp/ak" || o.Addr != "127.0.0.1:9" ||
		o.HostKey != "/tmp/hk" || !o.ReadWrite || o.Partition != 2 {
		t.Fatalf("parsed %+v", o)
	}
}

func TestParseArgsDefaults(t *testing.T) {
	var out bytes.Buffer
	o, err := ParseArgs([]string{"-image", "i", "-authorized-keys", "a"}, &out)
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	// Read-only by default: an accidental write to a forensic or build
	// artefact is unrecoverable, so the safe direction is the default.
	if o.ReadWrite {
		t.Error("default must be read-only")
	}
	// Loopback by default, for the reason the package documentation gives.
	if !strings.HasPrefix(o.Addr, "127.0.0.1:") {
		t.Errorf("default addr = %q, want loopback", o.Addr)
	}
	if o.Partition != -1 {
		t.Errorf("default partition = %d, want -1", o.Partition)
	}
}

func TestParseArgsRequiredFlags(t *testing.T) {
	var out bytes.Buffer
	if _, err := ParseArgs([]string{"-authorized-keys", "a"}, &out); !errors.Is(err, ErrNoImage) {
		t.Errorf("missing -image gave %v, want ErrNoImage", err)
	}
	// There is deliberately no "authorise anybody" switch, so the absence of
	// -authorized-keys must be an error and not a permissive default.
	if _, err := ParseArgs([]string{"-image", "i"}, &out); !errors.Is(err, ErrNoAuthorizedKeys) {
		t.Errorf("missing -authorized-keys gave %v, want ErrNoAuthorizedKeys", err)
	}
}

func TestParseArgsBadFlag(t *testing.T) {
	var out bytes.Buffer
	if _, err := ParseArgs([]string{"-nope"}, &out); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if out.Len() == 0 {
		t.Error("nothing written to the supplied output; usage must be visible")
	}
}

func TestParseArgsHelp(t *testing.T) {
	var out bytes.Buffer
	if _, err := ParseArgs([]string{"-h"}, &out); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h gave %v, want flag.ErrHelp", err)
	}
}

// smallImage formats a minimal real image for the Build tests.
func smallImage(t *testing.T, dir string) string {
	t.Helper()
	img := filepath.Join(dir, "small.img")
	fsys, err := fat32.Format(img, 16<<20, fat32.FormatConfig{Label: "SMALL"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fsys.WriteFile("/A.TXT", []byte("a"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fsys.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return img
}

func TestHostKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	priv, _ := genClientKey(t, dir) // an ed25519 PEM is an ed25519 PEM
	keys, err := hostKeys(Options{HostKey: priv})
	if err != nil {
		t.Fatalf("hostKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
}

func TestHostKeyEphemeralWhenUnset(t *testing.T) {
	// The point of the empty case: no path is consulted, nothing is written,
	// and the key exists only in memory for this process.
	keys, err := hostKeys(Options{})
	if err != nil {
		t.Fatalf("hostKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
}

func TestHostKeyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := hostKeys(Options{HostKey: filepath.Join(dir, "absent")}); err == nil {
		t.Error("a missing host key file was accepted")
	}
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hostKeys(Options{HostKey: junk}); err == nil {
		t.Error("an unparseable host key was accepted")
	}
}

func TestBuildFailures(t *testing.T) {
	dir := t.TempDir()
	img := smallImage(t, dir)
	_, authorized := genClientKey(t, dir)

	t.Run("missing image", func(t *testing.T) {
		if _, _, err := Build(Options{
			Image: filepath.Join(dir, "absent.img"), AuthorizedKeys: authorized, Partition: -1,
		}); err == nil {
			t.Fatal("a missing image was accepted")
		}
	})

	t.Run("missing authorized_keys", func(t *testing.T) {
		if _, _, err := Build(Options{
			Image: img, AuthorizedKeys: filepath.Join(dir, "absent"), Partition: -1,
		}); err == nil {
			t.Fatal("a missing authorized_keys was accepted")
		}
	})

	t.Run("unparseable authorized_keys", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.pub")
		if err := os.WriteFile(bad, []byte("ssh-ed25519 !!!not-base64!!! x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Build(Options{Image: img, AuthorizedKeys: bad, Partition: -1}); err == nil {
			t.Fatal("an unparseable authorized_keys was accepted")
		}
	})

	t.Run("empty authorized_keys", func(t *testing.T) {
		// An empty file parses to zero keys, which sshd.New must refuse:
		// a server that authorises nobody would accept connections and
		// reject every one of them, which looks like a network fault.
		empty := filepath.Join(dir, "empty.pub")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Build(Options{Image: img, AuthorizedKeys: empty, Partition: -1}); err == nil {
			t.Fatal("an empty authorized_keys was accepted")
		}
	})

	t.Run("bad host key", func(t *testing.T) {
		junk := filepath.Join(dir, "junkhk")
		if err := os.WriteFile(junk, []byte("nope"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Build(Options{
			Image: img, AuthorizedKeys: authorized, HostKey: junk, Partition: -1,
		}); err == nil {
			t.Fatal("a bad host key was accepted")
		}
	})
}

func TestBuildSucceedsAndClosesCleanly(t *testing.T) {
	dir := t.TempDir()
	img := smallImage(t, dir)
	_, authorized := genClientKey(t, dir)
	d, closeFS, err := Build(Options{
		Image: img, AuthorizedKeys: authorized, ReadWrite: true, Partition: -1,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := closeFS(); err != nil {
		t.Errorf("closeFS: %v", err)
	}
}

func TestRunReportsABadImage(t *testing.T) {
	dir := t.TempDir()
	_, authorized := genClientKey(t, dir)
	err := Run(t.Context(), Options{
		Image: filepath.Join(dir, "absent.img"), AuthorizedKeys: authorized,
		Addr: "127.0.0.1:0", Partition: -1,
	}, io.Discard)
	if err == nil {
		t.Fatal("Run accepted a missing image")
	}
}

func TestRunReportsABadAddress(t *testing.T) {
	dir := t.TempDir()
	img := smallImage(t, dir)
	_, authorized := genClientKey(t, dir)
	// A port that cannot be parsed: the failure must come from Listen, after
	// the image opened successfully, which is the ordering Build guarantees.
	err := Run(t.Context(), Options{
		Image: img, AuthorizedKeys: authorized, Addr: "127.0.0.1:notaport", Partition: -1,
	}, io.Discard)
	if err == nil {
		t.Fatal("Run accepted an unusable address")
	}
}

// TestRunServesUntilCancelled covers the success path of Run: it comes up,
// announces the address it actually bound, and stops cleanly — returning nil,
// not an error — when the context is cancelled. The nil is the contract a
// person pressing Ctrl-C relies on.
func TestRunServesUntilCancelled(t *testing.T) {
	dir := t.TempDir()
	img := smallImage(t, dir)
	_, authorized := genClientKey(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			Image: img, AuthorizedKeys: authorized, Addr: "127.0.0.1:0",
			ReadWrite: true, Partition: -1,
		}, &out)
	}()

	// The announced address is the only way to learn the ephemeral port, so
	// waiting for it is also the test that the announcement happens.
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s := out.String(); strings.Contains(s, " on ") {
			addr = strings.TrimSpace(s[strings.LastIndex(s, " on ")+4:])
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("Run never announced a listening address")
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial announced address %q: %v", addr, err)
	}
	c.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation; a clean stop must be nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// lockedBuffer is a bytes.Buffer safe to read while Run writes to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestSeamFailures exercises the two branches that no argument can provoke:
// a driver handing back a nil filesystem, and a CSPRNG that has stopped
// answering. See the comment on openImage and generateHostKey.
func TestSeamFailures(t *testing.T) {
	dir := t.TempDir()
	img := smallImage(t, dir)
	_, authorized := genClientKey(t, dir)

	t.Run("nil filesystem from the driver", func(t *testing.T) {
		orig := openImage
		t.Cleanup(func() { openImage = orig })
		openImage = func(string, int) (filesystem.Filesystem, error) { return nil, nil }
		_, _, err := Build(Options{Image: img, AuthorizedKeys: authorized, Partition: -1})
		if !errors.Is(err, sftp.ErrNilFilesystem) {
			t.Fatalf("Build error = %v, want sftp.ErrNilFilesystem "+
				"(and it must not panic in a cleanup path)", err)
		}
	})

	t.Run("host key generation fails", func(t *testing.T) {
		orig := generateHostKey
		t.Cleanup(func() { generateHostKey = orig })
		want := errors.New("no entropy")
		generateHostKey = func() (ssh.Signer, error) { return nil, want }
		_, _, err := Build(Options{Image: img, AuthorizedKeys: authorized, Partition: -1})
		if !errors.Is(err, want) {
			t.Fatalf("Build error = %v, want %v", err, want)
		}
	})
}

func TestMainExitCodes(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer

	// A usage error is 2, and says what was wrong.
	if code := Main(t.Context(), []string{"-image", "x"}, &out, &errOut); code != 2 {
		t.Errorf("missing -authorized-keys exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "authorized-keys") {
		t.Errorf("stderr = %q, want it to name the missing flag", errOut.String())
	}

	// -h is a request, not a failure.
	errOut.Reset()
	if code := Main(t.Context(), []string{"-h"}, &out, &errOut); code != 0 {
		t.Errorf("-h exit code = %d, want 0", code)
	}

	// A runtime failure is 1.
	errOut.Reset()
	_, authorized := genClientKey(t, dir)
	code := Main(t.Context(), []string{
		"-image", filepath.Join(dir, "absent.img"),
		"-authorized-keys", authorized,
		"-addr", "127.0.0.1:0",
	}, &out, &errOut)
	if code != 1 {
		t.Errorf("missing image exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "open image") {
		t.Errorf("stderr = %q, want it to name the failure", errOut.String())
	}
}

// TestMainCleanShutdownIsZero covers the success return: a server stopped by
// its context exits 0, because that is what a person pressing Ctrl-C meant.
func TestMainCleanShutdownIsZero(t *testing.T) {
	dir := t.TempDir()
	img := smallImage(t, dir)
	_, authorized := genClientKey(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	var out lockedBuffer
	var errOut bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Main(ctx, []string{
			"-image", img, "-authorized-keys", authorized, "-addr", "127.0.0.1:0",
		}, &out, &errOut)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), " on ") {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("clean shutdown exit code = %d, want 0 (stderr: %s)", code, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Main did not return after cancellation")
	}
}
