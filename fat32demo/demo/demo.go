// Package demo is the real-image harness for the SFTP server.
//
// It exists as a SEPARATE MODULE from the parent because it imports the fat32
// driver. The core module depends on nothing but
// [github.com/go-filesystems/interface] and golang.org/x/crypto — a driver
// dependency in it would be inherited by every consumer that only wanted to
// serve its own filesystem. This is the same split
// [github.com/go-filesystems/nfs] makes with its own fat32demo.
//
// What it is FOR is the verification the module's claims cannot be made
// without: the tests in the parent module prove the server agrees with
// itself, and that is not the same as a real client agreeing with it. This
// harness serves a genuine FAT32 image so that OpenSSH's own `sftp` binary
// can list it, fetch from it and write to it, and so that the bytes it
// receives can be compared with what the driver hands back through ReadFile.
//
// # Keys
//
// Nothing here reads a key from a fixed location, and nothing writes one into
// a repository. Host keys and authorised keys are paths the caller names; if
// no host key is named, an ephemeral one is generated in memory and never
// touches a disk. A private key that a program invents and then saves next to
// its source is a private key that gets committed.
package demo

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/sftp/sshd"
	"golang.org/x/crypto/ssh"
)

// ErrNoImage reports the required -image flag missing. It is a distinct error
// rather than a usage string so the test can assert on it.
var ErrNoImage = errors.New("demo: -image is required")

// ErrNoAuthorizedKeys reports -authorized-keys missing. The server refuses to
// start without one: a server that authorises nobody is useless, and one that
// authorises everybody is a hole. There is deliberately no "allow any key"
// switch, not even for a demo — such switches get copied into deployments.
var ErrNoAuthorizedKeys = errors.New("demo: -authorized-keys is required")

// Options is the parsed command line. It is a struct rather than a set of
// globals so the test can drive Run directly without a process.
type Options struct {
	Image          string
	Addr           string
	HostKey        string
	AuthorizedKeys string
	ReadWrite      bool
	Partition      int
}

// ParseArgs parses argv (without the program name) into Options.
//
// Errors are returned rather than causing an exit so that the caller decides
// what a bad invocation costs; flag output goes to out so a test can read it.
func ParseArgs(args []string, out io.Writer) (Options, error) {
	var o Options
	fs := flag.NewFlagSet("fat32demo", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&o.Image, "image", "", "path to the FAT32 image to serve (required)")
	fs.StringVar(&o.Addr, "addr", "127.0.0.1:2222", "address to listen on; keep it on loopback")
	fs.StringVar(&o.HostKey, "host-key", "", "PEM host key; if empty an ephemeral one is generated in memory")
	fs.StringVar(&o.AuthorizedKeys, "authorized-keys", "", "authorized_keys file naming the permitted client keys (required)")
	fs.BoolVar(&o.ReadWrite, "rw", false, "serve read/write; the default is read-only")
	fs.IntVar(&o.Partition, "partition", -1, "partition index within the image, or -1 for a bare filesystem")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.Image == "" {
		return o, ErrNoImage
	}
	if o.AuthorizedKeys == "" {
		return o, ErrNoAuthorizedKeys
	}
	return o, nil
}

// hostKeys returns the signer set for the options: the named PEM file, or one
// ephemeral key generated in memory.
func hostKeys(o Options) ([]ssh.Signer, error) {
	if o.HostKey == "" {
		k, err := sshd.GenerateHostKey()
		if err != nil {
			return nil, err
		}
		return []ssh.Signer{k}, nil
	}
	pem, err := os.ReadFile(o.HostKey)
	if err != nil {
		return nil, err
	}
	k, err := sshd.ParseHostKey(pem)
	if err != nil {
		return nil, err
	}
	return []ssh.Signer{k}, nil
}

// Build opens the image and assembles the SSH front-end for it, without
// listening.
//
// It is separate from [Run] so that a test can bind its own listener on port
// zero — the only way to run a server in a test without racing on a fixed
// port — and so that a failure to open the image is reported before anything
// is bound.
func Build(o Options) (*sshd.Server, func() error, error) {
	fsys, err := fat32.Open(o.Image, o.Partition)
	if err != nil {
		return nil, nil, fmt.Errorf("open image: %w", err)
	}
	ak, err := os.ReadFile(o.AuthorizedKeys)
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}
	keys, err := sshd.ParseAuthorizedKeys(ak)
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}
	hk, err := hostKeys(o)
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}

	var opts []sftp.Option
	if o.ReadWrite {
		opts = append(opts, sftp.ReadWrite())
	}
	srv, err := sftp.New(fsys, opts...)
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}
	d, err := sshd.New(srv, sshd.Config{HostKeys: hk, AuthorizedKeys: keys})
	if err != nil {
		fsys.Close()
		return nil, nil, err
	}
	// The closer is returned rather than deferred inside: the caller owns the
	// image for as long as the server serves it, and closing it underneath a
	// live session would surface as I/O errors on the wire instead of a clean
	// shutdown.
	return d, fsys.Close, nil
}

// Run builds the server and serves until it is closed.
func Run(o Options) error {
	d, closeFS, err := Build(o)
	if err != nil {
		return err
	}
	defer closeFS()
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return err
	}
	// The listening address is printed because -addr may name port 0, and a
	// caller that asked for an ephemeral port has no other way to learn which
	// one it got.
	fmt.Printf("serving %s on %s\n", o.Image, ln.Addr())
	return d.Serve(ln)
}

// Main is the whole command, returning a process exit code.
//
// main.go is one call to this, so that everything the command does is in a
// package the coverage gate covers.
func Main(args []string, out, errOut io.Writer) int {
	o, err := ParseArgs(args, errOut)
	if err != nil {
		// flag.ContinueOnError has already printed the usage for a parse
		// error; ErrHelp is a request, not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(errOut, err)
		return 2
	}
	if err := Run(o); err != nil && !errors.Is(err, sshd.ErrServerClosed) {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}
