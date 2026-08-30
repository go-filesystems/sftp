// Package sshd is the SSH front-end for
// [github.com/go-filesystems/sftp]: it authenticates clients with public
// keys, accepts the "sftp" subsystem, and hands the resulting channel to the
// SFTP server.
//
// # What is not written here
//
// No cryptography. The key exchange, the ciphers, the MACs and the
// authentication protocol all come from [golang.org/x/crypto/ssh], which is
// the reference implementation for Go and is pure Go, so CGO_ENABLED=0 holds
// through this package. Reimplementing any of it would be a way to acquire
// every mistake the last thirty years of SSH has already made. What this
// package contributes is the ten lines of policy around it — which keys, which
// channel type, which subsystem — and refusing everything else.
//
// # Keys come from the caller
//
// [Config] takes host keys and authorised keys as values. This package never
// reads ~/.ssh, never consults an environment variable, and never writes a
// key anywhere. That is the isolation model the module is built for: one
// image, one process, one key set, chosen by whoever starts it. A helper to
// parse the usual file formats is provided ([ParseHostKey],
// [ParseAuthorizedKeys]) so that a caller who does keep keys on disk reads
// them itself and stays in control of where they live.
//
// There is no way to disable authentication. A server with no authorised keys
// refuses to start rather than accepting everyone, because "no keys
// configured" and "everyone may connect" look identical in a config file and
// only one of them is ever intended.
package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// keyRand is the entropy source for [GenerateHostKey], indirected so a test
// can prove it REPORTS a failed CSPRNG rather than returning a key derived
// from whatever it got. There is no other way to reach that branch, and it is
// the one branch where the wrong behaviour would be silent.
var keyRand io.Reader = rand.Reader

// acceptChannel is ssh.NewChannel.Accept, indirected for the same reason:
// acceptance fails only when the connection dies between the peer's channel
// request and the reply, which cannot be provoked from outside without a
// race. The branch still has to be shown to close cleanly rather than leak
// the connection.
var acceptChannel = func(nc ssh.NewChannel) (ssh.Channel, <-chan *ssh.Request, error) {
	return nc.Accept()
}

// Errors returned by [New].
var (
	// ErrNilServer reports New called with no SFTP server.
	ErrNilServer = errors.New("sshd: nil sftp server")
	// ErrNoHostKey reports a Config with no host key. An SSH server
	// without one cannot prove its identity, so there is nothing sensible
	// to start.
	ErrNoHostKey = errors.New("sshd: no host key")
	// ErrNoAuthorizedKeys reports a Config with no authorised keys. See
	// the package documentation for why this is refused rather than
	// treated as "allow everyone".
	ErrNoAuthorizedKeys = errors.New("sshd: no authorized keys")
)

// ErrServerClosed is returned by [Server.Serve] after [Server.Close].
var ErrServerClosed = errors.New("sshd: server closed")

// Config is the policy for one SSH front-end. Every field is supplied by the
// caller; nothing is read from a fixed location.
type Config struct {
	// HostKeys are the server's own keys, at least one. A client pins
	// these, so a server that generates a fresh one per start (see
	// [GenerateHostKey]) will make every client warn about a changed key —
	// which is correct behaviour on the client's part and the reason a
	// long-lived deployment supplies a stable key here.
	HostKeys []ssh.Signer

	// AuthorizedKeys are the client public keys permitted to connect, at
	// least one. Comparison is over the full marshalled key, not a
	// fingerprint, so a truncated or mangled entry fails closed.
	AuthorizedKeys []ssh.PublicKey

	// Banner, if non-empty, is sent to the client before authentication.
	Banner string
}

// Server accepts SSH connections and serves the SFTP subsystem on them.
//
// It holds one [github.com/go-filesystems/sftp.Server], which holds one
// filesystem. Serving several tenants means several of these, one per
// process; that is the isolation boundary, and it is why nothing here is
// parameterised by user.
type Server struct {
	sftp *sftp.Server
	cfg  *ssh.ServerConfig

	mu     sync.Mutex
	closed bool
	ln     net.Listener
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

// New builds a front-end for srv.
func New(srv *sftp.Server, cfg Config) (*Server, error) {
	if srv == nil {
		return nil, ErrNilServer
	}
	if len(cfg.HostKeys) == 0 {
		return nil, ErrNoHostKey
	}
	if len(cfg.AuthorizedKeys) == 0 {
		return nil, ErrNoAuthorizedKeys
	}

	// The authorised set is indexed by the key's full wire form. Comparing
	// marshalled bytes is what ssh.KeysEqual does and is the only
	// comparison that is not a fingerprint — a fingerprint is a hash, and a
	// hash comparison is a place where a shortened value can be made to
	// match.
	allowed := make(map[string]struct{}, len(cfg.AuthorizedKeys))
	for _, k := range cfg.AuthorizedKeys {
		allowed[string(k.Marshal())] = struct{}{}
	}

	sc := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := allowed[string(key.Marshal())]; !ok {
				// The message reaches the server's caller, not the
				// client: OpenSSH tells a client only that
				// authentication failed, which is the right amount to
				// tell someone who has not proved who they are.
				return nil, fmt.Errorf("sshd: public key not authorized")
			}
			return &ssh.Permissions{}, nil
		},
	}
	if cfg.Banner != "" {
		sc.BannerCallback = func(ssh.ConnMetadata) string { return cfg.Banner }
	}
	for _, k := range cfg.HostKeys {
		sc.AddHostKey(k)
	}
	return &Server{sftp: srv, cfg: sc, conns: make(map[net.Conn]struct{})}, nil
}

// GenerateHostKey returns a fresh in-memory Ed25519 host key.
//
// It is for tests and for short-lived servers: the key exists only in this
// process's memory and is never written anywhere, so a client that has seen a
// previous run will report a changed host key. That warning is the client
// doing its job. A deployment that clients return to supplies a stable key
// through [Config.HostKeys] instead.
//
// Ed25519 rather than RSA because it is small, fast, has no parameter
// choices to get wrong, and every SSH client in use has supported it for a
// decade.
func GenerateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(keyRand)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// ParseHostKey parses a PEM-encoded private key, as `ssh-keygen` writes it.
//
// It is a thin pass-through so that a caller reading a key file does not have
// to import x/crypto/ssh itself to make sense of what it read. The reading is
// still the caller's: this package opens nothing.
func ParseHostKey(pem []byte) (ssh.Signer, error) { return ssh.ParsePrivateKey(pem) }

// ParseAuthorizedKeys parses an authorized_keys file's contents.
//
// Blank lines and comments are skipped. A line that does not parse is an
// error rather than a skip: silently ignoring a malformed entry is how a
// server ends up denying the one person it was configured for, with nothing
// in the logs to say why.
func ParseAuthorizedKeys(data []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	rest := data
	for len(rest) > 0 {
		k, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			// ParseAuthorizedKey reports the same error for "malformed"
			// and for "nothing left but whitespace", so a failure with
			// nothing parsed yet is genuinely empty input, and a failure
			// after progress is a bad line.
			if allSpace(rest) {
				break
			}
			return nil, err
		}
		keys = append(keys, k)
		rest = next
	}
	return keys, nil
}

// allSpace reports whether b holds nothing but ASCII whitespace.
func allSpace(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}
	return true
}

// ListenAndServe listens on addr and serves until [Server.Close].
//
// Bind to loopback unless the keys and the exported image are both meant to
// be reachable from elsewhere. Unlike the module's NFS sibling, this being
// reachable is not automatically a mistake — the channel is encrypted and the
// client is authenticated by key — but the export is still one image with no
// per-user view, so who may connect is the whole access decision.
func (d *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return d.Serve(ln)
}

// Serve accepts connections on ln until [Server.Close]. It always returns a
// non-nil error, and closes ln before returning.
func (d *Server) Serve(ln net.Listener) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		ln.Close()
		return ErrServerClosed
	}
	d.ln = ln
	d.mu.Unlock()

	for {
		c, err := ln.Accept()
		if err != nil {
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			return err
		}
		d.track(c, true)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer d.track(c, false)
			// A failed connection is one client's problem. It must not end
			// the accept loop, and it must not be a panic path: everything
			// below returns errors.
			_ = d.HandleConn(c)
		}()
	}
}

// track adds or removes a connection from the set Close will drop.
func (d *Server) track(c net.Conn, add bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if add {
		if d.closed {
			// Raced with Close: never leave the connection open, since
			// nothing will come back for it.
			c.Close()
			return
		}
		d.conns[c] = struct{}{}
		return
	}
	delete(d.conns, c)
	c.Close()
}

// Close stops accepting, drops every live connection and waits for their
// handlers to finish.
//
// It does not close the exported filesystem: this package did not open it,
// and the caller may still want it.
func (d *Server) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	ln := d.ln
	conns := make([]net.Conn, 0, len(d.conns))
	for c := range d.conns {
		conns = append(conns, c)
	}
	d.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	d.wg.Wait()
	return nil
}

// HandleConn runs one SSH connection to completion.
//
// It is exported because a program that already accepts its own TCP
// connections — a supervisor multiplexing tenants, say — can hand them here
// without this package owning a listener.
func (d *Server) HandleConn(c net.Conn) error {
	conn, chans, reqs, err := ssh.NewServerConn(c, d.cfg)
	if err != nil {
		// Includes every authentication failure, which is the common case
		// on a reachable port and is not remarkable.
		return err
	}
	defer conn.Close()

	// Global requests are keepalives and port-forwarding asks. Nothing here
	// serves either; discarding them (which replies "no" to those wanting an
	// answer) is what keeps a client from waiting on one.
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			// The channel types this does not serve are exactly the ones
			// that would turn a file server into a network relay:
			// direct-tcpip is a proxy, forwarded-tcpip is an inbound
			// tunnel. Refusing them by name is the point.
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels are served")
			continue
		}
		ch, chReqs, err := acceptChannel(nc)
		if err != nil {
			return err
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleSession(ch, chReqs)
		}()
	}
	return nil
}

// subsystemRequest is the payload of an SSH "subsystem" channel request
// (RFC 4254 §6.5): a single string.
type subsystemRequest struct {
	Name string
}

// handleSession serves one session channel: exactly one "sftp" subsystem
// request and nothing else.
//
// "shell" and "exec" are refused. That is the difference between this and an
// SSH server: there is no shell here to give anyone, and a client that asks
// for one must be told no rather than left waiting.
func (d *Server) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "subsystem" {
			replyNo(req)
			continue
		}
		var s subsystemRequest
		if err := ssh.Unmarshal(req.Payload, &s); err != nil || s.Name != "sftp" {
			replyNo(req)
			continue
		}
		replyYes(req)
		// Serve owns the channel until the client closes it. Any error is
		// this one client's; the connection's other channels are unaffected.
		_ = d.sftp.Serve(ch)
		// SFTP is the whole session. Sending the exit status is what makes
		// a client's own `sftp` process exit 0 instead of reporting that
		// the remote command died without status.
		sendExitStatus(ch, 0)
		return
	}
}

// exitStatusMsg is the payload of an "exit-status" channel request.
type exitStatusMsg struct {
	Status uint32
}

// sendExitStatus reports the subsystem's exit code to the client.
func sendExitStatus(ch ssh.Channel, code uint32) {
	// Best effort: the client may already be gone, which is the normal way
	// a transfer ends when someone interrupts it.
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: code}))
}

// replyNo declines a channel request that wanted an answer.
func replyNo(req *ssh.Request) {
	if req.WantReply {
		_ = req.Reply(false, nil)
	}
}

// replyYes accepts a channel request that wanted an answer.
func replyYes(req *ssh.Request) {
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}
