package sshd

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/sftp/wire"
	"golang.org/x/crypto/ssh"
)

// Two additions, and they answer one question between them: WHO is asking, and
// what do they get. A caller whose users have passwords rather than keys can
// now authenticate them, and a caller with several of them can hand each
// connection a view of its own.

// channelAs authenticates as one user, by whatever method, and asks for the
// sftp subsystem.
func channelAs(t *testing.T, addr string, hostPub ssh.PublicKey, user string, auth ssh.AuthMethod) (io.ReadWriter, func(), error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, func() {}, err
	}
	sess, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, func() {}, err
	}
	w, err := sess.StdinPipe()
	if err != nil {
		conn.Close()
		return nil, func() {}, err
	}
	r, err := sess.StdoutPipe()
	if err != nil {
		conn.Close()
		return nil, func() {}, err
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		conn.Close()
		return nil, func() {}, err
	}
	return rw{r: r, w: w}, func() { sess.Close(); conn.Close() }, nil
}

// readOver fetches one file through an sftp channel, or says why it could not.
func readOver(t *testing.T, ch io.ReadWriter, path string) ([]byte, error) {
	t.Helper()
	var out, in []byte
	send := func(m wire.Message) {
		var err error
		if out, err = wire.Send(ch, m, out); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	recv := func() (uint8, []byte) {
		typ, payload, next, err := wire.ReadPacket(ch, in, 0)
		in = next
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		return typ, append([]byte(nil), payload...)
	}
	send(wire.InitRequest{Version: 3})
	if typ, _ := recv(); typ != wire.FxpVersion {
		t.Fatalf("first reply type %d, want VERSION", typ)
	}
	send(wire.OpenRequest{ID: 1, Path: path, PFlags: wire.FxfRead})
	typ, payload := recv()
	if typ != wire.FxpHandle {
		st, _ := wire.DecodeStatus(payload)
		return nil, errors.New(st.Code.String())
	}
	h, _ := wire.DecodeHandleReply(payload)
	var got []byte
	for off := uint64(0); ; {
		send(wire.ReadRequest{ID: 2, Handle: h.Handle, Offset: off, Length: 4096})
		typ, payload := recv()
		if typ == wire.FxpStatus {
			st, _ := wire.DecodeStatus(payload)
			if st.Code != wire.StatusEOF {
				return nil, errors.New(st.Code.String())
			}
			break
		}
		d, _ := wire.DecodeData(payload)
		got = append(got, d.Data...)
		off += uint64(len(d.Data))
	}
	return got, nil
}

// A password is how the people this is for actually authenticate: not every
// caller's users have SSH keys, and asking each of them for one first would
// make SFTP the protocol nobody uses.
func TestPasswordAuthentication(t *testing.T) {
	fsys := tinyFS{files: map[string][]byte{"/data.bin": []byte("hello")}}
	addr, _, hostPub, _ := harness(t, fsys, func(c *Config) {
		c.AuthorizedKeys = nil // passwords only
		c.Password = func(user, password string) bool {
			return user == "alice" && password == "hunter2"
		}
	})

	ch, done, err := channelAs(t, addr, hostPub, "alice", ssh.Password("hunter2"))
	if err != nil {
		t.Fatalf("alice with the right password: %v", err)
	}
	defer done()
	if got, err := readOver(t, ch, "/data.bin"); err != nil || string(got) != "hello" {
		t.Errorf("read %q, %v", got, err)
	}

	if _, _, err := channelAs(t, addr, hostPub, "alice", ssh.Password("wrong")); err == nil {
		t.Error("a wrong password was accepted")
	}
	if _, _, err := channelAs(t, addr, hostPub, "mallory", ssh.Password("hunter2")); err == nil {
		t.Error("a user nobody knows was accepted")
	}
}

// One daemon, several people, and nobody sees anybody else's files.
func TestEachConnectionSeesItsOwn(t *testing.T) {
	alice := tinyFS{files: map[string][]byte{"/mine.txt": []byte("alice's")}}
	bob := tinyFS{files: map[string][]byte{"/mine.txt": []byte("bob's")}}
	aliceSrv, err := sftp.New(alice)
	if err != nil {
		t.Fatal(err)
	}
	bobSrv, err := sftp.New(bob)
	if err != nil {
		t.Fatal(err)
	}

	// The single server is nil: with ServerFor there is nothing for it to be.
	addr, _, hostPub, _ := harnessFor(t, Config{
		Password: func(user, password string) bool { return password == "open" },
		ServerFor: func(user string) (*sftp.Server, error) {
			switch user {
			case "alice":
				return aliceSrv, nil
			case "bob":
				return bobSrv, nil
			}
			return nil, errors.New("no such user here")
		},
	})

	for _, tc := range []struct{ user, want string }{{"alice", "alice's"}, {"bob", "bob's"}} {
		ch, done, err := channelAs(t, addr, hostPub, tc.user, ssh.Password("open"))
		if err != nil {
			t.Fatalf("%s: %v", tc.user, err)
		}
		got, err := readOver(t, ch, "/mine.txt")
		done()
		if err != nil || string(got) != tc.want {
			t.Errorf("%s read %q (%v), want %q", tc.user, got, err, tc.want)
		}
	}

	// A user the caller refuses is DISCONNECTED, not given an empty view:
	// "you have nothing here" and "you are not welcome" are different answers
	// and a client acts differently on them.
	ch, done, err := channelAs(t, addr, hostPub, "carol", ssh.Password("open"))
	if err == nil {
		// The refusal happens after authentication, so the dial may succeed
		// and the session then fail.
		defer done()
		if _, err := readOver(t, ch, "/mine.txt"); err == nil {
			t.Error("a user the caller refused was served anyway")
		}
	}
}

// harnessFor is harness without the assumption that there is one filesystem.
func harnessFor(t *testing.T, cfg Config) (string, ssh.Signer, ssh.PublicKey, *Server) {
	t.Helper()
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, pub := clientKey(t)
	cfg.HostKeys = append(cfg.HostKeys, hostKey)
	if cfg.Password == nil && cfg.AuthorizedKeys == nil {
		cfg.AuthorizedKeys = []ssh.PublicKey{pub}
	}
	d, err := New(nil, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := listenLoopback(t)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Serve(ln) }()
	t.Cleanup(func() {
		d.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ErrServerClosed) {
				t.Errorf("Serve = %v, want ErrServerClosed", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop within 5s")
		}
	})
	return ln.Addr().String(), signer, hostKey.PublicKey(), d
}

// What New will and will not accept, now that there are two ways to
// authenticate and two ways to say what a connection sees.
func TestNewValidatesTheWaysIn(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	host, _ := GenerateHostKey()
	_, pub := clientKey(t)
	keys := []ssh.PublicKey{pub}
	password := func(string, string) bool { return false }
	serverFor := func(string) (*sftp.Server, error) { return srv, nil }

	for _, tc := range []struct {
		name string
		srv  *sftp.Server
		cfg  Config
		want error
	}{
		{"no server and no ServerFor", nil, Config{HostKeys: []ssh.Signer{host}, AuthorizedKeys: keys}, ErrNilServer},
		{"no server, but ServerFor", nil, Config{HostKeys: []ssh.Signer{host}, AuthorizedKeys: keys, ServerFor: serverFor}, nil},
		{"no host key", srv, Config{AuthorizedKeys: keys}, ErrNoHostKey},
		{"no way to authenticate", srv, Config{HostKeys: []ssh.Signer{host}}, ErrNoAuthorizedKeys},
		{"password only", srv, Config{HostKeys: []ssh.Signer{host}, Password: password}, nil},
		{"keys only", srv, Config{HostKeys: []ssh.Signer{host}, AuthorizedKeys: keys}, nil},
		{"both", srv, Config{HostKeys: []ssh.Signer{host}, AuthorizedKeys: keys, Password: password}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.srv, tc.cfg)
			if !errors.Is(err, tc.want) {
				t.Errorf("New = %v, want %v", err, tc.want)
			}
		})
	}
}

// A server that cannot perform password authentication must not offer it: a
// client that is offered it prompts a person for something that will be
// refused.
func TestOnlyTheMethodsThatCanWorkAreOffered(t *testing.T) {
	addr, _, hostPub, _ := harness(t, tinyFS{files: map[string][]byte{}})
	_, _, err := channelAs(t, addr, hostPub, "anyone", ssh.Password("anything"))
	if err == nil {
		t.Fatal("a keys-only server accepted a password")
	}
	if !strings.Contains(err.Error(), "no supported methods") &&
		!strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("the refusal was %v", err)
	}
}

var _ filesystem.Filesystem = tinyFS{}

// A callback this package cannot vouch for is a place a panic can come from,
// and one client's bad day must not be every client's.
func TestAPanicStaysInOneConnection(t *testing.T) {
	fsys := tinyFS{files: map[string][]byte{"/mine.txt": []byte("still here")}}
	good, err := sftp.New(fsys)
	if err != nil {
		t.Fatal(err)
	}
	addr, _, hostPub, _ := harnessFor(t, Config{
		Password: func(string, string) bool { return true },
		ServerFor: func(user string) (*sftp.Server, error) {
			if user == "trouble" {
				panic("a caller's callback did something it should not")
			}
			return good, nil
		},
	})

	// The connection that panics fails...
	if ch, done, err := channelAs(t, addr, hostPub, "trouble", ssh.Password("x")); err == nil {
		defer done()
		if _, err := readOver(t, ch, "/mine.txt"); err == nil {
			t.Error("a connection whose callback panicked was served")
		}
	}

	// ...and the server is still there for everybody else.
	ch, done, err := channelAs(t, addr, hostPub, "alice", ssh.Password("x"))
	if err != nil {
		t.Fatalf("the server did not survive: %v", err)
	}
	defer done()
	if got, err := readOver(t, ch, "/mine.txt"); err != nil || string(got) != "still here" {
		t.Errorf("after the panic, a good connection read %q (%v)", got, err)
	}
}
