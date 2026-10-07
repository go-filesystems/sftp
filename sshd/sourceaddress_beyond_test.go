package sshd

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// sourceaddress_test.go dials from 127.0.0.1 and nothing else, so it cannot
// tell a source-address that is matched against the connection's address
// from one that is matched against "loopback", or against IPv4 only. These
// tests dial from two more addresses: ::1, and a second IPv4 loopback address,
// 127.0.0.2.
//
// Neither is always available. A host without IPv6 has no ::1, and macOS
// routes only 127.0.0.1 on lo0 unless an alias is added. Where an address is
// missing the test skips and says why -- unless SFTP_REQUIRE_LOOPBACK_ADDRESSES
// is set, which the Linux CI lane does: there both addresses exist, and a skip
// would turn the experiment into a silent no-op.
const requireLoopbackAddresses = "SFTP_REQUIRE_LOOPBACK_ADDRESSES"

// needAddress skips, or fails when the CI lane requires it, if a listener
// cannot be bound to ip on this host.
func needAddress(t *testing.T, ip, why string) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err == nil {
		ln.Close()
		return
	}
	if os.Getenv(requireLoopbackAddresses) != "" {
		t.Fatalf("%s is required here (%s is set): %v", ip, requireLoopbackAddresses, err)
	}
	t.Skipf("%s is not available on this host (%s): %v", ip, why, err)
}

// channelFrom is channelAs dialling from a chosen local address, so the
// server sees that address as the connection's source.
func channelFrom(t *testing.T, local, addr string, hostPub ssh.PublicKey, user string, auth ssh.AuthMethod) (func(), error) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}, Timeout: 10 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialling %s from %s: %v", addr, local, err)
	}
	if got := c.LocalAddr().(*net.TCPAddr).IP.String(); got != local {
		c.Close()
		t.Fatalf("dialled from %s, wanted %s: the experiment would not be the one it names", got, local)
	}
	sc, chans, reqs, err := ssh.NewClientConn(c, addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		c.Close()
		return func() {}, err
	}
	conn := ssh.NewClient(sc, chans, reqs)
	sess, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return func() {}, err
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		conn.Close()
		return func() {}, err
	}
	return func() { sess.Close(); conn.Close() }, nil
}

// paths are the two ways a certificate reaches the server: signed by a CA it
// trusts, where x/crypto's CertChecker enforces source-address, and signed by
// the user's own key, where CertificateFor decides and this package carries
// source-address into the permissions. Both must answer alike.
type certPath struct {
	name string
	cfg  func(srv *sftp.Server, caPub ssh.PublicKey) Config
	// signer picks who signs the certificate: the CA, or the user.
	signer func(ca, user ssh.Signer) ssh.Signer
}

func certPaths() []certPath {
	return []certPath{
		{
			name: "trusted CA",
			cfg: func(srv *sftp.Server, caPub ssh.PublicKey) Config {
				return Config{
					TrustedUserCAs: []ssh.PublicKey{caPub},
					ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
				}
			},
			signer: func(ca, _ ssh.Signer) ssh.Signer { return ca },
		},
		{
			name: "CertificateFor",
			cfg: func(srv *sftp.Server, _ ssh.PublicKey) Config {
				return Config{
					Password:       func(string, string) bool { return false },
					CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { return nil, nil },
					ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
				}
			},
			signer: func(_, user ssh.Signer) ssh.Signer { return user },
		},
	}
}

// A certificate pinned to ::1/128 is let in from [::1] and refused from
// 127.0.0.1; one pinned to 127.0.0.1/32 is the mirror image. The unpinned
// certificate is let in from both: the refusals are the pin's, not the dial's.
func TestSourceAddressIPv6Loopback(t *testing.T) {
	needAddress(t, "::1", "the host has no IPv6 loopback")
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	caSigner, caPub := clientKey(t)
	for _, p := range certPaths() {
		t.Run(p.name, func(t *testing.T) {
			v6, _, hostPub6, _ := harnessOn(t, "[::1]:0", p.cfg(srv, caPub))
			v4, _, hostPub4, _ := harnessOn(t, "127.0.0.1:0", p.cfg(srv, caPub))
			for _, tc := range []struct {
				name     string
				critical map[string]string
				from     string
				admit    bool
			}{
				{"unpinned, from ::1", nil, "::1", true},
				{"unpinned, from 127.0.0.1", nil, "127.0.0.1", true},
				{"::1/128, from ::1", srcOnly("::1/128"), "::1", true},
				{"::1/128, from 127.0.0.1", srcOnly("::1/128"), "127.0.0.1", false},
				{"127.0.0.1/32, from ::1", srcOnly("127.0.0.1/32"), "::1", false},
				{"127.0.0.1/32 or ::1/128, from ::1", srcOnly("127.0.0.1/32,::1/128"), "::1", true},
			} {
				addr, hostPub := v4, hostPub4
				if tc.from == "::1" {
					addr, hostPub = v6, hostPub6
				}
				cert := srcCert(t, p.signer(caSigner, userSigner), userSigner, tc.critical)
				done, err := channelFrom(t, tc.from, addr, hostPub, "alice", ssh.PublicKeys(cert))
				done()
				if (err == nil) != tc.admit {
					t.Errorf("%s: admitted = %v (%v), want %v", tc.name, err == nil, err, tc.admit)
				}
			}
		})
	}
}

// From 127.0.0.2, a certificate pinned to 127.0.0.1/32 is refused and one
// pinned to 127.0.0.0/8 is let in: the pin is matched against the address the
// connection came from, not against "this is loopback".
func TestSourceAddressSecondIPv4Loopback(t *testing.T) {
	why := "Linux routes all of 127.0.0.0/8 on lo"
	if runtime.GOOS == "darwin" {
		why = "macOS routes only 127.0.0.1 on lo0; `sudo ifconfig lo0 alias 127.0.0.2` adds it"
	}
	needAddress(t, "127.0.0.2", why)
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	caSigner, caPub := clientKey(t)
	for _, p := range certPaths() {
		t.Run(p.name, func(t *testing.T) {
			addr, _, hostPub, _ := harnessOn(t, "127.0.0.1:0", p.cfg(srv, caPub))
			for _, tc := range []struct {
				name     string
				critical map[string]string
				from     string
				admit    bool
			}{
				{"unpinned, from 127.0.0.2", nil, "127.0.0.2", true},
				{"127.0.0.1/32, from 127.0.0.1", srcOnly("127.0.0.1/32"), "127.0.0.1", true},
				{"127.0.0.1/32, from 127.0.0.2", srcOnly("127.0.0.1/32"), "127.0.0.2", false},
				{"127.0.0.0/8, from 127.0.0.2", srcOnly("127.0.0.0/8"), "127.0.0.2", true},
				{"127.0.0.2/32, from 127.0.0.2", srcOnly("127.0.0.2/32"), "127.0.0.2", true},
				{"127.0.0.2/32, from 127.0.0.1", srcOnly("127.0.0.2/32"), "127.0.0.1", false},
			} {
				cert := srcCert(t, p.signer(caSigner, userSigner), userSigner, tc.critical)
				done, err := channelFrom(t, tc.from, addr, hostPub, "alice", ssh.PublicKeys(cert))
				done()
				if (err == nil) != tc.admit {
					t.Errorf("%s: admitted = %v (%v), want %v", tc.name, err == nil, err, tc.admit)
				}
			}
		})
	}
}
