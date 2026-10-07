package sshd

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// The test server listens on 127.0.0.1 and every client dials it from there,
// so these two values are the whole experiment: one source-address admits
// the connection, the other excludes it.
const (
	allowsLoopback   = "127.0.0.1/32"
	excludesLoopback = "10.0.0.0/8"
)

// srcCert issues a user certificate for userPub carrying these critical
// options, signed by signer: the user's own key for the CertificateFor path,
// a CA for the trusted one.
func srcCert(t *testing.T, signer, userSigner ssh.Signer, critical map[string]string) ssh.Signer {
	t.Helper()
	now := time.Now()
	cert := &ssh.Certificate{
		Key: userSigner.PublicKey(), CertType: ssh.UserCert, KeyId: "alice@example.org",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{CriticalOptions: critical},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// srcOnly is a certificate's critical options holding just a source-address.
func srcOnly(v string) map[string]string { return map[string]string{"source-address": v} }

// A certificate on the CertificateFor path may carry source-address, and it
// is ENFORCED, over a real TCP connection, whatever the callback returns:
// nil permissions, permissions without critical options, or permissions with
// critical options of their own -- which are kept, not replaced.
func TestCertificateForEnforcesSourceAddress(t *testing.T) {
	srv, err := sftp.New(tinyFS{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	userSigner, _ := clientKey(t)

	for _, cb := range []struct {
		name    string
		returns func() *ssh.Permissions
		// keeps is a critical option the callback set that must still be
		// there when ServerForLogin is asked.
		keeps string
	}{
		{"nil permissions", func() *ssh.Permissions { return nil }, ""},
		{"permissions without critical options", func() *ssh.Permissions {
			return &ssh.Permissions{Extensions: map[string]string{"groups@example.org": "photos"}}
		}, ""},
		{"permissions with critical options of its own", func() *ssh.Permissions {
			return &ssh.Permissions{CriticalOptions: map[string]string{"policy@example.org": "kept"}}
		}, "policy@example.org"},
	} {
		t.Run(cb.name, func(t *testing.T) {
			var got *ssh.Permissions
			addr, _, hostPub, _ := harnessFor(t, Config{
				Password:       func(string, string) bool { return false },
				CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { return cb.returns(), nil },
				ServerForLogin: func(_ string, p *ssh.Permissions) (*sftp.Server, error) { got = p; return srv, nil },
			})
			for _, tc := range []struct {
				name  string
				value string
				admit bool
			}{
				{"an address it allows", allowsLoopback, true},
				{"one of several it allows", excludesLoopback + ",127.0.0.1", true},
				{"an address it excludes", excludesLoopback, false},
			} {
				got = nil
				_, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, userSigner, userSigner, srcOnly(tc.value))))
				if err == nil {
					done()
				}
				if (err == nil) != tc.admit {
					t.Errorf("%s (%s): admitted = %v (%v), want %v", tc.name, tc.value, err == nil, err, tc.admit)
					continue
				}
				if !tc.admit {
					continue
				}
				if got == nil || got.CriticalOptions["source-address"] != tc.value {
					t.Errorf("%s: ServerForLogin was given %+v, without the certificate's source-address", tc.name, got)
				}
				if cb.keeps != "" && got != nil && got.CriticalOptions[cb.keeps] != "kept" {
					t.Errorf("%s: the callback's own critical option %q was dropped: %+v", tc.name, cb.keeps, got.CriticalOptions)
				}
			}
		})
	}
}

// A callback that sets a source-address of its own: the same value as the
// certificate's is fine; a different one refuses the login, in BOTH
// directions -- whichever of the two would have admitted this address.
func TestCertificateForSourceAddressConflict(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	for _, tc := range []struct {
		name           string
		cert, callback string
		admit          bool
	}{
		{"the same value", allowsLoopback, allowsLoopback, true},
		{"the callback would loosen the certificate's", excludesLoopback, allowsLoopback, false},
		{"the callback would narrow the certificate's", allowsLoopback, excludesLoopback, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, _, hostPub, _ := harnessFor(t, Config{
				Password: func(string, string) bool { return false },
				CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) {
					return &ssh.Permissions{CriticalOptions: srcOnly(tc.callback)}, nil
				},
				ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
			})
			_, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, userSigner, userSigner, srcOnly(tc.cert))))
			if err == nil {
				done()
			}
			if (err == nil) != tc.admit {
				t.Errorf("admitted = %v (%v), want %v", err == nil, err, tc.admit)
			}
		})
	}
}

// A callback that hands back one shared Permissions value must not have it
// written to: one login's source-address would otherwise bind every later
// login through the same value -- and race with them.
func TestCertificateForDoesNotWriteToTheCallbacksPermissions(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	shared := &ssh.Permissions{CriticalOptions: map[string]string{"policy@example.org": "kept"}}
	addr, _, hostPub, _ := harnessFor(t, Config{
		Password:       func(string, string) bool { return false },
		CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { return shared, nil },
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	_, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, userSigner, userSigner, srcOnly(excludesLoopback))))
	if err == nil {
		done()
		t.Fatal("a certificate excluding this address was admitted")
	}
	if _, set := shared.CriticalOptions["source-address"]; set || len(shared.CriticalOptions) != 1 {
		t.Fatalf("the callback's permissions were written to: %+v", shared.CriticalOptions)
	}
	// And so the next certificate, with no restriction, is not bound by it.
	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, userSigner, userSigner, nil))); err != nil {
		t.Fatalf("a certificate without source-address, after one with: %v", err)
	} else {
		done()
	}
}

// A certificate without critical options is handled exactly as before: what
// the callback returned is what ServerForLogin gets, the very same value.
func TestCertificateForWithoutCriticalOptionsIsUnchanged(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	mine := &ssh.Permissions{Extensions: map[string]string{"groups@example.org": "photos"}}
	var got *ssh.Permissions
	addr, _, hostPub, _ := harnessFor(t, Config{
		Password:       func(string, string) bool { return false },
		CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { return mine, nil },
		ServerForLogin: func(_ string, p *ssh.Permissions) (*sftp.Server, error) { got = p; return srv, nil },
	})
	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, userSigner, userSigner, nil))); err != nil {
		t.Fatal(err)
	} else {
		done()
	}
	if got != mine {
		t.Fatalf("ServerForLogin was given %+v, not the callback's own value", got)
	}
}

// Every critical option but source-address is still refused on the
// CertificateFor path, before the callback is asked -- alone, or beside an
// allowed source-address.
func TestCertificateForRefusesOtherCriticalOptions(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	asked := 0
	addr, _, hostPub, _ := harnessFor(t, Config{
		Password:       func(string, string) bool { return false },
		CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { asked++; return nil, nil },
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	for name, critical := range map[string]map[string]string{
		"force-command":                    {"force-command": "/bin/true"},
		"verify-required":                  {"verify-required": ""},
		"force-command and source-address": {"force-command": "/bin/true", "source-address": allowsLoopback},
	} {
		if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, userSigner, userSigner, critical))); err == nil {
			done()
			t.Errorf("%s: admitted", name)
		}
	}
	if asked != 0 {
		t.Errorf("the callback was asked %d times about certificates with options nobody here acts on", asked)
	}
}

// The trusted-CA path is untouched: x/crypto's CertChecker.Authenticate
// already enforced source-address there, still refuses any other critical
// option, and never hands the certificate to CertificateFor.
func TestTrustedCASourceAddressIsUnchanged(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	caSigner, caPub := clientKey(t)
	asked := 0
	addr, _, hostPub, _ := harnessFor(t, Config{
		TrustedUserCAs: []ssh.PublicKey{caPub},
		CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { asked++; return nil, nil },
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	for _, tc := range []struct {
		name     string
		critical map[string]string
		admit    bool
	}{
		{"source-address allowing this address", srcOnly(allowsLoopback), true},
		{"source-address excluding it", srcOnly(excludesLoopback), false},
		{"force-command", map[string]string{"force-command": "/bin/true"}, false},
	} {
		_, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(srcCert(t, caSigner, userSigner, tc.critical)))
		if err == nil {
			done()
		}
		if (err == nil) != tc.admit {
			t.Errorf("%s: admitted = %v (%v), want %v", tc.name, err == nil, err, tc.admit)
		}
	}
	if asked != 0 {
		t.Errorf("CertificateFor was asked %d times about CA-signed certificates", asked)
	}
}
