package sshd

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// A certificate no trusted authority signed -- an OpenPubkey (opkssh) one,
// signed by the user's own key -- reaches CertificateFor, after everything a
// certificate can be checked for without trusting its signer. And what the
// callback decided reaches ServerForLogin.
func TestCertificateFor(t *testing.T) {
	srv, err := sftp.New(tinyFS{files: map[string][]byte{"/a.txt": []byte("a")}})
	if err != nil {
		t.Fatal(err)
	}
	userSigner, userPub := clientKey(t)
	caSigner, caPub := clientKey(t)

	// selfCert is the opkssh shape: signed by the key it certifies.
	selfCert := func(principals []string, after, before time.Time, ext map[string]string, critical map[string]string, typ uint32) ssh.Signer {
		t.Helper()
		cert := &ssh.Certificate{
			Key: userPub, CertType: typ, KeyId: "alice@example.org",
			ValidPrincipals: principals,
			ValidAfter:      uint64(after.Unix()), ValidBefore: uint64(before.Unix()),
			Permissions: ssh.Permissions{Extensions: ext, CriticalOptions: critical},
		}
		if err := cert.SignCert(rand.Reader, userSigner); err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewCertSigner(cert, userSigner)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	var asked []string
	var got *ssh.Permissions
	addr, _, hostPub, _ := harnessFor(t, Config{
		TrustedUserCAs: []ssh.PublicKey{caPub},
		CertificateFor: func(user string, cert *ssh.Certificate) (*ssh.Permissions, error) {
			asked = append(asked, user)
			if cert.Extensions["proof@example.org"] != "good" {
				return nil, errors.New("no proof")
			}
			return &ssh.Permissions{Extensions: map[string]string{"groups@example.org": "photos"}}, nil
		},
		ServerForLogin: func(user string, perms *ssh.Permissions) (*sftp.Server, error) {
			got = perms
			return srv, nil
		},
	})

	now := time.Now()
	good := map[string]string{"proof@example.org": "good"}
	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(selfCert(nil, now.Add(-time.Hour), now.Add(time.Hour), good, nil, ssh.UserCert))); err != nil {
		t.Fatalf("a self-signed certificate the callback accepts: %v", err)
	} else {
		done()
	}
	if got == nil || got.Extensions["groups@example.org"] != "photos" {
		t.Fatalf("ServerForLogin was given %+v, not what CertificateFor decided", got)
	}

	// Refused BEFORE the callback: what a certificate is checked for
	// without trusting its signer.
	before := len(asked)
	for name, s := range map[string]ssh.Signer{
		"expired":             selfCert(nil, now.Add(-2*time.Hour), now.Add(-time.Hour), good, nil, ssh.UserCert),
		"for another user":    selfCert([]string{"bob"}, now.Add(-time.Hour), now.Add(time.Hour), good, nil, ssh.UserCert),
		"a host certificate":  selfCert(nil, now.Add(-time.Hour), now.Add(time.Hour), good, nil, ssh.HostCert),
		"an unknown critical": selfCert(nil, now.Add(-time.Hour), now.Add(time.Hour), good, map[string]string{"restrict-to@example.org": "x"}, ssh.UserCert),
	} {
		if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(s)); err == nil {
			done()
			t.Errorf("%s: admitted", name)
		}
	}
	if len(asked) != before {
		t.Errorf("the callback was asked about certificates that failed the checks before it: %v", asked[before:])
	}
	// Refused BY the callback.
	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(selfCert(nil, now.Add(-time.Hour), now.Add(time.Hour), nil, nil, ssh.UserCert))); err == nil {
		done()
		t.Error("a certificate the callback refused was admitted")
	}

	// A certificate the trusted CA signed does NOT go to the callback: the
	// CA decides, as before, and its extensions reach ServerForLogin.
	cert := &ssh.Certificate{Key: userPub, CertType: ssh.UserCert, ValidPrincipals: []string{"alice"},
		ValidAfter: uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"groups@example.org": "staff"}}}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	bySigner, _ := ssh.NewCertSigner(cert, userSigner)
	before = len(asked)
	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(bySigner)); err != nil {
		t.Fatalf("a CA certificate: %v", err)
	} else {
		done()
	}
	if len(asked) != before {
		t.Error("a CA-signed certificate was handed to CertificateFor")
	}
	if got.Extensions["groups@example.org"] != "staff" {
		t.Errorf("the CA certificate's extensions did not reach ServerForLogin: %+v", got)
	}
}

// CertificateFor alone is a way in, so New accepts it without keys.
func TestNewAcceptsCertificateForAlone(t *testing.T) {
	host, _ := clientKey(t)
	if _, err := New(nil, Config{
		HostKeys:       []ssh.Signer{host},
		CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { return nil, nil },
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return nil, nil },
	}); err != nil {
		t.Fatal(err)
	}
}

// With CertificateFor as the only way in, a bare key is refused: nothing
// here vouches for it.
func TestCertificateForRefusesABareKey(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	userSigner, _ := clientKey(t)
	addr, _, hostPub, _ := harnessFor(t, Config{
		// A password that is never right, so that the harness adds no
		// authorised key of its own: certificates are the only way in.
		Password:       func(string, string) bool { return false },
		CertificateFor: func(string, *ssh.Certificate) (*ssh.Permissions, error) { return nil, nil },
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(userSigner)); err == nil {
		done()
		t.Fatal("a bare key was admitted by a server that only takes certificates")
	}
}
