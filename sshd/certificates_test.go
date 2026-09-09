package sshd

import (
	"errors"
	"testing"
	"time"

	"crypto/rand"

	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// A key belongs to somebody. A server with several people on it must know
// WHOSE key it just saw, or the view chosen from the user name is chosen from
// a name nobody proved.
func TestAKeyBelongsToOneUser(t *testing.T) {
	fsys := tinyFS{files: map[string][]byte{"/mine.txt": []byte("hello")}}
	srv, err := sftp.New(fsys)
	if err != nil {
		t.Fatal(err)
	}
	aliceSigner, alicePub := clientKey(t)
	bobSigner, bobPub := clientKey(t)
	keys := map[string]ssh.PublicKey{"alice": alicePub, "bob": bobPub}

	addr, _, hostPub, _ := harnessFor(t, Config{
		PublicKeyFor: func(user string, key ssh.PublicKey) bool {
			want, known := keys[user]
			return known && string(want.Marshal()) == string(key.Marshal())
		},
		ServerFor: func(string) (*sftp.Server, error) { return srv, nil },
	})

	if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(aliceSigner)); err != nil {
		t.Errorf("alice with her own key: %v", err)
	} else {
		done()
	}
	// The whole point: a key that IS authorised, offered as somebody else.
	if _, _, err := channelAs(t, addr, hostPub, "bob", ssh.PublicKeys(aliceSigner)); err == nil {
		t.Error("alice's key logged bob in")
	}
	if _, _, err := channelAs(t, addr, hostPub, "carol", ssh.PublicKeys(bobSigner)); err == nil {
		t.Error("a user nobody has a key for was let in")
	}
}

// A certificate carries its own principals and validity, signed by an
// authority this server trusts. It is what makes a fleet's access issued and
// expired elsewhere, with no file here to edit when somebody joins or leaves.
func TestCertificatesFromATrustedAuthority(t *testing.T) {
	fsys := tinyFS{files: map[string][]byte{"/mine.txt": []byte("hello")}}
	srv, err := sftp.New(fsys)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, caPub := clientKey(t)
	userSigner, userPub := clientKey(t)

	// sign issues a certificate for these principals and this window.
	sign := func(principals []string, after, before time.Time) ssh.Signer {
		t.Helper()
		cert := &ssh.Certificate{
			Key:             userPub,
			CertType:        ssh.UserCert,
			KeyId:           "test",
			ValidPrincipals: principals,
			ValidAfter:      uint64(after.Unix()),
			ValidBefore:     uint64(before.Unix()),
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewCertSigner(cert, userSigner)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	addr, _, hostPub, _ := harnessFor(t, Config{
		TrustedUserCAs: []ssh.PublicKey{caPub},
		ServerFor:      func(string) (*sftp.Server, error) { return srv, nil },
	})

	now := time.Now()
	for _, tc := range []struct {
		name      string
		user      string
		signer    ssh.Signer
		wantAdmit bool
	}{
		{"a certificate naming this user", "alice",
			sign([]string{"alice", "bob"}, now.Add(-time.Hour), now.Add(time.Hour)), true},
		{"a certificate naming somebody else", "carol",
			sign([]string{"alice"}, now.Add(-time.Hour), now.Add(time.Hour)), false},
		{"a certificate that has expired", "alice",
			sign([]string{"alice"}, now.Add(-2*time.Hour), now.Add(-time.Hour)), false},
		{"a certificate not yet valid", "alice",
			sign([]string{"alice"}, now.Add(time.Hour), now.Add(2*time.Hour)), false},
		{"the bare key the certificate was issued for", "alice", userSigner, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, done, err := channelAs(t, addr, hostPub, tc.user, ssh.PublicKeys(tc.signer))
			if err == nil {
				done()
			}
			if (err == nil) != tc.wantAdmit {
				t.Errorf("admitted = %v (%v), want %v", err == nil, err, tc.wantAdmit)
			}
		})
	}

	// And a certificate from an authority nobody trusts is a stranger's word.
	otherCA, _ := clientKey(t)
	cert := &ssh.Certificate{
		Key: userPub, CertType: ssh.UserCert, KeyId: "forged",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, otherCA); err != nil {
		t.Fatal(err)
	}
	forged, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(forged)); err == nil {
		t.Error("a certificate from an untrusted authority was accepted")
	}
}

// With a CA AND keys, both ways in work: a fleet moving to certificates does
// not have to move everybody on the same day.
func TestACertificateAndAKeyTogether(t *testing.T) {
	srv, err := sftp.New(tinyFS{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	caSigner, caPub := clientKey(t)
	keySigner, keyPub := clientKey(t)
	certSigner, certPub := clientKey(t)

	now := time.Now()
	cert := &ssh.Certificate{
		Key: certPub, CertType: ssh.UserCert, KeyId: "id",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	withCert, err := ssh.NewCertSigner(cert, certSigner)
	if err != nil {
		t.Fatal(err)
	}

	addr, _, hostPub, _ := harnessFor(t, Config{
		TrustedUserCAs: []ssh.PublicKey{caPub},
		AuthorizedKeys: []ssh.PublicKey{keyPub},
		ServerFor:      func(string) (*sftp.Server, error) { return srv, nil },
	})
	for _, tc := range []struct {
		name   string
		signer ssh.Signer
	}{
		{"the certificate", withCert},
		{"the listed key", keySigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, done, err := channelAs(t, addr, hostPub, "alice", ssh.PublicKeys(tc.signer)); err != nil {
				t.Errorf("%s was refused: %v", tc.name, err)
			} else {
				done()
			}
		})
	}
}

func TestNewAcceptsTheNewWaysIn(t *testing.T) {
	srv, _ := sftp.New(tinyFS{files: map[string][]byte{}})
	host, _ := GenerateHostKey()
	_, pub := clientKey(t)
	for _, tc := range []struct {
		name string
		cfg  Config
		want error
	}{
		{"per-user keys alone", Config{HostKeys: []ssh.Signer{host},
			PublicKeyFor: func(string, ssh.PublicKey) bool { return false }}, nil},
		{"a certificate authority alone", Config{HostKeys: []ssh.Signer{host},
			TrustedUserCAs: []ssh.PublicKey{pub}}, nil},
		{"nothing at all", Config{HostKeys: []ssh.Signer{host}}, ErrNoAuthorizedKeys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(srv, tc.cfg); !errors.Is(err, tc.want) {
				t.Errorf("New = %v, want %v", err, tc.want)
			}
		})
	}
}
