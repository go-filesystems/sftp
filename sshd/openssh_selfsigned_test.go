package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-filesystems/sftp"
	"golang.org/x/crypto/ssh"
)

// OpenSSH's own client, presenting a certificate OpenSSH's own ssh-keygen
// signed with the certified key itself -- the shape of an opkssh
// certificate. What reaches CertificateFor is what a real client sends.
func TestOpenSSHSelfSignedCertificate(t *testing.T) {
	sftpBin, err1 := exec.LookPath("sftp")
	keygen, err2 := exec.LookPath("ssh-keygen")
	if err1 != nil || err2 != nil {
		if os.Getenv("SFTP_REQUIRE_OPENSSH") != "" {
			t.Fatal("OpenSSH's sftp and ssh-keygen are required here")
		}
		t.Skip("OpenSSH is not installed")
	}
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "id")
	os.WriteFile(key, pem.EncodeToMemory(blk), 0o600)
	signer, _ := ssh.NewSignerFromKey(priv)
	os.WriteFile(key+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644)
	// Signed by itself: -s names the certified key as the CA.
	if out, err := exec.Command(keygen, "-q", "-s", key, "-I", "alice@example.org", "-n", "alice",
		"-O", "extension:proof@example.org=good", key+".pub").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -s: %v\n%s", err, out)
	}

	srv, _ := sftp.New(tinyFS{files: map[string][]byte{"/a.txt": []byte("a")}})
	var saw *ssh.Certificate
	addr, _, _, _ := harnessFor(t, Config{
		CertificateFor: func(user string, cert *ssh.Certificate) (*ssh.Permissions, error) {
			saw = cert
			return nil, nil
		},
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	host, port, _ := strings.Cut(addr, ":")
	cmd := exec.Command(sftpBin, "-b", "-", "-P", port, "-i", key,
		"-o", "CertificateFile="+key+"-cert.pub", "-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
		"alice@"+host)
	cmd.Stdin = strings.NewReader("ls\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSH sftp with a self-signed certificate: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "a.txt") {
		t.Errorf("listing: %s", out)
	}
	if saw == nil || saw.KeyId != "alice@example.org" || saw.Extensions["proof@example.org"] != "good" {
		t.Fatalf("CertificateFor did not see ssh-keygen's certificate: %+v", saw)
	}
}
