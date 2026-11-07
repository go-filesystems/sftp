// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/ssh"
)

// timedRAM is ramFS plus the times capability: a.txt has an mtime, b.txt has
// none recorded.
type timedRAM struct{ *ramFS }

func (timedRAM) Times(p string) (filesystem.FileTimes, error) {
	switch p {
	case "/a.txt":
		return filesystem.FileTimes{
			Mtime: filesystem.NewTimestamp(time.Date(2019, 3, 4, 5, 6, 8, 0, time.UTC), 2*time.Second),
		}, nil
	case "/b.txt":
		return filesystem.FileTimes{}, nil
	}
	return filesystem.FileTimes{}, errors.New("no times")
}

// OpenSSH's own sftp client prints the longname the server sent for `ls -l`:
// the recorded mtime appears as a date, and a file with none recorded does not
// appear as 1 Jan 1970 -- or as now.
func TestOpenSSHLsShowsTheRecordedTimes(t *testing.T) {
	sftpBin, err := exec.LookPath("sftp")
	if err != nil {
		if os.Getenv("SFTP_REQUIRE_OPENSSH") != "" {
			t.Fatal("OpenSSH's sftp is required here")
		}
		t.Skip("OpenSSH is not installed")
	}
	ram := &ramFS{files: map[string][]byte{"/a.txt": []byte("a"), "/b.txt": []byte("b")}}
	srv, err := sftp.New(timedRAM{ram})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	addr, _, _, _ := harnessFor(t, Config{
		AuthorizedKeys: []ssh.PublicKey{sshPub},
		ServerForLogin: func(string, *ssh.Permissions) (*sftp.Server, error) { return srv, nil },
	})
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	if err := os.WriteFile(key, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := strings.Cut(addr, ":")
	cmd := exec.Command(sftpBin, "-b", "-", "-P", port, "-i", key,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "alice@"+host)
	cmd.Stdin = strings.NewReader("ls -l /\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ls -l: %v\n%s", err, out)
	}
	var a, b string
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasSuffix(line, " a.txt"):
			a = line
		case strings.HasSuffix(line, " b.txt"):
			b = line
		}
	}
	if !strings.Contains(a, "Mar  4 05:06 a.txt") {
		t.Errorf("a.txt line = %q, want the recorded mtime", a)
	}
	if b == "" || strings.Contains(b, "1970") || strings.Contains(b, "Jan  1 00:00") || !strings.Contains(b, "??? ?? ??:?? b.txt") {
		t.Errorf("b.txt line = %q, want no date at all", b)
	}
}
