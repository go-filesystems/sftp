// Command fat32demo serves a real FAT32 image over SFTP.
//
// It is the harness behind this repository's end-to-end verification: it
// exists so that OpenSSH's own `sftp` client can be pointed at a genuine
// driver-produced image and the bytes it receives compared with what the
// driver returns directly.
//
//	fat32demo -image disk.img -authorized-keys ./ak.pub -addr 127.0.0.1:2222 -rw
//
// The host key is ephemeral and in-memory unless -host-key names one, and no
// key is ever read from or written to a fixed location.
package main

import (
	"os"

	"github.com/go-filesystems/sftp/fat32demo/demo"
)

func main() { os.Exit(demo.Main(os.Args[1:], os.Stdout, os.Stderr)) }
