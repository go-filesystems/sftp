module github.com/go-filesystems/sftp/fat32demo

go 1.26.4

// The demo is versioned with the server it demonstrates: it must build
// against the working tree, not against whatever the proxy last published.
replace github.com/go-filesystems/sftp => ../

require (
	github.com/go-filesystems/fat32 v0.4.0
	github.com/go-filesystems/interface v0.3.0
	github.com/go-filesystems/sftp v0.3.0
	golang.org/x/crypto v0.57.0
)

require (
	github.com/go-volumes/gpt v0.2.0 // indirect
	github.com/go-volumes/safeio v0.0.0-20260831125406-d8f54b2890d4 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
