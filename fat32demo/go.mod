module github.com/go-filesystems/sftp/fat32demo

go 1.26.4

// The demo is versioned with the server it demonstrates: it must build
// against the working tree, not against whatever the proxy last published.
replace github.com/go-filesystems/sftp => ../

require (
	github.com/go-filesystems/fat32 v0.3.0
	github.com/go-filesystems/interface v0.3.0
	github.com/go-filesystems/sftp v0.1.0
	golang.org/x/crypto v0.56.0
)

require (
	github.com/go-volumes/gpt v0.0.0-20260622072431-e1d6ba3b531c // indirect
	github.com/go-volumes/safeio v0.0.0-20260622072324-7f8eb19f6f8c // indirect
	golang.org/x/sys v0.47.0 // indirect
)
