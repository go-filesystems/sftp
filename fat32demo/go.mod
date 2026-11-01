module github.com/go-filesystems/sftp/fat32demo

go 1.27.1

// The demo is versioned with the server it demonstrates: it must build
// against the working tree, not against whatever the proxy last published.
replace github.com/go-filesystems/sftp => ../

require (
	github.com/go-filesystems/fat32 v0.7.1
	github.com/go-filesystems/interface v0.5.0
	github.com/go-filesystems/sftp v0.7.1
	golang.org/x/crypto v0.58.0
)

require (
	github.com/go-filesystems/hostcopy v0.1.0 // indirect
	github.com/go-volumes/gpt v0.3.0 // indirect
	github.com/go-volumes/safeio v0.0.0-20261011024942-5635ea21db3b // indirect
	golang.org/x/sys v0.49.0 // indirect
)
