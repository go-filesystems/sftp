module github.com/go-filesystems/sftp/fat32demo

// Raised with the root module on 2026-11-15 for GO-2026-6859 (net/http, fixed
// in 1.27.4); the reasoning is in ../go.mod.
//
// ⛔ A NESTED MODULE KEEPS ITS OWN DIRECTIVE, so a raise that stops at the root
// leaves this one behind and the sweep keeps reporting the repository.
go 1.27.4

// The demo is versioned with the server it demonstrates: it must build
// against the working tree, not against whatever the proxy last published.
replace github.com/go-filesystems/sftp => ../

require (
	github.com/go-filesystems/fat32 v0.13.0
	github.com/go-filesystems/interface v0.6.0
	github.com/go-filesystems/sftp v0.12.0
	github.com/go-filesystems/ssh v0.1.0
)

require (
	github.com/go-filesystems/hostcopy v0.1.0 // indirect
	github.com/go-filesystems/inflight v0.2.0 // indirect
	github.com/go-volumes/gpt v0.3.0 // indirect
	github.com/go-volumes/safeio v0.0.0-20261011024942-5635ea21db3b // indirect
	golang.org/x/crypto v0.58.1-0.20261009181718-2f1f834330b2 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
