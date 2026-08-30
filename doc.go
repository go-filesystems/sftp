// Package sftp implements an SFTP version 3 server
// (draft-ietf-secsh-filexfer-02) that exports any
// [github.com/go-filesystems/interface.Filesystem].
//
// Every driver in the family — ext4, xfs, btrfs, zfs, ntfs, fat32, exfat,
// hfsplus, apfs, iso9660, squashfs, ufs, ffs, uefi, oci — becomes something a
// person can reach from a file manager, an editor or a shell, over one TCP
// port, with SSH keys and encryption, from a pure-Go binary with no cgo.
//
// # Why SFTP
//
// The client already exists, everywhere, and nobody has to install it.
//
//   - `sftp` on the command line ships with OpenSSH, which is present on
//     macOS, on every Linux distribution, on the BSDs, and on Windows 10 and
//     later as an optional feature that is on by default in current builds.
//   - Graphical clients are abundant and free or cheap: Cyberduck, FileZilla,
//     WinSCP, Transmit.
//   - Editors speak it natively: VS Code, the JetBrains IDEs, Emacs by way of
//     TRAMP.
//   - GNOME mounts sftp:// through gvfs as an ordinary unprivileged user, with
//     no root and no entry in the kernel's mount table.
//
// And the security is not bolted on. Authentication is SSH public keys and
// the channel is encrypted, both from [golang.org/x/crypto/ssh] — see
// [github.com/go-filesystems/sftp/sshd]. NFSv3, the sibling of this module,
// has neither: its AUTH_UNIX credentials are claims a client makes about
// itself and the wire cannot disagree. It is one TCP port, so a firewall can
// reason about it, and nothing needs privilege on either side: no mount, no
// kernel extension, no FSKit entitlement, no root.
//
// # The isolation this is built for
//
// One image file per client, one server process per client, each with its own
// keys. The isolation boundary is the image file plus the process — not a
// chroot, not uid mapping, not namespaces.
//
// That is why [Server] takes exactly one [github.com/go-filesystems/interface.Filesystem]
// and holds no other capability. It never touches the host filesystem, never
// resolves a path against anything but the driver it was handed, and cannot
// be induced to: a client path is cleaned with ".." clamped at the root
// before it reaches the driver, so no sequence of components names anything
// outside the image, and a symbolic link inside the image resolves inside the
// image because the driver is the only thing doing the resolving. The tests
// assert this directly rather than leaving it to be inferred.
//
// A Server is cheap: no goroutine until a session arrives, no listener of its
// own, no global state. Running a hundred of them on one machine, one per
// tenant, is the intended shape, and [Server.Serve] is deliberately handed a
// stream rather than a listener so that an embedding program — a microVM
// supervisor, say — can wire it into an SSH server it already runs.
//
// # Serving one
//
//	fsys, err := fat32.Open("tenant.img", -1)
//	if err != nil {
//		return err
//	}
//	defer fsys.Close()
//
//	srv, err := sftp.New(fsys)          // read-only by default
//	if err != nil {
//		return err
//	}
//	// Then either hand srv.Serve a stream you own, or let the sshd
//	// subpackage own the SSH side:
//	d, err := sshd.New(srv, sshd.Config{HostKeys: ..., AuthorizedKeys: ...})
//
// # Two honest gaps, both in the contract and not in this server
//
// Reads. [github.com/go-filesystems/interface.Opener] is exactly the shape of
// SSH_FXP_READ: OpenFile(path) returns a File whose ReadAt(buf, off) answers
// the request as asked. This module uses it when a driver has it. At the time
// of writing NO driver in the fleet implements it, so in practice every read
// goes through the fallback, which calls ReadFile — materialising the WHOLE
// file — once per READ request. An OpenSSH client reads in 32 KiB chunks, so
// fetching an n-byte file costs n/32768 full-file reads: quadratic. That is
// measured in the README rather than described.
//
// The tempting fix — read the file once when the handle is opened and serve
// reads from that copy — is not taken, because it trades a quadratic time
// cost for a linear MEMORY cost and a 4 GiB image file becomes 4 GiB of
// resident memory in a process meant to run a hundred times over. The real
// fix is a driver implementing Opener, and leaving the cost visible is what
// keeps that pressure where it belongs.
//
// Writes. SSH_FXP_WRITE carries an offset, and the base contract has only
// WriteFile, which replaces a file whole. A write at an offset therefore
// becomes read-modify-write of the entire file: O(filesize) per request, and
// O(filesize²) for a client streaming a file in chunks. This is the same wall
// [github.com/go-filesystems/nfs] hit and measured at 90 kB/s. Exports are
// consequently READ-ONLY BY DEFAULT — see [ReadWrite] — and the number for
// this module is in the README.
//
// The escape is [WritableFile]: a File that also has WriteAt, Truncate and
// Sync. When a driver's File satisfies it, writes go to the offset directly
// and the wall disappears. The probe is here and tested; the implementations
// belong in the drivers.
package sftp
