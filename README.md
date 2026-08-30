<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems.png" alt="go-filesystems/sftp" width="720"></p>

# sftp

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/sftp.svg)](https://pkg.go.dev/github.com/go-filesystems/sftp)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/sftp/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/sftp/actions/workflows/ci.yml)

Pure-Go (CGO=0) **SFTP server** that exports any
[`go-filesystems/interface`](https://github.com/go-filesystems/interface)
`Filesystem` — so every driver in the family becomes reachable from **any
ordinary SFTP client**, with nothing installed on the client side and nothing
mounted.

No kernel extension. No FSKit entitlement. No cgo. No root, on either side.

## Why SFTP

`go-filesystems/nfs` makes a driver *mountable*. Mounting is powerful and it
has a price: it needs root on the client, a mount point, and an
administrator's cooperation. SFTP asks for none of that.

An SFTP client is already everywhere, and it is already the thing people
reach for:

| | |
|---|---|
| `sftp`, `scp` | ships with OpenSSH — every Linux, every macOS, **Windows 10 and later** |
| Cyberduck, Transmit, FileZilla, WinSCP | ordinary desktop file browsers |
| VS Code, TRAMP | edit a file in the image in place |
| GNOME Files (gvfs) | mounts `sftp://` **as a plain user**, no root |

And the protocol brings what NFSv3 does not have at all: **public-key
authentication and encryption**, built in rather than bolted on.

## Why it makes per-client isolation cheap

> *"SFTP would let us isolate clients in their own file, in user space, with a
> dedicated server."*

One disk image per client. One process per client. Its own keys.

**The isolation boundary is the image file plus the process** — not a chroot,
not permissions, not a uid. There is nothing to escape *to*, because the
server holds exactly one `Filesystem` and has no way to name anything else. It
never touches a host path, and the only paths it ever resolves are the ones
`clean` has already clamped inside the image.

That is a property, not an aspiration, so it is tested:
[`TestNoPathEscapesTheExport`](sftp_test.go) and
[`TestNoSymlinkEscapesTheExport`](sftp_test.go) do not merely assert that an
escape *fails* — they assert that it resolves to the file the image actually
contains at the clamped path, which is the much stronger statement.

`Serve` is cheap to instantiate and cheap to run N times on one machine, which
is what makes "a server per tenant" a real deployment shape rather than a
slogan. It is a library first (the target is **weft**, the fleet's microVM
cloud) and a standalone binary second.

## Install

```
go get github.com/go-filesystems/sftp
```

## Serving one

```go
fsys, err := fat32.Open("disk.img", -1)
if err != nil {
	return err
}
defer fsys.Close()

srv, err := sftp.New(fsys, sftp.ReadWrite()) // read-only by default
if err != nil {
	return err
}

d, err := sshd.New(srv, sshd.Config{
	HostKeys:       []ssh.Signer{hostKey},   // yours; nothing is read from a fixed path
	AuthorizedKeys: []ssh.PublicKey{clientKey},
})
if err != nil {
	return err
}
return d.ListenAndServe("127.0.0.1:2222")
```

Then, from anything:

```
sftp -P 2222 user@127.0.0.1
```

**Host keys and authorised keys are always supplied by the caller.** This
module opens no key file, consults no `~/.ssh`, and has no "allow any key"
switch — not even in the demo, because such switches get copied into
deployments.

## Layout

| package | depends on | why |
|---|---|---|
| `wire/` | **nothing but the standard library** | the v3 packet codec |
| `.` | `interface`, `wire` | the SFTP subsystem over a `Filesystem` |
| `sshd/` | `.`, `golang.org/x/crypto/ssh` | the SSH front-end |

**The codec is deliberately isolated.** `wire` imports neither the filesystem
interface nor the server — it is checked, not merely intended. The reason is
that an `sftp://` *client* transport may one day live in `go-streamkit`, and it
would share this encoding; keeping the dependency edge absent now means that
extraction is a **move rather than a rewrite**. `go-filesystems/nfs` made the
same split with its `xdr/` and `rpc/` packages.

Cryptography is **not** reimplemented: the transport is
`golang.org/x/crypto/ssh`. The SFTP subsystem itself
(`draft-ietf-secsh-filexfer-02`, **version 3** — what every client actually
speaks) is implemented here, because the protocol is the thing this repository
is *for*.

## The write path, measured

`SSH_FXP_READ(handle, offset, len)` lands exactly on `filesystem.Opener` /
`File.ReadAt`, and `SSH_FXP_WRITE(handle, offset, data)` lands exactly on
**`filesystem.WritableFile`** (`io.WriterAt` + `Truncate` + `Sync`), published
in interface v0.3.0 and implemented by `fat32` v0.3.0. Both are optional
capabilities, probed with a type assertion.

When a driver has **not** got `WritableFile`, the only write the base contract
offers is `WriteFile(path, data, perm)`, which replaces the file *whole*. A
write at an offset then costs read-all + splice + write-all, **per request** —
so streaming a file in fixed-size chunks is O(n²).

That cost is measured, not asserted. 2 MiB through the real OpenSSH client in
its own 32 KiB chunks, Apple M-series, `task measure`:

| path | time | throughput |
|---|---|---|
| `WritableFile` (positional) | **46 ms** | **44 066 kB/s** |
| `WriteFile` fallback (splice) | 1.021 s | 2 007 kB/s |

**22× slower** — and the gap *grows with the file*, which is the part that
matters:

| size | time | throughput | cost of doubling |
|---|---|---|---|
| 1 MiB | 182 ms | 5 638 kB/s | |
| 2 MiB | 1.109 s | 1 846 kB/s | **6.11×** |
| 4 MiB | 8.114 s | 505 kB/s | **7.31×** |

Worse than the 4× a purely quadratic term predicts, because the driver's
`WriteFile` also rewalks the cluster chain each time. `go-filesystems/nfs`
measured the identical construction at 90 kB/s, with a soft-mounted client
giving up with `EIO` partway through. **This is why the fallback is documented
as a wall and not as a slow path** — and why it is deliberately *not* hidden
behind a write-back cache, which would make the benchmark look fine while
turning "the server acknowledged this write" into a durability claim it cannot
honour.

## Verification

"It compiles" is not evidence. The gate is 100% of statements, error branches
included, on both modules — but the claim that matters is that a **real client**
agrees, so `fat32demo/` serves a genuine driver-formatted image to the `sftp`
binary that ships with OpenSSH and compares on content:

- `ls`, then `get` of a 1 MiB file — **sha256 of what the client received
  equals sha256 of what the driver returns from `ReadFile`**, not what the test
  wrote.
- `reget` resuming at offset 700 000, the only step that exercises a **non-zero
  READ offset**: a plain `get` always starts at zero, so a server that ignored
  the offset entirely would pass everything else.
- `put` of 64 KiB, verified by **reopening the image** and reading it back
  through the driver, so the assertion is about what reached the medium rather
  than state the live server still holds.
- a `put` against a read-only export must fail *and* leave nothing behind.

The wire is big-endian, so CI runs the test binaries under QEMU on **s390x**
as well as riscv64, loong64 and ppc64le — s390x being the arch on which a
forgotten `binary.BigEndian` would still pass on the developer's machine.

Every key in the test suite is generated with `ssh-keygen` into `t.TempDir()`,
outside every repository, and removed when the test ends. No key is read from
or written to a fixed location, `.gitignore` refuses key shapes as a net, and
CI fails the build if any key material or image survives in the work tree.

## Security posture

- **Bind to loopback** unless you have decided otherwise.
- Read-only is the **default**; `sftp.ReadWrite()` is opt-in, because an
  accidental write to a forensic or build artefact is unrecoverable.
- Authentication is public-key only. There is no password path, and no way to
  authorise a key the caller did not name.
- A server can reach **nothing but the one `Filesystem` it was given**. No host
  path, no `..` escape, no symlink out of the image.

## Licence

BSD-3-Clause.
