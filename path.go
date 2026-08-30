package sftp

import "strings"

// maxPath caps a resolved path. It is not a limit any filesystem imposes; it
// bounds the memory one hostile request can make the server hold while it
// builds a path out of components.
const maxPath = 4096

// clean normalises a client-supplied path into an absolute path inside the
// export, and reports whether it was acceptable at all.
//
// This is the containment guarantee of the whole module, so it is written out
// rather than delegated to path.Clean, for two reasons that matter:
//
//   - path.Clean leaves a leading ".." in place. "../../etc/passwd" stays
//     "../../etc/passwd", and whatever the driver then does with it is not
//     something this package gets to be surprised by. Here ".." is CLAMPED at
//     the root: it pops a component if there is one and is a no-op if there
//     is not, so no sequence of components can name anything above "/".
//   - A relative path must not be silently rooted by string concatenation
//     somewhere else. SFTP clients send relative paths constantly — "." is
//     the first thing OpenSSH's client sends, to REALPATH its way to a
//     starting directory — so relative input is normal input, and it is
//     resolved against the export root here, once.
//
// A NUL is rejected outright. It cannot appear in any name a driver can
// store, and admitting one would let the name a person sees differ from the
// name a C consumer downstream sees.
func clean(p string) (string, bool) {
	if strings.ContainsRune(p, 0) {
		return "", false
	}
	if len(p) > maxPath {
		return "", false
	}
	var out []string
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".":
			// Empty covers both a leading slash and a doubled one; a
			// trailing slash disappears the same way, so "/a/" and "/a"
			// name the same thing, as they must.
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, part)
		}
	}
	return "/" + strings.Join(out, "/"), true
}

// parent returns the containing directory, clamped at the root.
func parent(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// base returns the final component of a cleaned path. The root's own base is
// "/", which is what a REALPATH of "/" must display.
func base(p string) string {
	if p == "/" {
		return "/"
	}
	return p[strings.LastIndexByte(p, '/')+1:]
}

// join appends one directory entry name to a cleaned directory path.
//
// The name comes from the driver, not from the network, so this does not
// re-validate it; what it does guarantee is that a driver reporting a name
// containing a slash cannot produce a path that means something else. Such a
// name is rejected by returning false, and the entry is skipped rather than
// listed under a path that would not resolve back to it.
func join(dir, name string) (string, bool) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return "", false
	}
	if dir == "/" {
		return "/" + name, true
	}
	full := dir + "/" + name
	if len(full) > maxPath {
		return "", false
	}
	return full, true
}
