package config

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/rifqifitriady/ZAAFVesper/pkg/nofollow"
)

// requiredOwner is the uid every file read through SecureRead must belong
// to; -1 disables the owner and mode checks. It defaults to 0 (root) when the
// process runs as root, so a root ZAAFVesper never parses a file that a non-root
// user could have written. On Windows any value >= 0 means "protected": owned
// by SYSTEM, Administrators or TrustedInstaller and writable by nobody else
// (see files_windows.go); it defaults to 0 when the process is elevated.
var requiredOwner atomic.Int64

// RequireOwner sets the uid SecureRead demands (-1 = no ownership check).
// ZAAFVesper sets it from its effective uid; tests use their own uid.
func RequireOwner(uid int64) { requiredOwner.Store(uid) }

// RequiredOwner returns the current SecureRead owner policy (-1 = none).
func RequiredOwner() int64 { return requiredOwner.Load() }

// SecureRead opens path once without following a final symbolic link
// (O_NOFOLLOW; on Windows FILE_FLAG_OPEN_REPARSE_POINT), checks the open descriptor
// (regular file, at most max bytes, and - when an owner is required - owned
// by that uid, not group/world writable and without a write-permitting ACL) and returns the bytes read from
// that same descriptor. There is no window between the check and the read.
func SecureRead(path string, max int64) ([]byte, error) {
	f, err := nofollow.Open(path)
	if err != nil {
		if errors.Is(err, nofollow.ErrLink) {
			return nil, fmt.Errorf("%s: is a symbolic link (not allowed)", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if owner := requiredOwner.Load(); owner >= 0 {
		if err := checkOpenFile(path, f, fi, owner); err != nil {
			return nil, err
		}
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	return data, nil
}

// CheckOwnership verifies, like sshd's StrictModes, that each path,
// everything beneath the paths that are directories, and every ancestor
// directory up to / is owned by root, not writable by group or others, and
// carries no extended ACL entry that permits anyone a write-like right
// (deny entries are fine).
// The paths themselves and everything beneath them must not be symbolic
// links; ancestors are checked on their resolved location, so /etc ->
// /private/etc works.
//
// ZAAFVesper calls this before parsing anything when it runs as root: anyone who
// can write a rule, the configuration, or a directory on their path could
// otherwise make ZAAFVesper kill arbitrary processes.
//
// On Windows the same walk requires the owner to be SYSTEM, Administrators or
// TrustedInstaller and refuses any allow entry in the DACL that gives another
// SID a write-like right; see files_windows.go for what is and is not
// enforced there.
func CheckOwnership(paths ...string) error {
	return checkOwnership(0, paths...)
}
