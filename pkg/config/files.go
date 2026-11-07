package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
)

// requiredOwner is the uid every file read through SecureRead must belong
// to; -1 disables the owner and mode checks. It defaults to 0 (root) when the
// process runs as root, so a root ZAAFVesper never parses a file that a non-root
// user could have written.
var requiredOwner atomic.Int64

func init() {
	if os.Geteuid() == 0 {
		requiredOwner.Store(0)
	} else {
		requiredOwner.Store(-1)
	}
}

// RequireOwner sets the uid SecureRead demands (-1 = no ownership check).
// ZAAFVesper sets it from its effective uid; tests use their own uid.
func RequireOwner(uid int64) { requiredOwner.Store(uid) }

// RequiredOwner returns the current SecureRead owner policy (-1 = none).
func RequiredOwner() int64 { return requiredOwner.Load() }

// SecureRead opens path once with O_NOFOLLOW, checks the open descriptor
// (regular file, at most max bytes, and - when an owner is required - owned
// by that uid and not group/world writable) and returns the bytes read from
// that same descriptor. There is no window between the check and the read.
func SecureRead(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
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
		if err := checkInfo(path, fi, uint32(owner), false); err != nil {
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
// directory up to / is owned by root and not writable by group or others.
// The paths themselves and everything beneath them must not be symbolic
// links; ancestors are checked on their resolved location, so /etc ->
// /private/etc works.
//
// ZAAFVesper calls this before parsing anything when it runs as root: anyone who
// can write a rule, the configuration, or a directory on their path could
// otherwise make ZAAFVesper kill arbitrary processes.
func CheckOwnership(paths ...string) error {
	return checkOwnership(0, paths...)
}

// checkOwnership accepts owner 0 or wantUID (the same thing in production,
// where wantUID is 0; tests pass their own uid).
func checkOwnership(wantUID uint32, paths ...string) error {
	var errs []error
	seen := map[string]bool{}
	check := func(p string, fi fs.FileInfo, ancestor bool) {
		if seen[p] {
			return
		}
		seen[p] = true
		if err := checkInfo(p, fi, wantUID, ancestor); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Ancestors, on their real location.
		parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for d := parent; ; d = filepath.Dir(d) {
			fi, err := os.Lstat(d)
			if err != nil {
				errs = append(errs, err)
				break
			}
			check(d, fi, true)
			if d == filepath.Dir(d) {
				break
			}
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !fi.IsDir() {
			check(abs, fi, false)
			continue
		}
		err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			info, err := os.Lstat(path)
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			check(path, info, false)
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func checkInfo(p string, fi fs.FileInfo, wantUID uint32, ancestor bool) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: is a symbolic link (not allowed when running as root)", p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read owner", p)
	}
	if st.Uid != 0 && st.Uid != wantUID {
		what := "file"
		if ancestor {
			what = "parent directory"
		}
		return fmt.Errorf("%s: %s owned by uid %d, must be owned by root (install with 'sudo make install')", p, what, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: mode %v is group- or world-writable", p, fi.Mode().Perm())
	}
	return nil
}

// CreatePrivate creates a new file with mode 0600. It fails if the path
// already exists (including as a symbolic link), so an attacker cannot
// pre-plant a link that makes a root process overwrite another file.
func CreatePrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}
