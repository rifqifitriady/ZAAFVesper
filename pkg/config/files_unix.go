//go:build unix

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func init() {
	if os.Geteuid() == 0 {
		requiredOwner.Store(0)
	} else {
		requiredOwner.Store(-1)
	}
}

// checkOpenFile applies the owner, mode and ACL checks to the descriptor
// SecureRead opened.
func checkOpenFile(path string, f *os.File, fi fs.FileInfo, owner int64) error {
	if err := checkInfo(path, fi, uint32(owner), false); err != nil {
		return err
	}
	if err := checkACLFd(int(f.Fd())); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
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
			return
		}
		if err := checkACLPath(p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
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
		return fmt.Errorf("%s: %s owned by uid %d, must be owned by root (install the package built by 'make package')", p, what, st.Uid)
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
