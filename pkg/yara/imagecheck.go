//go:build unix

package yara

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

// trustedImagePrefixes are dyld shared cache locations: images there are
// served from the SIP-protected cache and may not exist as files.
var trustedImagePrefixes = []string{"/usr/lib/", "/System/"}

// checkImages returns an error naming the first image outside the trusted
// prefixes whose file, symlink target, or any ancestor directory (of the
// loaded path and of the resolved path) is not owned by root or is group- or
// world-writable. lstat and resolve are injected for tests.
func checkImages(names []string, lstat func(string) (fs.FileInfo, error), resolve func(string) (string, error)) error {
	for _, name := range names {
		if trusted(name) {
			continue
		}
		if !filepath.IsAbs(name) {
			return fmt.Errorf("yara: loaded image %q has a relative path", name)
		}
		if err := checkChain(name, lstat); err != nil {
			return fmt.Errorf("yara: loaded image %s is not root-protected: %w", name, err)
		}
		real, err := resolve(name)
		if err != nil {
			return fmt.Errorf("yara: loaded image %s: %w", name, err)
		}
		if real != name && !trusted(real) {
			if err := checkChain(real, lstat); err != nil {
				return fmt.Errorf("yara: loaded image %s (-> %s) is not root-protected: %w", name, real, err)
			}
		}
	}
	return nil
}

func trusted(p string) bool {
	for _, pre := range trustedImagePrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// checkChain checks p and every ancestor directory up to "/". A symlink's own
// mode is not meaningful (always 0755); its owner and directory are checked
// here and its target by the caller.
func checkChain(p string, lstat func(string) (fs.FileInfo, error)) error {
	for cur := filepath.Clean(p); ; cur = filepath.Dir(cur) {
		fi, err := lstat(cur)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: no ownership information", cur)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root", cur, st.Uid)
		}
		if fi.Mode()&fs.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is group- or world-writable (%s)", cur, fi.Mode().Perm())
		}
		if cur == "/" {
			return nil
		}
	}
}
