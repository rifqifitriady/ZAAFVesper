//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
)

// openOutputDir creates dir (0700) when it is missing, checks it and opens
// it. As root the directory and every ancestor must be root-owned and not
// group/world writable (config.CheckOwnership); in every mode the directory
// itself must not be group/world writable.
func openOutputDir(dir string, asRoot bool) (*outputDir, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(abs, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("output directory: %w", err)
	}
	if asRoot {
		if err := config.CheckOwnership(abs); err != nil {
			return nil, fmt.Errorf("output directory %s is not safe to write as root:\n%w", abs, err)
		}
	}
	fd, err := unix.Open(abs, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("output directory %s: %w", abs, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("output directory %s: %w", abs, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		err = errors.New("not a directory")
	case st.Mode&0o022 != 0:
		err = fmt.Errorf("mode %o is group- or world-writable", st.Mode&0o777)
	case asRoot && st.Uid != 0:
		err = fmt.Errorf("owned by uid %d, must be owned by root", st.Uid)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("output directory %s: %w", abs, err)
	}
	return &outputDir{path: abs, fd: fd, now: time.Now}, nil
}

// createExcl creates name in the directory (O_CREAT|O_EXCL|O_NOFOLLOW,
// 0600); an existing name gives an error matching fs.ErrExist.
func (d *outputDir) createExcl(name string) (*os.File, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(d.path, name)), nil
}

// names lists the directory through its descriptor.
func (d *outputDir) names() ([]string, error) {
	dfd, err := unix.Openat(d.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dfd), d.path)
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	return names, err
}

// regularSize returns the size of name when it is a regular file (never
// following a link).
func (d *outputDir) regularSize(name string) (int64, bool) {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, false
	}
	return st.Size, true
}

func (d *outputDir) unlink(name string) error { return unix.Unlinkat(d.fd, name, 0) }

func (d *outputDir) close() error { return unix.Close(d.fd) }
