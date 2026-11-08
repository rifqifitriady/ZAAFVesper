package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
)

// File name prefixes and extensions in the output directory.
const (
	alertsPrefix     = "alerts"
	alertsHighPrefix = "alerts-high"
	alertsExt        = ".jsonl"
	capturePrefix    = "capture"
	captureExt       = ".rcap"
	// outputStamp is fixed width, so names sort in time order.
	outputStamp = "20060102T150405.000000000Z"
)

// outputDir is the directory ZAAFVesper writes its own files into
// (--output-dir). Every file operation is relative to an open descriptor of
// the directory and never follows a symbolic link: files are created with
// O_CREAT|O_EXCL|O_NOFOLLOW 0600, and pruning only unlinks regular files
// whose names match ZAAFVesper's own pattern.
type outputDir struct {
	path string
	fd   int
	now  func() time.Time
}

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

// create makes a new file <prefix>-<UTC timestamp><ext> (0600, never an
// existing name, never through a link) and returns it with its name.
func (d *outputDir) create(prefix, ext string) (*os.File, error) {
	stamp := d.now().UTC().Format(outputStamp)
	for i := 0; i < 100; i++ {
		name := prefix + "-" + stamp + ext
		if i > 0 {
			name = prefix + "-" + stamp + "-" + strconv.Itoa(i) + ext
		}
		fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(d.path, name), err)
		}
		return os.NewFile(uintptr(fd), filepath.Join(d.path, name)), nil
	}
	return nil, fmt.Errorf("%s: no free file name for %s", d.path, prefix)
}

// minPruneAge: alert and capture files younger than this (by the time in
// their own name, never by mtime, which the content's writer controls) are
// never deleted to make room. Evidence is preserved over completeness.
const minPruneAge = 7 * 24 * time.Hour

// ownFile is one of ZAAFVesper's files in the output directory.
type ownFile struct {
	name  string
	stamp time.Time
	seq   int // the -N suffix create adds on a name collision (0: none)
}

// ownName matches the names create produces for a prefix and extension and
// captures the timestamp and the optional collision suffix.
func ownName(prefix, ext string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `-(\d{8}T\d{6}\.\d{9}Z)(?:-(\d{1,2}))?` + regexp.QuoteMeta(ext) + `$`)
}

// list returns the own files of one kind, oldest first: by the timestamp in
// the name, then by the numeric collision suffix (so -2 sorts before -10 and
// the plain name before -1).
func (d *outputDir) list(prefix, ext string) ([]ownFile, error) {
	dfd, err := unix.Openat(d.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dfd), d.path)
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	re := ownName(prefix, ext)
	var own []ownFile
	for _, n := range names {
		m := re.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		stamp, err := time.Parse(outputStamp, m[1])
		if err != nil {
			continue
		}
		// Only regular files are ours; anything else is neither counted
		// nor touched.
		var st unix.Stat_t
		if err := unix.Fstatat(d.fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		seq := 0
		if m[2] != "" {
			seq, _ = strconv.Atoi(m[2])
		}
		own = append(own, ownFile{name: n, stamp: stamp, seq: seq})
	}
	sort.Slice(own, func(i, j int) bool {
		if !own[i].stamp.Equal(own[j].stamp) {
			return own[i].stamp.Before(own[j].stamp)
		}
		return own[i].seq < own[j].seq
	})
	return own, nil
}

// makeRoom deletes the oldest own files of one kind until at most keep-1
// remain, so that one new file fits in the keep budget, and reports whether
// it fits. A file is deleted only if it is a regular file, is not in open
// (the files ZAAFVesper is writing), and is either empty or named with a
// time at least minPruneAge before now. A file named in the future (the
// clock stepped back) is never old enough. Everything is fd-relative and
// nothing is followed.
func (d *outputDir) makeRoom(prefix, ext string, keep int, open map[string]bool) (room bool, removed []string, err error) {
	own, err := d.list(prefix, ext)
	if err != nil {
		return false, nil, err
	}
	now := d.now()
	left := len(own)
	var errs []error
	for _, f := range own {
		if left <= keep-1 {
			break
		}
		if open[f.name] {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(d.fd, f.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		if st.Size > 0 && now.Sub(f.stamp) < minPruneAge {
			continue
		}
		if err := unix.Unlinkat(d.fd, f.name, 0); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
			continue
		}
		removed = append(removed, f.name)
		left--
	}
	return left <= keep-1, removed, errors.Join(errs...)
}

func (d *outputDir) close() error { return unix.Close(d.fd) }
