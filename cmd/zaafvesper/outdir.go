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
// whose names match ZAAFVesper's own pattern. The file operations are in
// outdir_unix.go and outdir_windows.go.
type outputDir struct {
	path string
	fd   int // open directory descriptor (Unix) or held directory handle (Windows)
	now  func() time.Time
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
		f, err := d.createExcl(name)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(d.path, name), err)
		}
		return f, nil
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
	names, err := d.names()
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
		if _, ok := d.regularSize(n); !ok {
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
// clock stepped back) is never old enough. On Unix everything is
// fd-relative and nothing is followed; on Windows see outdir_windows.go.
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
		size, ok := d.regularSize(f.name)
		if !ok {
			continue
		}
		if size > 0 && now.Sub(f.stamp) < minPruneAge {
			continue
		}
		if err := d.unlink(f.name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
			continue
		}
		removed = append(removed, f.name)
		left--
	}
	return left <= keep-1, removed, errors.Join(errs...)
}
