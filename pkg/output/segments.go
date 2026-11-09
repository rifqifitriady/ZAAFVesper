//go:build unix

package output

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
)

// Segments writes NDJSON lines into rotating segment files in one
// directory, for scheduled hunts (`zaaf hunt DIR/*.ndjson`). The open
// segment is events-<UTC>.ndjson.part and is renamed to events-<UTC>.ndjson
// only once it is closed, so a hunt that globs *.ndjson never reads a
// segment that is still being written. As the spool: every operation is
// relative to an open descriptor of the directory, files are created with
// O_CREAT|O_EXCL|O_NOFOLLOW 0600, and only names matching segmentName are
// renamed or deleted. As root the directory and every ancestor must pass
// config.CheckOwnership; the directory must be accessible by its owner only.
//
// Write must be called with whole lines (the LineWriter does): rotation
// happens only between writes. It implements io.Writer, io.Closer and the
// LineWriter's rotator.
type Segments struct {
	mu        sync.Mutex
	cfg       SegmentConfig
	path      string
	fd        int
	cur       *os.File
	curName   string // final name of the open segment
	curSize   int64
	lineEnd   int64 // size of the open segment up to its last complete line
	opened    time.Time
	closed    []segment // oldest first
	total     int64     // bytes in closed segments
	pruned    uint64
	rotated   uint64
	recovered uint64
}

type segment struct {
	name string
	size int64
}

// OpenSegments creates dir (0700, with missing parents) and opens it. A
// segment left open by a crash (.part) is closed (renamed) first.
func OpenSegments(dir string, cfg SegmentConfig, asRoot bool) (*Segments, error) {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultSegmentBytes
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultSegmentAge
	}
	if cfg.KeepBytes <= 0 {
		cfg.KeepBytes = DefaultSegmentKeep
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("elegia dir: %w", err)
	}
	if asRoot {
		if err := config.CheckOwnership(abs); err != nil {
			return nil, fmt.Errorf("elegia dir %s is not safe to use as root:\n%w", abs, err)
		}
	}
	fd, err := unix.Open(abs, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("elegia dir %s: %w", abs, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("elegia dir %s: %w", abs, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		err = errors.New("not a directory")
	case st.Mode&0o077 != 0:
		err = fmt.Errorf("mode %o: the directory must be accessible by its owner only (0700)", st.Mode&0o777)
	case int(st.Uid) != os.Geteuid():
		err = fmt.Errorf("owned by uid %d, not by this process's uid %d", st.Uid, os.Geteuid())
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("elegia dir %s: %w", abs, err)
	}
	s := &Segments{cfg: cfg, path: abs, fd: fd}
	if err := s.scan(); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return s, nil
}

// scan lists closed segments and closes any left open by a crash.
func (s *Segments) scan() error {
	dfd, err := unix.Dup(s.fd)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(dfd), s.path)
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("elegia dir %s: %w", s.path, err)
	}
	for _, e := range ents {
		m := segmentName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if m[3] != "" { // a crash left it open
			trimPartialLine(s.fd, name)
			final := name[:len(name)-len(partExt)]
			if err := unix.Renameat(s.fd, name, s.fd, final); err != nil {
				continue
			}
			name = final
			s.recovered++
		}
		var st unix.Stat_t
		if err := unix.Fstatat(s.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		s.closed = append(s.closed, segment{name: name, size: st.Size})
		s.total += st.Size
	}
	sort.Slice(s.closed, func(i, j int) bool { return s.closed[i].name < s.closed[j].name })
	return s.prune()
}

// trimPartialLine cuts a segment left open by a crash back to its last
// complete line (the process may have died in the middle of a write).
func trimPartialLine(dirfd int, name string) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	end := fi.Size()
	buf := make([]byte, 64<<10)
	for end > 0 {
		off := end - int64(len(buf))
		if off < 0 {
			off = 0
		}
		n, err := f.ReadAt(buf[:end-off], off)
		if err != nil && n == 0 {
			return
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			_ = f.Truncate(off + int64(i) + 1)
			return
		}
		end = off
	}
	_ = f.Truncate(0)
}

// open starts a new segment. Caller holds mu.
func (s *Segments) open() error {
	now := s.cfg.Now()
	stamp := now.UTC().Format(segmentStamp)
	for i := 0; i < 1000; i++ {
		final := "events-" + stamp + segmentExt
		if i > 0 {
			final = "events-" + stamp + "-" + strconv.Itoa(i) + segmentExt
		}
		// Neither the final nor the open name may exist yet.
		if err := unix.Faccessat(s.fd, final, unix.F_OK, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			continue
		}
		fd, err := unix.Openat(s.fd, final+partExt, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_APPEND, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("elegia dir %s: %w", s.path, err)
		}
		s.cur, s.curName, s.curSize, s.lineEnd, s.opened = os.NewFile(uintptr(fd), filepath.Join(s.path, final+partExt)), final, 0, 0, now
		return nil
	}
	return fmt.Errorf("elegia dir %s: no free segment name", s.path)
}

// Write appends whole lines to the open segment (opening one if needed).
func (s *Segments) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return 0, errors.New("elegia dir: closed")
	}
	if s.cur == nil {
		if err := s.open(); err != nil {
			return 0, err
		}
	}
	n, err := s.cur.Write(p)
	if i := bytes.LastIndexByte(p[:n], '\n'); i >= 0 {
		s.lineEnd = s.curSize + int64(i) + 1
	}
	s.curSize += int64(n)
	if err != nil {
		s.dropPartial()
	}
	return n, err
}

// Recover drops a partial line left by a failed write (the LineWriter calls
// it after an error), so a segment never holds broken JSON.
func (s *Segments) Recover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropPartial()
}

// dropPartial truncates the open segment to its last complete line. Caller
// holds mu.
func (s *Segments) dropPartial() {
	if s.cur == nil || s.curSize == s.lineEnd {
		return
	}
	if err := s.cur.Truncate(s.lineEnd); err == nil {
		s.curSize = s.lineEnd
	}
}

// Due reports whether the open segment should be closed now.
func (s *Segments) Due() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur != nil && s.curSize > 0 &&
		(s.curSize >= s.cfg.MaxBytes || s.cfg.Now().Sub(s.opened) >= s.cfg.MaxAge)
}

// Rotate closes the open segment (renaming it to its final name) and
// prunes old segments. The next Write opens a new one.
func (s *Segments) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finish()
}

// finish closes the open segment. Caller holds mu.
func (s *Segments) finish() error {
	if s.cur == nil {
		return nil
	}
	// Data reaches the disk before the segment becomes visible as closed.
	err := errors.Join(s.cur.Sync(), s.cur.Close())
	s.cur = nil
	part := s.curName + partExt
	if s.curSize == 0 {
		return errors.Join(err, unix.Unlinkat(s.fd, part, 0))
	}
	if rerr := unix.Renameat(s.fd, part, s.fd, s.curName); rerr != nil {
		return errors.Join(err, fmt.Errorf("elegia dir %s: %w", s.path, rerr))
	}
	s.closed = append(s.closed, segment{name: s.curName, size: s.curSize})
	s.total += s.curSize
	s.rotated++
	return errors.Join(err, s.prune())
}

// prune deletes the oldest closed segments beyond KeepBytes. Caller holds mu.
func (s *Segments) prune() error {
	var errs []error
	for s.total > s.cfg.KeepBytes && len(s.closed) > 0 {
		old := s.closed[0]
		if err := unix.Unlinkat(s.fd, old.name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("elegia dir %s: %w", old.name, err))
		}
		s.closed = s.closed[1:]
		s.total -= old.size
		s.pruned++
	}
	return errors.Join(errs...)
}

// Close closes the open segment and the directory.
func (s *Segments) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	err := s.finish()
	err = errors.Join(err, unix.Close(s.fd))
	s.fd = -1
	return err
}

// Stats returns the writer's counters.
func (s *Segments) Stats() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]uint64{"segments_closed": uint64(len(s.closed)), "segments_bytes": uint64(s.total),
		"open_segment_bytes": uint64(s.curSize), "rotations": s.rotated, "pruned": s.pruned, "recovered_at_start": s.recovered}
}

var _ io.WriteCloser = (*Segments)(nil)
