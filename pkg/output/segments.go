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
// A file that carries a segment name but is not ours (a symbolic link, a
// file of another owner, a mode wider than 0600, a hard link) is never
// renamed, truncated, listed for deletion or read as a segment: it is left
// untouched, counted (unsafe_skipped) and reported (elegia_dir_error).
//
// Retention: closed segments beyond KeepBytes are deleted oldest first, but
// never one younger than the retention floor (MinKeep). When the floor keeps
// the closed segments above KeepBytes the writer is full: it opens no new
// segment, drops the records it is given (dropped_dir_full) and reports
// elegia_dir_full, until space is free again. Capture stops rather than
// erase young evidence.
//
// Write must be called with whole lines (the LineWriter does): rotation
// happens only between writes. It implements io.Writer, io.Closer and the
// LineWriter's rotator.
type Segments struct {
	mu      sync.Mutex
	cfg     SegmentConfig
	path    string
	fd      int
	cur     *os.File
	curName string // final name of the open segment
	curSize int64
	lineEnd int64 // size of the open segment up to its last complete line
	opened  time.Time
	closed  []segment // oldest first
	total   int64     // bytes in closed segments

	full      bool
	fullSince time.Time
	lastRetry time.Time

	seen map[string]bool // problems already reported, by name

	pruned, prunedBytes, rotated, recovered uint64
	unsafeSkipped, ioErrors, nameCollisions uint64
	droppedFull, fullEpisodes               uint64
}

type segment struct {
	name string
	size int64
	at   time.Time // when it was closed (modification time for files found at start)
}

// maxSeenNames bounds the names remembered as already reported.
const maxSeenNames = 256

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
	if cfg.MinKeep == 0 {
		cfg.MinKeep = DefaultSegmentMinKeep
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
	s := &Segments{cfg: cfg, path: abs, fd: fd, seen: map[string]bool{}}
	s.mu.Lock()
	err = s.scan(true)
	s.mu.Unlock()
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return s, nil
}

// report passes a problem to the owner. Caller holds mu.
func (s *Segments) report(cond, format string, args ...any) {
	if s.cfg.OnDegraded != nil {
		s.cfg.OnDegraded(cond, fmt.Sprintf(format, args...))
	}
}

// once reports key's first occurrence only. Caller holds mu.
func (s *Segments) once(key string) bool {
	if s.seen[key] {
		return false
	}
	if len(s.seen) < maxSeenNames {
		s.seen[key] = true
	}
	return true
}

// ioErr counts and reports an I/O error that used to be discarded. Caller
// holds mu.
func (s *Segments) ioErr(what, name string, err error) {
	s.ioErrors++
	s.report(CondDirError, "elegia dir %s: %s %s: %v", s.path, what, name, err)
}

// unsafe counts and reports (once per name) a file with a segment name that
// is not ours; it is left untouched. Caller holds mu.
func (s *Segments) unsafe(name string, why error) {
	if !s.once("unsafe:" + name) {
		return
	}
	s.unsafeSkipped++
	s.report(CondDirError, "elegia dir %s: %s is not a segment this writer can trust (%v); it is left untouched", s.path, name, why)
}

// vet applies the spool's checks (spool_unix.go): a regular file owned by
// this process's uid, no wider than 0600, with a single link.
func vet(st *unix.Stat_t) error {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return errors.New("not a regular file")
	case int(st.Uid) != os.Geteuid():
		return fmt.Errorf("owned by uid %d, not by this process's uid %d", st.Uid, os.Geteuid())
	case st.Mode&0o7777&^0o600 != 0:
		return fmt.Errorf("mode %o: wider than 0600", st.Mode&0o7777)
	case st.Nlink != 1:
		return fmt.Errorf("has %d links (a hard link is not allowed)", st.Nlink)
	}
	return nil
}

// scan lists the closed segments. With recoverPart it also closes the
// segments a crash left open; without it (a later re-listing) .part files are
// left alone. Caller holds mu.
func (s *Segments) scan(recoverPart bool) error {
	// A fresh descriptor, so every listing starts at the beginning.
	dfd, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("elegia dir %s: %w", s.path, err)
	}
	d := os.NewFile(uintptr(dfd), s.path)
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("elegia dir %s: %w", s.path, err)
	}
	now := s.cfg.Now()
	known := map[string]time.Time{} // when this writer closed a segment it already knows
	for _, c := range s.closed {
		known[c.name] = c.at
	}
	var closed []segment
	var total int64
	taken := map[string]bool{}
	for _, e := range ents {
		taken[e.Name()] = true
	}
	for _, e := range ents {
		m := segmentName.FindStringSubmatch(e.Name())
		if m == nil {
			continue // foreign files are never touched
		}
		name := e.Name()
		isPart := m[3] != ""
		if isPart && !recoverPart {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(s.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				s.ioErr("stat", name, err)
			}
			continue
		}
		if err := vet(&st); err != nil {
			s.unsafe(name, err)
			continue
		}
		if isPart { // a crash left it open
			final := name[:len(name)-len(partExt)]
			if taken[final] {
				s.unsafe(name, fmt.Errorf("the closed name %s already exists; neither is touched", final))
				continue
			}
			if err := trimPartialLine(s.fd, name, &st); err != nil {
				s.ioErr("recovering", name, err)
				continue
			}
			if err := unix.Renameat(s.fd, name, s.fd, final); err != nil {
				s.ioErr("closing", name, err)
				continue
			}
			s.recovered++
			name = final
			if err := unix.Fstatat(s.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				s.ioErr("stat", name, err)
				continue
			}
		}
		at, ok := known[name]
		if !ok {
			at = time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))
		}
		if at.After(now) {
			at = now // a modification time in the future must not stall pruning for ever
		}
		closed = append(closed, segment{name: name, size: st.Size, at: at})
		total += st.Size
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].name < closed[j].name })
	s.closed, s.total = closed, total
	// A segment that cannot be deleted is counted and reported by prune and
	// leaves the writer full; it must not stop the sensor from starting.
	_ = s.prune()
	return nil
}

// trimPartialLine cuts a segment left open by a crash back to its last
// complete line (the process may have died in the middle of a write). The
// file is opened without following a link and checked again through the
// descriptor, so what was vetted is what is truncated.
func trimPartialLine(dirfd int, name string, vetted *unix.Stat_t) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if err := vet(&st); err != nil {
		return err
	}
	if st.Dev != vetted.Dev || st.Ino != vetted.Ino {
		return errors.New("the file was replaced while it was checked")
	}
	end := st.Size
	buf := make([]byte, 64<<10)
	for end > 0 {
		off := end - int64(len(buf))
		if off < 0 {
			off = 0
		}
		n, err := f.ReadAt(buf[:end-off], off)
		if err != nil && n == 0 {
			return err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			if off+int64(i)+1 == st.Size {
				return nil // already ends at a line
			}
			return f.Truncate(off + int64(i) + 1)
		}
		end = off
	}
	if st.Size == 0 {
		return nil
	}
	return f.Truncate(0)
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
		// Neither the final nor the open name may exist yet. Anything that
		// does (a planted symbolic link, a file) is left alone, counted, and
		// the next name is tried.
		if err := unix.Faccessat(s.fd, final, unix.F_OK, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			s.collision(final)
			continue
		}
		fd, err := unix.Openat(s.fd, final+partExt, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_APPEND, 0o600)
		if errors.Is(err, unix.EEXIST) {
			s.collision(final + partExt)
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

// collision counts and reports (once per name) a segment name that is taken.
func (s *Segments) collision(name string) {
	s.nameCollisions++
	if !s.once("collision:" + name) {
		return
	}
	s.report(CondDirError, "elegia dir %s: the next segment name %s is already taken by a file or link that is not ours; it is left untouched and the next name is used", s.path, name)
}

// Write appends whole lines to the open segment (opening one if needed).
// While the writer is full (see the type comment) the lines are dropped and
// counted, and Write reports success so the caller does not treat it as a
// write error.
func (s *Segments) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return 0, errors.New("elegia dir: closed")
	}
	if s.cur == nil {
		if s.full {
			s.retryFull()
		}
		if s.full {
			s.dropFull(p)
			return len(p), nil
		}
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

// dropFull counts the lines of p as dropped. Caller holds mu.
func (s *Segments) dropFull(p []byte) {
	n := uint64(bytes.Count(p, []byte{'\n'}))
	if n == 0 {
		n = 1
	}
	before := s.droppedFull
	s.droppedFull += n
	if before == 0 || before/1000 != s.droppedFull/1000 {
		s.report(CondDirFull, "elegia dir %s is full of segments younger than the retention floor: %d records dropped so far; no new segment is opened until space is free", s.path, s.droppedFull)
	}
}

// retryFull looks at the directory again, at most once a second: files an
// operator removed free space, and time moves segments past the floor.
// Caller holds mu.
func (s *Segments) retryFull() {
	now := s.cfg.Now()
	if !s.lastRetry.IsZero() && now.Sub(s.lastRetry) < time.Second && !now.Before(s.lastRetry) {
		return
	}
	s.lastRetry = now
	if err := s.scan(false); err != nil {
		s.ioErr("listing", "", err)
	}
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
	if err := s.cur.Truncate(s.lineEnd); err != nil {
		s.ioErr("cutting the partial line of", s.curName+partExt, err)
		return
	}
	s.curSize = s.lineEnd
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
		if uerr := unix.Unlinkat(s.fd, part, 0); uerr != nil {
			s.ioErr("removing the empty", part, uerr)
			err = errors.Join(err, uerr)
		}
		return err
	}
	if rerr := unix.Renameat(s.fd, part, s.fd, s.curName); rerr != nil {
		s.ioErr("closing", part, rerr)
		return errors.Join(err, fmt.Errorf("elegia dir %s: %w", s.path, rerr))
	}
	s.closed = append(s.closed, segment{name: s.curName, size: s.curSize, at: s.cfg.Now()})
	s.total += s.curSize
	s.rotated++
	return errors.Join(err, s.prune())
}

// prune deletes the oldest closed segments beyond KeepBytes, none younger
// than the retention floor. If that leaves the closed segments above
// KeepBytes the writer becomes full; once they fit again it recovers. Caller
// holds mu.
func (s *Segments) prune() error {
	var errs []error
	now := s.cfg.Now()
	why := ""
	for s.total > s.cfg.KeepBytes && len(s.closed) > 0 {
		old := s.closed[0]
		if s.cfg.MinKeep > 0 && now.Sub(old.at) < s.cfg.MinKeep {
			why = fmt.Sprintf("the oldest closed segment %s is %v old, younger than the retention floor %v", old.name, now.Sub(old.at).Round(time.Second), s.cfg.MinKeep)
			break
		}
		if err := unix.Unlinkat(s.fd, old.name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			s.ioErr("deleting", old.name, err)
			errs = append(errs, fmt.Errorf("elegia dir %s: %w", old.name, err))
			why = fmt.Sprintf("the oldest closed segment %s cannot be deleted (%v)", old.name, err)
			break
		}
		s.closed = s.closed[1:]
		s.total -= old.size
		s.pruned++
		s.prunedBytes += uint64(old.size)
	}
	over := s.total > s.cfg.KeepBytes
	switch {
	case over && !s.full:
		s.full, s.fullSince = true, now
		s.fullEpisodes++
		s.report(CondDirFull, "elegia dir %s: %d bytes of closed segments exceed --elegia-keep-bytes %d and %s; no new segment is opened and records are dropped (counted) until space is free", s.path, s.total, s.cfg.KeepBytes, why)
	case !over && s.full:
		s.full = false
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
	full := uint64(0)
	if s.full {
		full = 1
	}
	return map[string]uint64{"segments_closed": uint64(len(s.closed)), "segments_bytes": uint64(s.total),
		"open_segment_bytes": uint64(s.curSize), "rotations": s.rotated, "pruned": s.pruned, "pruned_bytes": s.prunedBytes,
		"recovered_at_start": s.recovered, "unsafe_skipped": s.unsafeSkipped, "io_errors": s.ioErrors,
		"name_collisions": s.nameCollisions, "dir_full": full, "full_episodes": s.fullEpisodes, "dropped_dir_full": s.droppedFull}
}

var _ io.WriteCloser = (*Segments)(nil)
