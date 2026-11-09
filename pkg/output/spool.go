package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
)

// Spool defaults.
const (
	// DefaultSpoolMaxBytes caps one output's spool on disk.
	DefaultSpoolMaxBytes = 128 << 20
	// spoolFileBytes is the size at which a new spool file is started.
	spoolFileBytes = 1 << 20
	// maxSpoolFiles bounds the files a spool holds (and lists at start).
	maxSpoolFiles = 4096
	// maxSpoolLine bounds one line read back (a record plus its envelope).
	maxSpoolLine = 4 << 20
)

// spoolName matches the spool's own files; nothing else is ever read or
// removed.
var spoolName = regexp.MustCompile(`^spool-(\d{20})\.ndjson$`)

// Spool is a size-capped directory of NDJSON record files kept while an
// endpoint is down. Every file operation is relative to an open descriptor of
// the directory and never follows a symbolic link: files are created with
// O_CREAT|O_EXCL|O_NOFOLLOW 0600 and only names matching spoolName are read
// or removed. As root the directory and every ancestor must be root-owned and
// not group/world writable (config.CheckOwnership); the directory itself must
// never be group/world accessible. Records hold no secrets (tokens never
// enter a record).
//
// Policy when full: events are refused once the spool is half full, so the
// rest stays for alerts; alerts are refused only at the cap. Refusals are
// counted and reported.
type Spool struct {
	mu       sync.Mutex
	path     string
	fd       int
	max      int64
	fileMax  int64
	files    []spoolFile // oldest first; the last may be open for writing
	size     int64
	cur      *os.File
	curSize  int64
	next     uint64
	refused  map[string]uint64
	badLines uint64
}

type spoolFile struct {
	seq  uint64
	size int64
}

func (f spoolFile) name() string { return fmt.Sprintf("spool-%020d.ndjson", f.seq) }

// OpenSpool creates dir (0700, with any missing parents 0700) and opens it.
// asRoot applies the ownership checks.
func OpenSpool(dir string, max int64, asRoot bool) (*Spool, error) {
	if max <= 0 {
		max = DefaultSpoolMaxBytes
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// Missing directories are created 0700; existing ones are then checked
	// (as root: every ancestor root-owned and not group/world writable).
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	if asRoot {
		if err := config.CheckOwnership(abs); err != nil {
			return nil, fmt.Errorf("spool directory %s is not safe to use as root:\n%w", abs, err)
		}
	}
	fd, err := unix.Open(abs, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("spool %s: %w", abs, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("spool %s: %w", abs, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		err = errors.New("not a directory")
	case st.Mode&0o077 != 0:
		err = fmt.Errorf("mode %o: the spool directory must be accessible by its owner only (0700)", st.Mode&0o777)
	case int(st.Uid) != os.Geteuid():
		err = fmt.Errorf("owned by uid %d, not by this process's uid %d", st.Uid, os.Geteuid())
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("spool %s: %w", abs, err)
	}
	s := &Spool{path: abs, fd: fd, max: max, fileMax: spoolFileBytes, refused: map[string]uint64{}}
	if s.fileMax > max/4 {
		s.fileMax = max / 4
		if s.fileMax < 4096 {
			s.fileMax = 4096
		}
	}
	if err := s.scan(); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return s, nil
}

// scan lists the spool files left by an earlier run (oldest first).
func (s *Spool) scan() error {
	dfd, err := unix.Dup(s.fd)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(dfd), s.path)
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("spool %s: %w", s.path, err)
	}
	for _, e := range ents {
		m := spoolName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		seq, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(s.fd, e.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		s.files = append(s.files, spoolFile{seq: seq, size: st.Size})
		s.size += st.Size
		if seq >= s.next {
			s.next = seq + 1
		}
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].seq < s.files[j].seq })
	if len(s.files) > maxSpoolFiles {
		s.files = s.files[len(s.files)-maxSpoolFiles:]
	}
	return nil
}

// Append writes recs to the spool and returns how many were refused (spool
// full under the policy above).
func (s *Spool) Append(recs []Record) (refused int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range recs {
		r := &recs[i]
		line, merr := json.Marshal(r)
		if merr != nil {
			err = errors.Join(err, merr)
			continue
		}
		line = append(line, '\n')
		limit := s.max
		if r.Kind != KindAlert {
			limit = s.max / 2
		}
		if s.size+int64(len(line)) > limit {
			refused++
			s.refused[r.Kind]++
			continue
		}
		if werr := s.write(line); werr != nil {
			refused++
			s.refused[r.Kind]++
			err = errors.Join(err, werr)
		}
	}
	return refused, err
}

// write appends one line to the current file, starting a new one at the
// file size cap. Caller holds mu.
func (s *Spool) write(line []byte) error {
	if s.cur != nil && s.curSize+int64(len(line)) > s.fileMax {
		_ = s.cur.Close()
		s.cur = nil
	}
	if s.cur == nil {
		if len(s.files) >= maxSpoolFiles {
			return errors.New("spool holds too many files")
		}
		f := spoolFile{seq: s.next}
		fd, err := unix.Openat(s.fd, f.name(), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("spool %s: %w", s.path, err)
		}
		s.next++
		s.cur, s.curSize = os.NewFile(uintptr(fd), filepath.Join(s.path, f.name())), 0
		s.files = append(s.files, f)
	}
	n, err := s.cur.Write(line)
	s.curSize += int64(n)
	s.size += int64(n)
	s.files[len(s.files)-1].size += int64(n)
	return err
}

// Empty reports whether nothing is spooled.
func (s *Spool) Empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.files) == 0
}

// Oldest reads the oldest spool file (closing it for writing first when it is
// the current one). Lines that do not parse are skipped and counted.
func (s *Spool) Oldest() (seq uint64, recs []Record, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 {
		return 0, nil, io.EOF
	}
	f := s.files[0]
	if len(s.files) == 1 && s.cur != nil {
		_ = s.cur.Close()
		s.cur = nil
	}
	fd, err := unix.Openat(s.fd, f.name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			s.dropFirst()
		}
		return f.seq, nil, fmt.Errorf("spool %s: %w", f.name(), err)
	}
	file := os.NewFile(uintptr(fd), f.name())
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return f.seq, nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() {
		s.dropFirst() // never read it again; it is not ours
		return f.seq, nil, fmt.Errorf("spool %s: not a regular file owned by this process's uid; skipped", f.name())
	}
	sc := bufio.NewScanner(io.LimitReader(file, s.fileMax+maxSpoolLine))
	sc.Buffer(make([]byte, 64<<10), maxSpoolLine)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(bytes.TrimSpace(sc.Bytes()), &r); err != nil || (r.Kind != KindAlert && r.Kind != KindEvent) || len(r.Body) == 0 {
			s.badLines++
			continue
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil {
		s.badLines++
	}
	return f.seq, recs, nil
}

// Remove deletes the oldest file once its records were delivered.
func (s *Spool) Remove(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 || s.files[0].seq != seq {
		return nil
	}
	f := s.files[0]
	if len(s.files) == 1 && s.cur != nil {
		_ = s.cur.Close()
		s.cur = nil
	}
	err := unix.Unlinkat(s.fd, f.name(), 0)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("spool %s: %w", f.name(), err)
	}
	s.dropFirst()
	return nil
}

// dropFirst forgets the oldest file. Caller holds mu.
func (s *Spool) dropFirst() {
	s.size -= s.files[0].size
	if s.size < 0 {
		s.size = 0
	}
	s.files = s.files[1:]
}

// Stats returns the spool's counters.
func (s *Spool) Stats() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]uint64{"spool_bytes": uint64(s.size), "spool_files": uint64(len(s.files)),
		"spool_refused_alerts": s.refused[KindAlert], "spool_refused_events": s.refused[KindEvent],
		"spool_bad_lines": s.badLines}
}

// Close closes the current file and the directory.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.cur != nil {
		err = s.cur.Close()
		s.cur = nil
	}
	if s.fd >= 0 {
		err = errors.Join(err, unix.Close(s.fd))
		s.fd = -1
	}
	return err
}

// OpenAppendPrivate opens path for appending, creating it 0600 when missing,
// so a restarted daemon keeps writing to the same file. The path is never
// followed through a symbolic link, and the open descriptor must be a
// regular file owned by this process's uid, accessible by its owner only
// and with a single link (a hard link to another file is refused). As root
// the parent directory and every directory above it must pass
// config.CheckOwnership. It returns the file and its current size.
func OpenAppendPrivate(path string, asRoot bool) (*os.File, int64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, err
	}
	if asRoot {
		if err := config.CheckOwnership(filepath.Dir(abs)); err != nil {
			return nil, 0, fmt.Errorf("%s: its directory is not safe to write as root:\n%w", abs, err)
		}
	}
	fd, err := unix.Open(abs, unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, 0, fmt.Errorf("%s: is a symbolic link (not allowed)", abs)
		}
		return nil, 0, fmt.Errorf("%s: %w", abs, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, 0, fmt.Errorf("%s: %w", abs, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		err = errors.New("not a regular file")
	case int(st.Uid) != os.Geteuid():
		err = fmt.Errorf("owned by uid %d, not by this process's uid %d", st.Uid, os.Geteuid())
	case st.Mode&0o077 != 0:
		err = fmt.Errorf("mode %o: must be accessible by its owner only (0600)", st.Mode&0o777)
	case st.Nlink != 1:
		err = fmt.Errorf("has %d links (a hard link is not allowed)", st.Nlink)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, 0, fmt.Errorf("%s: %w", abs, err)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, 0, err
	}
	return os.NewFile(uintptr(fd), abs), st.Size, nil
}
