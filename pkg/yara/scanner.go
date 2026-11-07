//go:build yara

package yara

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	yr "github.com/hillu/go-yara/v4"
	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
)

// maxCache bounds the scan-result cache.
const maxCache = 8192

// Scanner is the libyara-backed source.Scanner.
type Scanner struct {
	cfg   Config
	rules *yr.Rules

	mu      sync.Mutex // guards started/closed for Start vs Close
	q       *jobQueue
	started bool
	closed  bool
	wg      sync.WaitGroup
	cancel  context.CancelFunc

	cacheMu sync.Mutex
	cache   map[cacheKey][]match

	submitted, dropped, droppedExec, droppedFile, scanned, cacheHits atomic.Uint64
	matched, errs, timeouts, notRegular, tooBig, symlinks            atomic.Uint64

	closeOnce sync.Once
}

type job struct {
	path    string
	trigger string
	exec    bool
	cdhash  string
	time    time.Time
	proc    *event.Proc
}

// cacheKey identifies file content. ctime is part of it because, unlike
// mtime, user code cannot set it back: rewriting a file and restoring its
// mtime (touch -r, utimes) still changes ctime, so a poisoned clean result is
// never reused. Exec scans also key on the ES-reported cdhash when present.
type cacheKey struct {
	path      string
	dev, ino  uint64
	size      int64
	mtimeNano int64
	ctimeNano int64
	cdhash    string
}

type match struct {
	rule, namespace string
	tags            []string
	meta            map[string]string
}

var _ source.Scanner = (*Scanner)(nil)

// New compiles every *.yar / *.yara file in cfg.RulesDir. Each file becomes
// its own namespace (the file name without extension). include directives
// are disabled so a rule file cannot pull in files from elsewhere.
func New(cfg Config) (source.Scanner, error) {
	cfg = cfg.WithDefaults()
	if cfg.RulesDir == "" {
		return nil, errors.New("yara: RulesDir is empty")
	}
	rules, n, err := compileDir(cfg.RulesDir)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("yara: no *.yar or *.yara files in %s", cfg.RulesDir)
	}
	return &Scanner{cfg: cfg, rules: rules, cache: map[cacheKey][]match{}, q: newJobQueue(cfg.QueueSize)}, nil
}

func compileDir(dir string) (*yr.Rules, int, error) {
	var files []string
	for _, pat := range []string{"*.yar", "*.yara"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, 0, fmt.Errorf("yara: %w", err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	c, err := yr.NewCompiler()
	if err != nil {
		return nil, 0, fmt.Errorf("yara: %w", err)
	}
	defer c.Destroy()
	c.DisableIncludes()
	for _, path := range files {
		// One O_NOFOLLOW open: the ownership/mode policy check and the bytes
		// compiled come from the same descriptor.
		src, err := config.SecureRead(path, MaxRuleFileSize)
		if err != nil {
			return nil, 0, fmt.Errorf("yara: rule file: %w", err) // err names the path
		}
		if magicImport.Match(src) {
			return nil, 0, fmt.Errorf("yara: rule file %s: %w", path, errMagicImport)
		}
		ns := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if err := c.AddString(string(src), ns); err != nil {
			var msgs []string
			for _, m := range c.Errors {
				msgs = append(msgs, fmt.Sprintf("%s:%d: %s", m.Filename, m.Line, m.Text))
			}
			return nil, 0, fmt.Errorf("yara: compiling %s: %v %s", path, err, strings.Join(msgs, "; "))
		}
	}
	if len(files) == 0 {
		return nil, 0, nil
	}
	r, err := c.GetRules()
	if err != nil {
		return nil, 0, fmt.Errorf("yara: %w", err)
	}
	return r, len(files), nil
}

// MaxRuleFileSize caps one YARA rule file.
const MaxRuleFileSize = 4 << 20

// magicImport matches `import "magic"`. The magic module makes libmagic load
// its database from a (Homebrew, user-owned) path at scan time, so rules may
// not use it in a root sensor.
var magicImport = regexp.MustCompile(`(?m)^\s*import\s+"magic"`)

var errMagicImport = errors.New(`import "magic" is not allowed (libmagic would load an unprotected database as root)`)

// Start launches the worker pool. Matches are sent to out as YaraMatch events.
func (s *Scanner) Start(ctx context.Context, out chan<- *event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("yara: scanner is closed")
	}
	if s.started {
		return errors.New("yara: already started")
	}
	scanners := make([]*yr.Scanner, 0, s.cfg.Workers)
	for range s.cfg.Workers {
		sc, err := yr.NewScanner(s.rules)
		if err != nil {
			for _, x := range scanners {
				x.Destroy()
			}
			return fmt.Errorf("yara: %w", err)
		}
		sc.SetTimeout(time.Duration(s.cfg.TimeoutSec) * time.Second)
		scanners = append(scanners, sc)
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.q.open()
	s.started = true
	s.wg.Add(1)
	go func() { // a cancelled parent ctx stops the workers too
		defer s.wg.Done()
		<-ctx.Done()
		s.q.close()
	}()
	for _, sc := range scanners {
		s.wg.Add(1)
		go s.worker(ctx, sc, out)
	}
	return nil
}

// Submit queues the scans e calls for and never blocks:
//   - CreateProcess: ps.exe (Apple platform binaries skipped unless ScanPlatform)
//   - CreateFile / WriteFile: file.path when it lies under a WatchDirs glob
//
// Exec scans take priority: they are scanned first, and when the queue is
// full an exec job displaces the oldest queued file job. Jobs that do not fit
// (or arrive before Start / after Close) are dropped and counted.
func (s *Scanner) Submit(e *event.Event) {
	if e == nil {
		return
	}
	j := job{trigger: e.Name, time: e.Time}
	switch e.Name {
	case event.CreateProcess:
		if e.Proc == nil || (e.Proc.IsPlatform && !s.cfg.ScanPlatform) {
			return
		}
		j.path, j.exec, j.cdhash = e.Proc.Exe, true, e.Proc.CDHash
	case event.CreateFile, event.WriteFile:
		if e.File == nil || !UnderWatchDir(e.File.Path, s.cfg.WatchDirs) {
			return
		}
		j.path = e.File.Path
	default:
		return
	}
	if j.path == "" || !filepath.IsAbs(j.path) {
		return
	}
	if e.Proc != nil {
		cp := *e.Proc
		if cp.Parent != nil {
			par := *cp.Parent
			cp.Parent = &par
		}
		j.proc = &cp
	}
	s.submitted.Add(1)
	switch s.q.push(j) {
	case pushOK:
	case pushDisplacedFile:
		s.dropped.Add(1)
		s.droppedFile.Add(1)
	case pushRejected:
		s.dropped.Add(1)
		if j.exec {
			s.droppedExec.Add(1)
		} else {
			s.droppedFile.Add(1)
		}
	}
}

// Close stops the workers, waits for them, and frees libyara resources.
// It is safe to call more than once and concurrently with Submit.
func (s *Scanner) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		started := s.started
		s.mu.Unlock()
		s.q.close()
		if started {
			s.cancel()
		}
		s.wg.Wait()
		if s.rules != nil {
			s.rules.Destroy()
		}
	})
	return nil
}

// Stats reports counters: submitted, dropped (= dropped_exec +
// dropped_file), scanned, cache_hits, matches, errors, timeouts,
// not_regular, too_big, symlinks.
func (s *Scanner) Stats() map[string]uint64 {
	return map[string]uint64{
		"submitted":    s.submitted.Load(),
		"dropped":      s.dropped.Load(),
		"dropped_exec": s.droppedExec.Load(),
		"dropped_file": s.droppedFile.Load(),
		"scanned":      s.scanned.Load(),
		"cache_hits":   s.cacheHits.Load(),
		"matches":      s.matched.Load(),
		"errors":       s.errs.Load(),
		"timeouts":     s.timeouts.Load(),
		"not_regular":  s.notRegular.Load(),
		"too_big":      s.tooBig.Load(),
		"symlinks":     s.symlinks.Load(),
	}
}

func (s *Scanner) worker(ctx context.Context, sc *yr.Scanner, out chan<- *event.Event) {
	defer s.wg.Done()
	defer sc.Destroy()
	for {
		j, ok := s.q.pop()
		if !ok || ctx.Err() != nil {
			return
		}
		ms, err := s.scan(sc, j)
		if err != nil {
			continue
		}
		for _, m := range ms {
			ev := &event.Event{
				Time:   j.time,
				Name:   event.YaraMatch,
				Source: "yara",
				Proc:   j.proc,
				File:   &event.File{Path: j.path},
				Args:   map[string]string{"trigger": j.trigger},
				Yara: &event.Yara{ // copies: cached results are shared between events
					Rule: m.rule, Namespace: m.namespace, Tags: append([]string(nil), m.tags...),
					Meta: maps.Clone(m.meta), Target: j.path,
				},
			}
			if ev.Time.IsZero() {
				ev.Time = time.Now().UTC()
			}
			s.matched.Add(1)
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

var errNotRegular = errors.New("not a regular file")

// errSymlink marks a path component that is a symbolic link.
var errSymlink = errors.New("path contains a symbolic link")

// openNoFollow opens an absolute, clean path for reading by walking it one
// component at a time from "/" with openat(2) and O_NOFOLLOW, so no symlink
// anywhere in the path (not only the last component) can redirect root's
// open, even if it is swapped in between checks. The final open adds
// O_NONBLOCK (no hang on FIFOs/devices); the opened descriptor must be a
// regular file. ES reports resolved paths (/private/tmp, not /tmp), so real
// paths never need a symlink.
func openNoFollow(path string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, st, fmt.Errorf("unclean path %q", path)
	}
	comps := strings.Split(path[1:], "/")
	dfd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	for _, c := range comps[:len(comps)-1] {
		nfd, err := unix.Openat(dfd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			err = classifyOpenErr(dfd, c, err)
			unix.Close(dfd)
			return nil, st, err
		}
		unix.Close(dfd)
		dfd = nfd
	}
	last := comps[len(comps)-1]
	fd, err := unix.Openat(dfd, last, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		err = classifyOpenErr(dfd, last, err)
		unix.Close(dfd)
		return nil, st, err
	}
	unix.Close(dfd)
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, st, errNotRegular
	}
	return os.NewFile(uintptr(fd), path), st, nil
}

// classifyOpenErr turns ELOOP/ENOTDIR on a component that is a symlink into
// errSymlink.
func classifyOpenErr(dfd int, name string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		var st unix.Stat_t
		if unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return errSymlink
		}
	}
	return err
}

func (s *Scanner) scan(sc *yr.Scanner, j job) ([]match, error) {
	f, st, err := openNoFollow(j.path)
	if err != nil {
		switch {
		case errors.Is(err, errNotRegular):
			s.notRegular.Add(1)
		case errors.Is(err, errSymlink):
			s.symlinks.Add(1)
		default:
			s.errs.Add(1)
		}
		return nil, err
	}
	defer f.Close()
	if st.Size > s.cfg.MaxFileSize {
		s.tooBig.Add(1)
		return nil, errors.New("too big")
	}
	key := cacheKey{
		path: j.path, dev: uint64(st.Dev), ino: st.Ino, size: st.Size,
		mtimeNano: unix.TimespecToNsec(st.Mtim), ctimeNano: unix.TimespecToNsec(st.Ctim),
	}
	if j.exec {
		key.cdhash = j.cdhash
	}
	s.cacheMu.Lock()
	cached, hit := s.cache[key]
	s.cacheMu.Unlock()
	if hit {
		s.cacheHits.Add(1)
		return cached, nil
	}
	var res yr.MatchRules
	err = sc.SetCallback(&res).ScanFileDescriptor(f.Fd())
	s.scanned.Add(1)
	if err != nil {
		if ye := (yr.Error{}); errors.As(err, &ye) && ye.Code == yr.ERROR_SCAN_TIMEOUT {
			s.timeouts.Add(1)
		} else {
			s.errs.Add(1)
		}
		return nil, err
	}
	ms := make([]match, 0, len(res))
	for _, r := range res {
		m := match{rule: r.Rule, namespace: r.Namespace, tags: append([]string(nil), r.Tags...)}
		if len(r.Metas) > 0 {
			m.meta = make(map[string]string, len(r.Metas))
			for _, mt := range r.Metas {
				if _, dup := m.meta[mt.Identifier]; !dup {
					m.meta[mt.Identifier] = fmt.Sprint(mt.Value)
				}
			}
		}
		ms = append(ms, m)
	}
	s.cacheMu.Lock()
	if len(s.cache) >= maxCache {
		clear(s.cache)
	}
	s.cache[key] = ms
	s.cacheMu.Unlock()
	return ms, nil
}
