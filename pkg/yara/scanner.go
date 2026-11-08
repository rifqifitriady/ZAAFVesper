//go:build yara

package yara

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	replaced, nonLocal, fileChanged, execUnbound, execGone           atomic.Uint64

	degraded degradedHook

	closeOnce sync.Once
}

type job struct {
	path    string
	trigger string
	exec    bool
	cdhash  string
	time    time.Time
	proc    *event.Proc
	// Identity of the file the event was about (the executable for exec,
	// the target for file events): the opened file must match it or the
	// scan is refused. ino 0 = unknown (scan as before); ctime 0 = unknown
	// (dev+ino only).
	dev, ino uint64
	ctimeNs  int64
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
		for _, f := range m {
			// Skip dotfiles, e.g. AppleDouble "._x.yar" companions that a
			// package payload can carry for files with extended attributes.
			if !strings.HasPrefix(filepath.Base(f), ".") {
				files = append(files, f)
			}
		}
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
		// Allow-listed imports only, no include: checked on the exact bytes
		// compiled below (see checkRuleSource).
		if err := checkRuleSource(src); err != nil {
			return nil, 0, fmt.Errorf("yara: rule file %s: %w", path, err)
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
	if err := checkImportsWithLibyara(r); err != nil {
		r.Destroy()
		return nil, 0, err
	}
	return r, len(files), nil
}

// importCheck is the scan callback of checkImportsWithLibyara.
type importCheck struct {
	modules    []string
	disallowed string
}

func (c *importCheck) RuleMatching(*yr.ScanContext, *yr.Rule) (bool, error) { return false, nil }

// ImportModule sees every module the compiled rules import, as libyara
// itself resolved the name (escapes decoded). A disallowed one aborts the
// scan with an error before libyara loads the module.
func (c *importCheck) ImportModule(_ *yr.ScanContext, name string) ([]byte, bool, error) {
	c.modules = append(c.modules, name)
	if !moduleAllowed(name) {
		c.disallowed = name
		return nil, true, errModuleNotAllowed
	}
	return nil, false, nil
}

// checkImportsWithLibyara is the second layer of the import allow-list,
// independent of checkRuleSource's lexer: it scans an empty buffer with the
// compiled rules and refuses them if libyara reports importing any module
// outside AllowedModules.
func checkImportsWithLibyara(r *yr.Rules) error {
	var c importCheck
	err := r.ScanMem(nil, 0, 5*time.Second, &c)
	if c.disallowed != "" {
		return fmt.Errorf("yara: %w: %q (reported by libyara; allowed: %v)", errModuleNotAllowed, c.disallowed, AllowedModules)
	}
	if err != nil {
		return fmt.Errorf("yara: import check scan: %w", err)
	}
	return nil
}

// MaxRuleFileSize caps one YARA rule file.
const MaxRuleFileSize = 4 << 20

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

// Submit queues the scans e calls for and never blocks (a Mount event only
// invalidates the cached mount table):
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
	case event.Mount:
		// A new mount may be a network share: re-read the mount table
		// before the next scan instead of waiting for the cache to expire.
		invalidateMountsFn()
		return
	case event.CreateProcess:
		if e.Proc == nil || (e.Proc.IsPlatform && !s.cfg.ScanPlatform) {
			return
		}
		j.path, j.exec, j.cdhash = e.Proc.Exe, true, e.Proc.CDHash
		j.dev, j.ino, j.ctimeNs = e.Proc.ExeDev, e.Proc.ExeIno, e.Proc.ExeCtimeNs
		if j.ino == 0 {
			// No exec-time stat from the source: the scan cannot be bound
			// to the file that ran. Counted, not reported (it would fire on
			// every such exec).
			s.execUnbound.Add(1)
		}
	case event.CreateFile, event.WriteFile:
		if e.File == nil || !UnderWatchDir(e.File.Path, s.cfg.WatchDirs) {
			return
		}
		j.path = e.File.Path
		j.dev, j.ino, j.ctimeNs = e.File.Dev, e.File.Ino, e.File.CtimeNs
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
		s.degraded.report(CondQueueFull, "", fmt.Sprintf("displaced a queued file scan for exec scan of %q; dropped=%d", j.path, s.dropped.Load()))
	case pushRejected:
		s.dropped.Add(1)
		if j.exec {
			s.droppedExec.Add(1)
		} else {
			s.droppedFile.Add(1)
		}
		s.degraded.report(CondQueueFull, "", fmt.Sprintf("dropped %s scan of %q; dropped=%d", j.trigger, j.path, s.dropped.Load()))
	case pushNotRunning:
		s.dropped.Add(1)
		if j.exec {
			s.droppedExec.Add(1)
		} else {
			s.droppedFile.Add(1)
		}
	}
}

// OnDegraded registers fn to be told when scanning is degraded: CondQueueFull,
// CondExecReplaced, CondSkippedNonLocal. Each condition is reported at most
// once a minute. fn is called synchronously from the goroutine that hit the
// condition (Submit's caller for CondQueueFull, a scan worker otherwise), so
// it must be safe for concurrent use and must not block. nil unregisters.
func (s *Scanner) OnDegraded(fn func(condition, detail string)) {
	s.degraded.set(fn)
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
// not_regular, too_big, symlinks, exec_replaced, non_local, file_changed,
// exec_unbound (exec submissions without an exec-time stat), exec_gone
// (executable deleted after its process had exited; not reported).
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

		"exec_replaced": s.replaced.Load(),
		"non_local":     s.nonLocal.Load(),
		"file_changed":  s.fileChanged.Load(),
		"exec_unbound":  s.execUnbound.Load(),
		"exec_gone":     s.execGone.Load(),
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

// errNonLocal marks a path on a file system without MNT_LOCAL.
var errNonLocal = errors.New("not on a local file system")

// errReplaced marks an exec target whose file is not the one that ran.
var errReplaced = errors.New("executable replaced since exec")

// errFileChanged marks a file-event target that changed since the event.
var errFileChanged = errors.New("file changed since the event")

// localFS and nonLocalMountList are the platform checks; tests replace them.
var (
	localFS            = isLocalFS
	nonLocalMountList  = nonLocalMounts
	procAliveCheck     = procAlive
	invalidateMountsFn = invalidateMounts
)

func (s *Scanner) skipNonLocal(j job) {
	s.nonLocal.Add(1)
	s.degraded.report(CondSkippedNonLocal, j.path, fmt.Sprintf("%s scan of %q skipped", j.trigger, j.path))
}

// procAlive reports whether the exec job's process is still running
// (same pid and start time). Without a pid it cannot tell: alive.
func (s *Scanner) procAlive(j job) bool {
	if j.proc == nil || j.proc.PID <= 0 {
		return true
	}
	return procAliveCheck(j.proc.PID, j.proc.StartTime)
}

func (s *Scanner) execReplaced(j job, why string) {
	s.replaced.Add(1)
	var pid int32
	if j.proc != nil {
		pid = j.proc.PID
	}
	s.degraded.report(CondExecReplaced, strconv.Itoa(int(pid)), fmt.Sprintf("pid=%d path=%q (%s)", pid, j.path, why))
}

// checkLocal returns errNonLocal unless fd is on a local file system.
func checkLocal(fd int) error {
	ok, err := localFS(fd)
	if err != nil {
		return err
	}
	if !ok {
		return errNonLocal
	}
	return nil
}

// openNoFollow opens an absolute, clean path for reading by walking it one
// component at a time from "/" with openat(2) and O_NOFOLLOW, so no symlink
// anywhere in the path (not only the last component) can redirect root's
// open, even if it is swapped in between checks. The final open adds
// O_NONBLOCK (no hang on FIFOs/devices); the opened descriptor must be a
// regular file. ES reports resolved paths (/private/tmp, not /tmp), so real
// paths never need a symlink. Every directory on the way and the file itself
// must be on a local file system (fstatfs MNT_LOCAL): the walk stops at the
// first network mount, so a slow or hostile server cannot stall a worker.
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
		if err := checkLocal(dfd); err != nil {
			unix.Close(dfd)
			return nil, st, err
		}
	}
	last := comps[len(comps)-1]
	fd, err := unix.Openat(dfd, last, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		err = classifyOpenErr(dfd, last, err)
		unix.Close(dfd)
		return nil, st, err
	}
	unix.Close(dfd)
	if err := checkLocal(fd); err != nil {
		unix.Close(fd)
		return nil, st, err
	}
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
	// Paths under a known network mount are skipped before any syscall
	// touches them (the per-descriptor MNT_LOCAL check in openNoFollow
	// still catches what this cached list misses).
	if onNonLocalMount(j.path, nonLocalMountList()) {
		s.skipNonLocal(j)
		return nil, errNonLocal
	}
	f, st, err := openNoFollow(j.path)
	if err != nil {
		switch {
		case errors.Is(err, errNonLocal):
			s.skipNonLocal(j)
		case j.exec && (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR)):
			// The file that ran is gone. While that process still runs,
			// deleting its own image is malware behaviour: reported. Once
			// it has exited, a deleted binary is normal (go run, test
			// binaries, installers): counted only.
			if !s.procAlive(j) {
				s.execGone.Add(1)
				return nil, err
			}
			s.execReplaced(j, "gone while running: "+err.Error())
			return nil, errReplaced
		case j.exec && errors.Is(err, errSymlink):
			// ES reports resolved paths, so a symlink in the path is a
			// component swapped since exec.
			s.execReplaced(j, "path now contains a symlink")
			return nil, errReplaced
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
	// Bind the scan to the file the event was about (ES's stat of it).
	if j.ino != 0 {
		idChanged := uint64(uint32(st.Dev)) != j.dev || st.Ino != j.ino
		ctimeChanged := j.ctimeNs != 0 && unix.TimespecToNsec(st.Ctim) != j.ctimeNs
		switch {
		case j.exec && (idChanged || ctimeChanged):
			// Not the file that ran (swapped, or rewritten in place):
			// scanning it would clear the wrong file.
			s.execReplaced(j, "stat differs from exec")
			return nil, errReplaced
		case idChanged:
			// A file event whose path now holds another file: skipped;
			// whatever replaced it raises its own create/close event.
			s.fileChanged.Add(1)
			return nil, errFileChanged
		}
		// A file event with only a newer ctime (chmod, xattr, rewrite in
		// place) is scanned as it is now: skipping it would let a chmod
		// after close hide the content.
	}
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
