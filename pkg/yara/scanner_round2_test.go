//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	yr "github.com/hillu/go-yara/v4"
	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// hookLog records OnDegraded calls; workers call it concurrently.
type hookLog struct {
	mu    sync.Mutex
	calls []string
}

func (h *hookLog) fn(cond, detail string) {
	h.mu.Lock()
	h.calls = append(h.calls, cond+" "+detail)
	h.mu.Unlock()
}

func (h *hookLog) get() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

func statOf(t *testing.T, p string) (dev, ino uint64, ctime int64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return uint64(uint32(st.Dev)), st.Ino, unix.TimespecToNsec(st.Ctim)
}

// TestExecScanBoundToExecStat (M3): the exec scan only reads the file whose
// dev/inode/ctime Endpoint Security reported at exec. A binary swapped (or
// rewritten in place) after exec is not scanned and is reported as
// yara_exec_replaced; an event without a stat scans as before.
func TestExecScanBoundToExecStat(t *testing.T) {
	sc, watch := setup(t, nil)
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	sc.degraded.now = func() time.Time { return time.Time{} } // fixed clock: rate limit applies
	out := make(chan *event.Event, 8)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(watch, "dropper")
	write(t, exe, "\xcf\xfa\xed\xfeZAAFVESPER-TEST-MARKER-7f3a")
	dev, ino, ctime := statOf(t, exe)
	execEv := func(dev, ino uint64, ctime int64) *event.Event {
		return &event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: 4242, Exe: exe, ExeDev: dev, ExeIno: ino, ExeCtimeNs: ctime}}
	}

	// The file that ran is still there: scanned, matched.
	sc.Submit(execEv(dev, ino, ctime))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("matching stat not scanned: %v", sc.Stats())
	}

	// Swap: another file renamed over the path (new inode). It ALSO
	// matches the rule, so "no YaraMatch" proves the scan was refused, not
	// that the file scanned clean.
	repl := filepath.Join(watch, "other")
	write(t, repl, "\xcf\xfa\xed\xfeother build ZAAFVESPER-TEST-MARKER-7f3a")
	if err := os.Rename(repl, exe); err != nil {
		t.Fatal(err)
	}
	sc.Submit(execEv(dev, ino, ctime))
	waitStat(t, sc, "exec_replaced", 1)
	if e := recv(t, out, 300*time.Millisecond); e != nil {
		t.Fatalf("replaced executable was scanned: %+v", e.Yara)
	}
	calls := h.get()
	if len(calls) != 1 || calls[0] != CondExecReplaced+` pid=4242 path="`+exe+`" (stat differs from exec)` {
		t.Fatalf("hook calls %q", calls)
	}

	// In-place rewrite keeps dev and inode but changes ctime.
	dev2, ino2, ctime2 := statOf(t, exe)
	sc.Submit(execEv(dev2, ino2, ctime2-1))
	waitStat(t, sc, "exec_replaced", 2)
	if e := recv(t, out, 300*time.Millisecond); e != nil {
		t.Fatalf("rewritten executable was scanned: %+v", e.Yara)
	}
	if len(h.get()) != 1 {
		t.Errorf("second report for the same pid within a minute not rate-limited: %q", h.get())
	}

	// Event without a stat: scanned as before (no binding possible).
	write(t, exe, "\xcf\xfa\xed\xfeZAAFVESPER-TEST-MARKER-7f3a")
	sc.Submit(execEv(0, 0, 0))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("exec without stat not scanned: %v", sc.Stats())
	}
	// dev+ino known, ctime unknown: dev+ino suffice.
	dev3, ino3, _ := statOf(t, exe)
	sc.Submit(execEv(dev3, ino3, 0))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("exec with dev+ino only not scanned: %v", sc.Stats())
	}
	if st := sc.Stats(); st["exec_replaced"] != 2 || st["exec_unbound"] != 1 {
		t.Errorf("stats %v", st)
	}
}

// TestNonLocalFileSystemSkipped: a target on a file system without
// MNT_LOCAL is never read; the skip is counted and reported.
func TestNonLocalFileSystemSkipped(t *testing.T) {
	prev := localFS
	t.Cleanup(func() { localFS = prev }) // registered first: runs after the scanner is closed
	var mu sync.Mutex
	nonLocal := ""
	localFS = func(fd int) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if nonLocal == "" {
			return prev(fd)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return false, err
		}
		dev, _, _ := statOf(t, nonLocal)
		return uint64(uint32(st.Dev)) != dev, nil // pretend the watch dir's device is a network share
	}
	sc, watch := setup(t, nil)
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(watch, "share.sh")
	write(t, p, "echo ZAAFVESPER-TEST-MARKER-7f3a\n")
	// The real check: the temp dir is on a local volume and is scanned.
	sc.Submit(&event.Event{Name: event.CreateFile, File: &event.File{Path: p}})
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("local file not scanned: %v", sc.Stats())
	}
	mu.Lock()
	nonLocal = watch
	mu.Unlock()
	write(t, p, "echo ZAAFVESPER-TEST-MARKER-7f3a again\n")
	sc.Submit(&event.Event{Name: event.WriteFile, File: &event.File{Path: p}})
	waitStat(t, sc, "non_local", 1)
	if e := recv(t, out, 300*time.Millisecond); e != nil {
		t.Fatal("non-local file scanned")
	}
	if calls := h.get(); len(calls) != 1 || !strings.HasPrefix(calls[0], CondSkippedNonLocal+" ") || !strings.Contains(calls[0], p) {
		t.Fatalf("hook calls %q", calls)
	}
}

// TestQueueFullReported: dropped submissions are reported once a minute;
// drops before Start are counted but are not a queue condition.
func TestQueueFullReported(t *testing.T) {
	sc, watch := setup(t, func(c *Config) { c.QueueSize = 1; c.Workers = 1 })
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	sc.degraded.now = func() time.Time { return time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC) } // fixed clock
	p := filepath.Join(watch, "x")
	write(t, p, "ZAAFVESPER-TEST-MARKER-7f3a")
	ev := &event.Event{Name: event.CreateFile, File: &event.File{Path: p}}
	sc.Submit(ev)
	if len(h.get()) != 0 || sc.Stats()["dropped"] != 1 {
		t.Fatalf("pre-start drop: %q %v", h.get(), sc.Stats())
	}
	out := make(chan *event.Event) // never read: the worker blocks, the queue fills
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		sc.Submit(ev)
	}
	calls := h.get()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], CondQueueFull+" ") {
		t.Fatalf("hook calls %q (stats %v)", calls, sc.Stats())
	}
}

// TestImportAndIncludeBypassesRefused: the allow-list check runs on what
// New compiles; each of these got past the old `import "magic"` regex.
func TestImportAndIncludeBypassesRefused(t *testing.T) {
	for name, src := range map[string]string{
		"comment-hidden": "rule a { condition: true } /* */ import \"magic\"\n",
		"escape-encoded": "import \"m\\x61gic\"\nrule a { condition: true }\n",
		"include-based":  "include \"" + filepath.Join(t.TempDir(), "magic.yar") + "\"\nrule a { condition: true }\n",
		"other module":   "import \"cuckoo\"\nrule a { condition: true }\n",
	} {
		dir := t.TempDir()
		write(t, filepath.Join(dir, "r.yar"), src)
		if sc, err := New(Config{RulesDir: dir}); err == nil {
			sc.Close()
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
	// The escape bypass was real: libyara itself decodes the literal and
	// imports the magic module (when it is compiled in).
	c, err := yr.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if c.AddString("import \"m\\x61gic\"\nrule a { condition: true }\n", "probe") == nil {
		t.Log(`libyara accepts import "m\x61gic" (decodes to magic): the old regex check was bypassable`)
	}
}

// TestFileScanBoundToEventStat: a CreateFile/WriteFile scan reads only the
// file whose dev/inode/ctime the event reported. A changed file is skipped
// and counted (file_changed), not reported: the newer write's own close
// event rescans it. A ctime-only difference (same file) scans the current
// content.
func TestFileScanBoundToEventStat(t *testing.T) {
	sc, watch := setup(t, nil)
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	out := make(chan *event.Event, 8)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(watch, "drop.sh")
	write(t, p, "echo ZAAFVESPER-TEST-MARKER-7f3a\n")
	dev, ino, ctime := statOf(t, p)
	fileEv := func(dev, ino uint64, ctime int64) *event.Event {
		return &event.Event{Name: event.WriteFile, File: &event.File{Path: p, Dev: dev, Ino: ino, CtimeNs: ctime}}
	}
	sc.Submit(fileEv(dev, ino, ctime))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("matching stat not scanned: %v", sc.Stats())
	}
	// Replaced by a new inode (that also matches: no event proves the skip).
	repl := filepath.Join(watch, "other")
	write(t, repl, "echo ZAAFVESPER-TEST-MARKER-7f3a again\n")
	if err := os.Rename(repl, p); err != nil {
		t.Fatal(err)
	}
	sc.Submit(fileEv(dev, ino, ctime))
	waitStat(t, sc, "file_changed", 1)
	if e := recv(t, out, 300*time.Millisecond); e != nil {
		t.Fatal("changed file scanned")
	}
	// Same inode, only ctime differs: scanned as it is now.
	dev2, ino2, ctime2 := statOf(t, p)
	sc.Submit(fileEv(dev2, ino2, ctime2-1))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("ctime-only change skipped: %v", sc.Stats())
	}
	if calls := h.get(); len(calls) != 0 {
		t.Errorf("file change reported as degraded: %q", calls)
	}
	// The newer event (current stat) and an event without a stat both scan.
	sc.Submit(fileEv(dev2, ino2, ctime2))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("current stat not scanned: %v", sc.Stats())
	}
	sc.Submit(fileEv(0, 0, 0))
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("no-stat event not scanned: %v", sc.Stats())
	}
	if st := sc.Stats(); st["file_changed"] != 1 || st["exec_replaced"] != 0 {
		t.Errorf("stats %v", st)
	}
}

// TestChmodAfterCloseStillScanned (F5a): a chmod (or xattr change) after the
// close changes only ctime; the file is the same, so it is scanned as it is
// now and still matches. Only another dev/inode skips a file scan.
func TestChmodAfterCloseStillScanned(t *testing.T) {
	sc, watch := setup(t, nil)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(watch, "stage2.sh")
	write(t, p, "echo ZAAFVESPER-TEST-MARKER-7f3a\n")
	dev, ino, ctime := statOf(t, p)
	time.Sleep(10 * time.Millisecond)
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, c2 := statOf(t, p); c2 == ctime {
		t.Fatal("test setup: chmod did not change ctime")
	}
	sc.Submit(&event.Event{Name: event.WriteFile, File: &event.File{Path: p, Dev: dev, Ino: ino, CtimeNs: ctime}})
	if recv(t, out, 5*time.Second) == nil {
		t.Fatalf("chmod after close hid the file: %v", sc.Stats())
	}
	if sc.Stats()["file_changed"] != 0 {
		t.Errorf("stats %v", sc.Stats())
	}
}

// TestDecoyThenRealReplacementBothReported (F5c): a decoy replacement for
// one process must not hide the real one for another within the minute.
func TestDecoyThenRealReplacementBothReported(t *testing.T) {
	sc, watch := setup(t, nil)
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	sc.degraded.now = func() time.Time { return time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC) } // all in one minute
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	swapped := func(pid int32, name string) {
		exe := filepath.Join(watch, name)
		write(t, exe, "\xcf\xfa\xed\xfefirst")
		dev, ino, ctime := statOf(t, exe)
		tmp := exe + ".new"
		write(t, tmp, "\xcf\xfa\xed\xfesecond")
		if err := os.Rename(tmp, exe); err != nil {
			t.Fatal(err)
		}
		sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: pid, Exe: exe, ExeDev: dev, ExeIno: ino, ExeCtimeNs: ctime}})
	}
	swapped(1000, "decoy")
	waitStat(t, sc, "exec_replaced", 1)
	swapped(2000, "real")
	waitStat(t, sc, "exec_replaced", 2)
	calls := h.get()
	if len(calls) != 2 || !strings.Contains(calls[0], "pid=1000 ") || !strings.Contains(calls[1], "pid=2000 ") {
		t.Fatalf("hook calls %q", calls)
	}
}

// TestKnownNetworkMountSkippedBeforeOpen (F9): a path under a mount point
// that getfsstat lists without MNT_LOCAL is skipped before any syscall on
// the path (the per-descriptor check never runs).
func TestKnownNetworkMountSkippedBeforeOpen(t *testing.T) {
	prevFS, prevMounts := localFS, nonLocalMountList
	t.Cleanup(func() { localFS, nonLocalMountList = prevFS, prevMounts })
	var mu sync.Mutex
	var fdChecks int
	var mounts []string
	localFS = func(fd int) (bool, error) {
		mu.Lock()
		fdChecks++
		mu.Unlock()
		return prevFS(fd)
	}
	nonLocalMountList = func() []string {
		mu.Lock()
		defer mu.Unlock()
		return mounts
	}
	sc, watch := setup(t, nil)
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	mounts = []string{watch}
	mu.Unlock()
	p := filepath.Join(watch, "on-share.sh")
	write(t, p, "echo ZAAFVESPER-TEST-MARKER-7f3a\n")
	sc.Submit(&event.Event{Name: event.CreateFile, File: &event.File{Path: p}})
	waitStat(t, sc, "non_local", 1)
	mu.Lock()
	n := fdChecks
	mu.Unlock()
	if n != 0 {
		t.Errorf("path was opened (%d fstatfs calls) despite the mount list", n)
	}
	if calls := h.get(); len(calls) != 1 || !strings.HasPrefix(calls[0], CondSkippedNonLocal) {
		t.Fatalf("hook calls %q", calls)
	}
	// The real mount table of this Mac is read without error.
	t.Logf("non-local mounts here: %q", prevMounts())
}

// TestLibyaraImportCheck (judge L3): the second layer asks libyara itself
// which modules the compiled rules import. Compiled here without the lexer,
// `import "m\x61gic"` is reported by libyara as "magic" and refused; an
// allowed module passes.
func TestLibyaraImportCheck(t *testing.T) {
	compile := func(src string) *yr.Rules {
		t.Helper()
		c, err := yr.NewCompiler()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Destroy()
		if err := c.AddString(src, "t"); err != nil {
			t.Skipf("libyara refused the source itself (module not compiled in?): %v", err)
		}
		r, err := c.GetRules()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Destroy)
		return r
	}
	err := checkImportsWithLibyara(compile("import \"m\\x61gic\"\nrule a { condition: true }\n"))
	if err == nil || !strings.Contains(err.Error(), `"magic"`) {
		t.Fatalf("escape-encoded magic: %v", err)
	}
	t.Log(err)
	if err := checkImportsWithLibyara(compile("import \"math\"\nimport \"pe\"\nrule a { condition: math.entropy(0, filesize) >= 0 }\n")); err != nil {
		t.Fatalf("allowed modules refused: %v", err)
	}
	if err := checkImportsWithLibyara(compile(testRule)); err != nil {
		t.Fatalf("rule without imports refused: %v", err)
	}
}
