//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

const testRule = `
rule ZAAFVesper_Test_Marker : test stealer
{
    meta:
        author = "zaafvesper"
        severity = 3
        description = "test marker string"
    strings:
        $a = "ZAAFVESPER-TEST-MARKER-7f3a"
    condition:
        $a
}
`

// setup writes a rule dir and a watch dir; returns the scanner and watch dir.
func setup(t *testing.T, mut func(*Config)) (*Scanner, string) {
	t.Helper()
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "marker.yar"), []byte(testRule), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not a rule file; must be ignored.
	if err := os.WriteFile(filepath.Join(rules, "README.md"), []byte("not yara"), 0o600); err != nil {
		t.Fatal(err)
	}
	watch, err := filepath.EvalSymlinks(t.TempDir()) // ES reports resolved paths
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{RulesDir: rules, WatchDirs: []string{watch}, Workers: 2}
	if mut != nil {
		mut(&cfg)
	}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sc.Close() })
	// Rate limits never depend on the wall clock in tests (PF-09); a test
	// that needs time to pass replaces this clock.
	sc.(*Scanner).degraded.now = func() time.Time { return testClock }
	return sc.(*Scanner), watch
}

// testClock is the fixed time of every scanner's rate limiter in tests.
var testClock = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, out <-chan *event.Event, d time.Duration) *event.Event {
	t.Helper()
	select {
	case e := <-out:
		return e
	case <-time.After(d):
		return nil
	}
}

func TestMatchOnCreateFile(t *testing.T) {
	sc, watch := setup(t, nil)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(watch, "payload.sh")
	write(t, bad, "#!/bin/sh\necho ZAAFVESPER-TEST-MARKER-7f3a\n")
	trig := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	sc.Submit(&event.Event{Name: event.CreateFile, Time: trig, File: &event.File{Path: bad},
		Proc: &event.Proc{PID: 42, Exe: "/usr/bin/curl", Parent: &event.Proc{PID: 1, Exe: "/sbin/launchd"}}})
	e := recv(t, out, 5*time.Second)
	if e == nil {
		t.Fatalf("no match; stats %v", sc.Stats())
	}
	if e.Name != event.YaraMatch || e.Source != "yara" || !e.Time.Equal(trig) {
		t.Errorf("event %+v", e)
	}
	if e.Get("yara.rule") != "ZAAFVesper_Test_Marker" || e.Get("yara.namespace") != "marker" ||
		!slices.Equal(e.Yara.Tags, []string{"test", "stealer"}) || e.Get("yara.target") != bad {
		t.Errorf("yara %+v", e.Yara)
	}
	if e.GetIndexed("yara.meta", "author") != "zaafvesper" || e.GetIndexed("yara.meta", "severity") != "3" {
		t.Errorf("meta %v", e.Yara.Meta)
	}
	if e.Get("ps.exe") != "/usr/bin/curl" || e.Get("ps.parent.exe") != "/sbin/launchd" || e.Get("file.path") != bad || e.GetIndexed("evt.arg", "trigger") != event.CreateFile {
		t.Errorf("context: %+v", e)
	}

	// Same file again: served from the cache, still reported.
	sc.Submit(&event.Event{Name: event.WriteFile, File: &event.File{Path: bad}})
	if recv(t, out, 5*time.Second) == nil {
		t.Fatal("no match on cached rescan")
	}
	// A benign file and a file outside the watch dirs produce nothing.
	good := filepath.Join(watch, "fine.txt")
	write(t, good, "hello")
	sc.Submit(&event.Event{Name: event.WriteFile, File: &event.File{Path: good}})
	sc.Submit(&event.Event{Name: event.CreateFile, File: &event.File{Path: "/etc/hosts"}})
	sc.Submit(&event.Event{Name: event.OpenFile, File: &event.File{Path: bad}}) // not a scan trigger
	if e := recv(t, out, 500*time.Millisecond); e != nil {
		t.Fatalf("unexpected match %+v", e.Yara)
	}
	st := sc.Stats()
	if st["cache_hits"] != 1 || st["scanned"] != 2 || st["matches"] != 2 || st["submitted"] != 3 {
		t.Errorf("stats %v", st)
	}
}

func TestCreateProcessScansExe(t *testing.T) {
	sc, watch := setup(t, nil)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(watch, "tool")
	write(t, exe, "\xcf\xfa\xed\xfeZAAFVESPER-TEST-MARKER-7f3a")
	// Platform binaries are skipped by default.
	sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{Exe: exe, IsPlatform: true}})
	if recv(t, out, 300*time.Millisecond) != nil {
		t.Fatal("platform binary scanned")
	}
	// exec of a non-platform binary is scanned wherever it lives.
	sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{Exe: exe}})
	e := recv(t, out, 5*time.Second)
	if e == nil || e.GetIndexed("evt.arg", "trigger") != event.CreateProcess {
		t.Fatalf("exe not scanned: %+v stats %v", e, sc.Stats())
	}
}

func TestRefusesSymlinksFifosAndBigFiles(t *testing.T) {
	sc, watch := setup(t, func(c *Config) { c.MaxFileSize = 64 })
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(watch, "real")
	write(t, target, "ZAAFVESPER-TEST-MARKER-7f3a")
	link := filepath.Join(watch, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(watch, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(watch, "big")
	write(t, big, "ZAAFVESPER-TEST-MARKER-7f3a"+string(make([]byte, 100)))
	for _, p := range []string{link, fifo, big, filepath.Join(watch, "missing")} {
		sc.Submit(&event.Event{Name: event.CreateFile, File: &event.File{Path: p}})
	}
	if e := recv(t, out, time.Second); e != nil {
		t.Fatalf("unexpected match on %s", e.Yara.Target)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := sc.Stats()
		if st["symlinks"] == 1 && st["not_regular"] == 1 && st["too_big"] == 1 && st["errors"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stats %v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSubmitNeverBlocks(t *testing.T) {
	sc, watch := setup(t, func(c *Config) { c.QueueSize = 1; c.Workers = 1 })
	p := filepath.Join(watch, "x")
	write(t, p, "ZAAFVESPER-TEST-MARKER-7f3a")
	ev := &event.Event{Name: event.CreateFile, File: &event.File{Path: p}}

	// Before Start: dropped, not blocked.
	sc.Submit(ev)
	if sc.Stats()["dropped"] != 1 {
		t.Fatalf("pre-start submit not dropped: %v", sc.Stats())
	}
	// Unbuffered out that nobody reads: the worker blocks on its first
	// match, the queue (size 1) fills, and further submits must drop.
	out := make(chan *event.Event)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for range 1000 {
			sc.Submit(ev)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Submit blocked")
	}
	if d := sc.Stats()["dropped"]; d < 990 {
		t.Errorf("dropped %d", d)
	}
	if err := sc.Start(t.Context(), out); err == nil {
		t.Error("second Start accepted")
	}
	// Close must not hang on the blocked worker (its ctx is cancelled), is
	// idempotent, and later submits are dropped without panicking.
	closed := make(chan struct{})
	go func() { sc.Close(); sc.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	sc.Submit(ev)
}

func TestNewErrors(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty RulesDir accepted")
	}
	empty := t.TempDir()
	if _, err := New(Config{RulesDir: empty}); err == nil {
		t.Error("dir without rules accepted")
	}
	bad := t.TempDir()
	write(t, filepath.Join(bad, "broken.yar"), "rule x { condition: nope_undefined }")
	if _, err := New(Config{RulesDir: bad}); err == nil {
		t.Error("broken rule accepted")
	}
	inc := t.TempDir()
	write(t, filepath.Join(inc, "inc.yar"), `include "/etc/hosts"
rule y { condition: true }`)
	if _, err := New(Config{RulesDir: inc}); err == nil {
		t.Error("include directive accepted")
	}
	// A symlinked rule file is refused (O_NOFOLLOW).
	sl := t.TempDir()
	real := filepath.Join(t.TempDir(), "real.yar")
	write(t, real, testRule)
	if err := os.Symlink(real, filepath.Join(sl, "link.yar")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{RulesDir: sl}); err == nil {
		t.Error("symlinked rule file accepted")
	}
}
