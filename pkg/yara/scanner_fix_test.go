//go:build yara

package yara

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// TestCachePoisoningByRestoredMtime: a clean file is scanned and cached, then
// rewritten with malicious content of the same size and its mtime restored.
// ctime in the cache key forces a rescan.
func TestCachePoisoningByRestoredMtime(t *testing.T) {
	sc, watch := setup(t, nil)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(watch, "doc.sh")
	evil := "echo ZAAFVESPER-TEST-MARKER-7f3a\n"
	write(t, p, strings.Repeat("#", len(evil)))
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	ev := &event.Event{Name: event.WriteFile, File: &event.File{Path: p}}
	sc.Submit(ev)
	waitStat(t, sc, "scanned", 1)
	time.Sleep(20 * time.Millisecond)
	write(t, p, evil)
	if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if fi2, _ := os.Stat(p); fi2.Size() != fi.Size() || !fi2.ModTime().Equal(fi.ModTime()) {
		t.Fatal("test setup: size or mtime differs")
	}
	sc.Submit(ev)
	if e := recv(t, out, 5*time.Second); e == nil {
		t.Fatalf("poisoned cache served a stale clean result; stats %v", sc.Stats())
	}
	if sc.Stats()["cache_hits"] != 0 {
		t.Errorf("cache hit after rewrite: %v", sc.Stats())
	}
}

func TestExecCacheKeysOnCDHash(t *testing.T) {
	sc, watch := setup(t, nil)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(watch, "bin")
	write(t, exe, "plain")
	submit := func(cd string) {
		sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{Exe: exe, CDHash: cd}})
	}
	submit("aa")
	waitStat(t, sc, "scanned", 1)
	submit("aa")
	waitStat(t, sc, "cache_hits", 1)
	submit("bb") // different code identity: rescan
	waitStat(t, sc, "scanned", 2)
}

func TestMiddleSymlinkRefused(t *testing.T) {
	sc, watch := setup(t, nil)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(watch, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(real, "f"), "ZAAFVESPER-TEST-MARKER-7f3a")
	if err := os.Symlink(real, filepath.Join(watch, "link")); err != nil {
		t.Fatal(err)
	}
	sc.Submit(&event.Event{Name: event.CreateFile, File: &event.File{Path: filepath.Join(watch, "link", "f")}})
	waitStat(t, sc, "symlinks", 1)
	if e := recv(t, out, 300*time.Millisecond); e != nil {
		t.Fatal("scanned through a symlinked directory")
	}
	// Direct checks of the walk.
	if _, _, err := openNoFollow("/var/log/system.log"); !errors.Is(err, errSymlink) { // /var -> private/var
		t.Errorf("/var: %v", err)
	}
	for _, bad := range []string{"relative", "/a/../b", "/", "/a//b"} {
		if _, _, err := openNoFollow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	f, _, err := openNoFollow(filepath.Join(real, "f"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestQueuePriority(t *testing.T) {
	q := newJobQueue(3)
	if q.push(job{exec: true}) != pushNotRunning {
		t.Fatal("push before open accepted")
	}
	q.open()
	for i := 0; i < 3; i++ {
		if q.push(job{path: "/f"}) != pushOK {
			t.Fatal("file push")
		}
	}
	if q.push(job{path: "/f4"}) != pushRejected {
		t.Error("file push into full queue accepted")
	}
	// Exec jobs displace file jobs while any are queued.
	for i := 0; i < 3; i++ {
		if r := q.push(job{path: "/e", exec: true}); r != pushDisplacedFile {
			t.Fatalf("exec push %d = %v", i, r)
		}
	}
	if e, f := q.lens(); e != 3 || f != 0 {
		t.Fatalf("lens %d %d", e, f)
	}
	if q.push(job{exec: true}) != pushRejected {
		t.Error("exec push into a queue full of exec jobs accepted")
	}
	// Pop order: exec first.
	q2 := newJobQueue(10)
	q2.open()
	q2.push(job{path: "/f1"})
	q2.push(job{path: "/e1", exec: true})
	q2.push(job{path: "/f2"})
	q2.push(job{path: "/e2", exec: true})
	var order []string
	for range 4 {
		j, ok := q2.pop()
		if !ok {
			t.Fatal("pop")
		}
		order = append(order, j.path)
	}
	if strings.Join(order, ",") != "/e1,/e2,/f1,/f2" {
		t.Errorf("order %v", order)
	}
	// close wakes a blocked pop.
	done := make(chan bool)
	go func() { _, ok := q2.pop(); done <- ok }()
	time.Sleep(20 * time.Millisecond)
	q2.close()
	if <-done {
		t.Error("pop after close returned a job")
	}
	if q2.push(job{exec: true}) != pushNotRunning {
		t.Error("push after close accepted")
	}
}

// TestExecNotDroppedUnderFileFlood: with a stuck worker and a full queue of
// file jobs, exec submissions are still queued (file jobs are dropped).
func TestExecNotDroppedUnderFileFlood(t *testing.T) {
	sc, watch := setup(t, func(c *Config) { c.QueueSize = 8; c.Workers = 1 })
	p := filepath.Join(watch, "x")
	write(t, p, "ZAAFVESPER-TEST-MARKER-7f3a")
	out := make(chan *event.Event) // never read: the worker blocks on its first match
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		sc.Submit(&event.Event{Name: event.WriteFile, File: &event.File{Path: p}})
	}
	for range 5 {
		sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{Exe: p}})
	}
	st := sc.Stats()
	if st["dropped_exec"] != 0 || st["dropped_file"] < 90 {
		t.Errorf("stats %v", st)
	}
	if e, _ := sc.q.lens(); e != 5 {
		t.Errorf("queued exec jobs %d", e)
	}
}

func waitStat(t *testing.T, sc *Scanner, key string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for sc.Stats()[key] < want {
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached %d: %v", key, want, sc.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCheckLoadedImagesLive(t *testing.T) {
	err := CheckLoadedImages()
	t.Logf("CheckLoadedImages() = %v", err)
	// The test binary lives in a user-owned temp dir and, unless statically
	// linked, loads libyara from a user-owned /opt/homebrew: must fail closed.
	if err == nil {
		t.Fatal("expected an error for a test binary in a user-owned directory")
	}
}

// TestHomebrewLibyaraFlagged: ignoring the test binary itself, a dynamically
// linked libyara from a user-owned Homebrew prefix must be reported; a
// statically linked build has nothing outside /usr/lib to report.
func TestHomebrewLibyaraFlagged(t *testing.T) {
	imgs := loadedImages()
	if len(imgs) < 2 {
		t.Skip("no images besides the executable")
	}
	dynamic := false
	for _, n := range imgs[1:] {
		if strings.Contains(n, "libyara") {
			dynamic = true
		}
	}
	err := checkImages(imgs[1:], os.Lstat, filepath.EvalSymlinks)
	t.Logf("dynamic libyara=%v, check=%v", dynamic, err)
	if fi, serr := os.Stat("/opt/homebrew"); dynamic && serr == nil && fi.Sys() != nil {
		if err == nil {
			t.Fatal("dynamically loaded Homebrew libyara not flagged")
		}
	}
	if !dynamic && err != nil {
		t.Fatalf("static build flagged: %v", err)
	}
}

func TestMagicImportRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "m.yar"), "import \"magic\"\nrule m { condition: magic.mime_type() == \"text/plain\" }\n")
	if _, err := New(Config{RulesDir: dir}); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("got %v", err)
	}
	ok := t.TempDir()
	write(t, filepath.Join(ok, "pe.yar"), "import \"math\"\nrule n { condition: math.entropy(0, filesize) > 7.9 }\n")
	sc, err := New(Config{RulesDir: ok})
	if err != nil {
		t.Fatalf("other modules must still work: %v", err)
	}
	sc.Close()
}

// TestRuleFilesReadThroughSecureRead: with an owner policy in force, a
// group-writable or symlinked rule file is refused; a proper one compiles.
func TestRuleFilesReadThroughSecureRead(t *testing.T) {
	prev := config.RequiredOwner()
	config.RequireOwner(int64(os.Geteuid()))
	t.Cleanup(func() { config.RequireOwner(prev) })

	good := t.TempDir()
	write(t, filepath.Join(good, "ok.yar"), testRule)
	sc, err := New(Config{RulesDir: good})
	if err != nil {
		t.Fatalf("owned 0600 rule refused: %v", err)
	}
	sc.Close()

	gw := t.TempDir()
	p := filepath.Join(gw, "gw.yar")
	write(t, p, testRule)
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{RulesDir: gw}); err == nil {
		t.Error("group-writable rule file accepted")
	} else {
		t.Logf("group-writable: %v", err)
	}

	sl := t.TempDir()
	real := filepath.Join(t.TempDir(), "real.yar")
	write(t, real, testRule)
	if err := os.Symlink(real, filepath.Join(sl, "link.yar")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{RulesDir: sl}); err == nil {
		t.Error("symlinked rule file accepted")
	} else {
		t.Logf("symlink: %v", err)
	}

	// Owned by someone else (policy uid that is not ours).
	config.RequireOwner(int64(os.Geteuid()) + 1)
	if _, err := New(Config{RulesDir: good}); err == nil {
		t.Error("rule file owned by another uid accepted")
	}

	big := t.TempDir()
	config.RequireOwner(int64(os.Geteuid()))
	write(t, filepath.Join(big, "big.yar"), testRule+"//"+strings.Repeat("x", MaxRuleFileSize))
	if _, err := New(Config{RulesDir: big}); err == nil {
		t.Error("oversize rule file accepted")
	}
}

// TestDotfilesSkipped: AppleDouble companions ("._x.yar") that a package
// payload may carry are not rule files and must not be compiled.
func TestDotfilesSkipped(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.yar"), "rule a { condition: false }\n")
	write(t, filepath.Join(dir, "._a.yar"), "\x00\x05\x16\x07 not yara {{{")
	sc, err := New(Config{RulesDir: dir})
	if err != nil {
		t.Fatalf("dotfile must be skipped: %v", err)
	}
	sc.Close()
}
