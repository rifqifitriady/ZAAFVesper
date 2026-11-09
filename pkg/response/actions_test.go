//go:build darwin

package response

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/netpoll"
	"golang.org/x/sys/unix"
)

// rig is a responder wired to temp directories and stubbed commands: no
// test here runs pfctl, launchctl or codesign, sends a real signal or
// touches /var/db.
type rig struct {
	t       *testing.T
	now     time.Time
	dir     string // symlink-free temp dir
	logs    []Decision
	cmds    []string // "bin arg arg"
	stdins  []string
	signals []string // "pid SIG"
	ids     map[int32]Identity
	degr    []string
	// run, when set, answers a command (else success with no output).
	run func(bin string, args []string) ([]byte, error)
	r   *Responder
}

func newRig(t *testing.T, dry bool, mod func(*Config)) *rig {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := &rig{t: t, now: start.Add(time.Hour), dir: d, ids: map[int32]Identity{}}
	state := filepath.Join(d, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DryRun:   dry,
		Now:      func() time.Time { return g.now },
		Log:      func(dd Decision) { g.logs = append(g.logs, dd) },
		StateDir: state, VaultDir: filepath.Join(state, "quarantine"),
		Runner: func(_ context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
			g.cmds = append(g.cmds, strings.Join(append([]string{bin}, args...), " "))
			if stdin != nil {
				g.stdins = append(g.stdins, string(stdin))
			}
			if g.run != nil {
				return g.run(bin, args)
			}
			return nil, nil
		},
		AppleSigned: func(string) (bool, error) { return false, nil },
		ConsoleUID:  func() (uint32, error) { return 501, nil },
		LocalAddrs:  func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil },
		KillFunc: func(pid int, sig syscall.Signal) error {
			g.signals = append(g.signals, strconv.Itoa(pid)+" "+unix.SignalName(sig))
			return nil
		},
		Identify: func(pid int32) (Identity, error) {
			id, ok := g.ids[pid]
			if !ok {
				return Identity{}, syscall.ESRCH
			}
			return id, nil
		},
		OnDegraded: func(c, det string) { g.degr = append(g.degr, c+": "+det) },
	}
	if mod != nil {
		mod(&cfg)
	}
	g.r = New(cfg)
	return g
}

// proc is a verified, killable process whose kernel identity matches.
func (g *rig) proc(pid int32, exe string) *event.Proc {
	g.ids[pid] = Identity{CSKnown: true, StartTime: start, Exe: exe, UniqueID: uniq(pid), UniqueKnown: true}
	me := int64(os.Geteuid())
	return &event.Proc{PID: pid, PPID: 1, Exe: exe, Name: filepath.Base(exe), StartTime: start, UniqueID: uniq(pid), UID: me, EUID: me}
}

// file writes rel under the rig dir and returns its path and an event about
// it (dev/ino from lstat), written by an untrusted process.
func (g *rig) file(rel, content string, mode os.FileMode) (string, *event.Event) {
	g.t.Helper()
	p := filepath.Join(g.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		g.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		g.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		g.t.Fatal(err)
	}
	return p, g.eventFor(p, event.CreateFile)
}

func (g *rig) eventFor(p, name string) *event.Event {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		g.t.Fatal(err)
	}
	e := &event.Event{Name: name, Source: ESSource, Proc: g.proc(4242, "/private/tmp/dropper"),
		File: &event.File{Path: p, Dev: uint64(uint32(st.Dev)), Ino: st.Ino}}
	if name == event.DeleteXattr {
		e.Args = map[string]string{"xattr": QuarantineXattr}
	}
	return e
}

// pf returns the pfctl commands run so far (the gateway lookups through
// /sbin/route are left out).
func (g *rig) pf() []string {
	var out []string
	for _, c := range g.cmds {
		if strings.HasPrefix(c, PfctlBin+" ") {
			out = append(out, c)
		}
	}
	return out
}

func (g *rig) last() Decision {
	g.t.Helper()
	if len(g.logs) == 0 {
		g.t.Fatal("no decision logged")
	}
	return g.logs[len(g.logs)-1]
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestActionNamesMatchRules(t *testing.T) {
	for a, b := range map[string]string{ActionKill: rules.ActionKill, ActionSuspend: rules.ActionSuspend,
		ActionQuarantineFile: rules.ActionQuarantineFile, ActionRequarantine: rules.ActionRequarantine,
		ActionRemovePersistence: rules.ActionRemovePersistence, ActionIsolateProcess: rules.ActionIsolateProcess,
		TargetFile: rules.TargetFile, TargetProcess: rules.TargetProcess, TargetParent: rules.TargetParent} {
		if a != b {
			t.Fatalf("%q != %q", a, b)
		}
	}
}

func TestProtectedPath(t *testing.T) {
	own := []string{"/usr/local/sbin/zaafvesper", "/usr/local/etc/zaafvesper"}
	for p, want := range map[string]bool{
		"/System/Library/x":                        true,
		"/SYSTEM/Library/x":                        true, // APFS is case-insensitive
		"/ſystem/Library/x":                        true, // long s folds to s
		"/usr/bin/curl":                            true,
		"/USR/bin/curl":                            true,
		"/usr/local/bin/tool":                      false,
		"/bin/sh":                                  true,
		"/sbin/launchd":                            true,
		"/Library/Apple/System/x":                  true,
		"/private/var/db/zaafvesper/quarantine":    true,
		"/private/etc/hosts":                       true,
		"/Library/LaunchDaemons/com.apple.x.plist": true,
		"/Library/LaunchDaemons/com.evil.plist":    false,
		"/usr/local/sbin/zaafvesper":               true,
		"/usr/local/sbin/ZAAFVesper":               true,
		"/usr/local/etc/zaafvesper/rules/x.yml":    true,
		"/usr/local/etc/zaafvesperx":               false,
		"/private/tmp/payload":                     false,
		"/Users/a/Downloads/x":                     false,
		"/private/tmp/../../System/x":              true, // not clean
		"relative/x":                               true,
		"/usr":                                     true,
	} {
		if got := protectedPath(p, own) != ""; got != want {
			t.Errorf("protectedPath(%q) = %v (%q), want %v", p, got, protectedPath(p, own), want)
		}
	}
	if got := bundlesOf("/Applications/Xcode.app/Contents/Frameworks/A.framework/A"); !reflect.DeepEqual(got,
		[]string{"/Applications/Xcode.app", "/Applications/Xcode.app/Contents/Frameworks/A.framework"}) {
		t.Fatalf("bundlesOf = %v", got)
	}
	if got := bundlesOf("/Users/a/Evil.APP"); got != nil {
		t.Fatalf("a bundle is not inside itself: %v", got)
	}
}

func TestQuarantineAndRestore(t *testing.T) {
	g := newRig(t, false, nil)
	p, e := g.file("drop/payload", "MZ-payload", 0o755)
	if err := unix.Setxattr(p, "com.example.tag", []byte("v1"), 0); err != nil {
		t.Fatal(err)
	}
	if err := g.r.QuarantineFile(e, TargetFile, "rule-q", "rule Q"); err != nil {
		t.Fatalf("quarantine: %v (%+v)", err, g.logs)
	}
	d := g.last()
	if d.Outcome != OutcomeQuarantined || d.Action != ActionQuarantineFile || d.Path != p {
		t.Fatalf("decision = %+v", d)
	}
	if exists(p) {
		t.Fatal("original still in place")
	}
	v := Vault{Dir: g.r.cfg.VaultDir}
	items, err := v.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("list = %v, %v", items, err)
	}
	id := items[0].ID
	fi, err := os.Stat(filepath.Join(v.Dir, id))
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("vault file mode = %v, %v (exec bits must be stripped)", fi, err)
	}
	if vfi, _ := os.Stat(v.Dir); vfi.Mode().Perm() != 0o700 {
		t.Fatalf("vault dir mode %v", vfi.Mode())
	}
	rec := items[0].Records[0]
	if rec.OriginalPath != p || rec.Mode != 0o755 || string(rec.Xattrs["com.example.tag"]) != "v1" || rec.Rule != "rule-q" || rec.Size != 10 {
		t.Fatalf("record = %+v", rec)
	}
	if !strings.Contains(d.Detail, id) {
		t.Fatalf("detail %q lacks id", d.Detail)
	}
	// Restore puts it back with mode and attributes, then empties the vault.
	got, warn, err := v.Restore(id[:10])
	if err != nil {
		t.Fatalf("restore: %v %v", err, warn)
	}
	b, _ := os.ReadFile(p)
	fi, _ = os.Stat(p)
	val := make([]byte, 16)
	n, _ := unix.Getxattr(p, "com.example.tag", val)
	if string(b) != "MZ-payload" || fi.Mode().Perm() != 0o755 || string(val[:n]) != "v1" || got.OriginalPath != p {
		t.Fatalf("restored %q mode %v xattr %q", b, fi.Mode(), val[:n])
	}
	if items, _ := v.List(); len(items) != 0 || exists(filepath.Join(v.Dir, id)) {
		t.Fatalf("vault not emptied: %v", items)
	}
	// A second quarantine, then restore refuses to overwrite a new file.
	_, e = g.file("drop/payload2", "second", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "rule-q", "rule Q"); err != nil {
		t.Fatal(err)
	}
	items, _ = v.List()
	if err := os.WriteFile(items[0].Records[0].OriginalPath, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Restore(items[0].ID); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("restore over an existing file: %v", err)
	}
	if _, _, err := v.Restore("abc"); err == nil {
		t.Fatal("short id accepted")
	}
}

func TestRestoreRefusesProtectedAndSetuid(t *testing.T) {
	g := newRig(t, false, nil)
	_, e := g.file("drop/suid", "x", 0o755)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err != nil {
		t.Fatal(err)
	}
	v := Vault{Dir: g.r.cfg.VaultDir}
	items, _ := v.List()
	// Tamper with the sidecar as an attacker with vault access would.
	sc, _ := os.ReadFile(filepath.Join(v.Dir, items[0].ID+".json"))
	var s sidecar
	_ = json.Unmarshal(sc, &s)
	s.Records[0].OriginalPath = "/usr/bin/evil"
	b, _ := json.Marshal(s)
	_ = os.WriteFile(filepath.Join(v.Dir, items[0].ID+".json"), b, 0o600)
	if _, _, err := v.Restore(items[0].ID); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("restore to /usr/bin: %v", err)
	}
	// setuid bits are never restored.
	s.Records[0].OriginalPath = filepath.Join(g.dir, "drop/suid")
	s.Records[0].Mode = 0o4755
	b, _ = json.Marshal(s)
	_ = os.WriteFile(filepath.Join(v.Dir, items[0].ID+".json"), b, 0o600)
	_, warn, err := v.Restore(items[0].ID)
	fi, _ := os.Stat(filepath.Join(g.dir, "drop/suid"))
	if err != nil || fi.Mode()&os.ModeSetuid != 0 || len(warn) == 0 {
		t.Fatalf("setuid restore: %v mode %v warn %v", err, fi.Mode(), warn)
	}
}

// checkTempBundles makes the test temp dir (under /private/var/folders)
// count as a protected location, so the Apple-bundle checks run there.
func checkTempBundles(t *testing.T) {
	old := userWritableBundles
	userWritableBundles = nil
	t.Cleanup(func() { userWritableBundles = old })
}

func TestQuarantineGuardRails(t *testing.T) {
	checkTempBundles(t)
	g := newRig(t, false, func(c *Config) {
		c.MaxQuarantineBytes = 64
		c.AppleSigned = func(b string) (bool, error) { return strings.HasSuffix(b, "Apple.app"), nil }
	})
	check := func(name string, e *event.Event, target, outcome string, path string) {
		t.Helper()
		err := g.r.QuarantineFile(e, target, "rule-"+name, name)
		d := g.last()
		if err == nil || d.Outcome != outcome {
			t.Fatalf("%s: err %v decision %+v, want %s", name, err, d, outcome)
		}
		if path != "" && !exists(path) {
			t.Fatalf("%s: %s was removed", name, path)
		}
	}
	// Replaced since the event: dev/ino differ.
	p, e := g.file("a/replaced", "one", 0o644)
	_ = os.Remove(p)
	_ = os.WriteFile(p, []byte("two"), 0o644)
	check("replaced", e, TargetFile, OutcomeFileCheck, p)
	// No identity in the event.
	p, e = g.file("a/noid", "x", 0o644)
	e.File.Dev, e.File.Ino = 0, 0
	check("noid", e, TargetFile, OutcomeFileCheck, p)
	// A symbolic link as the file.
	target, _ := g.file("a/real", "real", 0o644)
	link := filepath.Join(g.dir, "a/link")
	_ = os.Symlink(target, link)
	e = g.eventFor(link, event.CreateFile)
	check("symlink file", e, TargetFile, OutcomeFileCheck, target)
	// A symbolic link in the directory path.
	_ = os.Symlink(filepath.Join(g.dir, "a"), filepath.Join(g.dir, "dirlink"))
	e = g.eventFor(target, event.CreateFile)
	e.File.Path = filepath.Join(g.dir, "dirlink/real")
	check("symlink dir", e, TargetFile, OutcomeFileCheck, target)
	// Hard link to a file that does not belong to the process.
	p, e = g.file("a/hard", "h", 0o644)
	_ = os.Link(p, filepath.Join(g.dir, "a/hard2"))
	e.Proc.UID, e.Proc.EUID = 4321, 4321
	check("hardlink foreign", e, TargetFile, OutcomeFileCheck, p)
	// Too large.
	p, e = g.file("a/big", strings.Repeat("x", 65), 0o644)
	check("big", e, TargetFile, OutcomeFileCheck, p)
	// FIFO: not a regular file, and opening it must not block.
	fifo := filepath.Join(g.dir, "a/fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	check("fifo", g.eventFor(fifo, event.CreateFile), TargetFile, OutcomeFileCheck, fifo)
	// Directory.
	_ = os.Mkdir(filepath.Join(g.dir, "a/dir"), 0o755)
	check("dir", g.eventFor(filepath.Join(g.dir, "a/dir"), event.CreateFile), TargetFile, OutcomeFileCheck, "")
	// Inside an Apple-signed bundle.
	p, e = g.file("Apps/Apple.app/Contents/MacOS/Apple", "x", 0o755)
	check("apple bundle", e, TargetFile, OutcomeProtectedPath, p)
	// Bundle signature unknown: refused.
	g.r.cfg.AppleSigned = func(string) (bool, error) { return false, errors.New("codesign failed") }
	p, e = g.file("Apps/Other.app/Contents/MacOS/Other", "x", 0o755)
	check("bundle unknown", e, TargetFile, OutcomeProtectedPath, p)
	g.r.cfg.AppleSigned = func(string) (bool, error) { return false, nil }
	// Protected and own paths, never opened.
	check("system", &event.Event{Proc: g.proc(4242, "/private/tmp/x"), File: &event.File{Path: "/System/Library/x", Dev: 1, Ino: 2}}, TargetFile, OutcomeProtectedPath, "")
	check("vault", &event.Event{Proc: g.proc(4242, "/private/tmp/x"), File: &event.File{Path: g.r.cfg.VaultDir + "/x", Dev: 1, Ino: 2}}, TargetFile, OutcomeProtectedPath, "")
	// Seeded or unverified process of the event.
	p, e = g.file("a/seeded", "x", 0o644)
	e.Proc.Seeded = true
	check("seeded", e, TargetFile, OutcomeUnknown, p)
	p, e = g.file("a/unverified", "x", 0o644)
	e.Args = map[string]string{ps.ArgIdentity: ps.Unverified}
	check("unverified", e, TargetFile, OutcomeUnknown, p)
	// Target process: an Apple platform binary is refused.
	pe := &event.Event{Name: event.CreateProcess, Proc: g.proc(4243, "/bin/zsh")}
	pe.Proc.IsPlatform = true
	check("platform exe", pe, TargetProcess, OutcomeProtectedPath, "")
}

// TestQuarantineHardLinkOwned: a hard link costs a payload one link()
// call, so a multiply-linked file that belongs to the offender is still
// quarantined; the other name is reported.
func TestQuarantineHardLinkOwned(t *testing.T) {
	g := newRig(t, false, nil)
	p, e := g.file("h/payload", "x", 0o755)
	other := filepath.Join(g.dir, "h/other")
	_ = os.Link(p, other)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err != nil || exists(p) || !exists(other) ||
		!strings.Contains(g.last().Detail, "1 other hard link") {
		t.Fatalf("owned hard link: %v %+v", err, g.last())
	}
}

// TestQuarantineForeignExecutable: target process refuses an executable
// that belongs to another uid (root must not clear someone else's file from
// a sticky directory because the offender ran it).
func TestQuarantineForeignExecutable(t *testing.T) {
	g := newRig(t, false, nil)
	p, fe := g.file("tmp/helper", "x", 0o755)
	e := &event.Event{Name: event.CreateProcess, Source: ESSource, Proc: g.proc(5001, p)}
	e.Proc.ExeDev, e.Proc.ExeIno = fe.File.Dev, fe.File.Ino
	e.Proc.UID, e.Proc.EUID = 4321, 4321
	if err := g.r.QuarantineFile(e, TargetProcess, "r", "r"); err == nil || !exists(p) || !strings.Contains(g.last().Detail, "belongs to uid") {
		t.Fatalf("foreign executable: %v %+v", err, g.last())
	}
}

// TestCodesignFailClosed: a codesign that times out or dies is not an
// answer (refused), and deep bundle nesting is refused before any codesign
// run.
func TestCodesignFailClosed(t *testing.T) {
	checkTempBundles(t)
	var runs int
	check := appleSignedByCodesign(func(ctx context.Context, bin string, args []string, _ []byte) ([]byte, error) {
		runs++
		switch args[len(args)-1] {
		case "/a/Slow.app":
			<-ctx.Done()
			return nil, &ExitError{Code: -1}
		case "/a/Dead.app":
			return nil, &ExitError{Code: -1}
		case "/a/Unsigned.app":
			return nil, &ExitError{Code: 1}
		case "/a/Other.app":
			return nil, &ExitError{Code: 3}
		}
		return nil, nil
	})
	if ok, err := check("/a/Apple.app"); !ok || err != nil {
		t.Fatalf("apple: %v %v", ok, err)
	}
	for _, b := range []string{"/a/Unsigned.app", "/a/Other.app"} {
		if ok, err := check(b); ok || err != nil {
			t.Fatalf("%s: %v %v", b, ok, err)
		}
	}
	if testing.Short() {
		t.Skip("codesign timeout waits 5 s")
	}
	for _, b := range []string{"/a/Dead.app", "/a/Slow.app"} {
		if _, err := check(b); err == nil {
			t.Fatalf("%s: no error (fail open)", b)
		}
	}
	g := newRig(t, false, func(c *Config) {
		c.AppleSigned = func(string) (bool, error) { runs++; return false, nil }
	})
	runs = 0
	p, e := g.file("n/a.app/b.app/c.app/d.app/x", "x", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err == nil || runs != 0 || !exists(p) || !strings.Contains(g.last().Detail, "nested") {
		t.Fatalf("deep nesting: %v runs=%d %+v", err, runs, g.last())
	}
}

func TestQuarantineTargetProcessAndRename(t *testing.T) {
	g := newRig(t, false, nil)
	p, fe := g.file("tmp/stage2", "\xcf\xfa\xed\xfe", 0o755)
	e := &event.Event{Name: event.CreateProcess, Source: ESSource, Proc: g.proc(5000, p)}
	e.Proc.ExeDev, e.Proc.ExeIno = fe.File.Dev, fe.File.Ino
	if err := g.r.QuarantineFile(e, TargetProcess, "rule-x", "x"); err != nil || exists(p) {
		t.Fatalf("target process: %v %+v", err, g.logs)
	}
	// Rename: the file now lives at the destination.
	src, re := g.file("tmp/src", "renamed", 0o644)
	dst := filepath.Join(g.dir, "tmp/dst")
	_ = os.Rename(src, dst)
	re.Name, re.File.Dest = event.RenameFile, dst
	if err := g.r.QuarantineFile(re, TargetFile, "rule-x", "x"); err != nil || exists(dst) {
		t.Fatalf("rename: %v %+v", err, g.logs)
	}
}

func TestQuarantineDryRunAndBudget(t *testing.T) {
	g := newRig(t, true, nil)
	p, e := g.file("d/x", "x", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err != nil || g.last().Outcome != OutcomeDryRun || !exists(p) {
		t.Fatalf("dry-run: %v %+v", err, g.logs)
	}
	if exists(filepath.Join(g.dir, "state/quarantine")) {
		t.Fatal("dry-run created the vault")
	}
	// File and network actions have their own budget of 10 per rule a
	// minute (owner decision 9 Nov 2026), separate from kill and suspend.
	g = newRig(t, false, nil)
	for i := 0; i < DefaultMaxPerRulePerMinute; i++ {
		_, e := g.file("b/f"+strconv.Itoa(i), strconv.Itoa(i), 0o644)
		if err := g.r.QuarantineFile(e, TargetFile, "rule-b", "rule B"); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	p, e = g.file("b/over", "over", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "rule-b", "rule B"); !errors.Is(err, ErrRateLimited) || !exists(p) {
		t.Fatalf("11th: %v", err)
	}
	if len(g.degr) != 1 || !strings.HasPrefix(g.degr[0], CondRateLimited) || !strings.Contains(g.degr[0], "file/network action budget") {
		t.Fatalf("degraded = %v", g.degr)
	}
	// Decoy file actions do not spend the kill budget: the kill of the same
	// rule still happens.
	if err := g.r.KillEvent(&event.Event{Source: ESSource, Proc: g.proc(6000, "/private/tmp/p")}, "rule-b", "rule B"); err != nil {
		t.Fatalf("kill after 10 quarantines: %v", err)
	}
	// And the other way round: 30 kills leave the file actions their budget.
	h := newRig(t, false, nil)
	for i := 0; i < DefaultMaxPerMinute; i++ {
		if err := h.r.KillEvent(&event.Event{Source: ESSource, Proc: h.proc(int32(6100+i), "/private/tmp/p")}, "rule-"+strconv.Itoa(i%3), "r"); err != nil {
			t.Fatalf("kill %d: %v", i, err)
		}
	}
	if err := h.r.KillEvent(&event.Event{Source: ESSource, Proc: h.proc(6200, "/private/tmp/p")}, "rule-x", "r"); !errors.Is(err, ErrRateLimited) ||
		!strings.Contains(h.degr[0], "global kill/suspend budget") {
		t.Fatalf("31st kill: %v %v", err, h.degr)
	}
	p, e = h.file("b/after", "after", 0o644)
	if err := h.r.QuarantineFile(e, TargetFile, "rule-x", "r"); err != nil || exists(p) {
		t.Fatalf("quarantine after 30 kills: %v", err)
	}
}

func TestRequarantine(t *testing.T) {
	checkTempBundles(t)
	g := newRig(t, false, nil)
	p, _ := g.file("dl/tool", "x", 0o755)
	e := g.eventFor(p, event.DeleteXattr)
	if err := g.r.Requarantine(e, "rule-r", "r"); err != nil || g.last().Outcome != OutcomeRequarantined {
		t.Fatalf("requarantine: %v %+v", err, g.logs)
	}
	val := make([]byte, 64)
	n, err := unix.Getxattr(p, QuarantineXattr, val)
	if err != nil || !strings.HasPrefix(string(val[:n]), "0001;") || !strings.HasSuffix(string(val[:n]), ";ZAAFVesper;") {
		t.Fatalf("attribute = %q, %v", val[:n], err)
	}
	// Present again: left alone, no budget spent.
	if err := g.r.Requarantine(e, "rule-r", "r"); err != nil || g.last().Outcome != OutcomeAlreadyQuarantined {
		t.Fatalf("second: %v %+v", err, g.last())
	}
	// A bundle directory is accepted.
	app := filepath.Join(g.dir, "dl/X.app")
	_ = os.Mkdir(app, 0o755)
	if err := g.r.Requarantine(g.eventFor(app, event.DeleteXattr), "rule-r", "r"); err != nil {
		t.Fatalf("directory: %v %+v", err, g.last())
	}
	// Replaced file refused, nothing written.
	p, _ = g.file("dl/swap", "a", 0o644)
	e = g.eventFor(p, event.DeleteXattr)
	_ = os.Remove(p)
	_ = os.WriteFile(p, []byte("b"), 0o644)
	if err := g.r.Requarantine(e, "rule-r", "r"); err == nil || g.last().Outcome != OutcomeFileCheck {
		t.Fatalf("replaced: %v %+v", err, g.last())
	}
	if _, err := unix.Getxattr(p, QuarantineXattr, nil); err == nil {
		t.Fatal("attribute set on the replacement file")
	}
	// Refusals that never touch the file: not a quarantine removal, a
	// trusted remover (xattr under a platform shell), a seeded remover, a
	// remover whose platform flag is unknown, an Apple-signed bundle.
	refuse := func(name string, e *event.Event, outcome string) {
		t.Helper()
		if err := g.r.Requarantine(e, "rule-r", "r"); err == nil || g.last().Outcome != outcome {
			t.Fatalf("%s: %v %+v", name, err, g.last())
		}
		if _, err := unix.Getxattr(e.File.Path, QuarantineXattr, nil); err == nil {
			t.Fatalf("%s: attribute set", name)
		}
	}
	p, _ = g.file("dl/r1", "x", 0o644)
	e = g.eventFor(p, event.DeleteXattr)
	e.Args["xattr"] = "com.apple.metadata:kMDItemWhereFroms"
	refuse("other attribute", e, OutcomeFileCheck)
	e = g.eventFor(p, event.WriteFile)
	refuse("write event", e, OutcomeFileCheck)
	e = g.eventFor(p, event.DeleteXattr)
	e.Proc.IsPlatform, e.Proc.Exe = true, "/usr/bin/xattr"
	e.Proc.Parent = &event.Proc{PID: 1, Exe: "/bin/zsh", IsPlatform: true}
	refuse("trusted remover", e, OutcomeWriterNotUntrusted)
	e = g.eventFor(p, event.DeleteXattr)
	e.Proc.Seeded = true
	refuse("seeded", e, OutcomeUnknown)
	e = g.eventFor(p, event.DeleteXattr)
	e.Source, e.Proc.UniqueID = "fixture", 0
	refuse("platform unknown", e, OutcomeUnknown)
	g.r.cfg.AppleSigned = func(b string) (bool, error) { return strings.HasSuffix(b, "Apple.app"), nil }
	_ = os.Mkdir(filepath.Join(g.dir, "dl/Apple.app"), 0o755)
	refuse("apple bundle dir", g.eventFor(filepath.Join(g.dir, "dl/Apple.app"), event.DeleteXattr), OutcomeProtectedPath)
	// An Apple tool under an untrusted parent counts as untrusted.
	e = g.eventFor(p, event.DeleteXattr)
	e.Proc.IsPlatform, e.Proc.Exe = true, "/usr/bin/xattr"
	e.Proc.Parent = &event.Proc{PID: 1, Exe: "/Volumes/Setup/Setup", CSCategory: event.CSLocalSigning}
	if err := g.r.Requarantine(e, "rule-r", "r"); err != nil || g.last().Outcome != OutcomeRequarantined {
		t.Fatalf("xattr under untrusted parent: %v %+v", err, g.last())
	}
	// Dry-run sets nothing.
	g = newRig(t, true, nil)
	p, _ = g.file("dl/dry", "x", 0o644)
	_ = g.r.Requarantine(g.eventFor(p, event.DeleteXattr), "rule-r", "r")
	if _, err := unix.Getxattr(p, QuarantineXattr, nil); err == nil || g.last().Outcome != OutcomeDryRun {
		t.Fatalf("dry-run set the attribute: %+v", g.last())
	}
}

const plistXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>ProgramArguments</key><array><string>/tmp/x</string></array><key>Label</key><string>%s</string></dict></plist>`

func plist(label string) string { return strings.Replace(plistXML, "%s", label, 1) }

func TestPlistLabel(t *testing.T) {
	bin, _ := hex.DecodeString("62706c6973743030d3010203040507554c6162656c5f101050726f6772616d417267756d656e7473594b656570416c6976655e636f6d2e6576696c2e6167656e74a106562f746d702f7809080f15283241434a000000000000010100000000000000080000000000000000000000000000004b")
	uni, _ := hex.DecodeString("62706c6973743030d10102554c6162656c6e0063006f006d002e00e900760069006c002e00e400670065006e0074080b11000000000000010100000000000000030000000000000000000000000000002e")
	for _, c := range []struct {
		in, want, err string
	}{
		{plist("com.evil.agent"), "com.evil.agent", ""},
		{string(bin), "com.evil.agent", ""},
		{string(uni), "com.évil.ägent", ""},
		{`<plist><dict><key>Label</key><string>a</string><key>Label</key><string>b</string></dict></plist>`, "", "more than once"},
		{`<plist><dict><key>Label</key><integer>1</integer></dict></plist>`, "", "not a string"},
		{`<plist><dict><key>X</key><dict><key>Label</key><string>nested</string></dict></dict></plist>`, "", "no Label"},
		{`<plist><array/></plist>`, "", "not a dict"},
		{"bplist00garbage", "", "bplist"},
		{"not xml", "", ""},
	} {
		got, err := PlistLabel([]byte(c.in))
		if got != c.want || (c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err))) || (c.want == "" && err == nil) {
			t.Errorf("PlistLabel(%.40q) = %q, %v", c.in, got, err)
		}
	}
	// Truncated binary plists never panic.
	for i := 0; i < len(bin); i++ {
		_, _ = PlistLabel(bin[:i])
		b := append([]byte(nil), bin...)
		b[i] ^= 0xff
		_, _ = PlistLabel(b)
	}
}

// TestRemovePersistence puts a fake /Users/alice/Library/LaunchAgents under
// the rig dir, mapped for launchDomain through launchRoot.
func TestRemovePersistence(t *testing.T) {
	g := newRig(t, false, func(c *Config) { c.MaxPerRulePerMinute, c.MaxPerMinute = 100, 100 })
	home := filepath.Join(g.dir, "Users", "alice")
	g.r.launchRoot = g.dir
	plistPath := filepath.Join(home, "Library/LaunchAgents/com.evil.agent.plist")
	loadedFrom := plistPath
	g.run = func(bin string, args []string) ([]byte, error) {
		if bin == LaunchctlBin && args[0] == "print" {
			return []byte("gui/501/com.evil.agent = {\n\tactive count = 1\n\tpath = " + loadedFrom + "\n\tstate = running\n}\n"), nil
		}
		return nil, nil
	}
	mk := func(label string) *event.Event {
		_, e := g.file("Users/alice/Library/LaunchAgents/com.evil.agent.plist", plist(label), 0o644)
		return e
	}
	e := mk("com.evil.agent")
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil {
		t.Fatalf("remove: %v %+v", err, g.logs)
	}
	d := g.last()
	uid := os.Geteuid()
	wantBootout := LaunchctlBin + " bootout gui/" + strconv.Itoa(uid) + "/com.evil.agent"
	if d.Outcome != OutcomePersistenceRemoved || exists(plistPath) || g.cmds[len(g.cmds)-1] != wantBootout {
		t.Fatalf("decision %+v cmds %v", d, g.cmds)
	}
	items, _ := Vault{Dir: g.r.cfg.VaultDir}.List()
	if len(items) != 1 || items[0].Records[0].Label != "com.evil.agent" || items[0].Records[0].Action != ActionRemovePersistence {
		t.Fatalf("vault = %+v", items)
	}
	// Borrowed label: launchd has it from another plist: no bootout, plist still quarantined.
	g.cmds = nil
	loadedFrom = "/Library/LaunchAgents/com.vendor.real.plist"
	e = mk("com.evil.agent")
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil || exists(plistPath) {
		t.Fatalf("borrowed: %v", err)
	}
	for _, c := range g.cmds {
		if strings.Contains(c, "bootout") {
			t.Fatalf("booted out a borrowed label: %v", g.cmds)
		}
	}
	if !strings.Contains(g.last().Detail, "borrowed label") {
		t.Fatalf("detail = %q", g.last().Detail)
	}
	// Refused labels are never booted out, but the plist is still quarantined.
	for _, label := range []string{"com.apple.evil", "COM.APPLE.evil", "com.rifqifitriady.zaafvesper", "../../system/x", "a b"} {
		g.cmds = nil
		e := mk(label)
		if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil || g.last().Outcome != OutcomePersistenceRemoved || exists(plistPath) || len(g.cmds) != 0 ||
			!strings.Contains(g.last().Detail, "nothing booted out") {
			t.Fatalf("label %q: %v %+v cmds %v", label, err, g.last(), g.cmds)
		}
	}
	// Written by an Apple tool (cp) under a fully trusted chain: refused,
	// nothing ran, the plist stays.
	trusted := &event.Proc{PID: 900, Exe: "/bin/zsh", Name: "zsh", IsPlatform: true}
	g.cmds = nil
	e = mk("com.evil.agent")
	e.Proc.IsPlatform, e.Proc.Exe, e.Proc.Parent = true, "/bin/cp", trusted
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err == nil || g.last().Outcome != OutcomeWriterNotUntrusted || len(g.cmds) != 0 || !exists(plistPath) {
		t.Fatalf("cp under a trusted chain: %v %+v %v", err, g.last(), g.cmds)
	}
	// A verified Developer ID writer: refused.
	e = mk("com.evil.agent")
	e.Proc.TeamID, e.Proc.CSCategory = "ABCDE12345", event.CSDeveloperID
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err == nil || g.last().Outcome != OutcomeWriterNotUntrusted || !exists(plistPath) {
		t.Fatalf("developer id writer: %v %+v", err, g.last())
	}
	// cp under an untrusted parent, and cp under a trusted parent but with an
	// untrusted ancestor (`sh -c` from a dropper): acted on (owner decision
	// 9 Nov 2026).
	for name, set := range map[string]func(p *event.Proc){
		"untrusted parent": func(p *event.Proc) {
			p.Parent = &event.Proc{PID: 901, Exe: "/Volumes/Setup/Setup", CSCategory: event.CSLocalSigning}
		},
		"untrusted ancestor": func(p *event.Proc) { p.Parent, p.AncestorsUntrusted = trusted, true },
	} {
		g.cmds = nil
		e = mk("com.evil.agent")
		e.Proc.IsPlatform, e.Proc.Exe = true, "/bin/cp"
		set(e.Proc)
		if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil || g.last().Outcome != OutcomePersistenceRemoved || exists(plistPath) {
			t.Fatalf("cp with %s: %v %+v", name, err, g.last())
		}
	}
	g.run = func(bin string, args []string) ([]byte, error) {
		if bin == LaunchctlBin && args[0] == "print" {
			return []byte("path = " + loadedFrom + "\n"), nil
		}
		return nil, nil
	}
	// Seeded writer and unknown platform flag: refused, nothing ran.
	g.cmds = nil
	e = mk("com.evil.agent")
	e.Proc.Seeded = true
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err == nil || g.last().Outcome != OutcomeUnknown || len(g.cmds) != 0 || !exists(plistPath) {
		t.Fatalf("seeded writer: %v %+v", err, g.last())
	}
	// launchctl cannot answer, or bootout fails: the plist is still
	// quarantined but the outcome is partial, never success.
	for _, fail := range []string{"print", "bootout"} {
		g.cmds = nil
		g.run = func(bin string, args []string) ([]byte, error) {
			if args[0] == fail {
				return nil, &ExitError{Code: 5, Output: "boom"}
			}
			return []byte("path = " + plistPath + "\n"), nil
		}
		e = mk("com.evil.agent")
		if err := g.r.RemovePersistence(e, "rule-p", "p"); err == nil || g.last().Outcome != OutcomePartial || exists(plistPath) {
			t.Fatalf("%s fails: %v %+v", fail, err, g.last())
		}
	}
	// Not loaded (launchctl print exit 113): success, nothing booted out.
	g.cmds = nil
	g.run = func(bin string, args []string) ([]byte, error) { return nil, &ExitError{Code: 113} }
	e = mk("com.evil.agent")
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil || g.last().Outcome != OutcomePersistenceRemoved || len(g.cmds) != 1 {
		t.Fatalf("not loaded: %v %+v %v", err, g.last(), g.cmds)
	}
	// Not a launch item location.
	_, e = g.file("Users/alice/Library/LaunchAgents/sub/x.plist", plist("com.x"), 0o644)
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err == nil || g.last().Outcome != OutcomeProtectedPath {
		t.Fatalf("subdirectory: %v %+v", err, g.last())
	}
	// No label: quarantined, nothing booted out.
	g.cmds = nil
	e = mk("")
	_ = os.WriteFile(plistPath, []byte("<plist><dict/></plist>"), 0o644)
	e = g.eventFor(plistPath, event.CreateFile)
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil || exists(plistPath) || len(g.cmds) != 0 {
		t.Fatalf("no label: %v %v", err, g.cmds)
	}
	// LaunchDaemons use the system domain; dry-run runs nothing.
	g = newRig(t, true, nil)
	g.r.launchRoot = g.dir
	_, e = g.file("Library/LaunchDaemons/com.evil.d.plist", plist("com.evil.d"), 0o644)
	if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil || len(g.cmds) != 0 ||
		!strings.Contains(g.last().Detail, "system/com.evil.d") || !exists(filepath.Join(g.dir, "Library/LaunchDaemons/com.evil.d.plist")) {
		t.Fatalf("dry-run daemon: %v %v %+v", err, g.cmds, g.last())
	}
}

func netEvent(g *rig, pid int32, dir, sip, dip string) *event.Event {
	return &event.Event{Name: event.NetworkConnect, Source: ESSource, Proc: g.proc(pid, "/private/tmp/implant"),
		Net: &event.Net{Proto: "tcp", Direction: dir, SrcIP: sip, DstIP: dip, DstPort: 443}}
}

func TestIsolateProcess(t *testing.T) {
	g := newRig(t, false, func(c *Config) {
		c.IsolationAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	g.run = func(bin string, args []string) ([]byte, error) {
		if bin == PfctlBin && len(args) == 1 && args[0] == "-E" {
			return []byte("pf enabled\nToken : 1234567\n"), nil
		}
		return nil, nil
	}
	// Peers seen earlier for the same process, plus noise that must never be blocked.
	for _, ip := range []string{"203.0.113.7", "127.0.0.1", "10.1.2.3", "fe80::1", "224.0.0.251", "1.2.3.4; pass all", "::ffff:198.51.100.9"} {
		g.r.Observe(netEvent(g, 7000, "outbound", "192.168.1.10", ip))
	}
	g.r.Observe(netEvent(g, 7000, "inbound", "198.51.100.20", "192.168.1.10")) // inbound: remote is the source
	g.r.Observe(netEvent(g, 7001, "outbound", "192.168.1.10", "192.0.2.99"))   // another process
	e := netEvent(g, 7000, "outbound", "192.168.1.10", "2001:db8::5")
	if err := g.r.IsolateProcess(e, TargetProcess, "rule-i", "rule I"); err != nil {
		t.Fatalf("isolate: %v %+v", err, g.logs)
	}
	want := []string{
		PfctlBin + " -a " + PFAnchor + " -f -",
		PfctlBin + " -E",
		PfctlBin + " -a " + PFAnchor + " -t " + PFTable + " -T add 198.51.100.9 198.51.100.20 203.0.113.7 2001:db8::5",
	}
	if !reflect.DeepEqual(g.pf()[:3], want) || g.stdins[0] != pfRules {
		t.Fatalf("pf commands = %q stdin %q", g.cmds, g.stdins)
	}
	for _, c := range g.cmds {
		if strings.Contains(c, "127.0.0.1") || strings.Contains(c, "10.1.2.3") || strings.Contains(c, "fe80") ||
			strings.Contains(c, "224.0.0.251") || strings.Contains(c, "pass") || strings.Contains(c, "192.0.2.99") || strings.Contains(c, "192.168.1.10") {
			t.Fatalf("blocked something it must not: %q", c)
		}
	}
	d := g.last()
	if d.Outcome != OutcomeIsolated || !strings.Contains(d.Detail, "whole host") || len(g.r.Isolations()) != 4 {
		t.Fatalf("decision %+v isolations %v", d, g.r.Isolations())
	}
	store := IsolationStore{Dir: g.r.cfg.StateDir}
	saved, err := store.Load()
	if err != nil || len(saved) != 4 || saved[0].Rule != "rule-i" {
		t.Fatalf("state = %+v %v", saved, err)
	}
	// The CLI releases one address; the sensor keeps that release.
	g.cmds = nil
	rel, err := ReleaseIsolation(store, g.r.cfg.Runner, "203.0.113.7")
	if err != nil || !reflect.DeepEqual(rel, []string{"203.0.113.7"}) || g.cmds[0] != PfctlBin+" -a "+PFAnchor+" -t "+PFTable+" -T delete 203.0.113.7" {
		t.Fatalf("release: %v %v %v", rel, err, g.cmds)
	}
	g.now = g.now.Add(time.Minute)
	g.r.Tick(g.now)
	if len(g.r.Isolations()) != 3 {
		t.Fatalf("CLI release not picked up: %v", g.r.Isolations())
	}
	if _, err := ReleaseIsolation(store, g.r.cfg.Runner, "1.2.3.4 -F all"); err == nil {
		t.Fatal("release accepted a non-address")
	}
	// Expiry after the TTL deletes the rest.
	g.cmds = nil
	g.now = g.now.Add(DefaultIsolationTTL)
	g.r.Tick(g.now)
	if len(g.r.Isolations()) != 0 || len(g.pf()) != 1 || !strings.Contains(g.pf()[0], "-T delete 198.51.100.9 198.51.100.20 2001:db8::5") {
		t.Fatalf("expiry: %v %v", g.r.Isolations(), g.cmds)
	}
	// Clean shutdown flushes the anchor and releases the pf token.
	g.cmds = nil
	if err := g.r.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.cmds, []string{PfctlBin + " -a " + PFAnchor + " -F all", PfctlBin + " -X 1234567"}) {
		t.Fatalf("close: %v", g.cmds)
	}
}

func TestIsolateRefusals(t *testing.T) {
	g := newRig(t, false, nil)
	// No peer at all.
	if err := g.r.IsolateProcess(&event.Event{Source: ESSource, Proc: g.proc(7100, "/private/tmp/x")}, TargetProcess, "r", "r"); !errors.Is(err, ErrNoPeers) {
		t.Fatalf("no peers: %v", err)
	}
	// Only loopback.
	if err := g.r.IsolateProcess(netEvent(g, 7101, "outbound", "127.0.0.1", "127.0.0.1"), TargetProcess, "r", "r"); !errors.Is(err, ErrNoPeers) {
		t.Fatalf("loopback: %v", err)
	}
	// Protected process (Apple platform binary) and unverified identity.
	pe := netEvent(g, 7102, "outbound", "192.168.1.10", "203.0.113.1")
	pe.Proc.IsPlatform = true
	if err := g.r.IsolateProcess(pe, TargetProcess, "r", "r"); !errors.Is(err, ErrProtected) {
		t.Fatalf("platform: %v", err)
	}
	ue := netEvent(g, 7103, "outbound", "192.168.1.10", "203.0.113.1")
	ue.Proc.Seeded = true
	if err := g.r.IsolateProcess(ue, TargetProcess, "r", "r"); !errors.Is(err, ErrUnknownProc) {
		t.Fatalf("seeded: %v", err)
	}
	// Target parent: unknown parent refused.
	oe := netEvent(g, 7104, "outbound", "192.168.1.10", "203.0.113.1")
	oe.Proc.PPID = 7000
	if err := g.r.IsolateProcess(oe, TargetParent, "r", "r"); !errors.Is(err, ErrUnknownProc) {
		t.Fatalf("unknown parent: %v", err)
	}
	if len(g.pf()) != 0 {
		t.Fatalf("pfctl ran on a refusal: %v", g.cmds)
	}
	// Dry-run: no pfctl (only the read-only gateway lookup runs).
	g = newRig(t, true, nil)
	if err := g.r.IsolateProcess(netEvent(g, 7105, "outbound", "192.168.1.10", "203.0.113.1"), TargetProcess, "r", "r"); err != nil ||
		len(g.pf()) != 0 || g.last().Outcome != OutcomeDryRun {
		t.Fatalf("dry-run: %v %v", err, g.cmds)
	}
	// The peer table stays bounded.
	g = newRig(t, false, nil)
	for i := 0; i < maxTrackedProcs+10; i++ {
		g.r.Observe(&event.Event{Name: event.NetworkConnect, Proc: &event.Proc{PID: int32(10000 + i), UniqueID: uint64(i + 1)},
			Net: &event.Net{Direction: "outbound", DstIP: "203.0.113.1"}})
	}
	for i := 0; i < maxPeersPerProc+10; i++ {
		g.r.Observe(&event.Event{Name: event.NetworkConnect, Proc: &event.Proc{PID: 9, UniqueID: 9},
			Net: &event.Net{Direction: "outbound", DstIP: netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String()}})
	}
	if len(g.r.peers) > maxTrackedProcs || len(g.r.peers["u9"].addrs) != maxPeersPerProc {
		t.Fatalf("peer table %d, peers of one process %d", len(g.r.peers), len(g.r.peers["u9"].addrs))
	}
}

func TestStartResponseFlushes(t *testing.T) {
	g := newRig(t, false, nil)
	_ = IsolationStore{Dir: g.r.cfg.StateDir}.Save([]Isolation{{Addr: "203.0.113.1"}})
	if err := g.r.StartResponse(); err != nil {
		t.Fatal(err)
	}
	isos, _ := IsolationStore{Dir: g.r.cfg.StateDir}.Load()
	if !reflect.DeepEqual(g.cmds, []string{PfctlBin + " -a " + PFAnchor + " -F all"}) || len(isos) != 0 {
		t.Fatalf("start: %v %v", g.cmds, isos)
	}
	g = newRig(t, true, nil)
	_ = g.r.StartResponse()
	if len(g.cmds) != 0 {
		t.Fatalf("dry-run start ran %v", g.cmds)
	}
}

func TestSuspend(t *testing.T) {
	g := newRig(t, false, nil)
	e := &event.Event{Source: ESSource, Proc: g.proc(8000, "/private/tmp/stealer")}
	if err := g.r.SuspendEvent(e, "rule-s", "s"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.signals, []string{"8000 SIGSTOP"}) || g.last().Outcome != OutcomeSuspended || g.last().Action != ActionSuspend {
		t.Fatalf("signals %v decision %+v", g.signals, g.last())
	}
	// Not yet time: still stopped.
	g.now = g.now.Add(DefaultSuspendFor - time.Second)
	g.r.Tick(g.now)
	if len(g.signals) != 1 {
		t.Fatalf("resumed early: %v", g.signals)
	}
	g.now = g.now.Add(time.Second)
	g.r.Tick(g.now)
	if !reflect.DeepEqual(g.signals, []string{"8000 SIGSTOP", "8000 SIGCONT"}) || g.last().Outcome != OutcomeResumed || len(g.r.Suspended()) != 0 {
		t.Fatalf("resume: %v %+v", g.signals, g.last())
	}
	// Suspend then kill: no resume.
	g.signals = nil
	e = &event.Event{Source: ESSource, Proc: g.proc(8001, "/private/tmp/stealer")}
	_ = g.r.SuspendEvent(e, "rule-s", "s")
	_ = g.r.KillEvent(e, "rule-s", "s")
	g.now = g.now.Add(time.Hour)
	g.r.Tick(g.now)
	if !reflect.DeepEqual(g.signals, []string{"8001 SIGSTOP", "8001 SIGKILL"}) {
		t.Fatalf("suspend+kill: %v", g.signals)
	}
	// pid reused before the resume: no SIGCONT to the new process.
	g.signals = nil
	e = &event.Event{Source: ESSource, Proc: g.proc(8002, "/private/tmp/stealer")}
	_ = g.r.SuspendEvent(e, "rule-s", "s")
	g.ids[8002] = Identity{CSKnown: true, StartTime: start.Add(time.Minute), Exe: "/x", UniqueID: 99, UniqueKnown: true}
	g.now = g.now.Add(time.Hour)
	g.r.Tick(g.now)
	if !reflect.DeepEqual(g.signals, []string{"8002 SIGSTOP"}) || g.last().Outcome != OutcomeResumeSkipped {
		t.Fatalf("reused pid: %v %+v", g.signals, g.last())
	}
	// Guard rails of kill: protected path, seeded, launchd parent.
	g.signals = nil
	if err := g.r.SuspendEvent(&event.Event{Proc: g.proc(8003, "/usr/libexec/x")}, "rule-s", "s"); !errors.Is(err, ErrProtected) {
		t.Fatalf("protected: %v", err)
	}
	se := &event.Event{Proc: g.proc(8004, "/private/tmp/x")}
	se.Proc.Seeded = true
	if err := g.r.SuspendEvent(se, "rule-s", "s"); !errors.Is(err, ErrUnknownProc) {
		t.Fatalf("seeded: %v", err)
	}
	pe := &event.Event{Source: ESSource, Proc: g.proc(8005, "/usr/bin/osascript")}
	pe.Proc.Parent = &event.Proc{PID: 1, Exe: "/sbin/launchd", Name: "launchd", IsPlatform: true}
	if err := g.r.SuspendParent(pe, "rule-s", "s"); !errors.Is(err, ErrProtected) {
		t.Fatalf("launchd parent: %v", err)
	}
	if len(g.signals) != 0 {
		t.Fatalf("signalled a protected process: %v", g.signals)
	}
	// Parent suspend then kill, as the osascript rule does.
	par := g.proc(8100, "/Volumes/Setup/Setup.app/Contents/MacOS/Setup")
	ce := &event.Event{Source: ESSource, Proc: g.proc(8101, "/usr/bin/osascript")}
	ce.Proc.PPID, ce.Proc.Parent = 8100, par
	ce.Proc.IsPlatform = true
	_ = g.r.SuspendParent(ce, "rule-o", "o")
	_ = g.r.KillParent(ce, "rule-o", "o")
	if !reflect.DeepEqual(g.signals, []string{"8100 SIGSTOP", "8100 SIGKILL"}) || len(g.r.Suspended()) != 0 {
		t.Fatalf("parent suspend+kill: %v %v", g.signals, g.r.Suspended())
	}
	// Close resumes whatever is still stopped.
	g.signals = nil
	_ = g.r.SuspendEvent(&event.Event{Source: ESSource, Proc: g.proc(8200, "/private/tmp/y")}, "rule-z", "z")
	_ = g.r.Close()
	if !reflect.DeepEqual(g.signals, []string{"8200 SIGSTOP", "8200 SIGCONT"}) {
		t.Fatalf("close: %v", g.signals)
	}
	// Dry-run: no signal, nothing pending.
	g = newRig(t, true, nil)
	_ = g.r.SuspendEvent(&event.Event{Source: ESSource, Proc: g.proc(8300, "/private/tmp/y")}, "rule-s", "s")
	if len(g.signals) != 0 || len(g.r.Suspended()) != 0 || g.last().Outcome != OutcomeDryRun {
		t.Fatalf("dry-run: %v", g.signals)
	}
}

func TestSuspendForBounded(t *testing.T) {
	g := newRig(t, false, func(c *Config) { c.SuspendFor = 24 * time.Hour })
	if g.r.cfg.SuspendFor != MaxSuspendFor {
		t.Fatalf("SuspendFor = %v", g.r.cfg.SuspendFor)
	}
}

func TestVaultMustBePrivate(t *testing.T) {
	g := newRig(t, false, nil)
	_ = os.Chmod(g.r.cfg.StateDir, 0o755)
	if err := os.Mkdir(g.r.cfg.VaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	p, e := g.file("v/x", "x", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err == nil || !exists(p) || !strings.Contains(g.last().Detail, "0700") {
		t.Fatalf("open vault accepted: %v %+v", err, g.last())
	}
	if _, err := (Vault{Dir: g.r.cfg.VaultDir, RequireRootOwned: true}).List(); err == nil && os.Geteuid() != 0 {
		t.Fatal("vault owned by the user accepted as root-owned")
	}
}

func TestDecisionStringWithAction(t *testing.T) {
	d := Decision{Action: ActionQuarantineFile, PID: 3, Path: "/tmp/\x1b[2Jx", Reason: "r", Outcome: OutcomeQuarantined}
	s := d.String()
	if strings.ContainsRune(s, 0x1b) || !strings.Contains(s, "action=quarantine_file") || !strings.Contains(s, "path=") {
		t.Fatalf("String = %q", s)
	}
	if k := (Decision{PID: 3, Outcome: OutcomeKilled}).String(); strings.Contains(k, "action=") {
		t.Fatalf("kill line changed: %q", k)
	}
}

// TestSuspendThenKillOneUnit: a kill that follows this responder's suspend
// of the same process completes one response and spends one budget unit.
func TestSuspendThenKillOneUnit(t *testing.T) {
	g := newRig(t, false, nil)
	for i := 0; i < DefaultMaxPerRulePerMinute; i++ {
		e := &event.Event{Source: ESSource, Proc: g.proc(int32(9000+i), "/private/tmp/s")}
		if err := g.r.SuspendEvent(e, "rule-o", "o"); err != nil {
			t.Fatalf("%d suspend: %v", i, err)
		}
		if err := g.r.KillEvent(e, "rule-o", "o"); err != nil {
			t.Fatalf("%d kill after suspend: %v", i, err)
		}
	}
	if err := g.r.SuspendEvent(&event.Event{Source: ESSource, Proc: g.proc(9100, "/private/tmp/s")}, "rule-o", "o"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("11th pair: %v", err)
	}
}

func TestIsolateNeverBlocksResolvers(t *testing.T) {
	g := newRig(t, false, func(c *Config) {
		c.Resolvers = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.1")} }
	})
	if err := g.r.IsolateProcess(netEvent(g, 7200, "outbound", "192.168.1.10", "192.168.1.1"), TargetProcess, "r", "r"); !errors.Is(err, ErrNoPeers) ||
		!strings.Contains(g.last().Detail, "DNS resolver") || len(g.pf()) != 0 {
		t.Fatalf("resolver: %v %+v %v", err, g.last(), g.cmds)
	}
}

// TestIsolationStateReconcile: an address released by the CLI is dropped
// and deleted from pf again (idempotent), and a state file that cannot be
// parsed is never taken as a release.
func TestIsolationStateReconcile(t *testing.T) {
	g := newRig(t, false, nil)
	_ = g.r.IsolateProcess(netEvent(g, 7300, "outbound", "192.168.1.10", "203.0.113.30"), TargetProcess, "r", "r")
	_ = g.r.IsolateProcess(netEvent(g, 7301, "outbound", "192.168.1.10", "203.0.113.31"), TargetProcess, "r2", "r2")
	state := filepath.Join(g.r.cfg.StateDir, isolationState)
	// Corrupt file: nothing is released.
	_ = os.WriteFile(state, []byte("{not json"), 0o600)
	g.r.Tick(g.now)
	if len(g.r.Isolations()) != 2 {
		t.Fatalf("corrupt state released: %v", g.r.Isolations())
	}
	// A rewrite without one address (the CLI's release, or a lost update).
	_ = IsolationStore{Dir: g.r.cfg.StateDir}.Save([]Isolation{{Addr: "203.0.113.31"}})
	g.cmds = nil
	g.r.Tick(g.now)
	if len(g.r.Isolations()) != 1 || len(g.cmds) != 1 || !strings.HasSuffix(g.cmds[0], "-T delete 203.0.113.30") {
		t.Fatalf("reconcile: %v %v", g.r.Isolations(), g.cmds)
	}
}

func TestSidecarNeverOverwritten(t *testing.T) {
	g := newRig(t, false, nil)
	_, e := g.file("s/one", "same", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err != nil {
		t.Fatal(err)
	}
	items, _ := Vault{Dir: g.r.cfg.VaultDir}.List()
	side := filepath.Join(g.r.cfg.VaultDir, items[0].ID+".json")
	_ = os.WriteFile(side, []byte("{broken"), 0o600)
	p, e := g.file("s/two", "same", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); err == nil || !exists(p) {
		t.Fatalf("overwrote an unreadable sidecar: %v", err)
	}
	if b, _ := os.ReadFile(side); string(b) != "{broken" {
		t.Fatalf("sidecar changed: %q", b)
	}
}

func TestWorkerQueue(t *testing.T) {
	g := newRig(t, false, nil)
	g.r.StartWorker(1)
	block := make(chan struct{})
	ran := 0
	if !g.r.Go(func() { <-block; ran++ }) {
		t.Fatal("first job refused")
	}
	// The worker may not have picked the first job yet: fill until refused.
	accepted := 0
	for i := 0; i < 3; i++ {
		if g.r.Go(func() { ran++ }) {
			accepted++
		}
	}
	if accepted > 1 {
		t.Fatalf("queue of 1 accepted %d more jobs", accepted)
	}
	close(block)
	g.r.Wait()
	if ran != 1+accepted {
		t.Fatalf("ran %d", ran)
	}
	g.r.StopWorker()
	if g.r.Go(func() {}) {
		t.Fatal("stopped worker accepted a job")
	}
}

// TestPlatformFlagMustBeKnown: an event that is neither from eslogger nor
// carries a process-table identity (kernel unique id) cannot prove the
// process is not an Apple platform binary: process and file actions refuse.
func TestPlatformFlagMustBeKnown(t *testing.T) {
	g := newRig(t, false, nil)
	e := netEvent(g, 7400, "outbound", "192.168.1.10", "203.0.113.40")
	e.Source, e.Proc.UniqueID = "netpoll", 0
	if err := g.r.IsolateProcess(e, TargetProcess, "r", "r"); !errors.Is(err, ErrUnknownProc) || len(g.cmds) != 0 {
		t.Fatalf("isolate: %v %v", err, g.cmds)
	}
	// From the socket poller with a process-table identity: accepted.
	e = netEvent(g, 7401, "outbound", "192.168.1.10", "203.0.113.41")
	e.Source = "netpoll"
	if err := g.r.IsolateProcess(e, TargetProcess, "r", "r"); err != nil {
		t.Fatalf("isolate with table identity: %v", err)
	}
	p, fe := g.file("pf/x", "x", 0o644)
	fe.Source, fe.Proc.UniqueID = "fixture", 0
	if err := g.r.QuarantineFile(fe, TargetFile, "r", "r"); !errors.Is(err, ErrUnknownProc) || !exists(p) {
		t.Fatalf("quarantine: %v", err)
	}
}

// TestTickNeverWaitsForSlowAction: Tick runs on the event loop; while a
// slow action holds actMu it resumes suspended processes and returns.
func TestTickNeverWaitsForSlowAction(t *testing.T) {
	g := newRig(t, false, nil)
	_ = g.r.SuspendEvent(&event.Event{Source: ESSource, Proc: g.proc(8400, "/private/tmp/s")}, "r", "r")
	g.r.actMu.Lock()
	done := make(chan struct{})
	go func() {
		g.r.Tick(g.now.Add(time.Hour))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Tick waited for the slow-action lock")
	}
	g.r.actMu.Unlock()
	if len(g.r.Suspended()) != 0 {
		t.Fatal("suspended process not resumed while a slow action ran")
	}
}

// TestCloseResumesFirstAndDropsQueue: at shutdown suspended processes are
// resumed before waiting for the running slow action, and queued actions
// that have not started are dropped.
func TestCloseResumesFirstAndDropsQueue(t *testing.T) {
	g := newRig(t, false, nil)
	g.r.StartWorker(4)
	_ = g.r.SuspendEvent(&event.Event{Source: ESSource, Proc: g.proc(8500, "/private/tmp/s")}, "r", "r")
	block, started := make(chan struct{}), make(chan struct{})
	ran := false
	g.r.Go(func() { close(started); <-block })
	<-started
	g.r.Go(func() { ran = true })
	closed := make(chan struct{})
	go func() { _ = g.r.Close(); close(closed) }()
	deadline := time.After(5 * time.Second)
	for len(g.r.Suspended()) != 0 {
		select {
		case <-deadline:
			t.Fatal("not resumed while the worker was busy")
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(block)
	<-closed
	if ran || g.r.Stats()["worker dropped at shutdown"] != 1 {
		t.Fatalf("queued action ran=%v stats=%v", ran, g.r.Stats())
	}
}

// TestIsolateNeverBlockSet: the default gateways (from /sbin/route) and
// Apple's 17.0.0.0/8 are never blocked; private RFC 1918 peers can be (owner
// decision 9 Nov 2026); a gateway lookup that cannot run refuses.
func TestIsolateNeverBlockSet(t *testing.T) {
	// Resolvers are pinned empty: the host's real /etc/resolv.conf may list
	// 192.168.1.1, which would report it as a resolver instead of a gateway.
	g := newRig(t, false, func(c *Config) {
		c.Gateways = nil
		c.Resolvers = func() []netip.Addr { return nil }
	})
	g.r.cfg.Gateways = routeGateways(g.r.cfg.Runner)
	g.run = func(bin string, args []string) ([]byte, error) {
		if bin == RouteBin {
			if args[2] == "-inet6" {
				return []byte("   route to: default\n    gateway: fe80::1%en0\n  interface: en0\n"), nil
			}
			return []byte("   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n"), nil
		}
		return nil, nil
	}
	for _, ip := range []string{"192.168.1.1", "17.253.144.10", "10.20.30.40"} {
		g.r.Observe(netEvent(g, 7500, "outbound", "192.168.1.10", ip))
	}
	if err := g.r.IsolateProcess(netEvent(g, 7500, "outbound", "192.168.1.10", "10.20.30.40"), TargetProcess, "r", "r"); err != nil {
		t.Fatalf("isolate: %v %+v", err, g.last())
	}
	d := g.last().Detail
	add := g.pf()[2]
	if !strings.HasSuffix(add, "-T add 10.20.30.40") || !strings.Contains(d, "192.168.1.1 (a default gateway") || !strings.Contains(d, "17.253.144.10 (Apple's network 17.0.0.0/8)") {
		t.Fatalf("add %q detail %q", add, d)
	}
	if got := parseRouteGateway([]byte("    gateway: link#14\n")); got != nil {
		t.Fatalf("interface gateway parsed as %v", got)
	}
	// No default route (route exits non-zero): not an error.
	g2 := newRig(t, false, nil)
	g2.r.cfg.Gateways = routeGateways(g2.r.cfg.Runner)
	g2.run = func(bin string, args []string) ([]byte, error) {
		if bin == RouteBin {
			return nil, &ExitError{Code: 1, Output: "route: writing to routing socket: not in table"}
		}
		return nil, nil
	}
	if err := g2.r.IsolateProcess(netEvent(g2, 7501, "outbound", "192.168.1.10", "203.0.113.50"), TargetProcess, "r", "r"); err != nil {
		t.Fatalf("no default route: %v", err)
	}
	// route times out or crashes (ExitError -1): refused, nothing blocked.
	g4 := newRig(t, false, nil)
	g4.r.cfg.Gateways = routeGateways(g4.r.cfg.Runner)
	g4.run = func(bin string, args []string) ([]byte, error) {
		if bin == RouteBin {
			return nil, &ExitError{Code: -1}
		}
		return nil, nil
	}
	if err := g4.r.IsolateProcess(netEvent(g4, 7503, "outbound", "192.168.1.10", "203.0.113.52"), TargetProcess, "r", "r"); !errors.Is(err, ErrNoPeers) || len(g4.pf()) != 0 {
		t.Fatalf("route timeout: %v %+v", err, g4.last())
	}
	// route cannot run: refused, nothing blocked.
	g3 := newRig(t, false, nil)
	g3.r.cfg.Gateways = routeGateways(g3.r.cfg.Runner)
	g3.run = func(bin string, args []string) ([]byte, error) {
		if bin == RouteBin {
			return nil, errors.New("exec: permission denied")
		}
		return nil, nil
	}
	if err := g3.r.IsolateProcess(netEvent(g3, 7502, "outbound", "192.168.1.10", "203.0.113.51"), TargetProcess, "r", "r"); !errors.Is(err, ErrNoPeers) || len(g3.pf()) != 0 ||
		!strings.Contains(g3.last().Detail, "default gateway") {
		t.Fatalf("route fails: %v %+v", err, g3.last())
	}
}

// npKernel is a fake netpoll kernel: fixed processes and sockets.
type npKernel struct {
	idents map[int32]netpoll.Ident
	socks  map[int32][]netpoll.Socket
}

func (k *npKernel) PIDs() ([]int32, error) {
	var out []int32
	for p := range k.socks {
		out = append(out, p)
	}
	return out, nil
}

func (k *npKernel) Ident(pid int32) (netpoll.Ident, error) {
	id, ok := k.idents[pid]
	if !ok {
		return netpoll.Ident{}, errors.New("no such process")
	}
	return id, nil
}

func (k *npKernel) Sockets(pid int32, _ netpoll.Window) (netpoll.SocketList, error) {
	s := k.socks[pid]
	return netpoll.SocketList{Socks: s, Calls: len(s), SocketFDs: len(s)}, nil
}

// TestIsolateWithNetpollEvents runs the real S2 socket poller (pkg/source/
// netpoll) on a fake kernel and feeds its NetworkConnect / NetworkAccept
// events to Observe and isolate_process (contract check at the S1/S2
// merge): a process the table knows is isolated from its outbound peer and
// from the remote side of an inbound connection (src, never this Mac's own
// dst); a process the table does not know gets an unverified kernel
// identity (netpoll sets its unique id itself but marks it Seeded) and is
// refused.
func TestIsolateWithNetpollEvents(t *testing.T) {
	g := newRig(t, false, nil)
	t0 := start
	table := map[int32]event.Proc{
		1:   {PID: 1, Exe: "/sbin/launchd", Name: "launchd", IsPlatform: true, UniqueID: 1, PIDVersion: 1, StartTime: t0.Add(-time.Hour)},
		700: {PID: 700, PPID: 1, Exe: "/private/tmp/implant", Name: "implant", UniqueID: 7000, PIDVersion: 7, StartTime: t0, UID: 501, EUID: 501},
	}
	k := &npKernel{
		idents: map[int32]netpoll.Ident{
			700: {PID: 700, PPID: 1, PIDVersion: 7, UniqueID: 7000, Exe: "/private/tmp/implant", StartTime: t0},
			800: {PID: 800, PPID: 1, PIDVersion: 8, UniqueID: 8000, Exe: "/private/tmp/unknown", StartTime: t0},
		},
		socks: map[int32][]netpoll.Socket{
			700: {
				{FD: 3, Proto: "tcp", Local: netip.MustParseAddrPort("192.168.1.10:50001"), Remote: netip.MustParseAddrPort("203.0.113.60:4444"), TCPState: netpoll.TCPEstablished, Gen: 1},
				{FD: 4, Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:7777"), TCPState: netpoll.TCPListen, Gen: 2},
				{FD: 5, Proto: "tcp", Local: netip.MustParseAddrPort("192.168.1.10:7777"), Remote: netip.MustParseAddrPort("198.51.100.70:61000"), TCPState: netpoll.TCPEstablished, Gen: 3},
			},
			800: {{FD: 3, Proto: "tcp", Local: netip.MustParseAddrPort("192.168.1.10:50002"), Remote: netip.MustParseAddrPort("203.0.113.61:443"), TCPState: netpoll.TCPEstablished, Gen: 4}},
		},
	}
	np := netpoll.New(netpoll.Config{Kernel: k, Interval: time.Hour, Now: func() time.Time { return g.now },
		Lookup: func(pid int32) (event.Proc, bool) { p, ok := table[pid]; return p, ok }})
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan *event.Event, 64)
	done := make(chan error, 1)
	go func() { done <- np.Run(ctx, nil, out) }()
	var evs []*event.Event
	deadline := time.After(5 * time.Second)
	for len(evs) < 4 { // 2 connects/accepts of 700, its listener, and 800's connect
		select {
		case e := <-out:
			evs = append(evs, e)
		case <-deadline:
			t.Fatalf("netpoll produced %d events", len(evs))
		}
	}
	cancel()
	<-done
	var known, unknown *event.Event
	for _, e := range evs {
		if e.Source != netpoll.Name {
			t.Fatalf("source %q", e.Source)
		}
		g.r.Observe(e)
		switch {
		case e.Proc.PID == 700 && e.Name == event.NetworkConnect:
			known = e
		case e.Proc.PID == 800:
			unknown = e
		}
	}
	if known == nil || unknown == nil {
		t.Fatalf("events: %+v", evs)
	}
	if !unknown.Proc.Seeded || unknown.Args[ps.ArgIdentity] != ps.Unverified || unknown.Proc.UniqueID == 0 {
		t.Fatalf("unknown process identity: %+v %v", unknown.Proc, unknown.Args)
	}
	if known.Proc.Seeded || known.Proc.UniqueID != 7000 || known.Proc.Parent == nil || known.Proc.Parent.PID != 1 {
		t.Fatalf("known process identity: %+v", known.Proc)
	}
	if err := g.r.IsolateProcess(known, TargetProcess, "rule-n", "n"); err != nil {
		t.Fatalf("isolate known: %v %+v", err, g.last())
	}
	add := g.pf()[2]
	if add != PfctlBin+" -a "+PFAnchor+" -t "+PFTable+" -T add 198.51.100.70 203.0.113.60" {
		t.Fatalf("add = %q", add)
	}
	g.cmds = nil
	if err := g.r.IsolateProcess(unknown, TargetProcess, "rule-n", "n"); !errors.Is(err, ErrUnknownProc) || len(g.pf()) != 0 {
		t.Fatalf("isolate unknown: %v %v", err, g.cmds)
	}
}

// TestNeverBlockRecheck: an isolated address that later becomes the
// default gateway (the Mac joined another network) is released at the next
// minute's check.
func TestNeverBlockRecheck(t *testing.T) {
	g := newRig(t, false, nil)
	gw := ""
	g.r.cfg.Gateways = func() ([]netip.Addr, error) {
		if gw == "" {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr(gw)}, nil
	}
	if err := g.r.IsolateProcess(netEvent(g, 7600, "outbound", "192.168.1.10", "192.168.0.1"), TargetProcess, "r", "r"); err != nil {
		t.Fatal(err)
	}
	gw = "192.168.0.1"
	g.cmds = nil
	g.now = g.now.Add(2 * time.Minute)
	g.r.Tick(g.now)
	if len(g.r.Isolations()) != 0 || len(g.pf()) != 1 || !strings.HasSuffix(g.pf()[0], "-T delete 192.168.0.1") ||
		!strings.Contains(g.last().Detail, "default gateway") {
		t.Fatalf("recheck: %v %v %+v", g.r.Isolations(), g.cmds, g.last())
	}
	// Apple's IPv6 network is never blocked either.
	if err := g.r.IsolateProcess(netEvent(g, 7601, "outbound", "192.168.1.10", "2620:149:a44::1"), TargetProcess, "r", "r"); !errors.Is(err, ErrNoPeers) {
		t.Fatalf("apple v6: %v", err)
	}
}

// TestUserWritableBundlesNotCodesigned: bundles in temp and home folders
// are user copies; their signature is not checked (no worker stall), while
// a bundle in /Applications still is.
func TestUserWritableBundlesNotCodesigned(t *testing.T) {
	g := newRig(t, false, nil)
	var checked []string
	g.r.cfg.AppleSigned = func(b string) (bool, error) { checked = append(checked, b); return false, nil }
	if why := g.r.checkBundles("/private/var/folders/x/T/a.app/b.app/c.app/f"); why != "" || len(checked) != 0 {
		t.Fatalf("temp bundles: %q %v", why, checked)
	}
	if why := g.r.checkBundles("/Applications/Tool.app/Contents/MacOS/tool"); why != "" || len(checked) != 1 {
		t.Fatalf("/Applications: %q %v", why, checked)
	}
}

// TestRetryAfterBudget (security re-check N2): ten decoy plists spend the
// per-rule budget, the real eleventh is refused, and a retry handles it
// once the budget frees; a file that changed meanwhile is dropped from the
// retry list; dry-run never retries.
func TestRetryAfterBudget(t *testing.T) {
	g := newRig(t, false, nil)
	g.r.launchRoot = g.dir
	g.run = func(bin string, args []string) ([]byte, error) { return nil, &ExitError{Code: 113} }
	for i := 0; i < DefaultMaxPerRulePerMinute; i++ {
		_, e := g.file("Users/alice/Library/LaunchAgents/decoy"+strconv.Itoa(i)+".plist", plist("com.decoy.a"+strconv.Itoa(i)), 0o644)
		if err := g.r.RemovePersistence(e, "rule-p", "p"); err != nil {
			t.Fatalf("decoy %d: %v", i, err)
		}
	}
	real, e := g.file("Users/alice/Library/LaunchAgents/com.real.agent.plist", plist("com.real.agent"), 0o644)
	if err := g.r.RemovePersistence(e, "rule-p", "p"); !errors.Is(err, ErrRateLimited) || !exists(real) || g.r.Retries() != 1 {
		t.Fatalf("real plist: %v retries=%d", err, g.r.Retries())
	}
	// Inside the minute: the retry is refused again and stays listed.
	g.now = g.now.Add(retryEvery)
	g.r.Tick(g.now)
	if !exists(real) || g.r.Retries() != 1 {
		t.Fatalf("early retry: retries=%d", g.r.Retries())
	}
	// After the minute the budget is free again: the retry removes it.
	g.now = g.now.Add(time.Minute)
	g.r.Tick(g.now)
	if exists(real) || g.r.Retries() != 0 || g.r.Stats()["retry succeeded"] != 1 {
		t.Fatalf("retry: exists=%v retries=%d stats=%v", exists(real), g.r.Retries(), g.r.Stats())
	}
	// A file replaced before its retry is refused and dropped.
	g2 := newRig(t, false, func(c *Config) { c.MaxPerRulePerMinute = 1 })
	_, e1 := g2.file("q/one", "1", 0o644)
	_ = g2.r.QuarantineFile(e1, TargetFile, "r", "r")
	p2, e2 := g2.file("q/two", "2", 0o644)
	if err := g2.r.QuarantineFile(e2, TargetFile, "r", "r"); !errors.Is(err, ErrRateLimited) || g2.r.Retries() != 1 {
		t.Fatalf("second: %v", err)
	}
	_ = os.Remove(p2)
	_ = os.WriteFile(p2, []byte("swapped"), 0o644)
	g2.now = g2.now.Add(2 * time.Minute)
	g2.r.Tick(g2.now)
	if !exists(p2) || g2.r.Retries() != 0 || g2.last().Outcome != OutcomeFileCheck {
		t.Fatalf("swapped file: retries=%d %+v", g2.r.Retries(), g2.last())
	}
	// Dry-run: nothing is listed for retry.
	g3 := newRig(t, true, func(c *Config) { c.MaxPerRulePerMinute = 1 })
	_, a := g3.file("d/a", "a", 0o644)
	_, b := g3.file("d/b", "b", 0o644)
	_ = g3.r.QuarantineFile(a, TargetFile, "r", "r")
	if err := g3.r.QuarantineFile(b, TargetFile, "r", "r"); !errors.Is(err, ErrRateLimited) || g3.r.Retries() != 0 {
		t.Fatalf("dry-run retry: %v %d", err, g3.r.Retries())
	}
}

func TestRetryAbandoned(t *testing.T) {
	g := newRig(t, false, func(c *Config) { c.MaxPerRulePerMinute = 1 })
	_, a := g.file("x/a", "a", 0o644)
	p, b := g.file("x/b", "b", 0o644)
	_ = g.r.QuarantineFile(a, TargetFile, "r", "r")
	_ = g.r.QuarantineFile(b, TargetFile, "r", "r")
	g.r.mu.Lock()
	for _, en := range g.r.retries {
		en.first = g.now.Add(-retryWindow - time.Second)
	}
	g.r.mu.Unlock()
	g.r.Tick(g.now)
	if g.r.Retries() != 0 || !exists(p) || g.last().Outcome != "retry-abandoned" {
		t.Fatalf("abandon: %d %+v", g.r.Retries(), g.last())
	}
}

// TestRetryListFullEvictsSameRule (security check R1): decoys filling the
// retry list do not push out the real action: the oldest entry of the same
// rule makes room and response_rate_limited is raised.
func TestRetryListFullEvictsSameRule(t *testing.T) {
	g := newRig(t, false, func(c *Config) { c.MaxPerRulePerMinute = 1 })
	_, first := g.file("f/first", "x", 0o644)
	_ = g.r.QuarantineFile(first, TargetFile, "r", "r")
	for i := 0; i < maxRetries; i++ {
		_, e := g.file("f/decoy"+strconv.Itoa(i), strconv.Itoa(i), 0o644)
		_ = g.r.QuarantineFile(e, TargetFile, "r", "r")
	}
	real, e := g.file("f/real", "real", 0o644)
	if err := g.r.QuarantineFile(e, TargetFile, "r", "r"); !errors.Is(err, ErrRateLimited) || g.r.Retries() != maxRetries ||
		g.r.Stats()["retry evicted"] != 1 || !strings.Contains(g.degr[len(g.degr)-1], "retry list full") {
		t.Fatalf("full list: %v retries=%d stats=%v degr=%v", err, g.r.Retries(), g.r.Stats(), g.degr)
	}
	key := fileRetryKey(ActionQuarantineFile, "r", e, TargetFile)
	g.r.mu.Lock()
	_, listed := g.r.retries[key]
	g.r.mu.Unlock()
	if !listed || !exists(real) {
		t.Fatal("real action not listed for retry")
	}
}

// TestRetryNotQueuedTwice (security check R2): an entry already handed to
// the worker is not handed again while it waits, and retries leave half the
// worker queue to fresh actions; Defer lists an action the full queue
// refused.
func TestRetryNotQueuedTwice(t *testing.T) {
	g := newRig(t, false, func(c *Config) { c.MaxPerRulePerMinute = 1 })
	g.r.StartWorker(4)
	block, started := make(chan struct{}), make(chan struct{})
	g.r.Go(func() { close(started); <-block })
	<-started
	_, a := g.file("n/a", "a", 0o644)
	_, b := g.file("n/b", "b", 0o644)
	_ = g.r.QuarantineFile(a, TargetFile, "r", "r")
	_ = g.r.QuarantineFile(b, TargetFile, "r", "r")
	for i := 0; i < 6; i++ {
		g.now = g.now.Add(retryEvery)
		g.r.Tick(g.now)
	}
	if n := len(g.r.work.Load().ch); n != 1 {
		t.Fatalf("queued %d copies of one retry", n)
	}
	ran := 0
	g.r.Defer("r2", "deferred action", func() { ran++ })
	if g.r.Retries() != 2 {
		t.Fatalf("retries = %d", g.r.Retries())
	}
	close(block)
	g.r.Wait()
	g.now = g.now.Add(time.Minute)
	g.r.Tick(g.now)
	g.r.Wait()
	if ran != 1 || g.r.Retries() != 0 {
		t.Fatalf("deferred ran %d, retries %d", ran, g.r.Retries())
	}
	g.r.StopWorker()
}
