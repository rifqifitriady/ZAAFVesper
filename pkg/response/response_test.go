package response

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type harness struct {
	now    time.Time
	killed []int
	logs   []Decision
	ids    map[int32]Identity // what the "kernel" reports now
	// uniqNow overrides the unique id the kernel reports for a pid;
	// uniqUnreadable makes it unreadable.
	uniqNow        map[int32]uint64
	uniqUnreadable map[int32]bool
	r              *Responder
}

func newHarness(dry bool, killErr error) *harness {
	h := &harness{now: start.Add(time.Hour), ids: map[int32]Identity{}, uniqNow: map[int32]uint64{}, uniqUnreadable: map[int32]bool{}}
	h.r = New(Config{
		DryRun: dry,
		Now:    func() time.Time { return h.now },
		Log:    func(d Decision) { h.logs = append(h.logs, d) },
		KillFunc: func(pid int, sig syscall.Signal) error {
			if sig != syscall.SIGKILL {
				panic("unexpected signal")
			}
			if killErr != nil {
				return killErr
			}
			h.killed = append(h.killed, pid)
			return nil
		},
		Identify: func(pid int32) (Identity, error) {
			id, ok := h.ids[pid]
			if !ok {
				return Identity{}, syscall.ESRCH
			}
			// The kernel unique id: the process's own unless a test
			// overrides it or makes it unreadable.
			if !h.uniqUnreadable[pid] && id.UniqueID == 0 {
				id.UniqueID, id.UniqueKnown = uniq(pid), true
			}
			if u, ok := h.uniqNow[pid]; ok {
				id.UniqueID = u
			}
			return id, nil
		},
		ProtectPIDs: []int32{777},
	})
	return h
}

// proc returns a killable process and registers the matching kernel identity.
func (h *harness) proc(pid int32, exe string) *event.Proc {
	h.ids[pid] = Identity{CSKnown: true, StartTime: start, Exe: exe}
	return &event.Proc{PID: pid, Exe: exe, Name: filepath.Base(exe), StartTime: start, UniqueID: uniq(pid)}
}

// uniq is the test kernel's unique id of the process with this pid.
func uniq(pid int32) uint64 { return uint64(pid) + 1_000_000 }

func TestGuardRails(t *testing.T) {
	type tc struct {
		name string
		p    func(h *harness) *event.Proc
		err  error
	}
	cases := []tc{
		{"pid 0", func(h *harness) *event.Proc { return h.proc(0, "/tmp/x") }, ErrProtected},
		{"pid 1", func(h *harness) *event.Proc { return h.proc(1, "/tmp/x") }, ErrProtected},
		{"negative", func(h *harness) *event.Proc { return h.proc(-5, "/tmp/x") }, ErrProtected},
		{"own pid", func(h *harness) *event.Proc { return h.proc(int32(os.Getpid()), "/tmp/x") }, ErrProtected},
		{"own ppid", func(h *harness) *event.Proc { return h.proc(int32(os.Getppid()), "/tmp/x") }, ErrProtected},
		{"configured pid", func(h *harness) *event.Proc { return h.proc(777, "/tmp/x") }, ErrProtected},
		{"platform binary anywhere", func(h *harness) *event.Proc {
			p := h.proc(60, "/usr/bin/osascript")
			p.IsPlatform = true
			return p
		}, ErrProtected},
		{"kernel_task", func(h *harness) *event.Proc { p := h.proc(50, "/x"); p.Name = "kernel_task"; return p }, ErrProtected},
		{"WindowServer by exe base", func(h *harness) *event.Proc { return h.proc(51, "/opt/WindowServer") }, ErrProtected},
		{"loginwindow", func(h *harness) *event.Proc { p := h.proc(52, "/x"); p.Name = "loginwindow"; return p }, ErrProtected},
		{"eslogger", func(h *harness) *event.Proc { return h.proc(53, "/usr/bin/eslogger") }, ErrProtected},
		{"/System", func(h *harness) *event.Proc {
			return h.proc(54, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")
		}, ErrProtected},
		{"/usr/libexec", func(h *harness) *event.Proc { return h.proc(55, "/usr/libexec/sshd-keygen-wrapper") }, ErrProtected},
		{"/sbin", func(h *harness) *event.Proc { return h.proc(56, "/sbin/mount") }, ErrProtected},
		{"/usr/sbin", func(h *harness) *event.Proc { return h.proc(57, "/usr/sbin/sshd") }, ErrProtected},
		{"no exe", func(h *harness) *event.Proc { return &event.Proc{PID: 58, StartTime: start} }, ErrUnknownProc},
		{"no start time", func(h *harness) *event.Proc { p := h.proc(59, "/tmp/p"); p.StartTime = time.Time{}; return p }, ErrUnknownProc},
		{"process gone", func(h *harness) *event.Proc { p := h.proc(61, "/tmp/p"); delete(h.ids, 61); return p }, ErrUnknownProc},
		{"pid reused (start time)", func(h *harness) *event.Proc {
			p := h.proc(62, "/tmp/p")
			h.ids[62] = Identity{CSKnown: true, StartTime: start.Add(5 * time.Second), Exe: "/tmp/p"}
			return p
		}, ErrMismatch},
		{"start time within tolerance", func(h *harness) *event.Proc {
			p := h.proc(63, "/tmp/p")
			h.ids[63] = Identity{CSKnown: true, StartTime: start.Add(900 * time.Microsecond), Exe: "/tmp/p"}
			return p
		}, nil},
		{"kernel unique id differs (another process)", func(h *harness) *event.Proc {
			p := h.proc(80, "/tmp/p")
			h.uniqNow[80] = uniq(80) + 1
			return p
		}, ErrMismatch},
		{"kernel unique id not recorded", func(h *harness) *event.Proc {
			p := h.proc(81, "/tmp/p")
			p.UniqueID = 0
			return p
		}, ErrUnknownProc},
		{"kernel unique id unreadable", func(h *harness) *event.Proc {
			p := h.proc(82, "/tmp/p")
			h.uniqUnreadable[82] = true
			return p
		}, ErrUnknownProc},
		{"start time 2 ms off (pid reused)", func(h *harness) *event.Proc {
			p := h.proc(72, "/tmp/p")
			h.ids[72] = Identity{CSKnown: true, StartTime: start.Add(2 * time.Millisecond), Exe: "/tmp/p"}
			return p
		}, ErrMismatch},
		{"other path now (renamed): killed, noted", func(h *harness) *event.Proc {
			p := h.proc(64, "/tmp/p")
			h.ids[64] = Identity{CSKnown: true, StartTime: start, Exe: "/Applications/Other.app/Contents/MacOS/Other"}
			return p
		}, nil},
		{"platform current image", func(h *harness) *event.Proc {
			p := h.proc(73, "/tmp/p")
			h.ids[73] = Identity{CSKnown: true, CSFlags: csPlatformBinary | 1, StartTime: start, Exe: "/tmp/p"}
			return p
		}, ErrProtected},
		{"code-signing status unreadable", func(h *harness) *event.Proc {
			p := h.proc(74, "/tmp/p")
			h.ids[74] = Identity{StartTime: start, Exe: "/tmp/p"}
			return p
		}, ErrUnknownProc},
		{"path unreadable (not unlinked)", func(h *harness) *event.Proc {
			p := h.proc(75, "/tmp/p")
			h.ids[75] = Identity{CSKnown: true, StartTime: start, ExeErr: syscall.EPERM}
			return p
		}, ErrUnknownProc},
		{"unlinked non-platform image", func(h *harness) *event.Proc {
			p := h.proc(76, "/tmp/p")
			p.ExeDev, p.ExeIno = 1, 2
			h.ids[76] = Identity{CSKnown: true, StartTime: start, ExeErr: ErrExeUnlinked}
			return p
		}, nil},
		{"unlinked platform image", func(h *harness) *event.Proc {
			p := h.proc(77, "/tmp/p")
			h.ids[77] = Identity{CSKnown: true, CSFlags: csPlatformBinary, StartTime: start, ExeErr: ErrExeUnlinked}
			return p
		}, ErrProtected},
		{"team id without signing category", func(h *harness) *event.Proc {
			p := h.proc(78, "/tmp/p")
			p.TeamID = "ABCDE12345"
			return p
		}, ErrUnknownProc},
		{"team id with signing category", func(h *harness) *event.Proc {
			p := h.proc(79, "/tmp/p")
			p.TeamID, p.CSCategory = "ABCDE12345", event.CSLocalSigning
			return p
		}, nil},
		{"exec into protected path", func(h *harness) *event.Proc {
			p := h.proc(65, "/tmp/sshd")
			h.ids[65] = Identity{CSKnown: true, StartTime: start, Exe: "/usr/sbin/sshd"}
			return p
		}, ErrProtected},
		{"same base name, other directory", func(h *harness) *event.Proc {
			p := h.proc(66, "/Users/a/payload")
			h.ids[66] = Identity{CSKnown: true, StartTime: start, Exe: "/tmp/payload"}
			return p
		}, nil},
		{"file identity matches", func(h *harness) *event.Proc {
			p := h.proc(68, "/tmp/payload")
			p.ExeDev, p.ExeIno = 16777232, 99
			h.ids[68] = Identity{CSKnown: true, StartTime: start, Exe: "/tmp/payload", Dev: 16777232, Ino: 99, HasFileID: true}
			return p
		}, nil},
		{"file replaced at the path (inode): killed, noted", func(h *harness) *event.Proc {
			p := h.proc(69, "/tmp/payload")
			p.ExeDev, p.ExeIno = 16777232, 99
			h.ids[69] = Identity{CSKnown: true, StartTime: start, Exe: "/tmp/payload", Dev: 16777232, Ino: 100, HasFileID: true}
			return p
		}, nil},
		{"file identity unreadable: killed, noted", func(h *harness) *event.Proc {
			p := h.proc(70, "/tmp/payload")
			p.ExeDev, p.ExeIno = 16777232, 99
			return p
		}, nil},
		{"seeded process", func(h *harness) *event.Proc {
			p := h.proc(71, "/tmp/payload")
			p.Seeded = true
			return p
		}, ErrUnknownProc},
		{"allowed", func(h *harness) *event.Proc { return h.proc(4242, "/tmp/payload") }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(false, nil)
			p := c.p(h)
			err := h.r.KillProc(p, "rule X")
			if !errors.Is(err, c.err) && !(err == nil && c.err == nil) {
				t.Fatalf("err = %v, want %v (logs %+v)", err, c.err, h.logs)
			}
			if len(h.logs) != 1 {
				t.Fatalf("decision not logged: %v", h.logs)
			}
			if c.err == nil && (len(h.killed) != 1 || h.killed[0] != int(p.PID)) {
				t.Fatalf("killed = %v", h.killed)
			}
			if c.err != nil && len(h.killed) != 0 {
				t.Fatalf("refused process killed: %v", h.killed)
			}
		})
	}
}

func TestKillEventUnverified(t *testing.T) {
	h := newHarness(false, nil)
	e := &event.Event{Name: event.CreateFile, Proc: h.proc(4242, "/tmp/payload"),
		Args: map[string]string{ps.ArgIdentity: ps.Unverified}}
	if err := h.r.KillEvent(e, "rule-1", "r"); !errors.Is(err, ErrUnknownProc) || len(h.killed) != 0 {
		t.Fatalf("unverified identity killed: %v %v", err, h.killed)
	}
	e.Args = nil
	if err := h.r.KillEvent(e, "rule-1", "r"); err != nil || len(h.killed) != 1 {
		t.Fatalf("verified identity: %v %v", err, h.killed)
	}
	if err := h.r.KillEvent(&event.Event{}, "rule-1", "r"); err == nil || len(h.killed) != 1 {
		t.Fatalf("event without process: %v", err)
	}
}

func TestKillParent(t *testing.T) {
	type tc struct {
		name    string
		ev      func(h *harness) *event.Event
		err     error
		wantPID int32
	}
	child := func(h *harness, parent *event.Proc) *event.Event {
		c := h.proc(5000, "/usr/bin/osascript")
		c.IsPlatform = true
		if parent != nil {
			c.PPID = parent.PID
			c.Parent = parent
		} else {
			c.PPID = 4999
		}
		return &event.Event{Name: event.CreateProcess, Proc: c}
	}
	cases := []tc{
		{"untrusted parent killed", func(h *harness) *event.Event { return child(h, h.proc(4999, "/tmp/dropper")) }, nil, 4999},
		{"unknown parent", func(h *harness) *event.Event { return child(h, nil) }, ErrUnknownProc, 0},
		{"seeded parent", func(h *harness) *event.Event {
			p := h.proc(4999, "/tmp/dropper")
			p.Seeded = true
			return child(h, p)
		}, ErrUnknownProc, 0},
		{"parent marked unverified", func(h *harness) *event.Event {
			e := child(h, h.proc(4999, "/tmp/dropper"))
			e.Args = map[string]string{ps.ArgParentIdentity: ps.Unverified}
			return e
		}, ErrUnknownProc, 0},
		{"parent pid disagrees with ppid", func(h *harness) *event.Event {
			e := child(h, h.proc(4999, "/tmp/dropper"))
			e.Proc.PPID = 4998
			return e
		}, ErrUnknownProc, 0},
		{"protected-path parent (not platform)", func(h *harness) *event.Event {
			return child(h, h.proc(4999, "/usr/libexec/foo"))
		}, ErrProtected, 0},
		{"platform parent protected", func(h *harness) *event.Event {
			p := h.proc(4999, "/bin/zsh")
			p.IsPlatform = true
			return child(h, p)
		}, ErrProtected, 0},
		{"parent pid reused", func(h *harness) *event.Event {
			e := child(h, h.proc(4999, "/tmp/dropper"))
			h.ids[4999] = Identity{CSKnown: true, StartTime: start.Add(time.Minute), Exe: "/tmp/dropper"}
			return e
		}, ErrMismatch, 0},
		{"no process", func(h *harness) *event.Event { return &event.Event{} }, ErrProtected, 0}, // pid 0
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(false, nil)
			err := h.r.KillParent(c.ev(h), "rule-x", "rule X")
			if !errors.Is(err, c.err) && !(err == nil && c.err == nil) {
				t.Fatalf("err = %v, want %v (logs %+v)", err, c.err, h.logs)
			}
			if len(h.logs) != 1 || h.logs[0].Target != TargetParent || !strings.Contains(h.logs[0].String(), "target=parent") {
				t.Fatalf("decision not logged with target: %+v", h.logs)
			}
			if c.err == nil && (len(h.killed) != 1 || h.killed[0] != int(c.wantPID)) {
				t.Fatalf("killed = %v, want %d", h.killed, c.wantPID)
			}
			if c.err != nil && len(h.killed) != 0 {
				t.Fatalf("refused parent killed: %v", h.killed)
			}
		})
	}
}

func TestKillEventSeeded(t *testing.T) {
	h := newHarness(false, nil)
	p := h.proc(4242, "/tmp/payload")
	p.Seeded = true
	if err := h.r.KillEvent(&event.Event{Proc: p}, "rule-1", "r"); !errors.Is(err, ErrUnknownProc) || len(h.killed) != 0 {
		t.Fatalf("seeded process killed: %v %v", err, h.killed)
	}
	if h.logs[0].Target != TargetProcess || !strings.Contains(h.logs[0].String(), "target=process") {
		t.Fatalf("target not recorded: %+v", h.logs[0])
	}
}

func TestDynamicProtect(t *testing.T) {
	h := newHarness(false, nil)
	current := int32(0)
	h.r.cfg.DynamicPIDs = func() []int32 { return []int32{current} }
	p := h.proc(4321, "/tmp/eslogger-lookalike")
	current = 4321 // e.g. eslogger restarted with this pid
	if err := h.r.KillProc(p, "r"); !errors.Is(err, ErrProtected) {
		t.Fatalf("dynamic pid not protected: %v", err)
	}
	current = 1
	if err := h.r.KillProc(p, "r"); err != nil {
		t.Fatal(err)
	}
}

func TestDryRun(t *testing.T) {
	h := newHarness(true, nil)
	if err := h.r.KillProc(h.proc(4242, "/tmp/payload"), "r"); err != nil {
		t.Fatal(err)
	}
	if len(h.killed) != 0 || h.logs[0].Outcome != OutcomeDryRun {
		t.Fatalf("dry run killed or mislogged: %v %+v", h.killed, h.logs)
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(false, nil)
	var notes []string
	h.r.cfg.OnDegraded = func(cond, detail string) { notes = append(notes, cond+": "+detail) }
	ev := func(pid int32) *event.Event { return &event.Event{Proc: h.proc(pid, "/tmp/payload")} }
	// Per rule: 10 kills per minute.
	for i := 0; i < DefaultMaxPerRulePerMinute; i++ {
		if err := h.r.KillEvent(ev(int32(5000+i)), "rule-a", "rule A"); err != nil {
			t.Fatalf("kill %d: %v", i, err)
		}
		h.now = h.now.Add(time.Second)
	}
	if err := h.r.KillEvent(ev(5100), "rule-a", "rule A"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("11th kill of one rule: %v", err)
	}
	if len(notes) != 1 || !strings.HasPrefix(notes[0], CondRateLimited) || !strings.Contains(notes[0], "rule A") {
		t.Fatalf("rate-limit notice = %q", notes)
	}
	// Another rule still has its own budget, up to the global cap of 30.
	for i := 0; i < DefaultMaxPerRulePerMinute; i++ {
		if err := h.r.KillEvent(ev(int32(6000+i)), "rule-b", "rule B"); err != nil {
			t.Fatalf("rule B kill %d: %v", i, err)
		}
		if err := h.r.KillEvent(ev(int32(7000+i)), "rule-c", "rule C"); err != nil {
			t.Fatalf("rule C kill %d: %v", i, err)
		}
	}
	if err := h.r.KillEvent(ev(8000), "rule-d", "rule D"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("31st kill overall: %v", err)
	}
	if len(notes) != 2 || !strings.Contains(notes[1], "global") {
		t.Fatalf("global notice = %q", notes)
	}
	// After the window, rule A can kill again.
	h.now = h.now.Add(time.Minute)
	if err := h.r.KillEvent(ev(5200), "rule-a", "rule A"); err != nil {
		t.Fatalf("after window: %v", err)
	}
	st := h.r.Stats()
	if st[OutcomeKilled] != 31 || st[OutcomeRateLimited] != 2 {
		t.Fatalf("stats = %v", st)
	}
}

// TestRepeatedRefusalsLoggedOnce: the same refusal for the same (rule,
// target, pid) is logged once a minute; kills are always logged.
func TestRepeatedRefusalsLoggedOnce(t *testing.T) {
	h := newHarness(false, nil)
	p := h.proc(4242, "/usr/libexec/x")
	for i := 0; i < 50; i++ {
		_ = h.r.KillEvent(&event.Event{Proc: p}, "rule-a", "rule A")
	}
	if len(h.logs) != 1 || h.r.Stats()["log_suppressed"] != 49 || h.r.Stats()[OutcomeProtected] != 50 {
		t.Fatalf("logs = %d stats = %v", len(h.logs), h.r.Stats())
	}
	_ = h.r.KillEvent(&event.Event{Proc: h.proc(4243, "/usr/libexec/x")}, "rule-a", "rule A") // other pid
	h.now = h.now.Add(LogRepeatEvery)
	_ = h.r.KillEvent(&event.Event{Proc: p}, "rule-a", "rule A") // window passed
	if len(h.logs) != 3 {
		t.Fatalf("logs = %d", len(h.logs))
	}
	for i := 0; i < 3; i++ {
		_ = h.r.KillEvent(&event.Event{Proc: h.proc(4300, "/tmp/payload")}, "rule-a", "rule A")
	}
	if len(h.logs) != 6 {
		t.Fatalf("kills must always be logged: %d", len(h.logs))
	}
}

func TestKillError(t *testing.T) {
	h := newHarness(false, syscall.ESRCH)
	err := h.r.KillProc(h.proc(4242, "/tmp/p"), "r")
	if !errors.Is(err, syscall.ESRCH) || h.logs[0].Outcome != OutcomeError {
		t.Fatalf("err = %v logs = %+v", err, h.logs)
	}
}

func TestKillByPID(t *testing.T) {
	h := newHarness(false, nil)
	if err := h.r.Kill(4242, "r"); !errors.Is(err, ErrUnknownProc) {
		t.Fatalf("Kill without lookup: %v", err)
	}
	h.r.cfg.Lookup = func(pid int32) (*event.Proc, bool) {
		if pid == 4242 {
			return h.proc(4242, "/tmp/p"), true
		}
		return h.proc(pid, "/sbin/launchd"), true
	}
	if err := h.r.Kill(4242, "r"); err != nil {
		t.Fatal(err)
	}
	if err := h.r.Kill(4243, "r"); !errors.Is(err, ErrProtected) {
		t.Fatalf("protected via lookup: %v", err)
	}
	h.r.Protect(4242)
	if err := h.r.Kill(4242, "r"); !errors.Is(err, ErrProtected) {
		t.Fatalf("Protect: %v", err)
	}
}

func TestDecisionStringSanitized(t *testing.T) {
	d := Decision{PID: 3, Exe: "/tmp/\x1b[2Jx", Reason: "r‮", Outcome: OutcomeKilled}
	if s := d.String(); strings.ContainsAny(s, "\x1b‮") {
		t.Fatalf("unsanitized: %q", s)
	}
}

// TestIdentifySelf exercises the real kernel lookup on this test process.
func TestIdentifySelf(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	id, err := identify(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if id.StartTime.IsZero() || time.Since(id.StartTime) > time.Hour || time.Since(id.StartTime) < 0 {
		t.Fatalf("start time %v", id.StartTime)
	}
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	if id.Exe != self {
		t.Fatalf("exe %q, want the full resolved path %q", id.Exe, self)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(self, &st); err != nil {
		t.Fatal(err)
	}
	if !id.HasFileID || id.Ino != st.Ino || uint32(id.Dev) != uint32(st.Dev) {
		t.Fatalf("file identity %+v, stat dev=%d ino=%d", id, st.Dev, st.Ino)
	}
	if !id.UniqueKnown || id.UniqueID == 0 {
		t.Fatalf("kernel unique id not read: %+v", id)
	}
	if again, _ := identify(int32(os.Getpid())); again.UniqueID != id.UniqueID {
		t.Fatalf("unique id unstable: %d then %d", id.UniqueID, again.UniqueID)
	}
	if p1, err := identify(1); err != nil || p1.UniqueID != 1 {
		t.Fatalf("launchd unique id = %d (%v), want 1", p1.UniqueID, err)
	}
	if _, err := identify(99999999); err == nil {
		t.Fatal("nonexistent pid identified")
	}
}

// TestHelperSleep is the child process of TestIdentifyChild.
func TestHelperSleep(t *testing.T) {
	if os.Getenv("ZAAFVESPER_HELPER_SLEEP") != "1" {
		t.Skip("helper process only")
	}
	fmt.Println("helper-ready") // the image is fully loaded
	time.Sleep(30 * time.Second)
}

// TestIdentifyChild checks a child started through a symbolic link with a
// misleading argv[0]: the kernel path is the real file, the start time and
// inode are read, and the process is not a platform binary.
func TestIdentifyChild(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "Finder")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// The child is this test binary, started through the link, sleeping in
	// TestHelperSleep.
	cmd := exec.Command(link, "-test.run=^TestHelperSleep$")
	cmd.Args[0] = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
	cmd.Env = append(os.Environ(), "ZAAFVESPER_HELPER_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := int32(cmd.Process.Pid)
	var id Identity
	for i := 0; i < 50; i++ { // wait for the exec to complete
		if id, err = identify(pid); err == nil && id.Exe == real {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || id.Exe != real {
		t.Fatalf("identify child: %+v %v, want exe %q", id, err, real)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(real, &st); err != nil {
		t.Fatal(err)
	}
	var killed []int
	r := New(Config{Log: func(d Decision) { t.Log(d.String()) }, KillFunc: func(p int, _ syscall.Signal) error { killed = append(killed, p); return nil }})
	proc := func(exe string, ino uint64) *event.Proc {
		return &event.Proc{PID: pid, Exe: exe, StartTime: id.StartTime, ExeDev: uint64(uint32(st.Dev)), ExeIno: ino, UniqueID: id.UniqueID}
	}
	if !id.CSKnown || id.CSFlags&csPlatformBinary != 0 {
		t.Fatalf("test binary code-signing status: %+v", id)
	}
	// A path or file discrepancy is logged but does not save the process.
	if err := r.KillProc(proc(link, st.Ino), "r"); err != nil {
		t.Fatalf("link path: %v", err)
	}
	if err := r.KillProc(proc(real, st.Ino), "r"); err != nil || len(killed) != 2 || killed[1] != int(pid) {
		t.Fatalf("real identity refused: %v %v", err, killed)
	}
}

// startHelper starts a copy of this test binary at exe, sleeping in
// TestHelperSleep, and returns it once the kernel reports exe as its path.
func startHelper(t *testing.T, exe string) (*exec.Cmd, Identity) {
	t.Helper()
	cmd := exec.Command(exe, "-test.run=^TestHelperSleep$")
	cmd.Env = append(os.Environ(), "ZAAFVESPER_HELPER_SLEEP=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	// Wait until the helper runs Go code: changing its file while dyld is
	// still loading the image makes the exec itself fail.
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.Contains(line, "helper-ready") {
		t.Fatalf("helper did not start: %q %v", line, err)
	}
	for i := 0; i < 100; i++ {
		if id, err := identify(int32(cmd.Process.Pid)); err == nil && id.Exe == exe {
			return cmd, id
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("helper %s did not start", exe)
	return nil, Identity{}
}

func copyExe(t *testing.T, dst string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestKillEvasionRealProcesses is the security review's round-3 harness as a
// regression test: a process that renames, deletes or replaces its own
// binary after exec is still killed (KillFunc is a stub), a platform image
// is refused, and a start time 2 ms off (pid reuse) is refused.
func TestKillEvasionRealProcesses(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newResponder := func(killed *[]int, logs *[]Decision) *Responder {
		return New(Config{Log: func(d Decision) { *logs = append(*logs, d) },
			KillFunc: func(p int, _ syscall.Signal) error { *killed = append(*killed, p); return nil }})
	}
	for _, mode := range []string{"none", "rename", "unlink", "replace"} {
		t.Run(mode, func(t *testing.T) {
			bin := filepath.Join(dir, "payload-"+mode)
			copyExe(t, bin)
			cmd, id0 := startHelper(t, bin)
			pid := int32(cmd.Process.Pid)
			if !id0.UniqueKnown || id0.UniqueID == 0 {
				t.Fatalf("unique id not read: %+v", id0)
			}
			ev := &event.Proc{PID: pid, Exe: id0.Exe, StartTime: id0.StartTime, ExeDev: id0.Dev, ExeIno: id0.Ino, UniqueID: id0.UniqueID}
			switch mode {
			case "rename":
				if err := os.Rename(bin, bin+".moved"); err != nil {
					t.Fatal(err)
				}
			case "unlink":
				if err := os.Remove(bin); err != nil {
					t.Fatal(err)
				}
			case "replace":
				if err := os.Remove(bin); err != nil {
					t.Fatal(err)
				}
				copyExe(t, bin)
			}
			id1, err := identify(pid)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: kernel now exe=%q exeErr=%v csKnown=%v", mode, id1.Exe, id1.ExeErr, id1.CSKnown)
			var killed []int
			var logs []Decision
			if err := newResponder(&killed, &logs).KillProc(ev, "test"); err != nil || len(killed) != 1 || killed[0] != int(pid) {
				t.Fatalf("%s: not killed: %v %v %+v", mode, err, killed, logs)
			}
			if mode != "none" && logs[0].Detail == "" {
				t.Fatalf("%s: discrepancy not recorded: %+v", mode, logs[0])
			}
		})
	}
	t.Run("platform current image", func(t *testing.T) {
		cmd := exec.Command("/bin/sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		pid := int32(cmd.Process.Pid)
		var id Identity
		for i := 0; i < 100; i++ {
			if id, err = identify(pid); err == nil && id.Exe == "/bin/sleep" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		// The event lies: a non-platform binary under /tmp.
		ev := &event.Proc{PID: pid, Exe: "/tmp/sleep", StartTime: id.StartTime, UniqueID: id.UniqueID}
		var killed []int
		var logs []Decision
		if err := newResponder(&killed, &logs).KillProc(ev, "test"); !errors.Is(err, ErrProtected) || len(killed) != 0 {
			t.Fatalf("platform image: %v %v %+v", err, killed, logs)
		}
	})
	t.Run("unique id differs", func(t *testing.T) {
		bin := filepath.Join(dir, "payload-uniq")
		copyExe(t, bin)
		cmd, id0 := startHelper(t, bin)
		ev := &event.Proc{PID: int32(cmd.Process.Pid), Exe: id0.Exe, StartTime: id0.StartTime, UniqueID: id0.UniqueID + 1}
		var killed []int
		var logs []Decision
		if err := newResponder(&killed, &logs).KillProc(ev, "test"); !errors.Is(err, ErrMismatch) || len(killed) != 0 {
			t.Fatalf("unique id differs: %v %v %+v", err, killed, logs)
		}
		ev.UniqueID = 0
		if err := newResponder(&killed, &logs).KillProc(ev, "test"); !errors.Is(err, ErrUnknownProc) || len(killed) != 0 {
			t.Fatalf("unique id not recorded: %v %v", err, killed)
		}
	})
	t.Run("pid reuse", func(t *testing.T) {
		bin := filepath.Join(dir, "payload-reuse")
		copyExe(t, bin)
		cmd, id0 := startHelper(t, bin)
		ev := &event.Proc{PID: int32(cmd.Process.Pid), Exe: id0.Exe, StartTime: id0.StartTime.Add(-2 * time.Millisecond), UniqueID: id0.UniqueID}
		var killed []int
		var logs []Decision
		if err := newResponder(&killed, &logs).KillProc(ev, "test"); !errors.Is(err, ErrMismatch) || len(killed) != 0 {
			t.Fatalf("pid reuse: %v %v %+v", err, killed, logs)
		}
	})
}
