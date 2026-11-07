package response

import (
	"errors"
	"os"
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
	r      *Responder
}

func newHarness(dry bool, killErr error) *harness {
	h := &harness{now: start.Add(time.Hour), ids: map[int32]Identity{}}
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
			return id, nil
		},
		ProtectPIDs: []int32{777},
	})
	return h
}

// proc returns a killable process and registers the matching kernel identity.
func (h *harness) proc(pid int32, exe string) *event.Proc {
	h.ids[pid] = Identity{StartTime: start, Exe: exe}
	return &event.Proc{PID: pid, Exe: exe, Name: filepath.Base(exe), StartTime: start}
}

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
			h.ids[62] = Identity{StartTime: start.Add(5 * time.Second), Exe: "/tmp/p"}
			return p
		}, ErrMismatch},
		{"start time within tolerance", func(h *harness) *event.Proc {
			p := h.proc(63, "/tmp/p")
			h.ids[63] = Identity{StartTime: start.Add(900 * time.Millisecond), Exe: "/tmp/p"}
			return p
		}, nil},
		{"exec since event (exe)", func(h *harness) *event.Proc {
			p := h.proc(64, "/tmp/p")
			h.ids[64] = Identity{StartTime: start, Exe: "/Applications/Other.app/Contents/MacOS/Other"}
			return p
		}, ErrMismatch},
		{"exec into protected path", func(h *harness) *event.Proc {
			p := h.proc(65, "/tmp/sshd")
			h.ids[65] = Identity{StartTime: start, Exe: "/usr/sbin/sshd"}
			return p
		}, ErrProtected},
		{"relative exec path in kernel", func(h *harness) *event.Proc {
			p := h.proc(66, "/Users/a/payload")
			h.ids[66] = Identity{StartTime: start, Exe: "./payload"}
			return p
		}, nil},
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
	if err := h.r.KillEvent(e, "r"); !errors.Is(err, ErrUnknownProc) || len(h.killed) != 0 {
		t.Fatalf("unverified identity killed: %v %v", err, h.killed)
	}
	e.Args = nil
	if err := h.r.KillEvent(e, "r"); err != nil || len(h.killed) != 1 {
		t.Fatalf("verified identity: %v %v", err, h.killed)
	}
	if err := h.r.KillEvent(&event.Event{}, "r"); err == nil || len(h.killed) != 1 {
		t.Fatalf("event without process: %v", err)
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
	p := h.proc(4242, "/tmp/payload")
	for i := 0; i < DefaultMaxPerMinute; i++ {
		if err := h.r.KillProc(p, "r"); err != nil {
			t.Fatalf("kill %d: %v", i, err)
		}
		h.now = h.now.Add(time.Second)
	}
	if err := h.r.KillProc(p, "r"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("11th kill: %v", err)
	}
	h.now = h.now.Add(50 * time.Second)
	if err := h.r.KillProc(p, "r"); err != nil {
		t.Fatalf("after window: %v", err)
	}
	st := h.r.Stats()
	if st[OutcomeKilled] != 11 || st[OutcomeRateLimited] != 1 {
		t.Fatalf("stats = %v", st)
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
	if filepath.Base(id.Exe) != filepath.Base(self) {
		t.Fatalf("exe %q, want base of %q", id.Exe, self)
	}
	if _, err := identify(99999999); err == nil {
		t.Fatal("nonexistent pid identified")
	}
	if _, err := procargsExe([]byte{1, 0, 0, 0}); err == nil {
		t.Fatal("short buffer accepted")
	}
	if exe, err := procargsExe(append([]byte{1, 0, 0, 0}, []byte("/bin/x\x00\x00x\x00")...)); err != nil || exe != "/bin/x" {
		t.Fatalf("procargsExe = %q, %v", exe, err)
	}
}
