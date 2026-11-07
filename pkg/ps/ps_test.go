package ps

import (
	"encoding/binary"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
)

var _ source.Enricher = (*Snapshotter)(nil)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func testSnap(max int) *Snapshotter {
	s := newSnapshotter(max, MaxBytes)
	s.lookupUser = func(uid int64) string {
		switch uid {
		case 0:
			return "root"
		case 501:
			return "alice"
		}
		return ""
	}
	s.now = func() time.Time { return t0 }
	return s
}

func proc(pid, ppid int32, pv uint32, exe string) *event.Proc {
	return &event.Proc{PID: pid, PPID: ppid, PIDVersion: pv, Exe: exe, Name: exe[len(exe)-3:], UID: 501}
}

func ev(name string, sec int, p *event.Proc) *event.Event {
	return &event.Event{Name: name, Time: t0.Add(time.Duration(sec) * time.Second), Proc: p}
}

// seed builds launchd(1) -> Terminal(100) -> zsh(200).
func seed(s *Snapshotter) {
	launchd := &event.Proc{PID: 1, PPID: 0, PIDVersion: 1, Exe: "/sbin/launchd", Name: "launchd"}
	s.Enrich(ev(event.CreateProcess, 0, launchd))
	s.Enrich(ev(event.CreateProcess, 0, proc(100, 1, 100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")))
	z := proc(200, 100, 200, "/bin/zsh")
	z.Args, z.Cmdline, z.Cwd = []string{"-zsh"}, "-zsh", "/Users/alice"
	z.Env = map[string]string{"HOME": "/Users/alice"}
	s.Enrich(ev(event.CreateProcess, 0, z))
}

func TestForkExecExitAncestry(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)

	// fork: the child inherits zsh's image details.
	child := &event.Proc{PID: 300, PPID: 200, PIDVersion: 300, Exe: "/bin/zsh", Name: "zsh", UID: 501}
	f := ev(event.Fork, 1, child)
	s.Enrich(f)
	if !slices.Equal(child.Args, []string{"-zsh"}) || child.Env["HOME"] != "/Users/alice" || child.Cwd != "/Users/alice" {
		t.Fatalf("fork did not inherit image details: %+v", child)
	}
	if child.Parent == nil || child.Parent.PID != 200 || child.Parent.Parent != nil {
		t.Fatalf("parent = %+v", child.Parent)
	}

	// exec replaces the image (new pidversion), keeps the pid.
	cp := &event.Proc{PID: 300, PPID: 200, PIDVersion: 301, Exe: "/usr/bin/curl", Name: "curl", UID: 501,
		Args: []string{"curl", "-s", "x"}, Cmdline: "curl -s x", Env: map[string]string{"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}}
	e := ev(event.CreateProcess, 2, cp)
	s.Enrich(e)
	if got, want := cp.Ancestors, []string{"/bin/zsh", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "/sbin/launchd"}; !slices.Equal(got, want) {
		t.Fatalf("ancestors %v want %v", got, want)
	}
	if e.Get("ps.parent.exe") != "/bin/zsh" || e.GetIndexed("ps.parent.env", "HOME") != "/Users/alice" {
		t.Errorf("parent fields: %v %v", e.Get("ps.parent.exe"), e.GetIndexed("ps.parent.env", "HOME"))
	}
	if e.Get("ps.uuid") != int64(300<<32|301) || e.Get("ps.username") != "alice" || e.Get("ps.parent.username") != "alice" {
		t.Errorf("uuid/username: %v %v", e.Get("ps.uuid"), e.Get("ps.username"))
	}

	// A later file event from curl carries no args; the table supplies them.
	op := &event.Proc{PID: 300, PPID: 200, PIDVersion: 301, Exe: "/usr/bin/curl", Name: "curl", UID: 501}
	o := ev(event.OpenFile, 3, op)
	s.Enrich(o)
	if op.Cmdline != "curl -s x" || o.GetIndexed("ps.env", "DYLD_INSERT_LIBRARIES") != "/tmp/x.dylib" {
		t.Errorf("open not enriched from table: %+v", op)
	}
	if len(op.Ancestors) != 3 || op.Parent.Exe != "/bin/zsh" {
		t.Errorf("open ancestry: %v", op.Ancestors)
	}

	// exit: still resolvable within the TTL, gone after it.
	s.Enrich(ev(event.TerminateProcess, 4, &event.Proc{PID: 300, PPID: 200, PIDVersion: 301, Exe: "/usr/bin/curl"}))
	gc := &event.Proc{PID: 400, PPID: 300, PIDVersion: 400, Exe: "/bin/sh", UID: 501}
	s.Enrich(ev(event.OpenFile, 10, gc))
	if gc.Parent == nil || gc.Parent.Exe != "/usr/bin/curl" {
		t.Fatalf("exited parent not resolvable within TTL: %+v", gc.Parent)
	}
	s.Enrich(ev(event.OpenFile, 4+int(ExitTTL/time.Second)+sweepEveryS(), proc(200, 100, 200, "/bin/zsh")))
	if _, ok := s.Lookup(300); ok {
		t.Error("exited process not swept after TTL")
	}
}

func sweepEveryS() int { return int(sweepEvery/time.Second) + 1 }

func TestPIDReuseDetected(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)
	s.Enrich(ev(event.CreateProcess, 1, &event.Proc{PID: 500, PPID: 200, PIDVersion: 500, Exe: "/usr/bin/old", Args: []string{"old", "--secret"}, Cmdline: "old --secret"}))
	// Exit was missed; pid 500 is now a different process.
	n := &event.Proc{PID: 500, PPID: 1, PIDVersion: 777, Exe: "/usr/bin/new"}
	s.Enrich(ev(event.OpenFile, 2, n))
	if n.Cmdline != "" || len(n.Args) != 0 {
		t.Errorf("stale args leaked into recycled pid: %+v", n)
	}
	got, _ := s.Lookup(500)
	if got.Exe != "/usr/bin/new" || got.PIDVersion != 777 {
		t.Errorf("table not replaced: %+v", got)
	}
}

func TestBootstrapEntryAdoptsIdentity(t *testing.T) {
	s := testSnap(MaxEntries)
	s.seed(event.Proc{PID: 42, PPID: 1, Exe: "/usr/sbin/sshd", Name: "sshd", Args: []string{"sshd", "-i"}, Cmdline: "sshd -i"})
	p := &event.Proc{PID: 42, PPID: 1, PIDVersion: 4242, Exe: "/usr/sbin/sshd", Name: "sshd", SigningID: "com.apple.sshd", IsPlatform: true, IsSigned: true}
	s.Enrich(ev(event.OpenFile, 1, p))
	if p.Cmdline != "sshd -i" {
		t.Errorf("bootstrap args not used: %q", p.Cmdline)
	}
	got, _ := s.Lookup(42)
	if got.SigningID != "com.apple.sshd" || !got.IsPlatform || got.PIDVersion != 4242 {
		t.Errorf("identity not adopted: %+v", got)
	}
}

func TestBounded(t *testing.T) {
	s := testSnap(8)
	seed(s) // 3 entries
	for i := int32(1000); i < 1100; i++ {
		s.Enrich(ev(event.CreateProcess, 1, proc(i, 200, uint32(i), "/bin/cat")))
	}
	if s.Len() > 8 {
		t.Fatalf("len %d > 8", s.Len())
	}
	if _, ok := s.Lookup(1); !ok {
		t.Error("launchd evicted")
	}
}

func TestEvictPrefersExited(t *testing.T) {
	s := testSnap(4)
	seed(s)
	s.Enrich(ev(event.CreateProcess, 1, proc(600, 200, 600, "/bin/cat")))
	s.Enrich(ev(event.TerminateProcess, 2, proc(600, 200, 600, "/bin/cat")))
	s.Enrich(ev(event.CreateProcess, 3, proc(700, 200, 700, "/bin/dog")))
	if _, ok := s.Lookup(600); ok {
		t.Error("exited entry should be evicted first")
	}
	for _, pid := range []int32{1, 100, 200, 700} {
		if _, ok := s.Lookup(pid); !ok {
			t.Errorf("pid %d evicted", pid)
		}
	}
}

func TestAncestorCycleAndCap(t *testing.T) {
	s := testSnap(MaxEntries)
	// A ppid cycle must not loop.
	s.Enrich(ev(event.CreateProcess, 0, proc(10, 11, 1, "/bin/aaa")))
	s.Enrich(ev(event.CreateProcess, 0, proc(11, 10, 1, "/bin/bbb")))
	p := proc(12, 10, 1, "/bin/ccc")
	s.Enrich(ev(event.OpenFile, 1, p))
	if !slices.Equal(p.Ancestors, []string{"/bin/aaa", "/bin/bbb"}) {
		t.Errorf("cycle: %v", p.Ancestors)
	}
	// A deep chain is capped.
	for i := int32(1000); i < 1040; i++ {
		s.Enrich(ev(event.CreateProcess, 0, proc(i+1, i, 1, "/bin/sub")))
	}
	q := proc(2000, 1040, 1, "/bin/end")
	s.Enrich(ev(event.OpenFile, 1, q))
	if len(q.Ancestors) != MaxAncestors {
		t.Errorf("ancestors %d", len(q.Ancestors))
	}
}

func TestTargetDecorated(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)
	e := ev(event.OpenProcess, 1, proc(900, 200, 900, "/tmp/inj"))
	e.Target = &event.Proc{PID: 200, PIDVersion: 200, Exe: "/bin/zsh", UID: 0}
	s.Enrich(e)
	if e.Target.UUID != UUID(200, 200) || e.Target.Username != "root" || e.Target.Cmdline != "-zsh" {
		t.Errorf("target: %+v", e.Target)
	}
	if e.Target.Parent != nil {
		t.Error("target should not get a parent")
	}
	s.Enrich(nil)                                  // no panic
	s.Enrich(&event.Event{Name: event.OpenFile})   // no proc
	s.Enrich(ev(event.OpenFile, 1, &event.Proc{})) // pid 0
}

func TestParseProcArgs(t *testing.T) {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = append(b, "/usr/bin/python3\x00\x00\x00\x00python3\x00-c\x00print(1)\x00HOME=/Users/a\x00DYLD_X=1\x00BAD\x00\x00junk"...)
	exe, args, env := parseProcArgs(b)
	if exe != "/usr/bin/python3" || !slices.Equal(args, []string{"python3", "-c", "print(1)"}) || env["HOME"] != "/Users/a" || env["DYLD_X"] != "1" || len(env) != 2 {
		t.Errorf("exe=%q args=%q env=%v", exe, args, env)
	}
	// Malformed inputs never panic.
	for _, in := range [][]byte{nil, {1}, {255, 255, 255, 127}, binary.LittleEndian.AppendUint32(nil, 5), append(binary.LittleEndian.AppendUint32(nil, 9), "x"...)} {
		parseProcArgs(in)
	}
}

func FuzzParseProcArgs(f *testing.F) {
	f.Add(append(binary.LittleEndian.AppendUint32(nil, 1), "/bin/a\x00\x00a\x00K=V\x00"...))
	f.Fuzz(func(t *testing.T, b []byte) { parseProcArgs(b) })
}

func TestBootstrapLive(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	s := NewSnapshotter(true)
	n, err := s.BootstrapStats()
	if err != nil || n == 0 || s.Len() != n {
		t.Fatalf("bootstrap: n=%d len=%d err=%v", n, s.Len(), err)
	}
	me, ok := s.Lookup(int32(os.Getpid()))
	if !ok || me.Exe == "" || len(me.Args) == 0 || me.PPID != int32(os.Getppid()) {
		t.Fatalf("own process not bootstrapped with exe/args: %+v", me)
	}
	if l, ok := s.Lookup(1); !ok || l.Name != "launchd" {
		t.Errorf("launchd: %+v", l)
	}
}

func TestParentPIDVersionChecked(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s) // zsh is pid 200, pidversion 200
	// The source says the parent is pid 200 incarnation 999: pid 200 was
	// recycled, so the zsh in the table must not be reported as the parent.
	p := proc(800, 200, 800, "/bin/xyz")
	p.Parent = &event.Proc{PID: 200, PIDVersion: 999}
	e := ev(event.OpenFile, 1, p)
	s.Enrich(e)
	if p.Parent != nil || len(p.Ancestors) != 0 || e.Get("ps.parent.exe") != nil {
		t.Fatalf("recycled pid taken as parent: parent=%+v ancestors=%v", p.Parent, p.Ancestors)
	}
	// Same pid with the right incarnation resolves, and the stub's pid wins
	// over a reparented ppid (1 = launchd).
	q := proc(801, 1, 801, "/bin/xyz")
	q.Parent = &event.Proc{PID: 200, PIDVersion: 200}
	s.Enrich(ev(event.OpenFile, 1, q))
	if q.Parent == nil || q.Parent.Exe != "/bin/zsh" || q.Parent.Username != "alice" {
		t.Fatalf("parent = %+v", q.Parent)
	}
	// The remembered parent ref is used by later events without a stub,
	// and by descendants walking the chain.
	r := proc(801, 1, 801, "/bin/xyz")
	s.Enrich(ev(event.OpenFile, 2, r))
	if r.Parent == nil || r.Parent.PID != 200 {
		t.Fatalf("remembered parent: %+v", r.Parent)
	}
	// A fork whose stub names a recycled parent inherits nothing from it.
	c := &event.Proc{PID: 802, PPID: 200, PIDVersion: 802, Exe: "/bin/xyz", Parent: &event.Proc{PID: 200, PIDVersion: 5}}
	s.Enrich(ev(event.Fork, 3, c))
	if c.Cwd != "" || c.Parent != nil {
		t.Fatalf("fork inherited from recycled parent: %+v", c)
	}
}

func TestCapsAreSpecValues(t *testing.T) {
	if MaxEntries != 65536 || ExitTTL != 30*time.Second || MaxAncestors != 16 {
		t.Fatalf("caps changed: %d %s %d", MaxEntries, ExitTTL, MaxAncestors)
	}
	if NewSnapshotter(false).max != MaxEntries {
		t.Fatal("NewSnapshotter does not use MaxEntries")
	}
}

func TestTableCapAtMaxEntries(t *testing.T) {
	s := testSnap(MaxEntries)
	for i := int32(2); i < MaxEntries+500; i++ {
		s.Enrich(ev(event.CreateProcess, 1, &event.Proc{PID: i, PPID: 1, PIDVersion: uint32(i), Exe: "/bin/cat"}))
	}
	if s.Len() != MaxEntries {
		t.Fatalf("len %d, want %d", s.Len(), MaxEntries)
	}
}

func TestExitRetentionBoundary(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)
	s.Enrich(ev(event.CreateProcess, 0, proc(300, 200, 300, "/bin/cat")))
	s.Enrich(ev(event.TerminateProcess, 100, proc(300, 200, 300, "/bin/cat")))
	s.Enrich(ev(event.OpenFile, 100+int(ExitTTL/time.Second)-1, proc(200, 100, 200, "/bin/zsh")))
	if _, ok := s.Lookup(300); !ok {
		t.Fatal("dropped before ExitTTL")
	}
	s.Enrich(ev(event.OpenFile, 100+int(ExitTTL/time.Second)+sweepEveryS(), proc(200, 100, 200, "/bin/zsh")))
	if _, ok := s.Lookup(300); ok {
		t.Fatal("kept after ExitTTL")
	}
}
