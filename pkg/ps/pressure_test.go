package ps

import (
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

type hookRec struct{ calls []string }

func (h *hookRec) fn(s *Snapshotter) func(string, string) {
	return func(cond, detail string) {
		_ = s.Len() // re-entering the snapshotter from the hook must not deadlock
		h.calls = append(h.calls, cond+" "+detail)
	}
}

// TestFloodKeepsParentSkeleton reproduces the round-2 attack: ~900 processes
// with argv at the decoder's caps push the table over its 128 MiB budget.
// Before the fix this evicted the malware's (older) parent, so the osascript
// prompt rule lost ps.parent.* and dropped from CRITICAL to HIGH. Now details
// are shed first; the parent's identity skeleton survives and the degraded
// hook fires (once: it is rate-limited).
func TestFloodKeepsParentSkeleton(t *testing.T) {
	s := testSnap(MaxEntries)
	h := &hookRec{}
	s.OnDegraded(h.fn(s))
	seed(s)

	start := t0.Add(-time.Hour)
	mal := &event.Proc{
		PID: 500, PPID: 1, PIDVersion: 9500, Exe: "/Users/alice/.cache/agent", Name: "agent", UID: 501, EUID: 501,
		SigningID: "agent", TeamID: "FAKETEAM01", CSCategory: event.CSLocalSigning, IsSigned: true, StartTime: start,
		ExeDev: 16777234, ExeIno: 4242, ExeCtimeNs: start.UnixNano(),
		Args: []string{"agent", "--quiet"}, Cmdline: "agent --quiet", Cwd: "/Users/alice",
		Parent: &event.Proc{PID: 1, PIDVersion: 1},
	}
	s.Enrich(ev(event.CreateProcess, 1, mal))

	// Flood: argv at the eslogger caps (4096 args, 64 KiB cmdline). The
	// strings are shared, so the test is cheap; the table accounts each copy.
	args := make([]string, 4096)
	for i := range args {
		args[i] = strings.Repeat("A", 16)
	}
	cmdline := strings.Repeat("A", 64<<10)
	for i := int32(0); i < 900; i++ {
		p := &event.Proc{PID: 10_000 + i, PPID: 1, PIDVersion: uint32(i + 1), Exe: "/private/tmp/flood", Name: "flood",
			UID: 501, Args: args, Cmdline: cmdline, Parent: &event.Proc{PID: 1, PIDVersion: 1}}
		s.Enrich(ev(event.CreateProcess, 2, p))
	}
	st := s.Stats()

	// The malware now runs the prompt.
	osa := &event.Proc{PID: 20_000, PPID: 500, PIDVersion: 20_001, Exe: "/usr/bin/osascript", Name: "osascript",
		UID: 501, IsPlatform: true, CSCategory: event.CSPlatform, Args: []string{"osascript", "-e", "display dialog"},
		Parent: &event.Proc{PID: 500, PIDVersion: 9500}}
	e := ev(event.CreateProcess, 3, osa)
	s.Enrich(e)
	par := e.Proc.Parent
	if par == nil {
		t.Fatalf("parent evicted by the flood (stats %v)", st)
	}
	if int64(st["bytes"]) > MaxBytes {
		t.Fatalf("bytes %d over budget", st["bytes"])
	}
	if st["shed"] == 0 {
		t.Fatalf("flood did not hit the budget (bytes %d); the test no longer reproduces the attack", st["bytes"])
	}
	if st["evictions"] != 0 {
		t.Errorf("%d evictions: skeletons must go only when nothing is left to shed", st["evictions"])
	}
	if par.Exe != mal.Exe || par.Name != "agent" || par.PIDVersion != 9500 || par.PPID != 1 || !par.StartTime.Equal(start) ||
		par.IsPlatform || !par.IsSigned || par.CSCategory != event.CSLocalSigning || par.Seeded ||
		par.TeamID != "FAKETEAM01" || par.SigningID != "agent" || par.UID != 501 || par.EUID != 501 ||
		par.ExeDev != 16777234 || par.ExeIno != 4242 || par.ExeCtimeNs != start.UnixNano() {
		t.Errorf("parent skeleton incomplete: %+v", par)
	}
	if e.Get("ps.parent.exe") != mal.Exe || e.Get("ps.parent.is_platform") != false || e.Get("ps.parent.cs_category") != event.CSLocalSigning {
		t.Errorf("rule fields: %v %v %v", e.Get("ps.parent.exe"), e.Get("ps.parent.is_platform"), e.Get("ps.parent.cs_category"))
	}
	if len(h.calls) != 1 || !strings.HasPrefix(h.calls[0], CondPressure+" ") {
		t.Fatalf("hook calls %q, want one %s", h.calls, CondPressure)
	}
	if !strings.Contains(h.calls[0], "shed=") {
		t.Errorf("detail %q", h.calls[0])
	}
	checkFatLists(t, s)

	// A minute later, renewed pressure is reported again.
	s.now = func() time.Time { return t0.Add(degradedEvery) }
	for i := int32(0); i < 50; i++ {
		s.Enrich(ev(event.CreateProcess, 4, &event.Proc{PID: 30_000 + i, PPID: 1, PIDVersion: 1, Exe: "/private/tmp/flood",
			Args: args, Cmdline: cmdline}))
	}
	if len(h.calls) != 2 {
		t.Errorf("after a minute: %d hook calls, want 2", len(h.calls))
	}
}

// TestSkeletonEvictionLastResort: when only skeletons are left, entries are
// evicted (exited first, then the oldest live), and that is reported too.
func TestSkeletonEvictionLastResort(t *testing.T) {
	s := testSnap(MaxEntries)
	s.maxBytes = 8 << 10
	h := &hookRec{}
	s.OnDegraded(h.fn(s))
	seed(s)
	for i := int32(0); s.Stats()["evictions"] == 0; i++ {
		if i > 1000 {
			t.Fatal("no eviction")
		}
		s.Enrich(ev(event.CreateProcess, 1, &event.Proc{PID: 1000 + i, PPID: 1, PIDVersion: 1, Exe: "/bin/" + strings.Repeat("x", 200)}))
	}
	if s.Stats()["shed"] == 0 {
		t.Error("zsh's details should have been shed before any eviction")
	}
	if len(h.calls) != 1 {
		t.Errorf("hook calls %q", h.calls)
	}
}

// TestUnknownParentIsNil: a parent that is not in the table (never seen, or
// evicted, or the pid recycled) gives e.Proc.Parent == nil, so every
// ps.parent.* field is nil and only `not` makes a comparison on it true.
func TestUnknownParentIsNil(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)
	for name, stub := range map[string]*event.Proc{
		"never seen":    {PID: 777, PIDVersion: 778},
		"pid recycled":  {PID: 200, PIDVersion: 999}, // zsh is pidversion 200
		"ppid only":     nil,
		"stub, no ppid": {PID: 888},
	} {
		p := &event.Proc{PID: 4000, PPID: 777, PIDVersion: 4001, Exe: "/usr/bin/osascript", Name: "osascript", Parent: stub}
		e := ev(event.CreateProcess, 1, p)
		s.Enrich(e)
		if e.Proc.Parent != nil {
			t.Errorf("%s: parent %+v, want nil", name, e.Proc.Parent)
		}
		for _, f := range []string{"ps.parent.exe", "ps.parent.pid", "ps.parent.name", "ps.parent.is_platform",
			"ps.parent.is_signed", "ps.parent.team_id", "ps.parent.signing_id", "ps.parent.cs_category", "ps.parent.uid"} {
			if v := e.Get(f); v != nil {
				t.Errorf("%s: %s = %v, want nil", name, f, v)
			}
		}
		s.Enrich(ev(event.TerminateProcess, 2, &event.Proc{PID: 4000, PIDVersion: 4001}))
	}
}

// TestSeededMarkOnProcAndParent: bootstrap entries carry Proc.Seeded (on the
// event's process, its Parent copy and a target) until an exec from ES
// replaces the image.
func TestSeededMarkOnProcAndParent(t *testing.T) {
	s := testSnap(MaxEntries)
	s.seed(event.Proc{PID: 1, Exe: "/sbin/launchd"})
	s.seed(event.Proc{PID: 60, PPID: 1, Exe: "/Applications/X.app/Contents/MacOS/X", StartTime: t0.Add(-time.Hour)})
	if p, _ := s.Lookup(60); !p.Seeded {
		t.Fatal("seeded entry not marked")
	}
	e := ev(event.CreateProcess, 1, &event.Proc{PID: 61, PPID: 60, PIDVersion: 61, Exe: "/usr/bin/osascript", Parent: &event.Proc{PID: 60}})
	s.Enrich(e)
	if e.Proc.Seeded || e.Proc.Parent == nil || !e.Proc.Parent.Seeded || e.Args[ArgParentIdentity] != Unverified ||
		!e.Proc.Parent.StartTime.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("child %+v parent %+v args %v", e.Proc, e.Proc.Parent, e.Args)
	}
	o := ev(event.OpenFile, 2, &event.Proc{PID: 60, Exe: "/Applications/X.app/Contents/MacOS/X"})
	s.Enrich(o)
	if !o.Proc.Seeded || o.Args[ArgIdentity] != Unverified {
		t.Fatalf("seeded event %+v %v", o.Proc, o.Args)
	}
	g := ev(event.OpenProcess, 3, &event.Proc{PID: 61, PIDVersion: 61, Exe: "/usr/bin/osascript"})
	g.Target = &event.Proc{PID: 60, Exe: "/Applications/X.app/Contents/MacOS/X"}
	s.Enrich(g)
	if !g.Target.Seeded {
		t.Fatal("seeded target not marked")
	}
	x := ev(event.CreateProcess, 4, &event.Proc{PID: 60, PPID: 1, PIDVersion: 70, Exe: "/bin/sh"})
	s.Enrich(x)
	if p, _ := s.Lookup(60); p.Seeded || x.Proc.Seeded {
		t.Fatal("exec from ES must clear Seeded")
	}
}

// TestReparentedKeepsRealParent: a double-forked child reparented to launchd
// has launchd as Parent; the fork-time parent stays visible only as
// ps.original_ppid, on the process and on Parent copies.
func TestReparentedKeepsRealParent(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)
	mal := &event.Proc{PID: 500, PPID: 200, OriginalPPID: 200, PIDVersion: 500, Exe: "/tmp/mal", Parent: &event.Proc{PID: 200, PIDVersion: 200}}
	s.Enrich(ev(event.CreateProcess, 1, mal))
	orphan := &event.Proc{PID: 600, PPID: 1, OriginalPPID: 500, PIDVersion: 600, Exe: "/tmp/mal", Parent: &event.Proc{PID: 1, PIDVersion: 1}}
	s.Enrich(ev(event.Fork, 2, orphan))
	osa := &event.Proc{PID: 700, PPID: 600, OriginalPPID: 600, PIDVersion: 700, Exe: "/usr/bin/osascript", Parent: &event.Proc{PID: 600, PIDVersion: 600}}
	e := ev(event.CreateProcess, 3, osa)
	s.Enrich(e)
	if e.Proc.Parent == nil || e.Proc.Parent.PID != 600 || e.Proc.Parent.OriginalPPID != 500 || e.Proc.Parent.PPID != 1 {
		t.Fatalf("parent %+v", e.Proc.Parent)
	}
	if e.Get("ps.parent.original_ppid") != int64(500) || e.Get("ps.original_ppid") != int64(600) {
		t.Errorf("fields %v %v", e.Get("ps.parent.original_ppid"), e.Get("ps.original_ppid"))
	}
	o := ev(event.OpenFile, 4, &event.Proc{PID: 600, PIDVersion: 600, Exe: "/tmp/mal", Parent: &event.Proc{PID: 1, PIDVersion: 1}})
	s.Enrich(o)
	if o.Proc.Parent == nil || o.Proc.Parent.PID != 1 || len(o.Proc.Ancestors) != 1 || o.Proc.Ancestors[0] != "/sbin/launchd" {
		t.Errorf("reparented process: parent %+v ancestors %v", o.Proc.Parent, o.Proc.Ancestors)
	}
}
