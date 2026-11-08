package ps

import (
	"errors"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// TestUniqueIDRead: in live mode the table reads p_uniqueid when it first
// sees a process, only when the kernel's pidversion for that pid is the
// event's, and carries it on the event, Parent copies and through shedding.
// Replay (no reader) leaves it 0.
func TestUniqueIDRead(t *testing.T) {
	s := testSnap(MaxEntries)
	kernel := map[int32][2]uint64{1: {1, 1}, 100: {9100, 100}, 200: {9200, 200}, 300: {9300, 301}}
	reads := 0
	s.readUniq = func(pid int32) (uint64, uint32, error) {
		reads++
		k, ok := kernel[pid]
		if !ok {
			return 0, 0, errors.New("no such process")
		}
		return k[0], uint32(k[1]), nil
	}
	seed(s) // launchd 1, Terminal 100, zsh 200 (exec events)
	if p, _ := s.Lookup(200); p.UniqueID != 9200 {
		t.Fatalf("zsh unique id %d", p.UniqueID)
	}
	// Child exec: read; the event and the Parent copy carry ids.
	c := proc(300, 200, 301, "/usr/bin/osascript")
	c.Parent = &event.Proc{PID: 200, PIDVersion: 200}
	e := ev(event.CreateProcess, 1, c)
	s.Enrich(e)
	if e.Proc.UniqueID != 9300 || e.Proc.Parent == nil || e.Proc.Parent.UniqueID != 9200 {
		t.Fatalf("event %d parent %+v", e.Proc.UniqueID, e.Proc.Parent)
	}
	// A later event of the same process gets it from the table, no read.
	n := reads
	o := ev(event.OpenFile, 2, proc(300, 200, 301, "/usr/bin/osascript"))
	s.Enrich(o)
	if o.Proc.UniqueID != 9300 || reads != n {
		t.Errorf("open: id %d, %d new reads", o.Proc.UniqueID, reads-n)
	}
	// Pidversion differs from the kernel's (pid recycled before the read): 0.
	s.Enrich(ev(event.CreateProcess, 3, proc(100, 1, 555, "/bin/other")))
	if p, _ := s.Lookup(100); p.UniqueID != 0 {
		t.Errorf("recycled pid lent its id: %d", p.UniqueID)
	}
	// Failed read: 0.
	s.Enrich(ev(event.CreateProcess, 4, proc(400, 1, 400, "/bin/gone")))
	if p, _ := s.Lookup(400); p.UniqueID != 0 {
		t.Errorf("failed read gave %d", p.UniqueID)
	}
	// Shedding keeps it (identity skeleton).
	for s.shedOne(-1) {
	}
	if p, _ := s.Lookup(200); p.UniqueID != 9200 || hasDetails(&p) {
		t.Errorf("skeleton: %+v", p)
	}
	// Replay snapshotter: no reader, nothing read.
	r := NewSnapshotter(false)
	r.Enrich(ev(event.CreateProcess, 1, proc(300, 1, 301, "/usr/bin/osascript")))
	if p, _ := r.Lookup(300); p.UniqueID != 0 || r.readUniq != nil {
		t.Errorf("replay read a unique id: %d", p.UniqueID)
	}
}

// TestAncestorsUntrusted (security New-2): any ancestor up to launchd that
// is neither a platform binary nor a verified vendor (Team ID with a
// Developer ID / App Store category), or a chain that does not reach
// launchd, makes ps.ancestors_untrusted true.
func TestAncestorsUntrusted(t *testing.T) {
	s := testSnap(MaxEntries)
	launchd := &event.Proc{PID: 1, PIDVersion: 1, Exe: "/sbin/launchd", IsPlatform: true}
	s.Enrich(ev(event.CreateProcess, 0, launchd))
	add := func(p *event.Proc, parent int32) {
		p.PPID = parent
		p.Parent = &event.Proc{PID: parent}
		s.Enrich(ev(event.CreateProcess, 1, p))
	}
	osa := func(pid, parent int32) *event.Event {
		e := ev(event.CreateProcess, 2, &event.Proc{PID: pid, PPID: parent, PIDVersion: uint32(pid), Exe: "/usr/bin/osascript",
			IsPlatform: true, Parent: &event.Proc{PID: parent}})
		s.Enrich(e)
		return e
	}
	// Terminal (platform) -> zsh (platform) -> osascript: trusted.
	add(&event.Proc{PID: 100, PIDVersion: 100, Exe: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", IsPlatform: true}, 1)
	add(&event.Proc{PID: 101, PIDVersion: 101, Exe: "/bin/zsh", IsPlatform: true}, 100)
	e := osa(102, 101)
	if e.Get("ps.ancestors_untrusted") != false || e.Get("ps.parent.ancestors_untrusted") != false {
		t.Errorf("Terminal chain: %v %v", e.Get("ps.ancestors_untrusted"), e.Get("ps.parent.ancestors_untrusted"))
	}
	// Platform shell -> ad-hoc payload in ~/Documents -> osascript: untrusted.
	add(&event.Proc{PID: 200, PIDVersion: 200, Exe: "/bin/zsh", IsPlatform: true}, 1)
	add(&event.Proc{PID: 201, PIDVersion: 201, Exe: "/Users/alice/Documents/helper", SigningID: "helper-55554944"}, 200)
	e = osa(202, 201)
	if e.Get("ps.ancestors_untrusted") != true || e.Get("ps.parent.ancestors_untrusted") != false {
		t.Errorf("payload chain: %v %v", e.Get("ps.ancestors_untrusted"), e.Get("ps.parent.ancestors_untrusted"))
	}
	// A payload higher up taints the grandchild too.
	add(&event.Proc{PID: 203, PIDVersion: 203, Exe: "/bin/sh", IsPlatform: true}, 201)
	e = osa(204, 203)
	if e.Get("ps.ancestors_untrusted") != true || e.Get("ps.parent.ancestors_untrusted") != true {
		t.Errorf("grandchild: %v %v", e.Get("ps.ancestors_untrusted"), e.Get("ps.parent.ancestors_untrusted"))
	}
	// Verified Developer ID app -> osascript: trusted.
	add(&event.Proc{PID: 300, PIDVersion: 300, Exe: "/Applications/Vendor.app/Contents/MacOS/Vendor", TeamID: "ABCDE12345",
		SigningID: "com.vendor.app", IsSigned: true, CSCategory: event.CSDeveloperID}, 1)
	e = osa(301, 300)
	if e.Get("ps.ancestors_untrusted") != false {
		t.Errorf("Developer ID app: %v", e.Get("ps.ancestors_untrusted"))
	}
	// Same Team ID but self-signed (local_signing) or no category: untrusted.
	add(&event.Proc{PID: 310, PIDVersion: 310, Exe: "/Users/alice/Vendor", TeamID: "ABCDE12345", IsSigned: true, CSCategory: event.CSLocalSigning}, 1)
	if e = osa(311, 310); e.Get("ps.ancestors_untrusted") != true {
		t.Error("forged Team ID trusted")
	}
	add(&event.Proc{PID: 320, PIDVersion: 320, Exe: "/Users/alice/Vendor2", TeamID: "ABCDE12345", IsSigned: true}, 1)
	if e = osa(321, 320); e.Get("ps.ancestors_untrusted") != true {
		t.Error("Team ID without a category trusted")
	}
	// Incomplete chain: parent unknown, or a known parent whose parent is not.
	if e = osa(401, 777); e.Get("ps.ancestors_untrusted") != true || e.Proc.Parent != nil {
		t.Errorf("unknown parent: %v", e.Get("ps.ancestors_untrusted"))
	}
	add(&event.Proc{PID: 500, PIDVersion: 500, Exe: "/bin/zsh", IsPlatform: true}, 888)
	if e = osa(501, 500); e.Get("ps.ancestors_untrusted") != true || e.Get("ps.parent.ancestors_untrusted") != true {
		t.Errorf("chain broken above parent: %v", e.Get("ps.ancestors_untrusted"))
	}
	// launchd itself, and a direct child of launchd.
	l := ev(event.OpenFile, 3, &event.Proc{PID: 1, PIDVersion: 1, Exe: "/sbin/launchd", IsPlatform: true})
	s.Enrich(l)
	if l.Proc.AncestorsUntrusted {
		t.Error("launchd untrusted")
	}
	if e = osa(601, 1); e.Get("ps.ancestors_untrusted") != false {
		t.Error("child of launchd untrusted")
	}
}

// TestAncestorsUntrustedDepthBound: a chain deeper than MaxAncestors never
// reaches launchd inside the bound and counts as incomplete.
func TestAncestorsUntrustedDepthBound(t *testing.T) {
	s := testSnap(MaxEntries)
	s.Enrich(ev(event.CreateProcess, 0, &event.Proc{PID: 1, PIDVersion: 1, Exe: "/sbin/launchd", IsPlatform: true}))
	parent := int32(1)
	for i := int32(0); i < MaxAncestors+2; i++ {
		pid := 1000 + i
		s.Enrich(ev(event.CreateProcess, 1, &event.Proc{PID: pid, PPID: parent, PIDVersion: uint32(pid), Exe: "/bin/sh",
			IsPlatform: true, Parent: &event.Proc{PID: parent}}))
		parent = pid
	}
	e := ev(event.CreateProcess, 2, &event.Proc{PID: 5000, PPID: parent, PIDVersion: 5000, Exe: "/bin/sh", IsPlatform: true, Parent: &event.Proc{PID: parent}})
	s.Enrich(e)
	if len(e.Proc.Ancestors) != MaxAncestors || !e.Proc.AncestorsUntrusted {
		t.Errorf("ancestors %d untrusted %v", len(e.Proc.Ancestors), e.Proc.AncestorsUntrusted)
	}
}
