package sysmonlinux

import (
	"errors"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestFixThreadParent(t *testing.T) {
	tg := map[int32]int32{5212: 5209, 5209: 5209}
	tgid := func(id int32) (int32, error) {
		if g, ok := tg[id]; ok {
			return g, nil
		}
		return 0, errors.New("gone")
	}
	mk := func(ppid int32, exe string) *event.Event {
		return &event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: 5622, PPID: ppid,
			Parent: &event.Proc{PID: ppid, PIDVersion: 7, GUID: "{x}", Exe: exe}}}
	}
	// A thread of a multi-threaded parent, unresolved by Sysmon: fixed.
	e := mk(5212, "")
	FixThreadParent(e, tgid)
	if e.Proc.PPID != 5209 || e.Proc.Parent.PID != 5209 || e.Proc.Parent.PIDVersion != 0 || e.Args[ArgParentThread] != "5212" {
		t.Fatalf("not fixed: %+v %v", e.Proc, e.Args)
	}
	// Sysmon named the parent, the id is a process, or the thread is gone: untouched.
	for _, c := range []*event.Event{mk(5212, "/usr/bin/java"), mk(5209, ""), mk(4444, "")} {
		FixThreadParent(c, tgid)
		if c.Proc.Parent.PIDVersion != 7 || c.Args != nil {
			t.Fatalf("changed: %+v", c.Proc)
		}
	}
	// Other events are never touched.
	o := mk(5212, "")
	o.Name = event.CreateFile
	FixThreadParent(o, tgid)
	if o.Proc.PPID != 5212 {
		t.Fatal("non-create event changed")
	}
}
