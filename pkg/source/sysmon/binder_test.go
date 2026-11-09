package sysmon

import (
	"errors"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestBinder(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	kernel := map[int32]Stamp{}
	b := NewBinder(func(pid int32) (Stamp, error) {
		s, ok := kernel[pid]
		if !ok {
			return Stamp{}, errors.New("no such process")
		}
		return s, nil
	}, 2*time.Millisecond)
	proc := func(pid int32, guid string) *event.Proc { return &event.Proc{PID: pid, GUID: guid} }

	// Created at the event time: bound.
	kernel[100] = Stamp{ID: 77, Start: t0.Add(-time.Millisecond), Precise: t0.Add(-time.Millisecond)}
	c := &event.Event{Name: event.CreateProcess, Time: t0, Proc: proc(100, "{G1}")}
	c.Proc.PPID = 99
	b.Bind(c)
	if c.Proc.UniqueID != 77 || !c.Proc.StartTime.Equal(t0.Add(-time.Millisecond)) {
		t.Fatalf("create not bound: %+v", c.Proc)
	}
	// A later event of the same GUID (any case) gets the identity.
	f := &event.Event{Name: event.CreateFile, Time: t0.Add(time.Second), Proc: proc(100, "{g1}")}
	b.Bind(f)
	if f.Proc.UniqueID != 77 || f.Proc.PPID != 99 {
		t.Fatalf("same GUID not matched: %+v", f.Proc)
	}
	// Another GUID on the same pid (recycled behind our back): none.
	o := &event.Event{Name: event.CreateFile, Time: t0.Add(time.Second), Proc: proc(100, "{G2}"), Target: proc(100, "{G1}")}
	o.Proc.UniqueID = 99 // a source value must not survive
	b.Bind(o)
	if o.Proc.UniqueID != 0 || o.Target.UniqueID != 77 {
		t.Fatalf("other GUID: proc %+v target %+v", o.Proc, o.Target)
	}
	// The pid now belongs to a process created after the event: not bound.
	kernel[200] = Stamp{ID: 88, Start: t0.Add(time.Second), Precise: t0.Add(time.Second)}
	l := &event.Event{Name: event.CreateProcess, Time: t0, Proc: proc(200, "{G3}")}
	b.Bind(l)
	if l.Proc.UniqueID != 0 || !l.Proc.StartTime.IsZero() {
		t.Fatalf("late process bound: %+v", l.Proc)
	}
	ll := &event.Event{Name: event.CreateFile, Time: t0, Proc: proc(200, "{G3}")}
	b.Bind(ll)
	if ll.Proc.UniqueID != 0 || !ll.Proc.StartTime.IsZero() {
		t.Fatalf("later event of a late process got an identity: %+v", ll.Proc)
	}
	// Unreadable process, or no GUID: not bound.
	u := &event.Event{Name: event.CreateProcess, Time: t0, Proc: proc(300, "{G4}")}
	b.Bind(u)
	n := &event.Event{Name: event.CreateProcess, Time: t0, Proc: proc(100, "")}
	b.Bind(n)
	if u.Proc.UniqueID != 0 || n.Proc.UniqueID != 0 {
		t.Fatal("bound without identity")
	}
	// The create without GUID on pid 100 forgot the old binding.
	again := &event.Event{Name: event.CreateFile, Time: t0, Proc: proc(100, "{G1}")}
	b.Bind(again)
	if again.Proc.UniqueID != 0 {
		t.Fatal("binding survived a new create on the pid")
	}
	// Terminate forgets the pid.
	kernel[400] = Stamp{ID: 5, Start: t0, Precise: t0}
	b.Bind(&event.Event{Name: event.CreateProcess, Time: t0, Proc: proc(400, "{G5}")})
	term := &event.Event{Name: event.TerminateProcess, Time: t0, Proc: proc(400, "{G5}")}
	b.Bind(term)
	after := &event.Event{Name: event.CreateFile, Time: t0, Proc: proc(400, "{G5}")}
	b.Bind(after)
	if term.Proc.UniqueID != 5 || after.Proc.UniqueID != 0 {
		t.Fatalf("terminate: %+v after %+v", term.Proc, after.Proc)
	}
	st := b.Stats()
	if st["identity_bound"] != 2 || st["identity_late"] != 1 || st["identity_read_errors"] != 1 {
		t.Fatalf("stats %v", st)
	}
}
