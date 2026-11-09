package sysmonlinux

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
)

func TestFixThreadParent(t *testing.T) {
	tg := map[int32]int32{5212: 5209, 5209: 5209}
	tgid := func(id int32) (int32, error) {
		if g, ok := tg[id]; ok {
			return g, nil
		}
		return 0, errors.New("gone")
	}
	t0 := time.Date(2026, 11, 9, 7, 0, 0, 0, time.UTC)
	starts := map[int32]time.Time{5209: t0.Add(-time.Minute)}
	started := func(pid int32) (time.Time, error) {
		if s, ok := starts[pid]; ok {
			return s, nil
		}
		return time.Time{}, errors.New("gone")
	}
	fix := func(e *event.Event) { FixThreadParent(e, tgid, started, 20*time.Millisecond) }
	mk := func(ppid int32, exe string) *event.Event {
		return &event.Event{Name: event.CreateProcess, Time: t0, Proc: &event.Proc{PID: 5622, PPID: ppid,
			Parent: &event.Proc{PID: ppid, PIDVersion: 7, GUID: "{x}", Exe: exe}}}
	}
	// A thread of a multi-threaded parent, unresolved by Sysmon: fixed.
	e := mk(5212, "")
	fix(e)
	if e.Proc.PPID != 5209 || e.Proc.Parent.PID != 5209 || e.Proc.Parent.PIDVersion != 0 || e.Args[ArgParentThread] != "5212" {
		t.Fatalf("not fixed: %+v %v", e.Proc, e.Args)
	}
	// Sysmon named the parent, the id is a process, or the thread is gone: untouched.
	for _, c := range []*event.Event{mk(5212, "/usr/bin/java"), mk(5209, ""), mk(4444, "")} {
		fix(c)
		if c.Proc.Parent.PIDVersion != 7 || c.Args != nil {
			t.Fatalf("changed: %+v", c.Proc)
		}
	}
	// The thread id now belongs to a process that started after the event
	// (reused): not attached.
	starts[5209] = t0.Add(time.Second)
	r := mk(5212, "")
	fix(r)
	if r.Proc.PPID != 5212 || r.Args != nil {
		t.Fatalf("reused thread id attached: %+v", r.Proc)
	}
	starts[5209] = t0.Add(-time.Minute)
	// Other events are never touched.
	o := mk(5212, "")
	o.Name = event.CreateFile
	fix(o)
	if o.Proc.PPID != 5212 {
		t.Fatal("non-create event changed")
	}
}

// TestLiveThreadParentFixture replays a Sysmon for Linux event captured on a
// live runner (testdata/README.md) through the feeder with the Linux fix:
// the parent thread id becomes the JVM's process id.
func TestLiveThreadParentFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/live_java_child_thread_parent.xml")
	if err != nil {
		t.Fatal(err)
	}
	evTime := time.Date(2026, 11, 9, 10, 32, 18, 844e6, time.UTC)
	tgid := func(id int32) (int32, error) {
		if id == 5600 {
			return 5598, nil
		}
		return id, nil
	}
	started := func(int32) (time.Time, error) { return evTime.Add(-2 * time.Second), nil }
	f := sysmon.NewFeeder(nil, nil)
	f.Fix = func(e *event.Event) { FixThreadParent(e, tgid, started, IdentityTolerance) }
	out := make(chan *event.Event, 1)
	if err := f.Handle(context.Background(), raw, out); err != nil {
		t.Fatal(err)
	}
	e := <-out
	if e.Name != event.CreateProcess || e.Proc.Exe != "/usr/bin/dash" || e.Proc.Cmdline != "/bin/sh -c id" {
		t.Fatalf("decoded %+v", e.Proc)
	}
	if e.Proc.PPID != 5598 || e.Proc.Parent == nil || e.Proc.Parent.PID != 5598 || e.Args[ArgParentThread] != "5600" {
		t.Fatalf("parent not fixed: ppid %d parent %+v args %v", e.Proc.PPID, e.Proc.Parent, e.Args)
	}
}
