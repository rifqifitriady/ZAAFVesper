package sysmonlinux

import (
	"strconv"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// ArgParentThread is the evt.arg key set when FixThreadParent replaced a
// parent thread id by its process id; it holds the thread id Sysmon reported.
const ArgParentThread = "parent_thread_id"

// FixThreadParent corrects the parent of a CreateProcess event from Sysmon
// for Linux. Sysmon reports the id of the thread that forked as
// ParentProcessId; when the parent is multi-threaded (a JVM, a Go program,
// most servers) that id is a thread, not a process, and Sysmon then cannot
// name the parent either (ParentImage "-"). The process table would then
// have no parent, and every ps.parent.* field would be nil. Found by the
// v0.3 live run on an Ubuntu runner ("Suspicious Java Children Processes"
// did not fire).
//
// When the event's parent has no image, tgid maps the reported id to its
// thread group; if that differs, the event's PPID and parent stub become the
// process (its incarnation unknown, so the table accepts its current entry),
// and evt.arg[parent_thread_id] keeps the thread id. tgid fails when the
// thread is gone; the event is then left as Sysmon reported it.
//
// The mapping is read some time after the fork (journald delay), so the
// thread id could meanwhile belong to another process. started gives the
// start time of the process found; when it started after the event (plus
// tolerance), it cannot be the parent and the event is left unchanged.
func FixThreadParent(e *event.Event, tgid func(int32) (int32, error), started func(int32) (time.Time, error), tolerance time.Duration) {
	if e == nil || e.Name != event.CreateProcess || e.Proc == nil {
		return
	}
	p := e.Proc
	par := p.Parent
	if par == nil || par.PID <= 0 || par.Exe != "" {
		return
	}
	g, err := tgid(par.PID)
	if err != nil || g <= 0 || g == par.PID {
		return
	}
	if st, err := started(g); err != nil || e.Time.IsZero() || st.After(e.Time.Add(tolerance)) {
		return
	}
	if e.Args == nil {
		e.Args = map[string]string{}
	}
	e.Args[ArgParentThread] = strconv.Itoa(int(par.PID))
	p.PPID = g
	p.Parent = &event.Proc{PID: g, UID: -1, EUID: -1}
}
