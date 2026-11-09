//go:build linux

package response

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// liveExeID returns the inode of the image the process of the event runs
// now (the /proc/<pid>/exe link names the mapped file, even after a rename
// or unlink), after checking twice, around the stat, that the pid is still
// that process (start ticks: the event's UniqueID). It is the binding of
// quarantine_file target process when the event carries no inode (Sysmon).
// A process that exited, or one the event cannot identify, gives none.
func (r *Responder) liveExeID(p *event.Proc) (dev, ino uint64, ok bool) {
	dev, ino, err := r.liveExe(p)
	return dev, ino, err == nil
}

func (r *Responder) liveExe(p *event.Proc) (dev, ino uint64, err error) {
	if p == nil || p.UniqueID == 0 || p.PID <= 1 {
		return 0, 0, fmt.Errorf("no process identity")
	}
	same := func() error {
		id, err := r.cfg.Identify(p.PID)
		switch {
		case err != nil:
			return err
		case !id.UniqueKnown || id.UniqueID != p.UniqueID:
			return fmt.Errorf("pid %d is now another process (start %d, event %d)", p.PID, id.UniqueID, p.UniqueID)
		}
		return nil
	}
	if err := same(); err != nil {
		return 0, 0, err
	}
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/exe", p.PID), &st); err != nil {
		return 0, 0, fmt.Errorf("stat /proc/%d/exe: %w", p.PID, err)
	}
	if err := same(); err != nil {
		return 0, 0, err
	}
	return st.Dev, st.Ino, nil
}

// BindExecutable returns e with the inode of its process's running image
// filled in (Proc.ExeDev, Proc.ExeIno) when the event has none, so that a
// quarantine_file with target process, which runs later on the worker,
// stays bound to that image even when a kill of the same rule ends the
// process first. e itself is not changed: a copy is returned.
func (r *Responder) BindExecutable(e *event.Event) *event.Event {
	if e == nil || e.Proc == nil || e.Proc.ExeDev != 0 || e.Proc.ExeIno != 0 {
		return e
	}
	dev, ino, ok := r.liveExeID(e.Proc)
	if !ok {
		return e
	}
	c := *e
	p := *e.Proc
	p.ExeDev, p.ExeIno = dev, ino
	c.Proc = &p
	return &c
}
