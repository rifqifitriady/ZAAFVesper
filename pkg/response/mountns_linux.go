//go:build linux

package response

import (
	"errors"
	"fmt"
	"os"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// writerMountNS checks that the writer of a file bound by creation time or
// hash sees the same file system as this sensor: its mount namespace
// (/proc/<pid>/ns/mnt) must be the host's (/proc/1/ns/mnt), which must be
// the sensor's too. A process in a container names paths in its own mount
// namespace: /tmp/x there is another file than the host's /tmp/x, and an
// event about it must not make root act on the host's file. The pid is
// checked around the read to still be the event's process (start ticks:
// UniqueID). A writer that has exited, or one the event cannot identify,
// cannot be checked: refused (fail closed).
func (r *Responder) writerMountNS(p *event.Proc) error {
	if p == nil || p.PID <= 0 {
		return errors.New("the event names no writer process")
	}
	if p.UniqueID == 0 {
		return fmt.Errorf("pid %d has no start identity in the event; its mount namespace cannot be checked", p.PID)
	}
	same := func() error {
		id, err := r.cfg.Identify(p.PID)
		switch {
		case err != nil:
			return fmt.Errorf("the writer (pid %d) is gone or unreadable (%v); its mount namespace cannot be checked", p.PID, err)
		case !id.UniqueKnown || id.UniqueID != p.UniqueID:
			return fmt.Errorf("pid %d is now another process; the writer's mount namespace cannot be checked", p.PID)
		}
		return nil
	}
	host, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return fmt.Errorf("cannot read the host mount namespace: %v", err)
	}
	if self, err := os.Readlink("/proc/self/ns/mnt"); err != nil || self != host {
		return fmt.Errorf("the sensor does not run in the host mount namespace (%s, host %s, %v)", self, host, err)
	}
	if err := same(); err != nil {
		return err
	}
	w, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", p.PID))
	if err != nil {
		return fmt.Errorf("cannot read the writer's mount namespace (pid %d): %v", p.PID, err)
	}
	if err := same(); err != nil {
		return err
	}
	if w != host {
		return fmt.Errorf("the writer (pid %d) runs in another mount namespace (%s, host %s): the event's path names a file of its namespace, not this host's", p.PID, w, host)
	}
	return nil
}
