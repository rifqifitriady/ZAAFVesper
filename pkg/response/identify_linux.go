//go:build linux

package response

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
)

// Linux process identity. A pid is bound to one process by its start time in
// /proc/<pid>/stat (field 22, clock ticks since boot): Identity.UniqueID is
// that tick count and Identity.StartTime its wall-clock value. The Sysmon
// source records both for an event's process only when the event's
// ProcessGuid was seen at exec and the start read then is not later than
// the event (pkg/source/sysmon Binder).
//
// There is no code-signing "platform binary" flag: CSKnown is true with no
// flags. Protection rests on ProtectedNames, ProtectedExePrefixes and
// ProtectedExes (below) and the pid guards. Kernel threads have no
// executable, so their identity has ExeErr set and verify refuses them.

func init() {
	ProtectedNames = append(ProtectedNames, "systemd", "init", "systemd-journald", "journalctl", "sysmon", "zaafvesper")
	ProtectedExePrefixes = append(ProtectedExePrefixes, "/usr/lib/systemd/", "/lib/systemd/", "/opt/sysmon/")
	ProtectedExes = append(ProtectedExes, "/usr/bin/journalctl", "/bin/journalctl")
}

var proc = procfs.Default

func identify(pid int32) (Identity, error) {
	st, err := proc.Stat(pid)
	if err != nil {
		return Identity{}, err
	}
	if st.StartTicks == 0 {
		return Identity{}, fmt.Errorf("pid %d: no start time", pid)
	}
	bt, err := proc.BootTime()
	if err != nil {
		return Identity{}, err
	}
	id := Identity{StartTime: procfs.StartTime(bt, st.StartTicks), UniqueID: st.StartTicks, UniqueKnown: true, CSKnown: true}
	exe, deleted, err := proc.Exe(pid)
	switch {
	case err != nil:
		id.ExeErr = err
	case deleted:
		id.ExeErr = ErrExeUnlinked
	default:
		id.Exe = exe
		var s unix.Stat_t
		if err := unix.Lstat(exe, &s); err == nil && s.Mode&unix.S_IFMT == unix.S_IFREG {
			id.Dev, id.Ino, id.HasFileID = s.Dev, s.Ino, true
		}
	}
	rememberStamp(pid, st.StartTicks)
	return id, nil
}

// defaultKill opens a pidfd for pid, checks that the process now at pid has
// the start time identify read, then signals through the pidfd: if the
// process the pidfd names died and the pid was reused, the start time
// differs and nothing is sent. Kernels before 5.3 have no pidfd_open; then
// the check and kill(2) are separate calls and a pid reused in between
// would be hit (a window of microseconds, stated in the README).
func defaultKill(pid int, sig syscall.Signal) error {
	want, err := takeStamp(int32(pid))
	if err != nil {
		return err
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ENOSYS) {
		if err := checkStart(pid, want); err != nil {
			return err
		}
		return syscall.Kill(pid, sig)
	}
	if err != nil {
		return fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	defer unix.Close(fd)
	if err := checkStart(pid, want); err != nil {
		return err
	}
	return unix.PidfdSendSignal(fd, sig, nil, 0)
}

func checkStart(pid int, want uint64) error {
	st, err := proc.Stat(int32(pid))
	if err != nil {
		return err
	}
	if st.StartTicks != want {
		return fmt.Errorf("pid %d now started at tick %d, verified %d (another process; not signalled)", pid, st.StartTicks, want)
	}
	return nil
}
