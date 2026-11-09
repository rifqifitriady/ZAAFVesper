//go:build windows

package response

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/rifqifitriady/ZAAFVesper/pkg/winproc"
)

// Windows process identity. A pid is bound to one process by its creation
// time (GetProcessTimes, 100 ns FILETIME): Identity.UniqueID is that raw
// FILETIME and Identity.StartTime the same instant. The Sysmon source
// records both for an event's process only when the event's ProcessGuid
// was seen at process creation and the creation time read then is not
// later than the event (pkg/source/sysmon Binder), so verify's unique-id
// and start-time comparison is a ProcessGuid plus creation-time check.
//
// There is no code-signing "platform binary" flag here: CSKnown is true
// with no flags. Protection rests on ProtectedNames (below), the critical
// process flag and the pid guards. A critical process (IsProcessCritical:
// csrss, wininit, smss, services and others; terminating one stops Windows)
// is never killed: identify returns an error, so the decision is
// refused-unknown-process with that reason.

func init() {
	ProtectedNames = append(ProtectedNames,
		"System", "Registry", "Memory Compression", "Secure System",
		"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
		"lsass.exe", "LsaIso.exe", "fontdrvhost.exe", "dwm.exe",
		"Sysmon.exe", "Sysmon64.exe", "Sysmon64a.exe", "MsMpEng.exe", "zaafvesper.exe")
}

// errCritical is returned for critical system processes.
var errCritical = errors.New("critical system process (terminating it stops Windows)")

func identify(pid int32) (Identity, error) {
	if pid <= 4 { // 0 Idle, 4 System
		return Identity{}, fmt.Errorf("pid %d is a kernel process", pid)
	}
	h, err := winproc.OpenQuery(uint32(pid))
	if err != nil {
		return Identity{}, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	ft, start, err := winproc.CreationTime(h)
	if err != nil {
		return Identity{}, err
	}
	crit, err := winproc.IsCritical(h)
	if err != nil {
		return Identity{}, fmt.Errorf("cannot tell whether pid %d is critical: %w", pid, err)
	}
	if crit {
		return Identity{}, errCritical
	}
	id := Identity{StartTime: start, UniqueID: ft, UniqueKnown: true, CSKnown: true}
	if exe, err := winproc.ImagePath(h); err != nil {
		id.ExeErr = err
	} else {
		id.Exe = exe
	}
	rememberStamp(pid, ft)
	return id, nil
}

// defaultKill opens the pid with PROCESS_TERMINATE, checks on that handle
// that its creation time is the one identify read, then terminates the
// process behind the same handle. sig is ignored (only SIGKILL is used).
func defaultKill(pid int, _ syscall.Signal) error {
	want, err := takeStamp(int32(pid))
	if err != nil {
		return err
	}
	h, err := winproc.Open(uint32(pid), windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	ft, _, err := winproc.CreationTime(h)
	if err != nil {
		return err
	}
	if ft != want {
		return fmt.Errorf("pid %d now has creation time %d, verified %d (another process; not terminated)", pid, ft, want)
	}
	if crit, err := winproc.IsCritical(h); err != nil || crit {
		return fmt.Errorf("pid %d: %v", pid, errors.Join(errCritical, err))
	}
	return windows.TerminateProcess(h, 1)
}
