//go:build windows

package response

import (
	"errors"
	"fmt"
	"os"
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
// with no flags. Protection rests on the image's full path
// (protectedWinImage in winprotect.go: critical System32 images, Sysmon,
// Defender, ZAAFVesper itself; case-insensitive, never a base name alone),
// the critical process flag and the pid guards. A critical process
// (IsProcessCritical: csrss, wininit, smss, services and others; terminating
// one stops Windows), a protected image, or a process whose image path
// cannot be read is never killed: identify returns an error, so the
// decision is refused-unknown-process with that reason. Pseudo-processes
// (System, Registry, Memory Compression, Secure System) cannot be opened,
// which refuses them the same way.

func init() {
	// The base list of protected names is macOS's (launchd, eslogger, ...);
	// matched by name on Windows it would only shield malware named that way.
	ProtectedNames = nil
}

// folders returns the Windows folders protectedWinImage compares against.
func folders() winFolders {
	f := winFolders{ProgramData: os.Getenv("ProgramData"), ProgramFiles: os.Getenv("ProgramFiles")}
	if d, err := windows.GetSystemWindowsDirectory(); err == nil {
		f.SystemRoot = d
	}
	if exe, err := os.Executable(); err == nil {
		f.Self = exe
	}
	return f
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
	exe, err := winproc.ImagePath(h)
	if err != nil {
		return Identity{}, fmt.Errorf("cannot read the image path of pid %d (protection unknown): %w", pid, err)
	}
	if why := protectedWinImage(exe, folders()); why != "" {
		return Identity{}, fmt.Errorf("%s: %s", why, exe)
	}
	id.Exe = exe
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
