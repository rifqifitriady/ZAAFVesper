//go:build windows

package ps

import (
	"golang.org/x/sys/windows"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/winproc"
)

// listProcesses reads the running processes from a Toolhelp32 snapshot
// (pid, parent pid, image base name) and, where PROCESS_QUERY_LIMITED_INFORMATION
// is granted, the full image path, creation time and command line
// (Windows 8.1+). Windows parent pids are not reference-counted: a parent
// that exited may have its pid reused, so seeded parent links are a best
// effort. These entries are seeded (unverified) and never killed.
func listProcesses() ([]event.Proc, error) {
	ents, err := winproc.Snapshot()
	if err != nil && len(ents) == 0 {
		return nil, err
	}
	out := make([]event.Proc, 0, len(ents))
	for _, e := range ents {
		if e.PID == 0 {
			continue // System Idle Process
		}
		p := event.Proc{PID: int32(e.PID), PPID: int32(e.PPID), Name: e.ExeFile, UID: -1, EUID: -1}
		if h, err := winproc.OpenQuery(e.PID); err == nil {
			if exe, err := winproc.ImagePath(h); err == nil && exe != "" {
				p.Exe = exe
			}
			if _, t, err := winproc.CreationTime(h); err == nil {
				p.StartTime = t
			}
			if cl, err := winproc.CommandLine(h); err == nil && cl != "" {
				p.Cmdline = cl
				p.Args = winproc.SplitCommandLine(cl, bootMaxArgs)
			}
			_ = windows.CloseHandle(h)
		}
		out = append(out, p)
	}
	return out, err
}
