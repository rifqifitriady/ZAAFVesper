//go:build linux

package ps

import (
	"path/filepath"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
)

// listProcesses reads the running processes from /proc: parent and start
// time from /proc/<pid>/stat, uids from status, the executable, argv
// (64 KiB) and cwd. A process can rewrite its own argv, so, as on macOS,
// these entries are seeded (unverified) and never killed. The environment
// is not read. Processes that exit during the walk are skipped.
func listProcesses() ([]event.Proc, error) {
	fs := procfs.Default
	pids, err := fs.PIDs()
	if err != nil {
		return nil, err
	}
	bt, btErr := fs.BootTime()
	out := make([]event.Proc, 0, len(pids))
	for _, pid := range pids {
		st, err := fs.Stat(pid)
		if err != nil {
			continue
		}
		p := event.Proc{PID: pid, PPID: st.PPID, Name: st.Comm, UID: -1, EUID: -1}
		if btErr == nil {
			p.StartTime = procfs.StartTime(bt, st.StartTicks)
		}
		if r, e, err := fs.UIDs(pid); err == nil {
			p.UID, p.EUID = r, e
		}
		if exe, _, err := fs.Exe(pid); err == nil && exe != "" {
			p.Exe, p.Name = exe, filepath.Base(exe)
		}
		if args, _, err := fs.Cmdline(pid); err == nil && len(args) > 0 {
			p.Args, p.Cmdline = args, joinCap(args, bootMaxCmdline)
		}
		if cwd, err := fs.Cwd(pid); err == nil {
			p.Cwd = cwd
		}
		out = append(out, p)
	}
	return out, nil
}
