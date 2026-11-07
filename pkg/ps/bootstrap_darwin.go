//go:build darwin

package ps

import (
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// listProcesses reads the running processes with sysctl kern.proc.all and,
// per pid, kern.procargs2 for the executable path, argv and environment.
// procargs2 needs root for other users' processes; those entries then carry
// only the short command name.
func listProcesses() ([]event.Proc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]event.Proc, 0, len(kps))
	for i := range kps {
		kp := &kps[i]
		pid := kp.Proc.P_pid
		if pid <= 0 {
			continue // kernel_task (pid 0) never appears in ES events as a process
		}
		p := event.Proc{
			PID:       pid,
			PPID:      kp.Eproc.Ppid,
			UID:       int64(kp.Eproc.Pcred.P_ruid),
			EUID:      int64(kp.Eproc.Ucred.Uid),
			Name:      cString(kp.Proc.P_comm[:]),
			StartTime: time.Unix(kp.Proc.P_starttime.Sec, int64(kp.Proc.P_starttime.Usec)*1000).UTC(),
		}
		if raw, err := unix.SysctlRaw("kern.procargs2", int(pid)); err == nil {
			exe, args, env := parseProcArgs(raw)
			if exe != "" {
				p.Exe, p.Name = exe, filepath.Base(exe)
			}
			p.Args, p.Env = args, env
			p.Cmdline = joinCap(args, bootMaxCmdline)
		}
		out = append(out, p)
	}
	return out, nil
}

func cString[T ~int8 | ~uint8](b []T) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
