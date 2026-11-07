//go:build darwin

package response

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// identify reads the process start time (kern.proc.pid, p_starttime) and the
// executable path recorded at exec (kern.procargs2) without cgo. procargs2
// holds the path given to execve, which can be relative; callers compare
// base names. Root can read every process; others only their own.
func identify(pid int32) (Identity, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return Identity{}, err
	}
	if kp.Proc.P_pid != pid {
		return Identity{}, fmt.Errorf("pid %d not found", pid)
	}
	id := Identity{StartTime: time.Unix(int64(kp.Proc.P_starttime.Sec), int64(kp.Proc.P_starttime.Usec)*1000).UTC()}
	raw, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil {
		return id, fmt.Errorf("kern.procargs2: %w", err)
	}
	exe, err := procargsExe(raw)
	if err != nil {
		return id, err
	}
	id.Exe = exe
	return id, nil
}

// procargsExe extracts the exec path that follows argc in a procargs2 buffer.
func procargsExe(b []byte) (string, error) {
	if len(b) < 4 {
		return "", errors.New("kern.procargs2: short buffer")
	}
	rest := b[4:]
	_ = binary.LittleEndian.Uint32(b[:4]) // argc
	for i, c := range rest {
		if c == 0 {
			if i == 0 {
				return "", errors.New("kern.procargs2: empty exec path")
			}
			return string(rest[:i]), nil
		}
	}
	return "", errors.New("kern.procargs2: unterminated exec path")
}
