//go:build yara && darwin

package yara

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// isLocalFS reports whether fd lies on a local file system (MNT_LOCAL).
func isLocalFS(fd int) (bool, error) {
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &sfs); err != nil {
		return false, err
	}
	return sfs.Flags&unix.MNT_LOCAL != 0, nil
}

const (
	// mountRefresh: the mount table is re-read at most this often.
	mountRefresh = 5 * time.Second
	// maxMounts bounds the mount table read (and so the list kept).
	maxMounts = 1024
)

var mountCache struct {
	sync.Mutex
	at       time.Time
	nonLocal []string
}

// nonLocalMounts returns the mount points without MNT_LOCAL, from
// getfsstat(MNT_NOWAIT) (cached statfs data: it never waits on a server),
// re-read at most every mountRefresh. On error the previous list is kept;
// the per-descriptor check still applies.
func nonLocalMounts() []string {
	mountCache.Lock()
	defer mountCache.Unlock()
	if !mountCache.at.IsZero() && time.Since(mountCache.at) < mountRefresh {
		return mountCache.nonLocal
	}
	mountCache.at = time.Now()
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return mountCache.nonLocal
	}
	buf := make([]unix.Statfs_t, min(n+8, maxMounts))
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return mountCache.nonLocal
	}
	var out []string
	for i := range buf[:min(n, len(buf))] {
		if buf[i].Flags&unix.MNT_LOCAL == 0 {
			out = append(out, cString(buf[i].Mntonname[:]))
		}
	}
	mountCache.nonLocal = out
	return out
}

// invalidateMounts makes the next nonLocalMounts call re-read the table.
func invalidateMounts() {
	mountCache.Lock()
	mountCache.at = time.Time{}
	mountCache.Unlock()
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// procAlive reports whether pid is still the process that started at start
// (kern.proc.pid start time within 1 ms; pids are allocated sequentially,
// so reuse within 1 ms does not happen). A zero start time checks only that
// the pid exists. A pid that is gone (sysctl returns no entry) or now
// belongs to a later process is not alive. Any other error counts as alive,
// so an unverifiable case is reported rather than silenced.
func procAlive(pid int32, start time.Time) bool {
	if pid <= 0 {
		return true
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return !errors.Is(err, unix.EIO) && !errors.Is(err, unix.ESRCH)
	}
	if kp.Proc.P_pid != pid {
		return false
	}
	if start.IsZero() {
		return true
	}
	got := time.Unix(kp.Proc.P_starttime.Sec, int64(kp.Proc.P_starttime.Usec)*1000)
	d := got.Sub(start)
	return d < time.Millisecond && d > -time.Millisecond
}
