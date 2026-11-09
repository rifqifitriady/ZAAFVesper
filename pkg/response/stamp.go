//go:build windows || linux

package response

import (
	"errors"
	"sync"
)

// On Windows and Linux the identity read by identify (the kernel's start
// stamp of the pid) is remembered for the kill that follows, and the kill
// re-reads the stamp on the very handle (Windows process handle, Linux
// pidfd) it then terminates or signals. Between verify and the kill the pid
// can therefore not be swapped for another process. decide calls Identify
// and KillFunc under the responder's lock, so the entry is the one verify
// just read.
var (
	stampMu sync.Mutex
	stamps  = map[int32]uint64{}
)

const maxStamps = 256

func rememberStamp(pid int32, stamp uint64) {
	stampMu.Lock()
	defer stampMu.Unlock()
	if len(stamps) >= maxStamps {
		clear(stamps)
	}
	stamps[pid] = stamp
}

// takeStamp returns and forgets the stamp identify read for pid.
func takeStamp(pid int32) (uint64, error) {
	stampMu.Lock()
	defer stampMu.Unlock()
	s, ok := stamps[pid]
	delete(stamps, pid)
	if !ok || s == 0 {
		return 0, errors.New("no kernel identity was read for this pid right before the kill (refusing)")
	}
	return s, nil
}
