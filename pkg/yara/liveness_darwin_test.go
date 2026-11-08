//go:build yara && darwin

package yara

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func startTimeOf(t *testing.T, pid int) time.Time {
	t.Helper()
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		t.Fatal(err)
	}
	return time.Unix(kp.Proc.P_starttime.Sec, int64(kp.Proc.P_starttime.Usec)*1000)
}

// TestExecGoneWhileRunningReported (F5b): the binary of a process that is
// still running (same pid and start time) is deleted: reported. Once the
// process has exited, a deleted binary is normal (go run, test binaries):
// counted under exec_gone, not reported. A pid now held by a process with
// another start time is not the same incarnation: exec_gone too.
func TestExecGoneWhileRunningReported(t *testing.T) {
	sc, watch := setup(t, nil)
	h := &hookLog{}
	sc.OnDegraded(h.fn)
	out := make(chan *event.Event, 4)
	if err := sc.Start(t.Context(), out); err != nil {
		t.Fatal(err)
	}
	deleted := func(name string) (string, uint64, uint64, int64) {
		exe := filepath.Join(watch, name)
		write(t, exe, "\xcf\xfa\xed\xfeZAAFVESPER-TEST-MARKER-7f3a")
		dev, ino, ctime := statOf(t, exe)
		if err := os.Remove(exe); err != nil {
			t.Fatal(err)
		}
		return exe, dev, ino, ctime
	}

	// Short-lived: spawned, exited and reaped before the scan.
	short := exec.Command("/usr/bin/true")
	if err := short.Run(); err != nil {
		t.Fatal(err)
	}
	exe, dev, ino, ctime := deleted("gotest")
	sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: int32(short.Process.Pid), Exe: exe,
		StartTime: time.Now(), ExeDev: dev, ExeIno: ino, ExeCtimeNs: ctime}})
	waitStat(t, sc, "exec_gone", 1)

	// Long-lived: still running when its binary disappears.
	long := exec.Command("/bin/sleep", "30")
	if err := long.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = long.Process.Kill(); _ = long.Wait() })
	pid := long.Process.Pid
	start := startTimeOf(t, pid)

	// Same pid, other start time: a different incarnation, so gone.
	exe, dev, ino, ctime = deleted("recycled")
	sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: int32(pid), Exe: exe,
		StartTime: start.Add(-time.Second), ExeDev: dev, ExeIno: ino, ExeCtimeNs: ctime}})
	waitStat(t, sc, "exec_gone", 2)
	if calls := h.get(); len(calls) != 0 || sc.Stats()["exec_replaced"] != 0 {
		t.Fatalf("exited process reported: %q %v", calls, sc.Stats())
	}

	exe, dev, ino, ctime = deleted("selfdelete")
	sc.Submit(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: int32(pid), Exe: exe,
		StartTime: start, ExeDev: dev, ExeIno: ino, ExeCtimeNs: ctime}})
	waitStat(t, sc, "exec_replaced", 1)
	calls := h.get()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], CondExecReplaced+" pid="+strconv.Itoa(pid)+` path="`+exe+`" (gone while running: `) {
		t.Fatalf("hook calls %q", calls)
	}
	if st := sc.Stats(); st["exec_gone"] != 2 {
		t.Errorf("stats %v", st)
	}
}

// TestMountEventInvalidatesMountCache (F9 residual): a Mount event passing
// through Submit makes the next scan re-read the mount table at once, so a
// share mounted inside the refresh window is not missed (the cache's
// timestamp is reset).
func TestMountEventInvalidatesMountCache(t *testing.T) {
	sc, _ := setup(t, nil)
	nonLocalMounts() // fill the cache
	mountCache.Lock()
	filled := !mountCache.at.IsZero()
	mountCache.Unlock()
	if !filled {
		t.Fatal("cache not filled")
	}
	sc.Submit(&event.Event{Name: event.Mount, File: &event.File{Path: "/Volumes/share"}})
	mountCache.Lock()
	reset := mountCache.at.IsZero()
	mountCache.Unlock()
	if !reset {
		t.Fatal("Mount event did not invalidate the mount cache")
	}
	if st := sc.Stats(); st["submitted"] != 0 {
		t.Errorf("Mount event queued a scan: %v", st)
	}
}
