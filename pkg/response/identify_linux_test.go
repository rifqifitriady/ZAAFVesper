//go:build linux

package response

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestIdentifyLinuxSelf(t *testing.T) {
	id, err := identify(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if !id.UniqueKnown || id.UniqueID == 0 || !id.CSKnown || id.StartTime.IsZero() {
		t.Fatalf("identity %+v", id)
	}
	self, _ := os.Executable()
	if id.Exe != self || !id.HasFileID {
		t.Fatalf("exe %q (%v), want %q", id.Exe, id.HasFileID, self)
	}
	if d := time.Since(id.StartTime); d < -2*time.Second || d > time.Hour {
		t.Fatalf("start time %v is not plausible", id.StartTime)
	}
}

// TestLinuxVerifiedKill runs the real identify + pidfd kill path on a child.
func TestLinuxVerifiedKill(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	pid := int32(cmd.Process.Pid)
	id, err := identify(pid)
	if err != nil {
		t.Fatal(err)
	}
	// A kill with no identity read just before is refused.
	if _, err := takeStamp(pid); err != nil {
		t.Fatal(err) // identify remembered it
	}
	if err := defaultKill(int(pid), syscall.SIGKILL); err == nil || !strings.Contains(err.Error(), "no kernel identity") {
		t.Fatalf("kill without identity: %v", err)
	}
	// A stale identity (another start time) is refused and nothing is sent.
	rememberStamp(pid, id.UniqueID+1)
	if err := defaultKill(int(pid), syscall.SIGKILL); err == nil || !strings.Contains(err.Error(), "another process") {
		t.Fatalf("mismatched kill: %v", err)
	}
	if err := syscall.Kill(int(pid), 0); err != nil {
		t.Fatalf("child died after a refused kill: %v", err)
	}
	// Through the responder: the event's process (unique id and start time
	// from the kernel, as the Binder records them) is killed.
	r := New(Config{Log: func(Decision) {}})
	p := &event.Proc{PID: pid, Exe: id.Exe, Name: "sleep", UniqueID: id.UniqueID, StartTime: id.StartTime}
	if err := r.KillEvent(&event.Event{Proc: p, Source: "sysmon"}, "rule", "test"); err != nil {
		t.Fatalf("KillEvent: %v (stats %v)", err, r.Stats())
	}
	if err := cmd.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("child not killed: %v", err)
	}
}

func TestLinuxProtected(t *testing.T) {
	r := New(Config{Log: func(Decision) {}, KillFunc: func(int, syscall.Signal) error { t.Fatal("kill called"); return nil }})
	for _, p := range []*event.Proc{
		{PID: 1234, Exe: "/usr/lib/systemd/systemd-logind", Name: "systemd-logind", UniqueID: 1, StartTime: time.Now()},
		{PID: 1235, Exe: "/opt/sysmon/sysmon", Name: "sysmon", UniqueID: 1, StartTime: time.Now()},
		{PID: 1236, Exe: "/usr/bin/journalctl", Name: "journalctl", UniqueID: 1, StartTime: time.Now()},
	} {
		if err := r.KillProc(p, "t"); err == nil {
			t.Errorf("%s not protected", p.Exe)
		}
	}
	// A copy of malware named like a protected program is not protected.
	for _, p := range []*event.Proc{
		{PID: 1300, Exe: "/tmp/sysmon", Name: "sysmon"},
		{PID: 1301, Exe: "/dev/shm/systemd", Name: "systemd"},
		{PID: 1302, Exe: "/home/u/journalctl", Name: "journalctl"},
	} {
		if why := r.protectedReason(p); why != "" {
			t.Errorf("%s protected by name: %s", p.Exe, why)
		}
	}
}

// TestLinuxSuspendResume runs the suspend action and its timed resume on a
// child through the real identify and pidfd paths.
func TestLinuxSuspendResume(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	pid := int32(cmd.Process.Pid)
	id, err := identify(pid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := New(Config{Log: func(Decision) {}, SuspendFor: time.Second, Now: func() time.Time { return now }})
	p := &event.Proc{PID: pid, Exe: id.Exe, Name: "sleep", UniqueID: id.UniqueID, StartTime: id.StartTime}
	if err := r.SuspendEvent(&event.Event{Proc: p, Source: "sysmon"}, "rule", "test"); err != nil {
		t.Fatalf("SuspendEvent: %v (stats %v)", err, r.Stats())
	}
	state := func() byte {
		st, err := proc.Stat(pid)
		if err != nil {
			t.Fatal(err)
		}
		return st.State
	}
	// Signal delivery is asynchronous: wait for the state to change.
	waitState := func(stopped bool) byte {
		var s byte
		for i := 0; i < 100; i++ {
			if s = state(); (s == 'T' || s == 't') == stopped {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return s
	}
	if s := waitState(true); s != 'T' && s != 't' {
		t.Fatalf("state %c after suspend, want T (stats %v)", s, r.Stats())
	}
	now = now.Add(2 * time.Second)
	r.Tick(now)
	if s := waitState(false); s == 'T' || s == 't' {
		t.Fatalf("still stopped after the resume (stats %v)", r.Stats())
	}
}
