//go:build windows

package response

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestIdentifyWindowsSelf(t *testing.T) {
	// The running binary is ZAAFVesper's own image (protectedWinImage):
	// never identified for an action.
	if _, err := identify(int32(os.Getpid())); err == nil || !strings.Contains(err.Error(), "ZAAFVesper itself") {
		t.Fatalf("own process: %v", err)
	}
	cmd := exec.Command("ping", "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	id, err := identify(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if !id.UniqueKnown || id.UniqueID == 0 || !id.CSKnown || id.StartTime.IsZero() || id.Exe == "" {
		t.Fatalf("identity %+v", id)
	}
	if _, err := identify(4); err == nil {
		t.Fatal("System (pid 4) identified")
	}
}

func TestWindowsVerifiedKill(t *testing.T) {
	cmd := exec.Command("ping", "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	pid := int32(cmd.Process.Pid)
	id, err := identify(pid)
	if err != nil {
		t.Fatal(err)
	}
	rememberStamp(pid, id.UniqueID+1)
	if err := defaultKill(int(pid), syscall.SIGKILL); err == nil || !strings.Contains(err.Error(), "another process") {
		t.Fatalf("mismatched kill: %v", err)
	}
	r := New(Config{Log: func(Decision) {}})
	p := &event.Proc{PID: pid, Exe: id.Exe, Name: "PING.EXE", UniqueID: id.UniqueID, StartTime: id.StartTime}
	if err := r.KillEvent(&event.Event{Proc: p, Source: "sysmon"}, "rule", "test"); err != nil {
		t.Fatalf("KillEvent: %v", err)
	}
	_ = cmd.Wait()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("child not terminated: %v", cmd.ProcessState)
	}
}
