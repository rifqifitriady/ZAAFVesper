//go:build linux

package ps

import (
	"os"
	"testing"
)

func TestListProcessesLinux(t *testing.T) {
	procs, err := listProcesses()
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	for _, p := range procs {
		if p.PID == int32(os.Getpid()) {
			if p.Exe != self || p.PPID != int32(os.Getppid()) || len(p.Args) == 0 || p.StartTime.IsZero() || p.UID != int64(os.Getuid()) {
				t.Fatalf("self entry %+v", p)
			}
			return
		}
	}
	t.Fatal("own process not listed")
}
