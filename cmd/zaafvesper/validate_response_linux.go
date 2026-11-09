//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

func validateTempRoot() string { return "/tmp" }

// waitState waits until pid is stopped (state T) or running again.
func waitState(pid int32, stopped bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil {
			s := string(b)
			if i := strings.LastIndexByte(s, ')'); i > 0 && i+2 < len(s) {
				if (s[i+2] == 'T' || s[i+2] == 't') == stopped {
					return true
				}
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (h *vHarness) platformConfig(*response.Config) {}

func (h *vHarness) runPlatform() {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		say(h.stdout, "kernel %s (pidfd_open needs 5.3 or later)", strings.TrimSpace(string(b)))
	}
	for _, a := range []string{"quarantine_file", "requarantine", "remove_persistence", "isolate_process"} {
		h.untestable(a, "all cases", "macOS only: refused-unsupported on Linux (run_linux.go supportedActions)")
	}
}
