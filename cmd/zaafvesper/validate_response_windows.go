//go:build windows

package main

import (
	"errors"
	"os"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

func sysExec(string, []string) error { return errors.New("exec is not used on Windows") }

func exeSuffix() string { return ".exe" }

func validateTempRoot() string { return os.TempDir() }

func waitState(int32, bool, time.Duration) bool { return false }

func (h *vHarness) platformConfig(*response.Config) {}

func (h *vHarness) runPlatform() {
	for _, a := range []string{"quarantine_file", "requarantine", "remove_persistence", "isolate_process"} {
		h.untestable(a, "all cases", "macOS only: refused-unsupported on Windows (run_windows.go supportedActions)")
	}
}
