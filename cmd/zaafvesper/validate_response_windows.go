//go:build zaafvesper_validate && windows

package main

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

func sysExec(string, []string) error { return errors.New("exec is not used on Windows") }

func exeSuffix() string { return ".exe" }

func validateTempRoot() string { return os.TempDir() }

func waitState(int32, bool, time.Duration) bool { return false }

func (h *vHarness) platformConfig(*response.Config) {}

func (h *vHarness) runPlatform() {
	h.untestable("kill", "Sysmon ProcessGuid binding", "done by the Sysmon source (pkg/source/sysmon Binder), which does not run here; the creation-time check it feeds is exercised above (workstream B validates Sysmon)")
	for _, a := range []string{"quarantine_file", "requarantine", "remove_persistence", "isolate_process"} {
		h.untestable(a, "all cases", "macOS only: refused-unsupported on Windows (run_windows.go supportedActions)")
	}
}

// platformAccidentGuard refuses where the ZAAFVesper service is installed.
func platformAccidentGuard() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+serviceName, registry.QUERY_VALUE)
	if err == nil {
		_ = k.Close()
		return errors.New("the ZAAFVesper service is installed here; the harness runs only on a throw-away runner")
	}
	return nil
}
