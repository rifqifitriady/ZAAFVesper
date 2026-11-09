package winevt

import (
	"errors"
	"fmt"

	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
)

// Provenance (security review, finding S4-1): any program can register an
// ETW provider under Sysmon's name, so an event is accepted only when the
// event log recorded it as written by LocalSystem
// (System/Security/@UserID S-1-5-18) from the process of a running Sysmon
// service (System/Execution/@ProcessID), as the Service Control Manager
// reports it (winevt_windows.go). Creating or reconfiguring a service needs
// an administrator. A Sysmon installed under another service name is not
// recognised: its events are then reported as untrusted.

// sysmonServices are the service names Sysmon installs under (64-bit,
// 32-bit, ARM64).
var sysmonServices = []string{"Sysmon64", "Sysmon", "Sysmon64a"}

const localSystemSID = "S-1-5-18"

// checkProvenance decides whether r was written by Sysmon; isSysmonPID says
// whether a pid is a running Sysmon service's process.
func checkProvenance(r *sysmon.Record, isSysmonPID func(uint32) bool) error {
	if r.UserID != localSystemSID {
		return fmt.Errorf("written as %q, not LocalSystem", r.UserID)
	}
	if r.ExecPID == 0 {
		return errors.New("no writer process id")
	}
	if !isSysmonPID(r.ExecPID) {
		return fmt.Errorf("written by pid %d, which is not a running Sysmon service", r.ExecPID)
	}
	return nil
}
