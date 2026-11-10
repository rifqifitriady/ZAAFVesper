//go:build windows

package response

import "syscall"

// Windows has no SIGSTOP/SIGCONT. These values only name the suspend
// action's two steps inside the responder; the Windows kill function
// (identify_windows.go) maps them to NtSuspendProcess and NtResumeProcess
// on a handle opened with PROCESS_SUSPEND_RESUME only, so a suspend can
// never become a terminate.
const (
	sigStop = syscall.Signal(0x13)
	sigCont = syscall.Signal(0x12)
)
