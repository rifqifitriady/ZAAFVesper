//go:build windows

package response

import "syscall"

// Windows has no SIGSTOP/SIGCONT. These values only name the suspend
// action's two steps inside the responder; the Windows kill function
// (identify_windows.go) refuses every signal but SIGKILL, so a suspend can
// never become a terminate. cmd/zaafvesper refuses the suspend action on
// Windows before it reaches the responder.
const (
	sigStop = syscall.Signal(0x13)
	sigCont = syscall.Signal(0x12)
)
