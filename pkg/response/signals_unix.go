//go:build !windows

package response

import "syscall"

// Signals of the suspend action (SIGSTOP, then SIGCONT on resume).
const (
	sigStop = syscall.SIGSTOP
	sigCont = syscall.SIGCONT
)
