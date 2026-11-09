//go:build !windows && !linux

package response

import "syscall"

// defaultKill sends the signal by pid. On macOS the kernel unique id and
// start time were checked by verify immediately before.
var defaultKill = syscall.Kill
