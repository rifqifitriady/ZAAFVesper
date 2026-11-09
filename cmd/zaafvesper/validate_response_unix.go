//go:build zaafvesper_validate && (darwin || linux)

package main

import (
	"syscall"
)

// sysExec replaces the test process with path (exec-into-platform case).
func sysExec(path string, argv []string) error { return syscall.Exec(path, argv, []string{}) }

func exeSuffix() string { return "" }
