//go:build yara && !darwin

package yara

import "time"

// isLocalFS has no portable MNT_LOCAL outside macOS; ZAAFVesper only runs
// there, so other builds accept every file system.
func isLocalFS(fd int) (bool, error) { return true, nil }

// procAlive cannot check outside macOS: assume alive (report).
func procAlive(pid int32, start time.Time) bool { return true }

func invalidateMounts() {}

// nonLocalMounts: no mount table outside macOS.
func nonLocalMounts() []string { return nil }
