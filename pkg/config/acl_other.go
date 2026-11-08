//go:build !darwin

package config

// Extended ACLs are only checked on macOS.
func checkACLPath(string) error { return nil }
func checkACLFd(int) error      { return nil }
