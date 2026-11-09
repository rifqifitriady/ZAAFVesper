//go:build !windows

// Command remotethread is a Windows-only test helper (see main_windows.go).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "remotethread: Windows only")
	os.Exit(2)
}
