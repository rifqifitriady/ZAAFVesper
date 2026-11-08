package main

import (
	"runtime"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// hostPlatform maps the build's GOOS to an event platform name. run loads
// only the rules for this platform; replay defaults to it (--platform).
func hostPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return event.PlatformMacOS
	case "windows":
		return event.PlatformWindows
	case "linux":
		return event.PlatformLinux
	}
	return ""
}
