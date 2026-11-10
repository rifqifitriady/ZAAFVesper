//go:build !darwin && !linux && !windows

package response

import "github.com/rifqifitriady/ZAAFVesper/pkg/event"

func trustedWriter(*event.Proc) string {
	return "remove_persistence is not implemented on this platform"
}
