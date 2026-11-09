//go:build !linux

package response

import "github.com/rifqifitriady/ZAAFVesper/pkg/event"

// writerMountNS: macOS and Windows have no per-process mount namespace
// that changes what a path names for the sensor.
func (r *Responder) writerMountNS(*event.Proc) error { return nil }
