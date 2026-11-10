//go:build !linux

package response

import "github.com/rifqifitriady/ZAAFVesper/pkg/event"

// liveExeID: macOS events carry the image's inode; Windows binds the image
// by the hash Sysmon reports.
func (r *Responder) liveExeID(*event.Proc) (dev, ino uint64, ok bool) { return 0, 0, false }

// BindExecutable returns e unchanged (see liveexe_linux.go).
func (r *Responder) BindExecutable(e *event.Event) *event.Event { return e }
