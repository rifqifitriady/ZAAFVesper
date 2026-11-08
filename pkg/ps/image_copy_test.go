package ps

import (
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// TestImageCopiedWithPlatformFlag (security note N1): when an event's
// process carries no image (fork without executable, or a later event
// without one), the table supplies the whole recorded image identity,
// IsPlatform and signing fields included, not only the path. Otherwise the
// Go zero value would claim "not a platform binary" for an Apple image.
func TestImageCopiedWithPlatformFlag(t *testing.T) {
	s := testSnap(MaxEntries)
	seed(s)
	sh := &event.Proc{PID: 500, PPID: 200, PIDVersion: 500, Exe: "/bin/sh", Name: "sh", UID: 501,
		IsPlatform: true, IsSigned: true, SigningID: "com.apple.sh", CSCategory: event.CSPlatform, ExeIno: 42}
	s.Enrich(ev(event.CreateProcess, 1, sh))

	// Fork with no executable in the event: the child runs sh's image.
	child := &event.Proc{PID: 501, PPID: 500, PIDVersion: 501, UID: 501}
	s.Enrich(ev(event.Fork, 2, child))
	if child.Exe != "/bin/sh" || !child.IsPlatform || !child.IsSigned || child.SigningID != "com.apple.sh" || child.CSCategory != event.CSPlatform || child.ExeIno != 42 {
		t.Fatalf("fork copied the path without the image identity: %+v", child)
	}
	if got, _ := s.Lookup(501); !got.IsPlatform {
		t.Fatalf("table entry of the forked child lost IsPlatform: %+v", got)
	}

	// A later event of sh whose process has no executable.
	op := &event.Proc{PID: 500, PPID: 200, PIDVersion: 500, UID: 501}
	o := ev(event.OpenFile, 3, op)
	s.Enrich(o)
	if op.Exe != "/bin/sh" || !op.IsPlatform || op.SigningID != "com.apple.sh" || op.CSCategory != event.CSPlatform {
		t.Fatalf("observe copied the path without the image identity: %+v", op)
	}

	// A non-platform image stays non-platform through the same paths.
	s.Enrich(ev(event.CreateProcess, 4, &event.Proc{PID: 600, PPID: 200, PIDVersion: 600, Exe: "/tmp/payload", Name: "payload", UID: 501}))
	c2 := &event.Proc{PID: 601, PPID: 600, PIDVersion: 601, UID: 501}
	s.Enrich(ev(event.Fork, 5, c2))
	if c2.Exe != "/tmp/payload" || c2.IsPlatform {
		t.Fatalf("fork of a payload: %+v", c2)
	}
}
