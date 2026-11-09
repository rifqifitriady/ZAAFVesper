package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// Response actions per platform: everything on macOS, kill and suspend on
// Linux, kill on Windows; the rest are refused with a reason.
func TestUnsupportedActionPerPlatform(t *testing.T) {
	want := map[string]map[string]bool{
		"darwin":  {rules.ActionKill: true, rules.ActionSuspend: true, rules.ActionQuarantineFile: true, rules.ActionRequarantine: true, rules.ActionRemovePersistence: true, rules.ActionIsolateProcess: true},
		"linux":   {rules.ActionKill: true, rules.ActionSuspend: true},
		"windows": {rules.ActionKill: true},
	}[runtime.GOOS]
	if want == nil {
		t.Skip("no response actions on " + runtime.GOOS)
	}
	for _, a := range []string{rules.ActionKill, rules.ActionSuspend, rules.ActionQuarantineFile, rules.ActionRequarantine, rules.ActionRemovePersistence, rules.ActionIsolateProcess} {
		why := unsupportedAction(a)
		if want[a] != (why == "") {
			t.Errorf("%s on %s: unsupported=%q", a, runtime.GOOS, why)
		}
		if why != "" && !strings.Contains(why, "macOS only") {
			t.Errorf("%s: reason %q", a, why)
		}
	}
	if pfAvailable != (runtime.GOOS == "darwin") {
		t.Errorf("pfAvailable=%v on %s", pfAvailable, runtime.GOOS)
	}
}

func TestWarnUnsupportedActions(t *testing.T) {
	rs, err := rules.LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	warnUnsupportedActions(rs, &b)
	if runtime.GOOS == "darwin" && b.Len() != 0 {
		t.Fatalf("warnings on macOS: %s", b.String())
	}
}
