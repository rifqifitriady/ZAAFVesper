package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The systemd unit's output folder must be one the ownership check accepts
// on Debian and Ubuntu, where /var/log is root:syslog 0775 (found by the v0.3
// live run): it lives under /var/lib, which systemd creates root-only.
func TestLinuxUnitOutputDir(t *testing.T) {
	b, err := os.ReadFile("../../packaging/linux/zaafvesper.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(b)
	m := regexp.MustCompile(`--output-dir (\S+)`).FindStringSubmatch(unit)
	if m == nil {
		t.Fatal("ExecStart has no --output-dir")
	}
	if !strings.HasPrefix(m[1], "/var/lib/zaafvesper/") {
		t.Errorf("--output-dir %s: must be under /var/lib/zaafvesper (StateDirectory)", m[1])
	}
	for _, want := range []string{"StateDirectory=zaafvesper", "StateDirectoryMode=0700", "ProtectSystem=strict"} {
		if !strings.Contains(unit, "\n"+want+"\n") {
			t.Errorf("unit lacks %s", want)
		}
	}
	if regexp.MustCompile(`(?m)^ReadWritePaths=.*/var/log`).MatchString(unit) {
		t.Error("the unit still writes under /var/log")
	}
}
