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

// The unit runs the eBPF source explicitly (no silent choice), with the two
// capabilities and two system calls eBPF needs added to the hardening, not
// in place of it.
func TestLinuxUnitEBPF(t *testing.T) {
	b, err := os.ReadFile("../../packaging/linux/zaafvesper.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(b)
	if !regexp.MustCompile(`(?m)^ExecStart=\S+ run --source ebpf `).MatchString(unit) {
		t.Error("ExecStart does not pass --source ebpf")
	}
	caps := regexp.MustCompile(`(?m)^CapabilityBoundingSet=(.*)$`).FindStringSubmatch(unit)
	if caps == nil {
		t.Fatal("no CapabilityBoundingSet")
	}
	for _, c := range []string{"CAP_BPF", "CAP_PERFMON"} {
		if !strings.Contains(" "+caps[1]+" ", " "+c+" ") {
			t.Errorf("CapabilityBoundingSet lacks %s", c)
		}
	}
	if strings.Contains(caps[1], "CAP_SYS_ADMIN") {
		t.Error("CAP_SYS_ADMIN granted")
	}
	for _, want := range []string{"SystemCallFilter=@system-service", "SystemCallFilter=bpf perf_event_open",
		"NoNewPrivileges=yes", "ProtectKernelModules=yes", "ProtectKernelTunables=yes", "MemoryDenyWriteExecute=yes",
		"RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any", "PrivateDevices=yes", "ProtectHome=read-only"} {
		if !strings.Contains(unit, "\n"+want+"\n") {
			t.Errorf("unit lacks %s", want)
		}
	}
}
