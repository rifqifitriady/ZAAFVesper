package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReplayPlatformFlag: replay runs only the host platform's rules by
// default, every platform with --platform all, and rejects unknown values.
func TestReplayPlatformFlag(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "windows"), 0o755); err != nil {
		t.Fatal(err)
	}
	rule := `name: Windows only test rule
id: 44444444-4444-4444-8444-444444444444
version: 1.0.0
platforms: [windows]
labels: {tactic.id: TA0002, technique.id: T1059}
condition: evt.name = 'CreateProcess' and ps.name = 'platformprobe'
output: "probe %ps.exe"
severity: low
min-engine-version: 0.1.0
`
	if err := os.WriteFile(filepath.Join(rulesDir, "windows", "probe.yml"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "events.jsonl")
	ev := `{"seq":1,"time":"2026-11-08T10:00:00Z","name":"CreateProcess","source":"fixture","proc":{"pid":900,"ppid":1,"exe":"/x/platformprobe","name":"platformprobe","uid":501,"euid":501}}` + "\n"
	if err := os.WriteFile(events, []byte(ev), 0o644); err != nil {
		t.Fatal(err)
	}
	none := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(none, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) (int, string, string) {
		args := append([]string{"replay", "--rules", rulesDir, "--config", none}, extra...)
		return runCLI(t, append(args, events)...)
	}
	if hostPlatform() != "windows" {
		if code, out, errs := run(); code != 0 || strings.Contains(out, "Windows only test rule") {
			t.Fatalf("default (host %s) ran the windows rule: %d %s %s", hostPlatform(), code, out, errs)
		}
	}
	if code, out, errs := run("--platform", "all"); code != 0 || !strings.Contains(out, "Windows only test rule") {
		t.Fatalf("--platform all: %d %s %s", code, out, errs)
	}
	if code, out, errs := run("--platform", "windows"); code != 0 || !strings.Contains(out, "Windows only test rule") {
		t.Fatalf("--platform windows: %d %s %s", code, out, errs)
	}
	if code, _, errs := run("--platform", "beos"); code != 2 || !strings.Contains(errs, "--platform") {
		t.Fatalf("--platform beos: %d %s", code, errs)
	}
}
