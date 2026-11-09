package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

func TestPlansLoadAndNameRealRules(t *testing.T) {
	rs, err := rules.LoadDir("../../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]map[string]bool{} // rule name -> platforms (macOS and Linux share some names)
	for _, r := range rs.Rules {
		if len(r.Platforms) == 1 {
			if names[r.Name] == nil {
				names[r.Name] = map[string]bool{}
			}
			names[r.Name][r.Platforms[0]] = true
		}
	}
	for _, plat := range []string{"windows", "linux"} {
		p, err := loadPlan("../" + plat + "-plan.json")
		if err != nil {
			t.Fatal(err)
		}
		if p.Platform != plat {
			t.Fatalf("%s plan says %s", plat, p.Platform)
		}
		covered := map[string]bool{}
		for _, tc := range p.Tests {
			for _, e := range tc.Expect {
				if !names[e][plat] {
					t.Errorf("%s: test %s expects unknown %s rule %q", plat, tc.ID, plat, e)
				}
				covered[e] = true
			}
		}
		for _, u := range p.Untestable {
			if !names[u.Rule][plat] || u.Reason == "" {
				t.Errorf("%s: untestable %q", plat, u.Rule)
			}
			covered[u.Rule] = true
		}
		for n, pl := range names {
			if pl[plat] && !covered[n] {
				t.Errorf("%s rule %q has no test and no reason", plat, n)
			}
		}
	}
}

func TestResolveAtomic(t *testing.T) {
	dir := t.TempDir()
	yml := `attack_technique: T0000
atomic_tests:
- name: Example
  auto_generated_guid: 11111111-2222-3333-4444-555555555555
  supported_platforms: [linux]
  input_arguments:
    path:
      default: /tmp/x
  dependencies:
  - description: needs a tool
  executor:
    name: sh
    command: |
      echo #{path} PathToAtomicsFolder #{unknown}
    cleanup_command: |
      rm -f #{path}
`
	if err := os.WriteFile(filepath.Join(dir, "T0000.yaml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	in, name, deps, err := resolveAtomic(dir, &Atomic{Technique: "T0000", GUID: "11111111-2222-3333-4444-555555555555"}, "linux")
	if err != nil || name != "Example" || len(deps) != 1 {
		t.Fatalf("%v %q %v", err, name, deps)
	}
	if in.Command != "echo /tmp/x "+dir+" #{unknown}\n" || in.Cleanup != "rm -f /tmp/x\n" || in.Executor != "sh" {
		t.Fatalf("%+v", in)
	}
	if _, _, _, err := resolveAtomic(dir, &Atomic{Technique: "T0000", GUID: "11111111-2222-3333-4444-555555555555"}, "windows"); err == nil {
		t.Fatal("platform not checked")
	}
}

func TestReportRows(t *testing.T) {
	rs, err := rules.LoadDir("../../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadPlan("../linux-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	alerts := `{"rule_id":"x","rule_name":"Cron job file created","output":"bash wrote /etc/cron.d/persistevil","time":"2026-11-09T10:00:01Z"}
{"rule_id":"y","rule_name":"Something else","output":"noise","time":"2026-11-09T10:00:01Z"}
`
	if err := os.WriteFile(filepath.Join(dir, "alerts-20261109T000000.000000000Z.jsonl"), []byte(alerts), 0o644); err != nil {
		t.Fatal(err)
	}
	fired, first, all, err := readAlerts(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	results := []Result{
		{ID: "art-T1053.003-078e69eb", Command: "x", Start: t0, End: t0.Add(2 * time.Second)},
		{ID: "art-T1053.003-2d943c18", Command: "x", Start: t0.Add(10 * time.Second), End: t0.Add(12 * time.Second)},
		{ID: "art-T1070.003-a934276e", Command: "x", Start: t0.Add(20 * time.Second), End: t0.Add(21 * time.Second)},
	}
	rows := buildRows(p, results, fired, first, all, rs, "linux")
	status := map[string]string{}
	for _, r := range rows {
		status[r.Rule] = r.Status
	}
	if status["Cron job file created"] != "fired for some tests" || status["Shell history file deleted"] != "did not fire" {
		t.Fatalf("%v", status)
	}
	md := render(rows, p, nil, "linux", "https://example.invalid/run", fired)
	if !strings.Contains(md, "1 fired for some tests only") || !strings.Contains(md, "078e69eb: fired") || !strings.Contains(md, "2d943c18: did not fire") || !strings.Contains(md, "Something else (1)") {
		t.Fatalf("%s", md)
	}
}
