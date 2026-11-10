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

// An incomplete run is an error with a banner, never a quiet "not tested".
func TestReportRefusesIncompleteRun(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "linux.md")
	args := []string{"-plan", "../linux-plan.json", "-alerts", dir, "-rules", "../../../../rules", "-platform", "linux", "-out", out}
	if err := cmdReport(append([]string{"-results", filepath.Join(dir, "missing.json")}, args...)); err == nil {
		t.Fatal("missing results accepted")
	}
	part := filepath.Join(dir, "part.json")
	if err := os.WriteFile(part, []byte(`[{"id":"art-T1053.003-078e69eb","kind":"atomic","command":"x"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdReport(append([]string{"-results", part}, args...)); err == nil || !strings.Contains(err.Error(), "1 of") {
		t.Fatalf("partial results: %v", err)
	}
	md, _ := os.ReadFile(out)
	if !strings.Contains(string(md), "INCOMPLETE RUN") {
		t.Fatalf("no banner:\n%s", md)
	}
}

// Every Atomic test a Windows or Linux rule links (tests.atomic) is either
// run by its plan or listed in skipped_atomics with a reason.
func TestLinkedAtomicsAccountedFor(t *testing.T) {
	rs, err := rules.LoadDir("../../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, plat := range []string{"windows", "linux"} {
		p, err := loadPlan("../" + plat + "-plan.json")
		if err != nil {
			t.Fatal(err)
		}
		known := map[string]bool{}
		for _, tc := range p.Tests {
			if tc.Atomic != nil {
				known[strings.ToLower(tc.Atomic.GUID)] = true
			}
		}
		for _, s := range p.SkippedAtomics {
			if s.Reason == "" {
				t.Errorf("%s: skipped %s without a reason", plat, s.GUID)
			}
			known[strings.ToLower(s.GUID)] = true
		}
		for _, r := range rs.Rules {
			if len(r.Platforms) != 1 || r.Platforms[0] != plat {
				continue
			}
			for _, g := range r.Tests.Atomic {
				if !known[strings.ToLower(g)] {
					t.Errorf("%s: %s links Atomic %s, which the plan neither runs nor skips", plat, r.Name, g)
				}
			}
		}
		canaries := 0
		for _, tc := range p.Tests {
			if tc.Canary {
				canaries++
			}
		}
		if canaries < 2 || !p.Tests[0].Canary || !p.Tests[len(p.Tests)-1].Canary {
			t.Errorf("%s: the plan must start and end with a canary", plat)
		}
	}
}

func TestCanaryProblem(t *testing.T) {
	p := &Plan{Tests: []Test{{ID: "c", Canary: true, Expect: []string{"R"}}}}
	t0 := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	res := []Result{{ID: "c", Command: "x", Start: t0, End: t0.Add(time.Second)}}
	if canaryProblem(p, res, []alertLine{{RuleName: "R", Time: t0.Add(500 * time.Millisecond)}}) != "" {
		t.Fatal("canary that fired reported")
	}
	if got := canaryProblem(p, res, []alertLine{{RuleName: "R", Time: t0.Add(time.Hour)}}); !strings.Contains(got, "not receiving") {
		t.Fatalf("silent canary: %q", got)
	}
}
