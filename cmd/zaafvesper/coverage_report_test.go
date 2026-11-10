package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

const miniBundle = `{"type":"bundle","id":"bundle--x","objects":[
 {"type":"x-mitre-tactic","name":"Collection","x_mitre_shortname":"collection","external_references":[{"source_name":"mitre-attack","external_id":"TA0009"}]},
 {"type":"x-mitre-tactic","name":"Exfiltration","x_mitre_shortname":"exfiltration","external_references":[{"source_name":"mitre-attack","external_id":"TA0010"}]},
 {"type":"attack-pattern","name":"Archive via Utility","external_references":[{"source_name":"mitre-attack","external_id":"T1560.001"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"collection"}]},
 {"type":"attack-pattern","name":"Old","revoked":true,"external_references":[{"source_name":"mitre-attack","external_id":"T1562.001"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"collection"}]},
 {"type":"relationship","relationship_type":"uses"}
],"spec_version":"2.1"}`

func coverageTree(t *testing.T, technique, tactic string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rules")
	rule := "name: R\nid: 0b3f6c1e-7a52-4d8e-9f64-2c1a8e5d7b90\nversion: 1.0.0\nplatforms: [linux]\nlabels:\n  tactic.id: " + tactic +
		"\n  tactic.name: Collection\n  technique.id: " + technique + "\ncondition: evt.name = 'CreateProcess'\noutput: x\nseverity: low\nmin-engine-version: 0.1.0\n"
	writeFile(t, filepath.Join(dir, "r.yml"), rule)
	return dir
}

func TestCoverageReportAndAttackCheck(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "ea.json")
	writeFile(t, bundle, miniBundle)

	dir := coverageTree(t, "T1560.001", "TA0009")
	code, stdout, stderr := runCLI(t, "coverage", "--report", "--rules", dir, "--attack", bundle)
	if code != 0 || !strings.Contains(stdout, "cover 1 ATT&CK techniques") || !strings.Contains(stdout, "linux      1 techniques") ||
		!strings.Contains(stdout, "0 problems, 0 warnings") || !strings.Contains(stdout, "r.yml") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, _ = runCLI(t, "coverage", "--report", "--json", "--rules", dir)
	var rep coverageReport
	if code != 0 || json.Unmarshal([]byte(stdout), &rep) != nil || rep.Techniques != 1 || len(rep.RulesNoAtomics) != 1 {
		t.Fatalf("json: exit %d %+v", code, rep)
	}

	// Revoked technique: exit 1. Unknown tactic: exit 1. Wrong tactic: warning only.
	for _, c := range []struct{ tech, tac, want string }{
		{"T1562.001", "TA0009", "is revoked"},
		{"T1999", "TA0009", "not in the ATT&CK data"},
		{"T1560.001", "TA0999", "tactic TA0999 is not in the ATT&CK data"},
	} {
		code, stdout, _ := runCLI(t, "coverage", "--report", "--rules", coverageTree(t, c.tech, c.tac), "--attack", bundle)
		if code != 1 || !strings.Contains(stdout, c.want) {
			t.Errorf("%s/%s: exit %d\n%s", c.tech, c.tac, code, stdout)
		}
	}
	code, stdout, _ = runCLI(t, "coverage", "--report", "--rules", coverageTree(t, "T1560.001", "TA0010"), "--attack", bundle)
	if code != 0 || !strings.Contains(stdout, "is not a tactic of its techniques") {
		t.Errorf("tactic mismatch must warn, not fail: exit %d\n%s", code, stdout)
	}
}

func TestAttackDataRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not json":     "nope",
		"array":        "[]",
		"no objects":   `{"type":"bundle"}`,
		"objects map":  `{"objects":{}}`,
		"empty object": `{"objects":[{},{}]}`,
	}
	for name, body := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		writeFile(t, p, body)
		if _, err := loadAttackData(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	link := filepath.Join(dir, "link.json")
	good := filepath.Join(dir, "good.json")
	writeFile(t, good, miniBundle)
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAttackData(link); err == nil {
		t.Error("symbolic link followed")
	}
	if ad, err := loadAttackData(good); err != nil || len(ad.techniques) != 2 || ad.tactics["TA0009"] != "Collection" {
		t.Errorf("mini bundle: %v %+v", err, ad)
	}
}

// coverageRule writes one rule file. platforms is the text after "platforms:"
// ("" leaves the key out, which means every platform); atomic is a GUID or "".
func coverageRule(t *testing.T, dir, file, id, platforms, technique, atomic string) {
	t.Helper()
	body := "name: " + file + "\nid: " + id + "\nversion: 1.0.0\n"
	if platforms != "" {
		body += "platforms: " + platforms + "\n"
	}
	body += "labels:\n  tactic.id: TA0009\n  tactic.name: Collection\n  technique.id: " + technique + "\n" +
		"condition: evt.name = 'CreateProcess'\noutput: x\nseverity: low\nmin-engine-version: 0.1.0\n"
	if atomic != "" {
		body += "tests:\n  atomic: [" + atomic + "]\n"
	}
	writeFile(t, filepath.Join(dir, file), body)
}

// A rule counts for each of its platforms, and a rule without platforms
// counts for all of them. A regression of the per-platform loop (counting
// only the first platform, or none for a platform-less rule) changes these
// numbers.
func TestCoverageReportCountsEveryPlatformOfARule(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rules")
	// two platforms, no atomic test
	coverageRule(t, dir, "two.yml", "1a000000-0000-4000-8000-000000000001", "[linux, windows]", "T1560.001", "")
	// no platforms key: every platform, no atomic test
	coverageRule(t, dir, "any.yml", "1a000000-0000-4000-8000-000000000002", "", "T1048", "")
	// one platform, with an atomic test
	coverageRule(t, dir, "mac.yml", "1a000000-0000-4000-8000-000000000003", "[macos]", "T1059.002", "11111111-2222-4333-8444-555555555555")
	// a second windows-only rule on a technique the first rule also has
	coverageRule(t, dir, "win.yml", "1a000000-0000-4000-8000-000000000004", "[windows]", "T1560.001", "")
	rs, err := rules.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep := buildCoverageReport(rs)

	if rep.Rules != 4 || rep.Techniques != 3 {
		t.Fatalf("rules %d techniques %d", rep.Rules, rep.Techniques)
	}
	wantPlat := map[string]int{"macos": 2, "windows": 2, "linux": 2}
	if !reflect.DeepEqual(rep.PerPlatform, wantPlat) {
		t.Errorf("techniques per platform %v, want %v", rep.PerPlatform, wantPlat)
	}
	wantBy := map[string][]string{
		"macos":   {"T1048", "T1059.002"},
		"windows": {"T1048", "T1560.001"},
		"linux":   {"T1048", "T1560.001"},
	}
	if !reflect.DeepEqual(rep.TechniquesByPlat, wantBy) {
		t.Errorf("techniques by platform %v, want %v", rep.TechniquesByPlat, wantBy)
	}
	if rep.RulesWithAtomics != 1 || !reflect.DeepEqual(rep.RulesNoAtomics, []string{"any.yml", "two.yml", "win.yml"}) {
		t.Errorf("atomics: with %d, without %v", rep.RulesWithAtomics, rep.RulesNoAtomics)
	}
	// Per-platform view of the rules without atomics: the rule with an
	// atomic test (mac.yml) is in none; the platform-less rule is in all.
	wantNo := map[string][]string{
		"macos":   {"any.yml"},
		"windows": {"any.yml", "two.yml", "win.yml"},
		"linux":   {"any.yml", "two.yml"},
	}
	if !reflect.DeepEqual(rep.NoAtomicsByPlat, wantNo) {
		t.Errorf("without atomics by platform %v, want %v", rep.NoAtomicsByPlat, wantNo)
	}

	// The text and JSON output carry the same numbers.
	code, stdout, stderr := runCLI(t, "coverage", "--report", "--rules", dir)
	for _, want := range []string{"4 enabled rules cover 3 ATT&CK techniques", "macos      2 techniques",
		"windows    2 techniques", "linux      2 techniques", "1 rules link an atomic test; 3 do not:"} {
		if code != 0 || !strings.Contains(stdout, want) {
			t.Errorf("missing %q: exit %d\n%s\n%s", want, code, stdout, stderr)
		}
	}
	code, stdout, _ = runCLI(t, "coverage", "--report", "--json", "--rules", dir)
	var got coverageReport
	if code != 0 || json.Unmarshal([]byte(stdout), &got) != nil || !reflect.DeepEqual(got.NoAtomicsByPlat, wantNo) || !reflect.DeepEqual(got.PerPlatform, wantPlat) {
		t.Errorf("json: exit %d %+v", code, got)
	}
}
