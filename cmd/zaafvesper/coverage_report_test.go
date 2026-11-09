package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
