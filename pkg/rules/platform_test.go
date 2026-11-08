package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

const ruleTmpl = `name: %s
id: %s
version: 1.0.0
platforms: [%s]
labels: {tactic.id: TA0002, technique.id: T1059}
condition: evt.name = 'CreateProcess' and ps.name = '%s'
output: "%%ps.exe"
severity: low
min-engine-version: 0.1.0
`

const fixtureTmpl = `match:
  - desc: m
    events:
      - name: CreateProcess
        proc: {pid: 10, ppid: 1, exe: /x/%s, name: %s}
nomatch:
  - desc: n
    events:
      - name: CreateProcess
        proc: {pid: 10, ppid: 1, exe: /x/other, name: other}
  - desc: n2
    events:
      - name: OpenFile
        proc: {pid: 11, ppid: 1, exe: /x/%s, name: %s}
`

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// TestRecursiveLoadAndPlatforms: rules in subdirectories load, their
// fixtures live next to them, and Enabled honours Ruleset.Platform.
func TestRecursiveLoadAndPlatforms(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mac.yml"), sprintf(ruleTmpl, "mac", "11111111-1111-4111-8111-111111111111", "macos", "a"))
	writeFile(t, filepath.Join(dir, "testdata", "mac.yml"), sprintf(fixtureTmpl, "a", "a", "a", "a"))
	writeFile(t, filepath.Join(dir, "windows", "win.yml"), sprintf(ruleTmpl, "win", "22222222-2222-4222-8222-222222222222", "windows", "b"))
	writeFile(t, filepath.Join(dir, "windows", "testdata", "win.yml"), sprintf(fixtureTmpl, "b", "b", "b", "b"))
	writeFile(t, filepath.Join(dir, "windows", "testdata", "orphan.yml"), sprintf(fixtureTmpl, "c", "c", "c", "c"))
	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 2 || len(rs.Enabled()) != 2 {
		t.Fatalf("rules %d enabled %d", len(rs.Rules), len(rs.Enabled()))
	}
	rs.Platform = "windows"
	if en := rs.Enabled(); len(en) != 1 || en[0].Name != "win" {
		t.Fatalf("windows enabled: %v", en)
	}
	res, err := RunFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	passed, orphan := 0, 0
	for _, r := range res {
		switch {
		case r.Err == "" && r.Kind != KindFixture:
			passed++
		case r.Kind == KindFixture && filepath.Base(r.FixtureFile) == "orphan.yml":
			orphan++
		default:
			t.Errorf("unexpected result: %+v", r)
		}
	}
	if passed != 6 || orphan != 1 {
		t.Fatalf("passed %d orphan %d", passed, orphan)
	}
	writeFile(t, filepath.Join(dir, "bad.yml"), sprintf(ruleTmpl, "bad", "33333333-3333-4333-8333-333333333333", "solaris", "d"))
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("unknown platform must be a load error")
	}
}
