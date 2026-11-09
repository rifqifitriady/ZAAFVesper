package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

const sigmaGood = `title: Good rule
id: 3603f18a-ec15-43a1-9af2-d196c8a7fec6
status: test
author: Jane Doe
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/csrutil'
        CommandLine|contains: 'disable'
    condition: selection
level: medium
`

const sigmaUnsupported = `title: Aggregation
id: 4e2f0b7c-1d3a-4b5e-8f6a-7c8d9e0f1a2b
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/curl'
    condition: selection | count() > 5
level: low
`

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sigmaTree(t *testing.T) (in, out string) {
	t.Helper()
	dir := t.TempDir()
	in = filepath.Join(dir, "sigma")
	writeFile(t, filepath.Join(in, "macos", "Good Rule.yml"), sigmaGood)
	writeFile(t, filepath.Join(in, "macos", "agg.yaml"), sigmaUnsupported)
	writeFile(t, filepath.Join(in, "macos", "broken.yml"), "title: [\n")
	writeFile(t, filepath.Join(in, "README.md"), "not a rule")
	writeFile(t, filepath.Join(in, ".git", "x.yml"), sigmaGood)
	return in, filepath.Join(dir, "out")
}

func TestSigmaConvertCLI(t *testing.T) {
	in, out := sigmaTree(t)
	report := filepath.Join(filepath.Dir(out), "report.json")
	// Flags after the input path, as in the usage line.
	code, stdout, stderr := runCLI(t, "sigma", "convert", in, "-o", out, "--report", report)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	noControls(t, stdout)
	if !strings.Contains(stdout, "3 Sigma files: 1 converted, 2 skipped (1 invalid, 1 unsupported), 0 errors") {
		t.Errorf("summary:\n%s", stdout)
	}
	if !strings.Contains(stdout, "rules test") {
		t.Error("summary must say converted rules have no fixtures")
	}
	data, err := os.ReadFile(filepath.Join(out, "good_rule.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "sigma.author: Jane Doe") {
		t.Errorf("rule:\n%s", data)
	}
	rs, err := rules.LoadDir(out)
	if err != nil || len(rs.Rules) != 1 {
		t.Fatalf("output does not load: %v", err)
	}
	var rep sigmaReport
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Converted != 1 || rep.Summary.Unsupported != 1 || rep.Summary.Invalid != 1 || len(rep.Skipped) != 2 {
		t.Errorf("report summary %+v", rep.Summary)
	}
	for _, s := range rep.Skipped {
		if s.Reason == "" || s.Source == "" {
			t.Errorf("skip without reason: %+v", s)
		}
	}

	// rules test on the output: the converted rule has no fixture, so it
	// fails like any hand-written rule without one.
	code, stdout, _ = runCLI(t, "rules", "test", out)
	if code == 0 || !strings.Contains(stdout, "missing fixture") {
		t.Errorf("rules test on converted rules without fixtures: exit %d\n%s", code, stdout)
	}

	// A second run does not replace the existing file.
	code, stdout, _ = runCLI(t, "sigma", "convert", "-o", out, in)
	if code != 1 || !strings.Contains(stdout, "already exists") {
		t.Errorf("second run: exit %d\n%s", code, stdout)
	}
	// --force replaces it.
	code, stdout, _ = runCLI(t, "sigma", "convert", "--force", "-o", out, in)
	if code != 0 {
		t.Errorf("--force: exit %d\n%s", code, stdout)
	}
}

func TestSigmaConvertSymlinks(t *testing.T) {
	in, out := sigmaTree(t)
	secret := filepath.Join(filepath.Dir(in), "secret.yml")
	writeFile(t, secret, sigmaGood)
	if err := os.Symlink(secret, filepath.Join(in, "link.yml")); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCLI(t, "sigma", "convert", in, "-o", out)
	if code != 1 || !strings.Contains(stdout, "symbolic link not followed") {
		t.Errorf("input symlink: exit %d\n%s", code, stdout)
	}

	// Output path that is a symlink is refused.
	target := t.TempDir()
	linkOut := filepath.Join(filepath.Dir(out), "linkout")
	if err := os.Symlink(target, linkOut); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "sigma", "convert", in, "-o", linkOut)
	if code != 1 || !strings.Contains(stderr, "symbolic link") {
		t.Errorf("output symlink: exit %d\n%s", code, stderr)
	}

	// A symlink planted at the output file name is never written through,
	// with or without --force.
	out2 := filepath.Join(filepath.Dir(out), "out2")
	if err := os.MkdirAll(out2, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(filepath.Dir(out), "victim.txt")
	writeFile(t, victim, "keep")
	if err := os.Symlink(victim, filepath.Join(out2, "good_rule.yml")); err != nil {
		t.Fatal(err)
	}
	runCLI(t, "sigma", "convert", in, "-o", out2)
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("wrote through a symlink without --force")
	}
	code, stdout, _ = runCLI(t, "sigma", "convert", "--force", in, "-o", out2)
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("wrote through a symlink with --force")
	}
	if code != 1 || !strings.Contains(stdout, "not a regular file") {
		t.Errorf("--force over a symlink: exit %d\n%s", code, stdout)
	}
	if fi, err := os.Lstat(filepath.Join(out2, "good_rule.yml")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("--force must leave the link alone: %v", err)
	}
}

// --force replaces only files the converter wrote, and a converted rule may
// not reuse an id already present under -o (security review findings 2, 3).
func TestSigmaConvertForceAndIDGuards(t *testing.T) {
	in, out := sigmaTree(t)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	hand := filepath.Join(out, "good_rule.yml")
	writeFile(t, hand, "name: hand-written\n")
	code, stdout, _ := runCLI(t, "sigma", "convert", "--force", in, "-o", out)
	if code != 1 || !strings.Contains(stdout, "not written by sigma convert") {
		t.Errorf("--force over a hand-written rule: exit %d\n%s", code, stdout)
	}
	if b, _ := os.ReadFile(hand); string(b) != "name: hand-written\n" {
		t.Fatal("hand-written rule was replaced")
	}

	out2 := filepath.Join(filepath.Dir(out), "out2")
	writeFile(t, filepath.Join(out2, "sub", "builtin.yml"), "name: built-in\nid: 3603F18A-EC15-43A1-9AF2-D196C8A7FEC6\n")
	code, stdout, _ = runCLI(t, "sigma", "convert", in, "-o", out2)
	if code != 1 || !strings.Contains(stdout, "is already used by") {
		t.Errorf("id collision with an existing rule: exit %d\n%s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(out2, "good_rule.yml")); err == nil {
		t.Error("colliding rule was written")
	}
}

func TestSigmaConvertUsage(t *testing.T) {
	for _, args := range [][]string{
		{"sigma"},
		{"sigma", "export"},
		{"sigma", "convert"},
		{"sigma", "convert", "in"},
		{"sigma", "convert", "a", "b", "-o", "x"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, "sigma", "convert", filepath.Join(t.TempDir(), "missing"), "-o", t.TempDir()); code != 1 {
		t.Errorf("missing input: exit %d", code)
	}
}

func TestSigmaOutName(t *testing.T) {
	for in, want := range map[string]string{
		"proc_creation_macos_x.yml":       "proc_creation_macos_x.yml",
		"Good Rule.yaml":                  "good_rule.yml",
		"../../etc/passwd.yml":            "passwd.yml",
		"a.b.c.yml":                       "a_b_c.yml",
		"___.yml":                         "sigma_rule.yml",
		"\x1b[31mred‮.yml":                "31mred.yml",
		strings.Repeat("x", 300) + ".yml": strings.Repeat("x", 150) + ".yml",
	} {
		if got := outName(in); got != want {
			t.Errorf("outName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The shipped rules in rules/sigma/macos/ must be byte for byte what the
// converter produces today from the vendored SigmaHQ originals in
// pkg/sigma/testdata/sigmahq (no hand edits, no stale output).
func TestShippedSigmaRulesRegenerate(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	rep, err := sigmaConvert("../../pkg/sigma/testdata/sigmahq", out, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Skipped != 0 || rep.Summary.Errors != 0 {
		t.Fatalf("vendored SigmaHQ rules did not all convert: %+v", rep)
	}
	shipped, _ := filepath.Glob("../../rules/sigma/macos/*.yml")
	if len(shipped) != rep.Summary.Converted {
		t.Fatalf("%d shipped rules, %d converted", len(shipped), rep.Summary.Converted)
	}
	for _, f := range shipped {
		want, err := os.ReadFile(filepath.Join(out, filepath.Base(f)))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(f)
		if string(got) != string(want) {
			t.Errorf("%s differs from the converter output; re-run: zaafvesper sigma convert pkg/sigma/testdata/sigmahq -o rules/sigma/macos --force", f)
		}
	}
}

// The shipped converted SigmaHQ rules keep the DRL 1.1 attribution.
func TestShippedSigmaRulesLoad(t *testing.T) {
	rs, err := rules.LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rs.Rules {
		if !strings.Contains(filepath.ToSlash(r.File), "/sigma/macos/") {
			continue
		}
		n++
		if r.Labels["sigma.author"] == "" || len(r.References) == 0 || r.Labels["sigma.id"] == "" {
			t.Errorf("%s: DRL 1.1 attribution missing (author, references, id)", r.File)
		}
		if len(r.Platforms) != 1 || r.Platforms[0] != "macos" {
			t.Errorf("%s: platforms %v", r.File, r.Platforms)
		}
		if !strings.Contains(r.Output, "Sigma rule by") {
			t.Errorf("%s: alert text must carry the Sigma author", r.File)
		}
	}
	if n == 0 {
		t.Fatal("no shipped Sigma rules found")
	}
}
