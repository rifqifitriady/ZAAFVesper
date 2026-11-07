package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMerge(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "zaafvesper.yml")
	write(t, main, `
rules_dir: /etc/zaafvesper/rules
eslogger:
  exclude_paths: [/dev/]
yara:
  workers: 2
  watch_dirs: [/tmp]
exclude:
  - name: A
    events: [OpenFile]
    condition: ps.signing_id = 'com.apple.mds'
`)
	write(t, filepath.Join(dir, "config.d", "20-b.yml"), "exclude:\n  - name: C\n    condition: ps.exe = '/x'\n")
	write(t, filepath.Join(dir, "config.d", "10-a.yml"), "rules_dir: /opt/rules\neslogger:\n  exclude_signing: [com.apple.mdworker]\nexclude:\n  - name: B\n    events: [WriteFile]\n")
	write(t, filepath.Join(dir, "config.d", "notes.txt"), "ignored")
	c, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if c.RulesDir != "/opt/rules" || c.Yara.Workers != 2 {
		t.Fatalf("scalars: %+v", c)
	}
	var names []string
	for _, e := range c.Exclude {
		names = append(names, e.Name)
	}
	if !reflect.DeepEqual(names, []string{"A", "B", "C"}) {
		t.Fatalf("exclusions merged as %v", names)
	}
	if !reflect.DeepEqual(c.Eslogger.ExcludeSigning, []string{"com.apple.mdworker"}) || len(c.Files) != 3 || len(c.Dirs) != 2 {
		t.Fatalf("lists/files: %+v", c)
	}
	write(t, filepath.Join(dir, "config.d", "30-bad.yml"), "enable_response: true\n")
	if _, err := Load(main); err == nil || !strings.Contains(err.Error(), "enable_response") {
		t.Fatalf("unknown key must be rejected (no config switch for kill): %v", err)
	}
	if c, err := Load(""); err != nil || c.RulesDir != "" {
		t.Fatalf("Load(\"\") = %+v, %v", c, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yml")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestExclusions(t *testing.T) {
	m := ql.NewMacros()
	if err := m.AddExpr("open_file", "evt.name = 'OpenFile'"); err != nil {
		t.Fatal(err)
	}
	x, err := CompileExclusions([]Exclusion{
		{Name: "spotlight", Events: []string{event.OpenFile, event.WriteFile}, Condition: "ps.signing_id istartswith 'com.apple.mdworker'"},
		{Name: "all forks", Events: []string{event.Fork}},
		{Name: "macro", Condition: "open_file and file.path startswith '/dev/'"},
		{Name: "anything from x", Condition: "ps.exe = '/opt/x'"},
	}, m)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		e    *event.Event
		want string
	}{
		{&event.Event{Name: event.OpenFile, Proc: &event.Proc{SigningID: "com.apple.mdworker_shared"}}, "spotlight"},
		{&event.Event{Name: event.CreateFile, Proc: &event.Proc{SigningID: "com.apple.mdworker_shared"}}, ""},
		{&event.Event{Name: event.Fork}, "all forks"},
		{&event.Event{Name: event.OpenFile, Proc: &event.Proc{}, File: &event.File{Path: "/dev/null"}}, "macro"},
		{&event.Event{Name: event.Mount, Proc: &event.Proc{Exe: "/opt/x"}}, "anything from x"},
		{&event.Event{Name: event.CreateProcess, Proc: &event.Proc{Exe: "/bin/ls"}}, ""},
	}
	for i, c := range cases {
		got, ok := x.Match(c.e)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("case %d: Match = %q,%v want %q", i, got, ok, c.want)
		}
	}
	if st := x.Stats(); st["spotlight"] != 1 || st["all forks"] != 1 || x.Len() != 4 {
		t.Fatalf("stats = %v", st)
	}
	for _, bad := range [][]Exclusion{
		{{Name: "empty"}},
		{{Name: "typo", Events: []string{"OpenFiles"}}},
		{{Name: "bad cond", Condition: "ps.nope = 1"}},
	} {
		if _, err := CompileExclusions(bad, m); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	var nilx *Exclusions
	if _, ok := nilx.Match(&event.Event{}); ok {
		t.Fatal("nil exclusions matched")
	}
}

func TestCheckOwnership(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	write(t, filepath.Join(rules, "a.yml"), "x")
	write(t, filepath.Join(rules, "macros", "m.yml"), "x")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{rules, filepath.Join(rules, "macros")} {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkOwnership(uid, rules); err != nil {
		t.Fatalf("clean tree rejected: %v", err)
	}
	// Owner mismatch: the same tree is not owned by root (tests do not run as root).
	if uid != 0 {
		if err := CheckOwnership(rules); err == nil || !strings.Contains(err.Error(), "must be owned by root") {
			t.Fatalf("non-root owner accepted: %v", err)
		}
	}
	// Group-writable file deep in the tree.
	if err := os.Chmod(filepath.Join(rules, "macros", "m.yml"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(uid, rules); err == nil || !strings.Contains(err.Error(), "m.yml") {
		t.Fatalf("group-writable file accepted: %v", err)
	}
	_ = os.Chmod(filepath.Join(rules, "macros", "m.yml"), 0o644)
	// World-writable parent directory of a checked file.
	if err := os.Chmod(rules, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(uid, filepath.Join(rules, "a.yml")); err == nil {
		t.Fatal("world-writable parent accepted")
	}
	_ = os.Chmod(rules, 0o755)
	// Symlink inside the tree and as the path itself.
	link := filepath.Join(rules, "link.yml")
	if err := os.Symlink(filepath.Join(rules, "a.yml"), link); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(uid, rules); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink in tree accepted: %v", err)
	}
	if err := checkOwnership(uid, link); err == nil {
		t.Fatal("symlink path accepted")
	}
	if err := checkOwnership(uid, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing path accepted")
	}
	_ = os.Remove(link)
	// Every ancestor up to / is checked, not only the direct parent.
	deep := filepath.Join(dir, "a", "b", "c")
	write(t, filepath.Join(deep, "r.yml"), "x")
	for _, d := range []string{filepath.Join(dir, "a"), filepath.Join(dir, "a", "b"), deep} {
		_ = os.Chmod(d, 0o755)
	}
	if err := checkOwnership(uid, deep); err != nil {
		t.Fatalf("clean deep tree rejected: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "a"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(uid, filepath.Join(deep, "r.yml")); err == nil || !strings.Contains(err.Error(), filepath.Join("001", "a")+":") {
		t.Fatalf("world-writable grandparent accepted: %v", err)
	}
	_ = os.Chmod(filepath.Join(dir, "a"), 0o755)
}

func TestSecureRead(t *testing.T) {
	prev := RequiredOwner()
	defer RequireOwner(prev)
	dir := t.TempDir()
	p := filepath.Join(dir, "f.yml")
	write(t, p, "hello")
	RequireOwner(int64(os.Getuid()))
	if b, err := SecureRead(p, 100); err != nil || string(b) != "hello" {
		t.Fatalf("SecureRead = %q, %v", b, err)
	}
	if _, err := SecureRead(p, 3); err == nil {
		t.Fatal("size limit ignored")
	}
	_ = os.Chmod(p, 0o666)
	if _, err := SecureRead(p, 100); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable file read: %v", err)
	}
	RequireOwner(-1)
	if _, err := SecureRead(p, 100); err != nil {
		t.Fatalf("no owner policy: %v", err)
	}
	link := filepath.Join(dir, "l.yml")
	_ = os.Symlink(p, link)
	if _, err := SecureRead(link, 100); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink followed: %v", err)
	}
	if _, err := SecureRead(dir, 100); err == nil {
		t.Fatal("directory read")
	}
	if os.Getuid() != 0 {
		RequireOwner(0)
		_ = os.Chmod(p, 0o644)
		if _, err := SecureRead(p, 100); err == nil || !strings.Contains(err.Error(), "must be owned by root") {
			t.Fatalf("non-root file read under root policy: %v", err)
		}
	}
}

func TestCreatePrivate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.jsonl")
	f, err := CreatePrivate(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if _, err := CreatePrivate(p); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing file reused: %v", err)
	}
	target := filepath.Join(dir, "victim")
	write(t, target, "keep")
	link := filepath.Join(dir, "planted")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePrivate(link); err == nil {
		t.Fatal("pre-planted symlink followed")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("symlink target modified")
	}
}

func TestSubscribeWrite(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "zaafvesper.yml")
	write(t, main, "rules_dir: r\n")
	c, err := Load(main)
	if err != nil || c.Source.SubscribeWrite {
		t.Fatalf("default must be false: %+v %v", c.Source, err)
	}
	write(t, filepath.Join(dir, "config.d", "x.yml"), "source:\n  subscribe_write: true\n")
	c, err = Load(main)
	if err != nil || !c.Source.SubscribeWrite {
		t.Fatalf("config.d override: %+v %v", c.Source, err)
	}
}
