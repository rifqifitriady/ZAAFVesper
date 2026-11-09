package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

const testRulesDir = "testdata/rules"

func TestLoadDir(t *testing.T) {
	rs, err := LoadDir(testRulesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rs.Rules))
	}
	if len(rs.Enabled()) != 2 {
		t.Fatalf("got %d enabled rules, want 2", len(rs.Enabled()))
	}
	if len(rs.Files()) != 4 {
		t.Fatalf("Files = %v", rs.Files())
	}
	var seq *Rule
	for _, r := range rs.Rules {
		if r.IsSequence() {
			seq = r
		}
	}
	if seq == nil || len(seq.Sequence().Steps) != 2 || seq.Sequence().MaxSpan != 2*time.Minute {
		t.Fatalf("sequence rule not compiled: %+v", seq)
	}
	en := NewEngine(rs, Options{})
	if got := en.RequiredEvents(); !reflect.DeepEqual(got, []string{"CreateFile", "CreateProcess"}) {
		t.Fatalf("RequiredEvents = %v", got)
	}
}

func TestRunFixturesTestdata(t *testing.T) {
	res, err := RunFixtures(testRulesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 10 {
		t.Errorf("got %d results, want 10", len(res))
	}
	for _, r := range res {
		if !r.Passed {
			t.Errorf("%s / %s %q: %s", r.RuleName, r.Kind, r.Desc, r.Err)
		}
	}
}

// writeRules creates a temporary rules dir from name -> content.
func writeRules(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const goodRule = `name: R
id: 9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b
version: 1.0.0
condition: evt.name = 'CreateProcess'
output: "%ps.exe"
severity: low
min-engine-version: 0.1.0
`

func TestLoadDirValidation(t *testing.T) {
	cases := []struct {
		name string
		rule string
		want string
	}{
		{"bad id", strings.Replace(goodRule, "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b", "not-a-uuid", 1), "not a UUID v4"},
		{"uuid v1", strings.Replace(goodRule, "9fc0f5b6-65d1-4d7c", "9fc0f5b6-65d1-1d7c", 1), "not a UUID v4"},
		{"severity", strings.Replace(goodRule, "severity: low", "severity: urgent", 1), "severity"},
		{"version", strings.Replace(goodRule, "version: 1.0.0", "version: v1", 1), "MAJOR.MINOR.PATCH"},
		{"engine", strings.Replace(goodRule, "min-engine-version: 0.1.0", "min-engine-version: 9.0.0", 1), "needs engine 9.0.0"},
		{"no engine", strings.Replace(goodRule, "min-engine-version: 0.1.0\n", "", 1), "min-engine-version is required"},
		{"technique", goodRule + "labels: {technique.id: T15.1}\n", "T1234"},
		{"tactic", goodRule + "labels: {tactic.id: T0003}\n", "TA1234"},
		{"action", goodRule + "action: [{name: block}]\n", "not supported"},
		{"action target", goodRule + "action: [{name: kill, target: grandparent}]\n", `target "grandparent" must be`},
		{"quarantine target", goodRule + "action: [{name: quarantine_file, target: parent}]\n", `target "parent" must be "file" or "process"`},
		{"requarantine target", goodRule + "action: [{name: requarantine, target: process}]\n", `must be "file"`},
		{"persistence target", goodRule + "action: [{name: remove_persistence, target: parent}]\n", `must be "file"`},
		{"isolate target", goodRule + "action: [{name: isolate_process, target: file}]\n", `must be "process" or "parent"`},
		{"suspend target", goodRule + "action: [{name: suspend, target: file}]\n", `must be "process" or "parent"`},
		{"duplicate action", goodRule + "action: [{name: kill}, {name: kill, target: process}]\n", "listed twice"},
		{"atomic", goodRule + "tests: {atomic: [xyz]}\n", "not a GUID"},
		{"unknown key", goodRule + "severty: low\n", "severty"},
		{"unknown field", strings.Replace(goodRule, "evt.name = 'CreateProcess'", "ps.nope = 1", 1), `rule "R": condition: line 1 col 1: unknown field`},
		{"output field", strings.Replace(goodRule, `"%ps.exe"`, `"%ps.nope"`, 1), "output"},
		{"output step", strings.Replace(goodRule, `"%ps.exe"`, `"%1.ps.exe"`, 1), "not a sequence"},
		{"two docs", goodRule + "---\n" + goodRule, "one rule per file"},
		{"empty", "", "empty"},
		{"no name", strings.Replace(goodRule, "name: R\n", "", 1), "name is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeRules(t, map[string]string{"r.yml": c.rule})
			_, err := LoadDir(dir)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v does not contain %q", err, c.want)
			}
		})
	}
}

func TestActionTargets(t *testing.T) {
	for _, c := range []struct{ target, display, kill string }{
		{"", "kill", TargetProcess},
		{"process", "kill", TargetProcess},
		{"parent", "kill:parent", TargetParent},
	} {
		rule := goodRule + "action: [{name: kill, target: " + c.target + "}]\n"
		if c.target == "" {
			rule = goodRule + "action: [{name: kill}]\n"
		}
		rs, err := LoadDir(writeRules(t, map[string]string{"r.yml": rule}))
		if err != nil {
			t.Fatalf("target %q: %v", c.target, err)
		}
		r := rs.Rules[0]
		if got := r.Actions(); !reflect.DeepEqual(got, []string{c.display}) {
			t.Fatalf("target %q: Actions = %v", c.target, got)
		}
		if got := r.Action[0].KillTarget(); got != c.kill {
			t.Fatalf("target %q: KillTarget = %q", c.target, got)
		}
		al := NewEngine(rs, Options{}).Process(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: 3, Exe: "/x"}})
		if len(al) != 1 || len(al[0].Response) != 1 || al[0].Response[0].KillTarget() != c.kill {
			t.Fatalf("target %q: alert response = %+v", c.target, al)
		}
	}
}

// TestResponseActionNames: every reserved action name of the v0.2 contract
// validates with its targets, and displays with a non-default target only.
func TestResponseActionNames(t *testing.T) {
	for _, c := range []struct {
		yaml, display, target string
	}{
		{"{name: suspend}", "suspend", TargetProcess},
		{"{name: suspend, target: parent}", "suspend:parent", TargetParent},
		{"{name: quarantine_file}", "quarantine_file", TargetFile},
		{"{name: quarantine_file, target: file}", "quarantine_file", TargetFile},
		{"{name: quarantine_file, target: process}", "quarantine_file:process", TargetProcess},
		{"{name: requarantine}", "requarantine", TargetFile},
		{"{name: remove_persistence}", "remove_persistence", TargetFile},
		{"{name: isolate_process}", "isolate_process", TargetProcess},
		{"{name: isolate_process, target: parent}", "isolate_process:parent", TargetParent},
	} {
		rs, err := LoadDir(writeRules(t, map[string]string{"r.yml": goodRule + "action: [" + c.yaml + "]\n"}))
		if err != nil {
			t.Fatalf("%s: %v", c.yaml, err)
		}
		a := rs.Rules[0].Action[0]
		if got := rs.Rules[0].Actions(); !reflect.DeepEqual(got, []string{c.display}) || a.EffectiveTarget() != c.target {
			t.Fatalf("%s: Actions = %v target = %q", c.yaml, got, a.EffectiveTarget())
		}
	}
	rs, err := LoadDir(writeRules(t, map[string]string{"r.yml": goodRule + "action: [{name: suspend, target: parent}, {name: kill, target: parent}]\n"}))
	if err != nil || !reflect.DeepEqual(rs.Rules[0].Actions(), []string{"suspend:parent", "kill:parent"}) {
		t.Fatalf("suspend then kill: %v %v", err, rs)
	}
	if len(ActionNames()) != 6 {
		t.Fatalf("ActionNames = %v", ActionNames())
	}
}

func TestLoadDirDuplicateID(t *testing.T) {
	dir := writeRules(t, map[string]string{"a.yml": goodRule, "b.yml": strings.Replace(goodRule, "name: R", "name: S", 1)})
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestLoadDirReportsAllErrors(t *testing.T) {
	dir := writeRules(t, map[string]string{
		"a.yml": strings.Replace(goodRule, "severity: low", "severity: x", 1),
		"b.yml": strings.Replace(goodRule, "evt.name", "evt.nme", 1),
	})
	_, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "a.yml") || !strings.Contains(err.Error(), "b.yml") {
		t.Fatalf("expected errors for both files, got %v", err)
	}
}

func TestSequenceParseErrors(t *testing.T) {
	m := ql.NewMacros()
	cases := []struct{ cond, want string }{
		{"sequence maxspan 2m |ps.pid = 1|", "at least 2 steps"},
		{"sequence |ps.pid = 1| |ps.pid = 2|", "needs maxspan"},
		{"sequence maxspan 2x |ps.pid = 1| |ps.pid = 2|", "not a positive duration"},
		{"sequence maxspan 48h |ps.pid = 1| |ps.pid = 2|", "exceeds"},
		{"sequence maxspan 2m within |ps.pid = 1| |ps.pid = 2|", "unexpected \"within\""},
		{"sequence maxspan 2m |ps.pid = 1| |ps.pid = 2", "missing closing"},
		{"sequence maxspan 2m |ps.pid = 1| x |ps.pid = 2|", "expected '|'"},
		{"sequence maxspan 2m |ps.pid = 1| by ps.exe |ps.pid = 2|", "every step"},
		{"sequence maxspan 2m by ps.uuid |ps.pid = 1| by ps.exe |ps.pid = 2|", "global by"},
		{"sequence maxspan 2m by ps.args |ps.pid = 1| |ps.pid = 2|", "string or integer"},
		{"sequence maxspan 2m |ps.pid = 1| |ps.nope = 2|", "step 2"},
		{"sequence maxspan 2m |a| |b| |c| |d| |e| |f|", "step 1"},
		{"sequence maxspan 1s |true| |true| |true| |true| |true| |true|", "more than 5"},
		{"sequence maxspan 1s || |true|", "empty"},
	}
	for _, c := range cases {
		_, err := parseSequence(c.cond, m)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: error %v does not contain %q", c.cond, err, c.want)
		}
	}
}

func TestSequenceStringWithPipe(t *testing.T) {
	seq, err := parseSequence(`sequence maxspan 1m by ps.pid
	  |ps.cmdline contains 'a | b'|
	  |ps.cmdline contains '\'|\''|`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seq.Steps) != 2 || seq.Steps[1].Expr != `ps.cmdline contains '\'|\''` {
		t.Fatalf("steps = %+v", seq.Steps)
	}
}

// seqRule builds an engine around one sequence condition.
func seqEngine(t *testing.T, cond string, max int) *Engine {
	t.Helper()
	m := ql.NewMacros()
	r := &Rule{Name: "seq", ID: "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b", Version: "1.0.0",
		Condition: cond, Output: "%1.file.path then %ps.exe", Severity: "low", MinEngineVersion: "0.1.0"}
	if err := r.Compile(m); err != nil {
		t.Fatal(err)
	}
	return NewEngine(&Ruleset{Rules: []*Rule{r}}, Options{MaxPartials: max})
}

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func create(at time.Duration, path string, pid int32) *event.Event {
	return &event.Event{Name: event.CreateFile, Time: t0.Add(at), Proc: &event.Proc{PID: pid, Exe: "/usr/bin/curl"}, File: &event.File{Path: path}}
}

func exec(at time.Duration, exe string, pid int32) *event.Event {
	return &event.Event{Name: event.CreateProcess, Time: t0.Add(at), Proc: &event.Proc{PID: pid, Exe: exe}}
}

const dropExec = `sequence maxspan 2m
  |evt.name = 'CreateFile' and file.path startswith '/tmp/'| by file.path
  |evt.name = 'CreateProcess'| by ps.exe`

func TestSequenceEngine(t *testing.T) {
	type step struct {
		ev   *event.Event
		want int
	}
	cases := []struct {
		name  string
		cond  string
		steps []step
	}{
		{"basic", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{exec(time.Minute, "/tmp/a", 2), 1},
		}},
		{"join mismatch", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{exec(time.Second, "/tmp/b", 2), 0},
		}},
		{"expired", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{exec(2*time.Minute+time.Millisecond, "/tmp/a", 2), 0},
		}},
		{"exactly maxspan", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{exec(2*time.Minute, "/tmp/a", 2), 1},
		}},
		{"matched sequence resets", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{exec(time.Second, "/tmp/a", 2), 1},
			{exec(2*time.Second, "/tmp/a", 3), 0},
		}},
		{"restart after reset", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{exec(time.Second, "/tmp/a", 2), 1},
			{create(3*time.Second, "/tmp/a", 1), 0},
			{exec(4*time.Second, "/tmp/a", 3), 1},
		}},
		{"newest start wins", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{create(90*time.Second, "/tmp/a", 1), 0},
			{exec(150*time.Second, "/tmp/a", 2), 1},
		}},
		{"independent keys", dropExec, []step{
			{create(0, "/tmp/a", 1), 0},
			{create(time.Second, "/tmp/b", 1), 0},
			{exec(2*time.Second, "/tmp/b", 2), 1},
			{exec(3*time.Second, "/tmp/a", 3), 1},
		}},
		{"step order enforced", dropExec, []step{
			{exec(0, "/tmp/a", 2), 0},
			{create(time.Second, "/tmp/a", 1), 0},
		}},
		{"global by", `sequence maxspan 10s by ps.pid
		  |evt.name = 'CreateFile'|
		  |evt.name = 'CreateProcess'|`, []step{
			{create(0, "/tmp/x", 7), 0},
			{exec(time.Second, "/bin/ls", 8), 0},
			{exec(2*time.Second, "/bin/ls", 7), 1},
		}},
		{"no join", `sequence maxspan 10s
		  |evt.name = 'CreateFile'|
		  |evt.name = 'CreateProcess'|`, []step{
			{create(0, "/tmp/x", 7), 0},
			{exec(time.Second, "/bin/ls", 8), 1},
		}},
		{"one event cannot fill two steps", `sequence maxspan 10s
		  |ps.pid = 7|
		  |ps.pid = 7|`, []step{
			{exec(0, "/bin/a", 7), 0},
			{exec(time.Second, "/bin/b", 7), 1},
		}},
		{"three steps", `sequence maxspan 1m by ps.pid
		  |evt.name = 'CreateProcess' and ps.exe = '/usr/bin/sw_vers'|
		  |evt.name = 'CreateProcess' and ps.exe = '/usr/sbin/system_profiler'|
		  |evt.name = 'CreateProcess' and ps.exe = '/usr/bin/whoami'|`, []step{
			{exec(0, "/usr/bin/sw_vers", 5), 0},
			{exec(time.Second, "/usr/bin/whoami", 5), 0},
			{exec(2*time.Second, "/usr/sbin/system_profiler", 5), 0},
			{exec(3*time.Second, "/usr/bin/whoami", 5), 1},
		}},
		{"missing join value", dropExec, []step{
			{&event.Event{Name: event.CreateFile, Time: t0, Proc: &event.Proc{PID: 1}}, 0},
			{exec(time.Second, "/tmp/a", 2), 0},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			en := seqEngine(t, c.cond, 0)
			for i, s := range c.steps {
				if got := len(en.Process(s.ev)); got != s.want {
					t.Fatalf("event %d: %d alerts, want %d", i+1, got, s.want)
				}
			}
		})
	}
}

func TestSequenceAlertContent(t *testing.T) {
	en := seqEngine(t, dropExec, 0)
	en.Process(create(0, "/tmp/a", 1))
	al := en.Process(exec(time.Second, "/tmp/a", 2))
	if len(al) != 1 {
		t.Fatalf("got %d alerts", len(al))
	}
	a := al[0]
	if a.Output != "/tmp/a then /tmp/a" || len(a.Events) != 2 || !a.Time.Equal(t0.Add(time.Second)) {
		t.Fatalf("alert = %+v", a)
	}
	if a.Last().Proc.PID != 2 {
		t.Fatal("Last is not the completing event")
	}
	if st := en.Stats(); st.Alerts != 1 || st.PerRule["seq"] != 1 || st.Partials != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestSequenceCapAndExpiry(t *testing.T) {
	en := seqEngine(t, dropExec, 3)
	for i := 0; i < 5; i++ {
		en.Process(create(time.Duration(i)*time.Second, "/tmp/"+string(rune('a'+i)), 1))
	}
	st := en.Stats()
	if st.Partials != 3 || st.Evicted != 2 {
		t.Fatalf("after cap: %+v", st)
	}
	// The oldest (a, b) were evicted; c still completes.
	if n := len(en.Process(exec(6*time.Second, "/tmp/a", 2))); n != 0 {
		t.Fatal("evicted partial completed")
	}
	if n := len(en.Process(exec(7*time.Second, "/tmp/c", 2))); n != 1 {
		t.Fatal("live partial did not complete")
	}
	// An unrelated event far in the future expires the rest.
	en.Process(exec(time.Hour, "/bin/ls", 3))
	if st := en.Stats(); st.Partials != 0 || st.Expired != 2 {
		t.Fatalf("after expiry: %+v", st)
	}
}

func TestSequenceClockForZeroTime(t *testing.T) {
	now := t0
	m := ql.NewMacros()
	r := &Rule{Name: "seq", ID: "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b", Version: "1.0.0",
		Condition: dropExec, Severity: "low", MinEngineVersion: "0.1.0"}
	if err := r.Compile(m); err != nil {
		t.Fatal(err)
	}
	en := NewEngine(&Ruleset{Rules: []*Rule{r}}, Options{Clock: func() time.Time { return now }})
	c := create(0, "/tmp/a", 1)
	c.Time = time.Time{}
	en.Process(c)
	now = now.Add(3 * time.Minute) // fake clock moves past maxspan
	x := exec(0, "/tmp/a", 2)
	x.Time = time.Time{}
	if n := len(en.Process(x)); n != 0 {
		t.Fatal("sequence completed after maxspan on the fake clock")
	}
	if en.Process(&event.Event{}) != nil || en.Process(nil) != nil {
		t.Fatal("unexpected alerts")
	}
}

func TestEngineSingleAndIndex(t *testing.T) {
	rs, err := LoadDir(testRulesDir)
	if err != nil {
		t.Fatal(err)
	}
	en := NewEngine(rs, Options{})
	e := &event.Event{Name: event.CreateFile, Time: t0,
		Proc: &event.Proc{PID: 3, Exe: "/usr/bin/curl"},
		File: &event.File{Path: "/Library/LaunchAgents/x.plist"}}
	al := en.Process(e)
	if len(al) != 1 {
		t.Fatalf("got %d alerts", len(al))
	}
	a := al[0]
	if a.Output != "/usr/bin/curl created launch agent /Library/LaunchAgents/x.plist" ||
		a.Severity != "high" || !reflect.DeepEqual(a.Actions, []string{"kill"}) ||
		a.Labels["technique.id"] != "T1543.001" {
		t.Fatalf("alert = %+v", a)
	}
	// Disabled rule never fires.
	x := &event.Event{Name: event.DeleteXattr, File: &event.File{Path: "/x"}, Args: map[string]string{"xattr": "com.apple.quarantine"}}
	if len(en.Process(x)) != 0 {
		t.Fatal("disabled rule fired")
	}
}

func TestEngineAnyRules(t *testing.T) {
	r := &Rule{Name: "any", ID: "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b", Version: "1.0.0",
		Condition: "ps.exe = '/tmp/x'", Severity: "low", MinEngineVersion: "0.1.0"}
	if err := r.Compile(nil); err != nil {
		t.Fatal(err)
	}
	en := NewEngine(&Ruleset{Rules: []*Rule{r}}, Options{})
	if en.RequiredEvents() != nil {
		t.Fatal("unconstrained rule must require every event")
	}
	if n := len(en.Process(&event.Event{Name: event.Mount, Proc: &event.Proc{Exe: "/tmp/x"}})); n != 1 {
		t.Fatalf("got %d alerts", n)
	}
	if a := en.Process(&event.Event{Name: event.Mount, Proc: &event.Proc{Exe: "/tmp/x"}}); a[0].Output != "any" {
		t.Fatalf("empty output should fall back to the rule name, got %q", a[0].Output)
	}
}

func TestTemplate(t *testing.T) {
	evs := []*event.Event{
		{Proc: &event.Proc{Exe: "/a", PID: 1, Args: []string{"x", "y"}}, File: &event.File{Path: "/f"}},
		{Proc: &event.Proc{Exe: "/b", PID: 2, IsSigned: true}, Args: map[string]string{"signal": "9"}},
	}
	cases := []struct{ tmpl, want string }{
		{"%ps.exe", "/b"},
		{"%1.ps.exe -> %2.ps.exe", "/a -> /b"},
		{"wrote %1.file.path.", "wrote /f."},
		{"100%% sure, pid %ps.pid", "100% sure, pid 2"},
		{"%ps.is_signed %1.ps.args", "true [x y]"},
		{"sig %evt.arg[signal]!", "sig 9!"},
		{"%file.path", "<none>"},
		{"50% ", "50% "},
		{"end %", "end %"},
	}
	for _, c := range cases {
		tp, err := parseTemplate(c.tmpl, 2)
		if err != nil {
			t.Fatalf("%q: %v", c.tmpl, err)
		}
		if got := tp.render(evs); got != c.want {
			t.Errorf("%q = %q, want %q", c.tmpl, got, c.want)
		}
	}
	for _, bad := range []string{"%3.ps.exe", "%ps.nope", "%0.ps.exe"} {
		if _, err := parseTemplate(bad, 2); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRunFixturesFailures(t *testing.T) {
	dir := writeRules(t, map[string]string{
		"a.yml": goodRule,
		"b.yml": strings.NewReplacer("name: R", "name: B", "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b", "2528a712-3399-4db7-8951-42b1f31db3d5").Replace(goodRule),
		"c.yml": strings.NewReplacer("name: R", "name: C", "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b", "734fbb6d-91e3-4b6a-af80-35c5188e3d10").Replace(goodRule),
		"testdata/a.yml": `match:
  - desc: fires
    events: [{name: CreateProcess, proc: {exe: /bin/ls}}]
  - desc: does not fire
    events: [{name: CreateFile}]
nomatch:
  - desc: fires
    events: [{name: CreateProcess}]
`,
		"testdata/b.yml":      "match:\n  - desc: typo\n    events: [{name: CreateProcess, proc: {exe_path: /x}}]\n",
		"testdata/orphan.yml": "match: []\n",
	})
	res, err := RunFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res {
		got = append(got, r.RuleName+"|"+r.Kind+"|"+r.Desc+"|"+boolStr(r.Passed))
		if !r.Passed && r.Err == "" {
			t.Errorf("failed result without error: %+v", r)
		}
	}
	want := []string{
		"R|fixture||fail", // too few nomatch scenarios
		"R|match|fires|pass",
		"R|match|does not fire|fail",
		"R|nomatch|fires|fail",
		"B|fixture||fail", // unknown key exe_path
		"C|fixture||fail", // missing fixture
		"|fixture||fail",  // orphan fixture
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func boolStr(b bool) string {
	if b {
		return "pass"
	}
	return "fail"
}

func TestNormalizeScenario(t *testing.T) {
	evs := []*event.Event{
		{Name: event.CreateProcess, Proc: &event.Proc{Exe: "/bin/zsh", Args: []string{"zsh", "-c", "id"}, Parent: &event.Proc{Exe: "/usr/bin/login"}}},
		{Name: event.Fork, Seq: 10},
		{Name: event.Fork},
	}
	if err := NormalizeScenario(evs); err != nil {
		t.Fatal(err)
	}
	if !evs[1].Time.Equal(FixtureBaseTime.Add(time.Second)) || evs[0].Seq != 1 || evs[1].Seq != 10 || evs[2].Seq != 11 {
		t.Fatalf("times/seqs: %v %d %d %d", evs[1].Time, evs[0].Seq, evs[1].Seq, evs[2].Seq)
	}
	p := evs[0].Proc
	if p.Name != "zsh" || p.Cmdline != "zsh -c id" || p.Parent.Name != "login" || evs[0].Source != "fixture" {
		t.Fatalf("proc = %+v", p)
	}
	if err := NormalizeScenario([]*event.Event{{Name: "Nope"}}); err == nil {
		t.Fatal("unknown event name accepted")
	}
}

func TestSequenceSlimEvents(t *testing.T) {
	en := seqEngine(t, dropExec, 0)
	big := strings.Repeat("A", 10000)
	c := create(0, "/tmp/a", 1)
	c.Proc.Env = map[string]string{"SECRET": "s3cr3t", "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}
	c.Proc.Cmdline = big
	c.Proc.Args = []string{"curl", big, "-o", "/tmp/a"}
	c.Proc.Parent = &event.Proc{Exe: "/bin/zsh", Env: map[string]string{"K": "v"}, Parent: &event.Proc{Exe: "/sbin/launchd"}}
	c.Args = map[string]string{"x": big}
	en.Process(c)
	if c.Proc.Env == nil || len(c.Proc.Cmdline) != 10000 {
		t.Fatal("original event was modified")
	}
	st := en.Stats()
	if st.PartialBytes <= 0 || st.PartialBytes > 3*MaxSlimField {
		t.Fatalf("PartialBytes = %d", st.PartialBytes)
	}
	al := en.Process(exec(time.Second, "/tmp/a", 2))
	if len(al) != 1 {
		t.Fatalf("alerts = %d", len(al))
	}
	first := al[0].Events[0]
	if first.Proc.Env != nil || first.Proc.Parent.Env != nil || first.Proc.Parent.Parent != nil {
		t.Fatalf("env kept in partial: %+v", first.Proc)
	}
	if len(first.Proc.Cmdline) != MaxSlimField || len(first.Args["x"]) != MaxSlimField {
		t.Fatalf("not capped: cmdline %d arg %d", len(first.Proc.Cmdline), len(first.Args["x"]))
	}
	if !reflect.DeepEqual(first.Proc.Args, []string{"curl"}) {
		t.Fatalf("args = %v", first.Proc.Args)
	}
	if en.Stats().PartialBytes != 0 {
		t.Fatalf("budget not released: %d", en.Stats().PartialBytes)
	}
}

func TestSequenceGlobalByteBudget(t *testing.T) {
	m := ql.NewMacros()
	mk := func(name, id string) *Rule {
		r := &Rule{Name: name, ID: id, Version: "1.0.0", Condition: dropExec, Severity: "low", MinEngineVersion: "0.1.0"}
		if err := r.Compile(m); err != nil {
			t.Fatal(err)
		}
		return r
	}
	rs := &Ruleset{Rules: []*Rule{
		mk("a", "9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b"),
		mk("b", "2528a712-3399-4db7-8951-42b1f31db3d5"),
	}}
	// Each CreateFile starts one partial in each rule (~350 bytes each).
	en := NewEngine(rs, Options{MaxPartialBytes: 2000})
	for i := 0; i < 10; i++ {
		en.Process(create(time.Duration(i)*time.Second, fmt.Sprintf("/tmp/f%d", i), 1))
	}
	st := en.Stats()
	if st.PartialBytes > 2000 || st.Evicted == 0 || st.Partials >= 20 {
		t.Fatalf("budget not enforced: %+v", st)
	}
	// The newest partial survives in both rules, the oldest is gone.
	if n := len(en.Process(exec(11*time.Second, "/tmp/f9", 2))); n != 2 {
		t.Fatalf("newest partial: %d alerts, want 2", n)
	}
	if n := len(en.Process(exec(12*time.Second, "/tmp/f0", 2))); n != 0 {
		t.Fatalf("oldest partial survived: %d alerts", n)
	}
}

func TestLoadDirSecureRead(t *testing.T) {
	prev := config.RequiredOwner()
	config.RequireOwner(int64(os.Getuid()))
	defer config.RequireOwner(prev)

	dir := writeRules(t, map[string]string{"a.yml": goodRule})
	if _, err := LoadDir(dir); err != nil {
		t.Fatalf("clean dir: %v", err)
	}
	// Group-writable rule file is refused on the open descriptor.
	if err := os.Chmod(filepath.Join(dir, "a.yml"), 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable rule accepted: %v", err)
	}
	_ = os.Chmod(filepath.Join(dir, "a.yml"), 0o644)
	// A symlinked rule or macro file is never followed.
	other := filepath.Join(t.TempDir(), "x.yml")
	if err := os.WriteFile(other, []byte(goodRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "b.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked rule accepted: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "b.yml"))
	if err := os.MkdirAll(filepath.Join(dir, "macros"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "macros", "m.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked macro file accepted: %v", err)
	}
}
