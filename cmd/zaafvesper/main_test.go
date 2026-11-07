package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

const (
	testRules   = "../../pkg/rules/testdata/rules"
	testEvents  = "../../pkg/capture/testdata/events.jsonl"
	testESTree  = "../../pkg/capture/testdata/eslogger_exec_tree.jsonl"
	killRuleSub = "Launch Agent persistence via plist write"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := realMain(args, &out, &errb)
	return code, out.String(), errb.String()
}

func noControls(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) {
			t.Fatalf("terminal output contains control %U: %q", r, s)
		}
	}
}

func TestUsageAndVersion(t *testing.T) {
	if code, _, _ := runCLI(t); code != 2 {
		t.Fatalf("no args: exit %d", code)
	}
	if code, _, errs := runCLI(t, "bogus\x1b[2J"); code != 2 || strings.Contains(errs, "\x1b") {
		t.Fatalf("unknown command: exit %d, %q", code, errs)
	}
	code, out, _ := runCLI(t, "version")
	if code != 0 || !strings.Contains(out, "rule engine "+rules.EngineVersion) {
		t.Fatalf("version: %d %q", code, out)
	}
}

func TestRulesCommands(t *testing.T) {
	code, out, errs := runCLI(t, "rules", "validate", testRules)
	if code != 0 || !strings.Contains(out, "OK: 3 rules (2 enabled, 1 sequences)") {
		t.Fatalf("validate: %d %q %q", code, out, errs)
	}
	code, out, _ = runCLI(t, "rules", "test", "--rules", testRules)
	if code != 0 || !strings.Contains(out, "10 passed, 0 failed") {
		t.Fatalf("test: %d %q", code, out)
	}
	code, out, _ = runCLI(t, "rules", "list", testRules)
	if code != 0 || !strings.Contains(out, "seq/2") || !strings.Contains(out, "kill") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, "rules", "frobnicate", testRules); code != 2 {
		t.Fatalf("unknown subcommand: %d", code)
	}
}

const evilRule = "name: \"Evil\\e[2J name\"\nid: 9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b\nversion: 1.0.0\n" +
	"condition: ps.exe = '\\u001b]0;x'\noutput: \"%ps.exe\"\nseverity: low\nmin-engine-version: 0.1.0\n"

func TestRulesOutputIsSanitized(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil.yml"), []byte(evilRule), 0o644); err != nil {
		t.Fatal(err)
	}
	// list shows the escape-laden name; test fails (no fixture) and prints it.
	for _, sub := range []string{"list", "test", "validate"} {
		_, out, errs := runCLI(t, "rules", sub, dir)
		noControls(t, out)
		noControls(t, errs)
	}
	_, out, _ := runCLI(t, "rules", "test", dir)
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "missing fixture") {
		t.Fatalf("expected a fixture failure: %q", out)
	}
	// A broken rule's error (which echoes the condition) is sanitized too.
	bad := strings.Replace(evilRule, "ps.exe = ", "ps.ex\x1b = ", 1)
	if err := os.WriteFile(filepath.Join(dir, "evil.yml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runCLI(t, "rules", "validate", dir)
	if code != 1 {
		t.Fatalf("broken rule validated: %d", code)
	}
	noControls(t, errs)
}

func TestReplayPlainJSONL(t *testing.T) {
	jsonOut := filepath.Join(t.TempDir(), "alerts.jsonl")
	code, out, errs := runCLI(t, "replay", "--rules", testRules, "--json", jsonOut, testEvents)
	if code != 0 {
		t.Fatalf("replay: %d %s", code, errs)
	}
	noControls(t, out)
	noControls(t, errs)
	if strings.Count(out, "\n    rule=") != 2 || !strings.Contains(out, "Binary dropped in /tmp then executed") || !strings.Contains(out, killRuleSub) {
		t.Fatalf("alerts: %s", out)
	}
	// replay can never kill, even for a rule with action kill.
	if strings.Contains(errs, "response") {
		t.Fatalf("replay produced a response decision: %s", errs)
	}
	fi, err := os.Stat(jsonOut)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("json file: %v %v", fi, err)
	}
	data, _ := os.ReadFile(jsonOut)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("json lines: %d", len(lines))
	}
	var a rules.Alert
	if err := json.Unmarshal([]byte(lines[0]), &a); err != nil || len(a.Events) != 2 {
		t.Fatalf("json alert: %v %+v", err, a)
	}
	// An existing output file is never reused.
	if code, _, errs := runCLI(t, "replay", "--rules", testRules, "--json", jsonOut, testEvents); code != 1 || !strings.Contains(errs, "exists") {
		t.Fatalf("existing json file reused: %d %s", code, errs)
	}
}

func TestReplayRcapWithExclusions(t *testing.T) {
	dir := t.TempDir()
	// Build an .rcap from the plain events.
	r, err := capture.Open(testEvents)
	if err != nil {
		t.Fatal(err)
	}
	rcap := filepath.Join(dir, "x.rcap")
	w, err := capture.Create(rcap)
	if err != nil {
		t.Fatal(err)
	}
	for {
		e, err := r.Next()
		if err != nil {
			break
		}
		_ = w.Write(e)
	}
	r.Close()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "zaafvesper.yml")
	if err := os.WriteFile(cfg, []byte("exclude:\n  - name: no tmp payload\n    condition: ps.exe = '/tmp/payload'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCLI(t, "replay", "--rules", testRules, "--config", cfg, rcap)
	if code != 0 {
		t.Fatalf("replay: %d %s", code, errs)
	}
	// The exclusion removes the exec and the launch agent write.
	if strings.Contains(out, "rule=") || !strings.Contains(errs, "excluded=2") || !strings.Contains(errs, "format=events") {
		t.Fatalf("out=%q errs=%q", out, errs)
	}
}

func TestReplayRawEsloggerIsEnriched(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Fires only if ps.parent.exe was filled by the snapshotter: raw eslogger
	// carries just a pid stub for the parent.
	write(filepath.Join(dir, "r.yml"), `name: curl from zsh
id: 9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b
version: 1.0.0
condition: evt.name = 'CreateProcess' and ps.exe = '/usr/bin/curl' and ps.parent.exe = '/bin/zsh' and ps.ancestors = '/bin/zsh'
output: "%ps.parent.exe ran %ps.cmdline"
severity: low
min-engine-version: 0.1.0
`)
	code, out, errs := runCLI(t, "replay", "--rules", dir, testESTree)
	if code != 0 || !strings.Contains(errs, "format=eslogger") {
		t.Fatalf("replay: %d %s", code, errs)
	}
	if !strings.Contains(out, "/bin/zsh ran curl -fsSL") {
		t.Fatalf("raw eslogger events were not enriched: out=%q errs=%q", out, errs)
	}
}

func TestReplayErrors(t *testing.T) {
	if code, _, _ := runCLI(t, "replay", "--rules", testRules); code != 2 {
		t.Fatal("missing file argument accepted")
	}
	if code, _, _ := runCLI(t, "replay", "--rules", testRules, "/nonexistent.rcap"); code != 1 {
		t.Fatal("missing capture accepted")
	}
	if code, _, _ := runCLI(t, "replay", "--rules", t.TempDir()+"/nope", testEvents); code != 1 {
		t.Fatal("missing rules dir accepted")
	}
}

func TestCoverage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "layer.json")
	code, stdout, errs := runCLI(t, "coverage", "--navigator", out, "--rules", testRules)
	if code != 0 {
		t.Fatalf("coverage: %d %s", code, errs)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var layer map[string]any
	if err := json.Unmarshal(data, &layer); err != nil {
		t.Fatal(err)
	}
	if layer["domain"] != "enterprise-attack" || layer["versions"].(map[string]any)["layer"] != "4.5" {
		t.Fatalf("layer header: %v %v", layer["domain"], layer["versions"])
	}
	techs := layer["techniques"].([]any)
	// Two enabled rules (the quarantine rule is disabled).
	if len(techs) != 2 || !strings.Contains(stdout, "T1543.001") {
		t.Fatalf("techniques: %v", techs)
	}
	if code, _, _ := runCLI(t, "coverage", "--rules", testRules); code != 2 {
		t.Fatal("missing --navigator accepted")
	}
}

func TestSubscription(t *testing.T) {
	got := subscription([]string{event.CreateFile, event.YaraMatch}, false)
	want := []string{event.CreateFile, event.CreateProcess, event.Fork, event.TerminateProcess}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subscription = %v", got)
	}
	got = subscription([]string{event.Signal}, true)
	want = []string{event.CreateFile, event.CreateProcess, event.Fork, event.Signal, event.TerminateProcess, event.WriteFile}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with yara = %v", got)
	}
	if subscription(nil, false) != nil {
		t.Fatal("nil (all events) must stay nil")
	}
}

func TestRunRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	code, _, errs := runCLI(t, "run", "--rules", testRules)
	if code != 1 || !strings.Contains(errs, "needs root") {
		t.Fatalf("run as non-root: %d %q", code, errs)
	}
}

// TestBuildSensorWiring checks run's wiring without starting eslogger.
func TestBuildSensorWiring(t *testing.T) {
	cases := []struct {
		enable, dry bool
		wantResp    bool
		wantDry     bool
	}{
		{false, false, false, false},
		{true, false, true, false},
		{false, true, true, true},
		{true, true, true, true}, // dry-run wins
	}
	for _, c := range cases {
		dir := t.TempDir()
		var out, errb bytes.Buffer
		s, err := buildSensor(runOptions{
			rulesDir: testRules, rulesGiven: true, configPath: filepath.Join(dir, "none.yml"),
			capturePath: filepath.Join(dir, "c.rcap"), jsonPath: filepath.Join(dir, "a.jsonl"),
			enableResponse: c.enable, dryRunResponse: c.dry,
		}, &out, &errb)
		if err != nil {
			t.Fatal(err)
		}
		if (s.p.responder != nil) != c.wantResp {
			t.Fatalf("%+v: responder present = %v", c, s.p.responder != nil)
		}
		if c.wantDry && !strings.Contains(errb.String(), "DRY-RUN") {
			t.Fatalf("%+v: dry-run not announced: %s", c, errb.String())
		}
		for _, n := range []string{event.CreateProcess, event.Fork, event.TerminateProcess, event.CreateFile} {
			found := false
			for _, x := range s.events {
				found = found || x == n
			}
			if !found {
				t.Fatalf("subscription %v lacks %s", s.events, n)
			}
		}
		if s.src == nil || s.p.enricher == nil || s.p.capture == nil || len(s.p.sinks) != 2 || s.p.dedup == nil {
			t.Fatalf("incomplete wiring: %+v", s.p)
		}
		if err := s.close(); err != nil {
			t.Fatal(err)
		}
		// The capture must be a readable gzip after close.
		r, err := capture.Open(filepath.Join(dir, "c.rcap"))
		if err != nil {
			t.Fatalf("capture unreadable after close: %v", err)
		}
		r.Close()
		noControls(t, errb.String())
	}
}

func TestPipelineResponse(t *testing.T) {
	rs, err := rules.LoadDir(testRules)
	if err != nil {
		t.Fatal(err)
	}
	var killed []int
	var decisions []response.Decision
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	resp := response.New(response.Config{
		KillFunc: func(pid int, _ syscall.Signal) error { killed = append(killed, pid); return nil },
		Identify: func(pid int32) (response.Identity, error) {
			return response.Identity{StartTime: t0, Exe: "/tmp/p"}, nil
		},
		Log: func(d response.Decision) { decisions = append(decisions, d) },
	})
	excl, _ := config.CompileExclusions(nil, rs.Macros)
	var errb bytes.Buffer
	p := &pipeline{engine: rules.NewEngine(rs, rules.Options{}), excl: excl, responder: resp, errw: &errb,
		dedup: alert.NewDeduper(10 * time.Second)}
	proc := func(pid int32, exe string) *event.Proc { return &event.Proc{PID: pid, Exe: exe, StartTime: t0} }
	// Sequence rule without action kill: no kill.
	p.handle(&event.Event{Name: event.CreateFile, Time: t0, Proc: proc(900, "/usr/bin/curl"), File: &event.File{Path: "/tmp/p"}}, false)
	p.handle(&event.Event{Name: event.CreateProcess, Time: t0.Add(time.Second), Proc: proc(901, "/tmp/p")}, false)
	if len(killed) != 0 || p.alerts != 1 {
		t.Fatalf("killed %v for a rule without action kill (alerts %d)", killed, p.alerts)
	}
	// Rule with action kill: the completing event's process is killed.
	p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(2 * time.Second), Proc: proc(901, "/tmp/p"), File: &event.File{Path: "/Library/LaunchAgents/x.plist"}}, false)
	if !reflect.DeepEqual(killed, []int{901}) || len(decisions) != 1 {
		t.Fatalf("killed = %v decisions = %+v", killed, decisions)
	}
	// Duplicate (same rule, same pid, inside the window): no alert, no second kill.
	p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(3 * time.Second), Proc: proc(901, "/tmp/p"), File: &event.File{Path: "/Library/LaunchAgents/z.plist"}}, false)
	if len(killed) != 1 || p.suppressed != 1 {
		t.Fatalf("duplicate: killed = %v suppressed = %d", killed, p.suppressed)
	}
	// Protected process: alert fires, kill refused.
	p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(4 * time.Second), Proc: proc(77, "/usr/libexec/x"), File: &event.File{Path: "/Library/LaunchAgents/y.plist"}}, false)
	if len(killed) != 1 || decisions[1].Outcome != response.OutcomeProtected {
		t.Fatalf("protected process: killed = %v decisions = %+v", killed, decisions)
	}
	// Unverified identity (seeded at bootstrap): refused.
	e := &event.Event{Name: event.CreateFile, Time: t0.Add(5 * time.Second), Proc: proc(902, "/tmp/p"),
		File: &event.File{Path: "/Library/LaunchAgents/w.plist"}, Args: map[string]string{ps.ArgIdentity: ps.Unverified}}
	p.handle(e, false)
	if len(killed) != 1 || decisions[2].Outcome != response.OutcomeUnknown {
		t.Fatalf("unverified: killed = %v decisions = %+v", killed, decisions)
	}
}

// TestKillNeedsEnableResponse proves (CK-14) that a kill rule never kills
// unless --enable-response is given, and that dry-run wins.
func TestKillNeedsEnableResponse(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		enable, dry bool
		wantKills   int
	}{
		{false, false, 0},
		{false, true, 0},
		{true, true, 0},
		{true, false, 1},
	}
	for _, c := range cases {
		dir := t.TempDir()
		var kills int
		var out, errb bytes.Buffer
		s, err := buildSensor(runOptions{
			rulesDir: testRules, rulesGiven: true, configPath: filepath.Join(dir, "none.yml"),
			enableResponse: c.enable, dryRunResponse: c.dry, noYara: true,
			killFunc: func(int, syscall.Signal) error { kills++; return nil },
			identify: func(int32) (response.Identity, error) { return response.Identity{StartTime: t0, Exe: "/tmp/p"}, nil },
		}, &out, &errb)
		if err != nil {
			t.Fatal(err)
		}
		s.p.enricher = nil // feed fully formed events
		s.p.handle(&event.Event{Name: event.CreateFile, Time: t0, Proc: &event.Proc{PID: 4242, Exe: "/tmp/p", StartTime: t0},
			File: &event.File{Path: "/Library/LaunchAgents/x.plist"}}, false)
		_ = s.close()
		if s.p.alerts != 1 || kills != c.wantKills {
			t.Fatalf("enable=%v dry=%v: alerts=%d kills=%d, want %d", c.enable, c.dry, s.p.alerts, kills, c.wantKills)
		}
		if !strings.Contains(out.String(), killRuleSub) {
			t.Fatalf("console did not get the alert: %q", out.String())
		}
	}
}

func TestBuildSensorAsRootRefusesUnsafeBinary(t *testing.T) {
	var out, errb bytes.Buffer
	_, err := buildSensor(runOptions{rulesDir: testRules, rulesGiven: true, configPath: "none.yml", asRoot: true, noYara: true}, &out, &errb)
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	// The test binary lives in a user-owned temp directory.
	if err == nil || !strings.Contains(err.Error(), "sudo make install") {
		t.Fatalf("unsafe binary accepted as root: %v", err)
	}
}

func TestEsloggerPinnedAsRoot(t *testing.T) {
	// Exercise the pin with the checks that need real root ownership
	// bypassed: call the part of buildSensor that compares the binary.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "zaafvesper.yml")
	if err := os.WriteFile(cfg, []byte("eslogger:\n  binary: /tmp/evil-eslogger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: testRules, rulesGiven: true, configPath: cfg, configGiven: true, noYara: true}, &out, &errb)
	if err != nil {
		t.Fatalf("non-root may override the binary (for tests): %v", err)
	}
	_ = s.close()
	if err := pinnedEslogger("/tmp/evil-eslogger"); err == nil {
		t.Fatal("eslogger override accepted as root")
	}
	if err := pinnedEslogger(""); err != nil {
		t.Fatal(err)
	}
	if err := pinnedEslogger("/usr/bin/eslogger"); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageStdoutAndNoOverwrite(t *testing.T) {
	code, out, errs := runCLI(t, "coverage", "--navigator", "-", "--rules", testRules)
	if code != 0 {
		t.Fatalf("coverage -: %d %s", code, errs)
	}
	var layer map[string]any
	if err := json.Unmarshal([]byte(out), &layer); err != nil {
		t.Fatalf("stdout is not only the layer JSON: %v\n%s", err, out)
	}
	if !strings.Contains(errs, "techniques covered") {
		t.Fatalf("summary should go to stderr: %q", errs)
	}
	p := filepath.Join(t.TempDir(), "l.json")
	if code, _, _ := runCLI(t, "coverage", "--navigator", p, "--rules", testRules); code != 0 {
		t.Fatal("first write failed")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if code, _, _ := runCLI(t, "coverage", "--navigator", p, "--rules", testRules); code != 1 {
		t.Fatal("existing layer file overwritten")
	}
}

func TestReplayJSONRedactsEnv(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "e.jsonl")
	line := `{"seq":1,"time":"2026-11-07T10:00:00Z","name":"CreateFile","proc":{"pid":5,"exe":"/tmp/p","start_time":"2026-11-07T09:00:00Z","env":{"API_TOKEN":"s3cret","DYLD_INSERT_LIBRARIES":"/tmp/x.dylib"}},"file":{"path":"/Library/LaunchAgents/a.plist"}}`
	if err := os.WriteFile(in, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, keep := range []bool{false, true} {
		out := filepath.Join(dir, fmt.Sprintf("a-%v.jsonl", keep))
		args := []string{"replay", "--rules", testRules, "--json", out}
		if keep {
			args = append(args, "--keep-env")
		}
		if code, _, errs := runCLI(t, append(args, in)...); code != 0 {
			t.Fatalf("replay: %s", errs)
		}
		data, _ := os.ReadFile(out)
		if strings.Contains(string(data), "s3cret") != keep || !strings.Contains(string(data), "x.dylib") || !strings.Contains(string(data), "API_TOKEN") {
			t.Fatalf("keep=%v: %s", keep, data)
		}
	}
}

func TestCaptureMaxBytesKeepsSensorRunning(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{
		rulesDir: testRules, rulesGiven: true, configPath: filepath.Join(dir, "none.yml"), noYara: true,
		capturePath: filepath.Join(dir, "c.rcap"), captureMaxBytes: 300,
	}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	s.p.enricher = nil
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		s.p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(time.Duration(i) * time.Minute),
			Proc: &event.Proc{PID: int32(100 + i), Exe: "/usr/bin/curl"}, File: &event.File{Path: "/Library/LaunchAgents/x.plist"}}, false)
	}
	_ = s.close()
	if s.p.alerts != 20 || !s.p.captureStopped || s.p.captureErrs != 0 {
		t.Fatalf("alerts=%d stopped=%v errs=%d", s.p.alerts, s.p.captureStopped, s.p.captureErrs)
	}
	if strings.Count(errb.String(), "size limit reached") != 1 {
		t.Fatalf("limit should be logged once: %q", errb.String())
	}
	r, err := capture.Open(filepath.Join(dir, "c.rcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	n := 0
	for {
		if _, err := r.Next(); err != nil {
			break
		}
		n++
	}
	if n == 0 || n >= 20 {
		t.Fatalf("capture holds %d events", n)
	}
}

func TestAsRootOrderAndYaraFailClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	origExe, origYara := checkExecutable, checkYaraImages
	defer func() { checkExecutable, checkYaraImages = origExe, origYara }()
	checkExecutable = func() error { return nil }
	checkYaraImages = func() error { return errors.New("/opt/homebrew/lib/libyara.10.dylib: owned by uid 501") }
	var out, errb bytes.Buffer
	o := runOptions{rulesDir: testRules, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"), asRoot: true}
	_, err := buildSensor(o, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "--no-yara") {
		t.Fatalf("YARA did not fail closed: %v", err)
	}
	// With --no-yara the image check is skipped; the user-owned rules tree
	// is then refused before any rule is parsed.
	o.noYara = true
	_, err = buildSensor(o, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "rules are not safe to use as root") {
		t.Fatalf("user-owned rules accepted as root: %v", err)
	}
	// An explicit user-owned config is refused before it is parsed.
	cfg := filepath.Join(t.TempDir(), "zaafvesper.yml")
	if err := os.WriteFile(cfg, []byte("not: [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	o.configPath, o.configGiven = cfg, true
	_, err = buildSensor(o, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "configuration is not safe") {
		t.Fatalf("config parsed before the ownership check: %v", err)
	}
}
