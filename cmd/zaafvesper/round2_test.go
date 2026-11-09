package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/yara"
)

const parentKillRule = `name: Prompt from untrusted parent
id: 1b6f3c1e-8a52-4d2e-9a0b-4c1d2e3f4a5b
version: 1.0.0
condition: evt.name = 'CreateProcess' and ps.name = 'osascript'
output: "prompt by %ps.parent.exe"
severity: critical
action: [{name: kill, target: parent}]
min-engine-version: 0.1.0
`

const degradedRule = `name: Sensor degraded
id: 2c7a4d2f-9b63-4e3f-8b1c-5d2e3f4a5b6c
version: 1.0.0
condition: evt.name = 'SensorDegraded' and evt.source = 'zaafvesper'
output: "degraded %evt.arg[condition]"
severity: high
min-engine-version: 0.1.0
`

const plistWriteRule = `name: Plist write
id: 3d8b5e30-ac74-4f40-9c2d-6e3f4a5b6c7d
version: 1.0.0
condition: evt.name = 'CreateFile' and file.path startswith '/Library/LaunchAgents/'
output: "%ps.exe wrote %file.path"
severity: high
min-engine-version: 0.1.0
`

// The process table and the YARA scanner report degraded telemetry through
// OnDegraded, which buildSensor wires by type assertion.
var (
	_ degradedReporter = (*ps.Snapshotter)(nil)
	_ degradedReporter = (*yara.Scanner)(nil)
)

func rulesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestKillTargetParent(t *testing.T) {
	rs, err := rules.LoadDir(rulesDir(t, map[string]string{"k.yml": parentKillRule}))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var killed []int
	var decisions []response.Decision
	var logLines bytes.Buffer
	resp := response.New(response.Config{
		KillFunc: func(pid int, _ syscall.Signal) error { killed = append(killed, pid); return nil },
		Identify: func(pid int32) (response.Identity, error) {
			return response.Identity{CSKnown: true, StartTime: t0, Exe: "/tmp/dropper", UniqueID: uint64(pid), UniqueKnown: true}, nil
		},
		Log: func(d response.Decision) { decisions = append(decisions, d); say(&logLines, "%s", d.String()) },
	})
	var errb bytes.Buffer
	p := &pipeline{engine: rules.NewEngine(rs, rules.Options{}), responder: resp, errw: &errb, dedup: alert.NewDeduper(time.Minute)}
	osa := func(parent *event.Proc) *event.Event {
		pr := &event.Proc{PID: 600, PPID: 500, Exe: "/usr/bin/osascript", Name: "osascript", IsPlatform: true, StartTime: t0, Parent: parent}
		return &event.Event{Name: event.CreateProcess, Time: t0, Proc: pr}
	}
	p.handle(osa(&event.Proc{PID: 500, Exe: "/tmp/dropper", Name: "dropper", StartTime: t0, UniqueID: 500}), false)
	if len(killed) != 1 || killed[0] != 500 || decisions[0].Target != response.TargetParent {
		t.Fatalf("parent not killed: %v %+v", killed, decisions)
	}
	if !strings.Contains(logLines.String(), "target=parent pid=500") {
		t.Fatalf("response log lacks the target: %q", logLines.String())
	}
	// Unknown parent, seeded parent, unverified parent: refused, osascript never touched.
	p.handle(osa(nil), false)
	p.handle(osa(&event.Proc{PID: 500, Exe: "/tmp/dropper", StartTime: t0, Seeded: true}), false)
	e := osa(&event.Proc{PID: 500, Exe: "/tmp/dropper", StartTime: t0})
	e.Args = map[string]string{ps.ArgParentIdentity: ps.Unverified}
	p.handle(e, false)
	// Three refusals; repeated refusals for the same (rule, target, pid,
	// outcome) are logged once a minute, so one log line.
	if len(killed) != 1 || len(decisions) != 2 || resp.Stats()[response.OutcomeUnknown+" (parent)"] != 3 {
		t.Fatalf("refusals: killed %v decisions %+v stats %v", killed, decisions, resp.Stats())
	}
	for _, d := range decisions[1:] {
		if d.Outcome != response.OutcomeUnknown || d.Target != response.TargetParent {
			t.Fatalf("refusal = %+v", d)
		}
	}
}

func TestSensorDegradedEvents(t *testing.T) {
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule, "w.yml": plistWriteRule})
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, jsonMaxBytes: 1, jsonKeep: 8, captureKeep: 2}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range s.events {
		if n == event.SensorDegraded {
			t.Fatal("SensorDegraded subscribed at the source")
		}
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.p.deg.clock = func() time.Time { return now }
	s.p.degraded("proctable_pressure", "evicted\x1b[2J 10 entries")
	s.p.degraded("proctable_pressure", "again") // inside the minute: rate-limited
	s.p.degraded("yara_queue_full", "queue full")
	s.p.drainDegraded()
	now = now.Add(2 * time.Minute)
	s.p.degraded("proctable_pressure", "later")
	// A report from another goroutine is picked up by the next event.
	done := make(chan struct{})
	go func() { s.p.degraded("yara_exec_replaced", "swap"); close(done) }()
	<-done
	s.p.enricher = nil
	s.p.handle(&event.Event{Name: event.CreateFile, Time: now, Proc: &event.Proc{PID: 9, Exe: "/tmp/x"}, File: &event.File{Path: "/tmp/f"}}, false)
	_ = s.close()
	// 4 reports plus one degraded_suppressed summary for the rate-limited one.
	if got := strings.Count(out.String(), "Sensor degraded"); got != 5 {
		t.Fatalf("SensorDegraded alerts = %d, want 5:\n%s", got, out.String())
	}
	for _, c := range []string{"degraded proctable_pressure", "degraded yara_queue_full", "degraded yara_exec_replaced", "degraded degraded_suppressed"} {
		if !strings.Contains(out.String(), c) {
			t.Fatalf("missing %q:\n%s", c, out.String())
		}
	}
	if strings.Count(errb.String(), "sensor degraded: condition=") != 5 || !strings.Contains(errb.String(), "proctable_pressure=1") {
		t.Fatalf("stderr lines:\n%s", errb.String())
	}
	noControls(t, errb.String())
	noControls(t, out.String())
	if st := s.p.deg.stats(); st["rate_limited"] != 1 || st["proctable_pressure"] != 3 {
		t.Fatalf("stats = %v", st)
	}
}

var (
	alertsName     = regexp.MustCompile(`^alerts-\d{8}T\d{6}\.\d{9}Z(-\d+)?\.jsonl$`)
	alertsHighName = regexp.MustCompile(`^alerts-high-\d{8}T\d{6}\.\d{9}Z(-\d+)?\.jsonl$`)
)

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestOutputDirRotationAndRestart(t *testing.T) {
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule, "w.yml": plistWriteRule})
	out := filepath.Join(t.TempDir(), "log", "zaafvesper")
	if err := os.Mkdir(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	o := runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"), noYara: true, noConsole: true,
		outputDir: out, captureInDir: true, jsonMaxBytes: 4000, jsonKeep: 3, captureKeep: 2, captureMaxBytes: 1 << 20}
	var stdout, errb bytes.Buffer
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for start := 0; start < 3; start++ { // three (re)starts, as KeepAlive would do
		s, err := buildSensor(o, &stdout, &errb)
		if err != nil {
			t.Fatalf("start %d: %v", start, err)
		}
		if len(s.p.sinks) != 2 { // alerts and alerts-high, no console
			t.Fatalf("--no-console: sinks = %d", len(s.p.sinks))
		}
		s.p.enricher = nil
		for i := 0; i < 40; i++ {
			s.p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(time.Duration(i) * time.Minute),
				Proc: &event.Proc{PID: int32(1000 + i), Exe: "/tmp/p", Cmdline: strings.Repeat("x", 200)},
				File: &event.File{Path: "/Library/LaunchAgents/a.plist"}}, false)
		}
		if err := s.close(); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("output dir: %v %v", fi, err)
	}
	var alerts, high, captures int
	for _, n := range listDir(t, out) {
		fi, _ := os.Lstat(filepath.Join(out, n))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", n, fi.Mode().Perm())
		}
		switch {
		case alertsName.MatchString(n):
			alerts++
			if fi.Size() > 4000 {
				t.Fatalf("%s holds %d bytes, cap 4000", n, fi.Size())
			}
		case alertsHighName.MatchString(n):
			high++
			if fi.Size() > 4000 {
				t.Fatalf("%s holds %d bytes, cap 4000", n, fi.Size())
			}
		case strings.HasPrefix(n, "capture-") && strings.HasSuffix(n, ".rcap"):
			captures++
		default:
			t.Fatalf("unexpected file %s", n)
		}
	}
	if alerts != 3 || high != defaultJSONHighKeep || captures != 2 {
		t.Fatalf("alerts files = %d (keep 3), capture files = %d (keep 2): %v", alerts, captures, listDir(t, out))
	}
	if stdout.Len() != 0 || !strings.Contains(errb.String(), "rotated to") || !strings.Contains(errb.String(), "condition=alerts_capped") {
		t.Fatalf("rotation not reported:\n%s", errb.String())
	}
}

func writeOwn(t *testing.T, dir, name string, size int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat("x", size)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func alertName(at time.Time, seq int) string {
	n := "alerts-" + at.UTC().Format(outputStamp)
	if seq > 0 {
		n += "-" + strconv.Itoa(seq)
	}
	return n + ".jsonl"
}

// TestOutputDirPrunePolicy covers finding F7: only own regular files are
// pruned, never one younger than 7 days (by the name, not mtime) unless it
// is empty, never an open file, oldest first with numeric -N order.
func TestOutputDirPrunePolicy(t *testing.T) {
	dir := t.TempDir()
	od, err := openOutputDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer od.close()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	od.now = func() time.Time { return now }
	victim := filepath.Join(t.TempDir(), "victim")
	writeOwn(t, filepath.Dir(victim), "victim", 7)
	old := now.Add(-8 * 24 * time.Hour)
	young := now.Add(-time.Hour)
	// Old files, out of lexical order: -10 is newer than -2.
	for _, n := range []string{alertName(old, 10), alertName(old, 2), alertName(old, 0)} {
		writeOwn(t, dir, n, 10)
	}
	writeOwn(t, dir, alertName(young, 0), 10)
	writeOwn(t, dir, alertName(young.Add(time.Minute), 0), 0) // young but empty
	// Never touched: a link with an own-looking name, unrelated files.
	if err := os.Symlink(victim, filepath.Join(dir, alertName(old.Add(-time.Hour), 0))); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"notes.txt", "alerts-old.jsonl", "capture-20200101T000000.000000000Z.rcap", "zaafvesper.log"} {
		writeOwn(t, dir, n, 1)
	}
	// Room for one file with keep 3: 5 own regular files -> 3 must go, oldest
	// first: plain, -2, -10 (the link is not counted).
	room, removed, err := od.makeRoom(alertsPrefix, alertsExt, 3, nil)
	want := []string{alertName(old, 0), alertName(old, 2), alertName(old, 10)}
	if err != nil || !room || strings.Join(removed, ",") != strings.Join(want, ",") {
		t.Fatalf("room=%v removed=%v err=%v", room, removed, err)
	}
	// keep 2: only the young empty file may go; the young file with
	// content stays and there is room for one more.
	room, removed, _ = od.makeRoom(alertsPrefix, alertsExt, 2, nil)
	if !room || len(removed) != 1 || removed[0] != alertName(young.Add(time.Minute), 0) {
		t.Fatalf("empty young file: room=%v removed=%v", room, removed)
	}
	// keep 1: the young file with content is never deleted -> no room.
	room, removed, _ = od.makeRoom(alertsPrefix, alertsExt, 1, nil)
	if room || len(removed) != 0 {
		t.Fatalf("young file pruned: room=%v removed=%v", room, removed)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "xxxxxxx" {
		t.Fatal("link target touched")
	}
	names := strings.Join(listDir(t, dir), " ")
	for _, n := range []string{"notes.txt", "alerts-old.jsonl", "capture-2020", "zaafvesper.log", alertName(old.Add(-time.Hour), 0), alertName(young, 0)} {
		if !strings.Contains(names, n) {
			t.Fatalf("%s removed: %s", n, names)
		}
	}
	// Clock stepped back 30 days: the open file (named in the "future") and
	// every other file are young; nothing open is ever deleted, even old.
	cur := alertName(now, 0)
	writeOwn(t, dir, cur, 10)
	now = now.Add(-30 * 24 * time.Hour)
	room, removed, _ = od.makeRoom(alertsPrefix, alertsExt, 1, map[string]bool{cur: true})
	if room || len(removed) != 0 {
		t.Fatalf("backward clock: room=%v removed=%v", room, removed)
	}
	now = now.Add(60 * 24 * time.Hour) // everything old now, but cur is open
	room, removed, _ = od.makeRoom(alertsPrefix, alertsExt, 1, map[string]bool{cur: true})
	if room || len(removed) != 1 || removed[0] != alertName(young, 0) {
		t.Fatalf("open file: room=%v removed=%v", room, removed)
	}
	// create never reuses a name.
	a, err1 := od.create(alertsPrefix, alertsExt)
	b, err2 := od.create(alertsPrefix, alertsExt)
	if err1 != nil || err2 != nil || a.Name() == b.Name() || !alertsName.MatchString(filepath.Base(b.Name())) {
		t.Fatalf("create: %v %v %v %v", a, b, err1, err2)
	}
	a.Close()
	b.Close()
}

// TestOutputDirBudgetFullOfYoungFiles: when the keep budget holds only
// young files, the sensor starts without a main alert file and keeps the
// files; the high/critical series has its own budget and still records the
// high alert, which is also written to stderr while the main file is
// stopped, and alerts_capped is raised.
func TestOutputDirBudgetFullOfYoungFiles(t *testing.T) {
	rdir := rulesDir(t, map[string]string{"d.yml": degradedRule, "w.yml": plistWriteRule,
		"l.yml": strings.NewReplacer("name: Plist write", "name: Low plist", "3d8b5e30", "4e9c6f41", "severity: high", "severity: low").Replace(plistWriteRule)})
	out := t.TempDir()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	var young []string
	for i := 0; i < 3; i++ {
		n := alertName(recent.Add(time.Duration(i)*time.Second), 0)
		writeOwn(t, out, n, 100)
		young = append(young, n)
	}
	var stdout, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: rdir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"), noYara: true,
		outputDir: out, jsonMaxBytes: 1 << 20, jsonKeep: 3, jsonHighKeep: 2, captureKeep: 2, clock: func() time.Time { return now }}, &stdout, &errb)
	if err != nil {
		t.Fatal(err)
	}
	s.p.enricher = nil
	s.p.handle(&event.Event{Name: event.CreateFile, Time: now, Proc: &event.Proc{PID: 9, Exe: "/tmp/p"},
		File: &event.File{Path: "/Library/LaunchAgents/a.plist"}}, false)
	_ = s.close()
	var highFiles []string
	for _, n := range listDir(t, out) {
		switch {
		case alertsHighName.MatchString(n):
			highFiles = append(highFiles, n)
		case alertsName.MatchString(n):
			if !strings.Contains(strings.Join(young, " "), n) {
				t.Fatalf("new main alert file %s despite a full budget", n)
			}
		}
	}
	for _, n := range young {
		if b, err := os.ReadFile(filepath.Join(out, n)); err != nil || len(b) != 100 {
			t.Fatalf("young file %s changed: %v", n, err)
		}
	}
	if len(highFiles) != 1 {
		t.Fatalf("high files: %v", highFiles)
	}
	data, _ := os.ReadFile(filepath.Join(out, highFiles[0]))
	if !strings.Contains(string(data), "Plist write") || strings.Contains(string(data), "Low plist") {
		t.Fatalf("high series content: %s", data)
	}
	e := errb.String()
	if !strings.Contains(e, "alerts are NOT written") || !strings.Contains(e, "condition=alerts_capped") ||
		strings.Count(e, `alert not in alert file: 2026-11-08T12:00:00Z HIGH rule=3d8b5e30-ac74-4f40-9c2d-6e3f4a5b6c7d pid=9 exe="/tmp/p" Plist write`) != 1 || strings.Contains(e, "Low plist") {
		t.Fatalf("stderr:\n%s", e)
	}
	if !strings.Contains(stdout.String(), "Plist write") {
		t.Fatalf("stdout:\n%s", stdout.String())
	}
}

func TestOutputDirRefusals(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutputDir(dir, false); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable dir accepted: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := openOutputDir(link, false); err == nil {
		t.Fatal("symbolic link accepted as output dir")
	}
	if os.Geteuid() != 0 {
		if _, err := openOutputDir(t.TempDir(), true); err == nil || !strings.Contains(err.Error(), "not safe to write as root") {
			t.Fatalf("user-owned dir accepted as root: %v", err)
		}
	}
	for _, args := range [][]string{
		{"run", "--output-dir", dir, "--json", "a.jsonl"},
		{"run", "--capture-in-dir"},
		{"run", "--output-dir", dir, "--capture-in-dir", "--capture", "c.rcap"},
		{"run", "--json-max-bytes", "0"},
		{"run", "--json-keep", "0"},
	} {
		if code, _, errs := runCLI(t, args...); code != 2 {
			t.Fatalf("%v: exit %d %s", args, code, errs)
		}
	}
}

func TestJSONMaxBytesExplicitPathStops(t *testing.T) {
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule, "w.yml": plistWriteRule})
	jp := filepath.Join(t.TempDir(), "a.jsonl")
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"), noYara: true,
		jsonPath: jp, jsonMaxBytes: 3000, jsonKeep: 8, captureKeep: 2}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	s.p.enricher = nil
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		s.p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(time.Duration(i) * time.Minute),
			Proc: &event.Proc{PID: int32(100 + i), Exe: "/tmp/p"}, File: &event.File{Path: "/Library/LaunchAgents/a.plist"}}, false)
	}
	_ = s.close()
	fi, err := os.Stat(jp)
	if err != nil || fi.Size() > 3000 || fi.Size() == 0 {
		t.Fatalf("json file: %v %v", fi, err)
	}
	if strings.Count(errb.String(), "condition=alerts_capped") != 1 || !strings.Contains(out.String(), "degraded alerts_capped") {
		t.Fatalf("cap not reported once:\n%s", errb.String())
	}
	// After the stop, each high alert (and the high SensorDegraded alert)
	// still reaches stderr as one bounded line.
	for _, line := range strings.Split(errb.String(), "\n") {
		if strings.HasPrefix(line, "alert not in alert file:") && len(line) > maxFallbackLine+len("...[truncated]") {
			t.Fatalf("fallback line too long: %d", len(line))
		}
		// Identity comes before the attacker-influenced output, so the
		// length bound can only cut the output.
		if strings.HasPrefix(line, "alert not in alert file:") && (!strings.Contains(line, " rule=") || !strings.Contains(line, " pid=")) {
			t.Fatalf("fallback line lost its identity: %q", line)
		}
	}
	if !strings.Contains(errb.String(), "alert not in alert file:") {
		t.Fatalf("no stderr fallback after the stop:\n%s", errb.String())
	}
	data, _ := os.ReadFile(jp)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var a rules.Alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("partial line in capped file: %v", err)
		}
	}
}

func TestCoverageSanitized(t *testing.T) {
	rule := "name: \"Evil\\e[2J \\u202e name\"\nid: 9fc0f5b6-65d1-4d7c-a071-1c98570d0a9b\nversion: 1.0.0\n" +
		"labels: {technique.id: T1059.002}\ncondition: evt.name = 'CreateProcess'\noutput: x\nseverity: low\nmin-engine-version: 0.1.0\n"
	dir := rulesDir(t, map[string]string{"evil.yml": rule})
	code, out, errs := runCLI(t, "coverage", "--navigator", "-", "--rules", dir)
	if code != 0 {
		t.Fatalf("coverage: %d %s", code, errs)
	}
	var layer navigatorLayer
	if err := json.Unmarshal([]byte(out), &layer); err != nil {
		t.Fatal(err)
	}
	if len(layer.Techniques) != 1 || !strings.Contains(layer.Techniques[0].Comment, "Evil") {
		t.Fatalf("layer: %+v", layer)
	}
	noControls(t, layer.Techniques[0].Comment)
	noControls(t, errs)
	p := filepath.Join(t.TempDir(), "l.json")
	if code, _, _ := runCLI(t, "coverage", "--navigator", p, "--rules", dir); code != 0 {
		t.Fatal("coverage file")
	}
	data, _ := os.ReadFile(p)
	if err := json.Unmarshal(data, &layer); err != nil {
		t.Fatal(err)
	}
	noControls(t, layer.Techniques[0].Comment)
}
