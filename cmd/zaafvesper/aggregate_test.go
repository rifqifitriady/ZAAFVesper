package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

const floodKillRule = `name: Flood kill
id: 4e9c6f41-bd85-4a51-8d3e-7f4a5b6c7d8e
version: 1.0.0
condition: evt.name = 'CreateFile' and file.path startswith '/Library/LaunchAgents/'
output: "%ps.exe wrote %file.path"
severity: high
action: [{name: kill}]
min-engine-version: 0.1.0
`

const quietRule = `name: Quiet exec
id: 5fad7052-ce96-4b62-9e4f-8a5b6c7d8e9f
version: 1.0.0
condition: evt.name = 'CreateProcess' and ps.exe = '/usr/bin/curl'
output: "curl ran"
severity: low
min-engine-version: 0.1.0
`

type jsonLine struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Output     string `json:"output"`
	Aggregated bool   `json:"aggregated"`
	Count      uint64 `json:"count"`
}

func readLines(t *testing.T, b *bytes.Buffer) []jsonLine {
	t.Helper()
	var out []jsonLine
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if l == "" {
			continue
		}
		var j jsonLine
		if err := json.Unmarshal([]byte(l), &j); err != nil {
			t.Fatalf("bad line %q: %v", l, err)
		}
		out = append(out, j)
	}
	return out
}

func countRule(ls []jsonLine, id string, aggregated bool) int {
	n := 0
	for _, l := range ls {
		if l.RuleID == id && l.Aggregated == aggregated {
			n++
		}
	}
	return n
}

// TestAggregationEndToEnd (owner decision 8 Nov 2026, R5-1): 100 alerts of
// one high rule inside a minute, each from its own process: the console,
// the main JSONL series and the high/critical series each get 20 full
// alerts and, after the minute, one summary with count 80. A second (low)
// rule firing meanwhile is untouched. The response is evaluated for all
// 100 alerts and the kill budget (10 per rule per minute) is unchanged.
func TestAggregationEndToEnd(t *testing.T) {
	rs, err := rules.LoadDir(rulesDir(t, map[string]string{"a.yml": floodKillRule, "b.yml": quietRule}))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	now := t0
	clock := func() time.Time { return now }
	var killed []int
	resp := response.New(response.Config{
		Now:      clock,
		KillFunc: func(pid int, _ syscall.Signal) error { killed = append(killed, pid); return nil },
		Identify: func(pid int32) (response.Identity, error) {
			return response.Identity{CSKnown: true, StartTime: t0, Exe: "/tmp/dropper", UniqueID: uint64(pid), UniqueKnown: true}, nil
		},
		Log: func(response.Decision) {},
	})
	excl, _ := config.CompileExclusions(nil, rs.Macros)
	var con, mainJ, highJ, errb bytes.Buffer
	p := &pipeline{engine: rules.NewEngine(rs, rules.Options{}), excl: excl, responder: resp, errw: &errb,
		dedup: alert.NewDeduper(time.Minute),
		agg:   alert.NewAggregator(alert.DefaultAggregateLimit, alert.DefaultAggregateWindow, clock),
		sinks: []alert.Sink{alert.NewConsole(&con, false), alert.NewJSONL(&mainJ),
			&alert.Filtered{Sink: alert.NewJSONL(&highJ), Allow: alert.HighOrCritical}},
	}
	floodID, quietID := rs.Rules[0].ID, rs.Rules[1].ID
	if rs.Rules[0].Name != "Flood kill" {
		floodID, quietID = quietID, floodID
	}
	for i := 0; i < 100; i++ {
		now = t0.Add(time.Duration(i) * 500 * time.Millisecond)
		pid := int32(3000 + i)
		exe := fmt.Sprintf("/tmp/dropper%d", i%7)
		p.handle(&event.Event{Name: event.CreateFile, Time: now, Proc: &event.Proc{PID: pid, Exe: exe, StartTime: t0, UniqueID: uint64(pid)},
			File: &event.File{Path: fmt.Sprintf("/Library/LaunchAgents/x%d.plist", i)}}, false)
		if i%10 == 0 {
			p.handle(&event.Event{Name: event.CreateProcess, Time: now, Proc: &event.Proc{PID: int32(5000 + i), Exe: "/usr/bin/curl", StartTime: t0}}, false)
		}
		p.flushAggregates(now, false) // the run loop's tick: nothing ends inside the minute
	}
	var decided uint64
	for _, n := range resp.Stats() {
		decided += n
	}
	if decided != 100 {
		t.Fatalf("response decisions = %d, want 100 (stats %v)", decided, resp.Stats())
	}
	if len(killed) != response.DefaultMaxPerRulePerMinute || resp.Stats()[response.OutcomeRateLimited] != 90 {
		t.Fatalf("killed %d, stats %v: the kill budget changed", len(killed), resp.Stats())
	}
	m, h := readLines(t, &mainJ), readLines(t, &highJ)
	if countRule(m, floodID, false) != 20 || countRule(h, floodID, false) != 20 || countRule(m, floodID, true) != 0 {
		t.Fatalf("inside the minute: main %d, high %d full alerts", countRule(m, floodID, false), countRule(h, floodID, false))
	}
	if countRule(m, quietID, false) != 10 || countRule(h, quietID, false) != 0 {
		t.Fatalf("second rule: main %d, high %d", countRule(m, quietID, false), countRule(h, quietID, false))
	}
	if got := strings.Count(con.String(), "Flood kill: "); got != 20 {
		t.Fatalf("console full alerts = %d", got)
	}
	// The minute ends: one summary per series, then nothing more.
	now = t0.Add(time.Minute)
	p.flushAggregates(now, false)
	p.flushAggregates(now.Add(time.Second), false)
	m, h = readLines(t, &mainJ), readLines(t, &highJ)
	for name, ls := range map[string][]jsonLine{"main": m, "high": h} {
		if countRule(ls, floodID, true) != 1 || countRule(ls, floodID, false) != 20 {
			t.Fatalf("%s series: %d summaries, %d full", name, countRule(ls, floodID, true), countRule(ls, floodID, false))
		}
		s := ls[len(ls)-1]
		if !s.Aggregated || s.Count != 80 || s.Severity != "high" || !strings.HasPrefix(s.Output, "rule fired 80 more times in the last minute; top sources: /tmp/dropper") {
			t.Fatalf("%s summary = %+v", name, s)
		}
		if strings.Count(s.Output, "×") != 5 {
			t.Fatalf("%s summary lists more or fewer than 5 sources: %q", name, s.Output)
		}
	}
	if countRule(m, quietID, true) != 0 {
		t.Fatal("summary for a rule that held nothing back")
	}
	if !strings.Contains(con.String(), "aggregated=80") {
		t.Fatalf("console lacks the summary: %q", con.String())
	}
	if p.aggregated != 80 || p.summaries != 1 || p.alerts != 20+10+1 {
		t.Fatalf("counters: aggregated %d summaries %d alerts %d", p.aggregated, p.summaries, p.alerts)
	}
	var stats bytes.Buffer
	p.printStats(&stats, nil)
	if !strings.Contains(stats.String(), "aggregated=80 aggregate_summaries=1") || !strings.Contains(stats.String(), `"Flood kill"=80`) {
		t.Fatalf("stats = %q", stats.String())
	}

	// Shutdown inside a window: the final flush writes the summary.
	for i := 0; i < 25; i++ {
		pid := int32(4000 + i)
		p.handle(&event.Event{Name: event.CreateFile, Time: now, Proc: &event.Proc{PID: pid, Exe: "/tmp/late", StartTime: t0, UniqueID: uint64(pid)},
			File: &event.File{Path: "/Library/LaunchAgents/late.plist"}}, false)
	}
	p.flushAggregates(now, true)
	m = readLines(t, &mainJ)
	if last := m[len(m)-1]; !last.Aggregated || last.Count != 5 || !strings.Contains(last.Output, "/tmp/late (parent (unknown parent)) ×5") {
		t.Fatalf("shutdown summary = %+v", last)
	}
}

// TestRunPipelineAggregates: the live pipeline built by buildSensor
// aggregates; SensorDegraded alerts are not aggregated (they are already
// limited per condition).
func TestRunPipelineAggregates(t *testing.T) {
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule})
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, jsonKeep: 8, captureKeep: 2}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.close() }()
	if s.p.agg == nil {
		t.Fatal("run pipeline without aggregation")
	}
	var sink bytes.Buffer
	s.p.sinks = []alert.Sink{alert.NewJSONL(&sink)}
	for i := 0; i < 30; i++ {
		s.p.handle(&event.Event{Name: event.SensorDegraded, Source: "zaafvesper", Time: time.Now(),
			Proc: &event.Proc{PID: 1}, Args: map[string]string{"condition": fmt.Sprintf("c%d", i)}}, false)
	}
	if n := len(readLines(t, &sink)); n != 30 || s.p.aggregated != 0 {
		t.Fatalf("SensorDegraded alerts written %d (want 30), aggregated %d", n, s.p.aggregated)
	}
}

// TestReplayAggregatesByEventTime: replay aggregates on event time, so a
// capture of 30 alerts of one rule within 15 s prints 20 in full and one
// summary of 10, and an alert of the same rule two minutes later opens a
// new window (written in full).
func TestReplayAggregatesByEventTime(t *testing.T) {
	dir := t.TempDir()
	rcap := filepath.Join(dir, "flood.rcap")
	w, err := capture.Create(rcap)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		at := t0.Add(time.Duration(i) * 500 * time.Millisecond)
		if err := w.Write(&event.Event{Seq: uint64(i + 1), Name: event.CreateProcess, Time: at,
			Proc: &event.Proc{PID: int32(6000 + i), Exe: "/usr/bin/curl", StartTime: at}}); err != nil {
			t.Fatal(err)
		}
	}
	at := t0.Add(2 * time.Minute)
	if err := w.Write(&event.Event{Seq: 31, Name: event.CreateProcess, Time: at, Proc: &event.Proc{PID: 7000, Exe: "/usr/bin/curl", StartTime: at}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rdir := rulesDir(t, map[string]string{"q.yml": quietRule})
	cfg := filepath.Join(dir, "zaafvesper.yml")
	if err := os.WriteFile(cfg, []byte("exclude: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCLI(t, "replay", "--rules", rdir, "--config", cfg, rcap)
	if code != 0 {
		t.Fatalf("replay: %d %s", code, errs)
	}
	if full := strings.Count(out, "Quiet exec: curl ran"); full != 21 {
		t.Fatalf("full alerts = %d, want 20 + 1 after the window: %s", full, out)
	}
	if strings.Count(out, "aggregated=") != 1 || !strings.Contains(out, "rule fired 10 more times in the last minute; top sources: /usr/bin/curl (parent (unknown parent)) ×10") {
		t.Fatalf("summary missing: %s", out)
	}
	if !strings.Contains(errs, "aggregated=10 aggregate_summaries=1") {
		t.Fatalf("stats: %s", errs)
	}
}

// TestSourcesExhaustedRaisesDegraded: 65 distinct sources of one rule in a
// minute raise one aggregate_sources_exhausted SensorDegraded event, which
// is written as an alert and never aggregated.
func TestSourcesExhaustedRaisesDegraded(t *testing.T) {
	dir := rulesDir(t, map[string]string{"q.yml": `name: Any exec
id: 6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d
version: 1.0.0
condition: evt.name = 'CreateProcess' and ps.name = 'decoy'
output: "decoy %ps.exe"
severity: high
min-engine-version: 0.1.0
`, "d.yml": degradedRule})
	t0 := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, jsonKeep: 8, captureKeep: 2, clock: func() time.Time { return t0 }}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.close() }()
	var sink bytes.Buffer
	s.p.sinks = []alert.Sink{alert.NewJSONL(&sink)}
	for i := 0; i <= alert.MaxAggregateSources+2; i++ {
		s.p.handle(&event.Event{Name: event.CreateProcess, Time: t0,
			Proc: &event.Proc{PID: int32(7000 + i), PIDVersion: uint32(i + 1), Exe: fmt.Sprintf("/tmp/d%03d/decoy", i), Name: "decoy", StartTime: t0}}, false)
	}
	s.p.drainDegraded()
	if n := strings.Count(errb.String(), condSourcesExhausted); n != 1 {
		t.Fatalf("stderr reports of %s = %d, want 1:\n%s", condSourcesExhausted, n, errb.String())
	}
	if !strings.Contains(sink.String(), condSourcesExhausted) {
		t.Fatalf("no SensorDegraded alert for %s in the alert file", condSourcesExhausted)
	}
}
