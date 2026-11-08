package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/eslogger"
)

// The eslogger source reports es_events_dropped through OnDegraded.
var _ degradedReporter = (*eslogger.Source)(nil)

// TestProcTablePressureEndToEnd (judge CK-IF03): the REAL snapshotter,
// wired by buildSensor, is flooded until it must evict; its OnDegraded
// report becomes exactly one SensorDegraded record in the capture, one
// alert and one stderr line. The table's byte budget is not settable from
// outside pkg/ps, so the flood uses its entry bound (ps.MaxEntries) instead.
func TestProcTablePressureEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("floods the process table")
	}
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule})
	rcap := filepath.Join(t.TempDir(), "c.rcap")
	var out, errb bytes.Buffer
	t0 := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return t0 } // the whole flood happens "in one second"
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, capturePath: rcap, jsonKeep: 8, captureKeep: 2, clock: clock}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	if s.p.enricher != s.snap {
		t.Fatal("the pipeline does not enrich through the snapshotter")
	}
	// buildSensor hands runOptions.clock to the process table (SetClock),
	// so its once-a-minute limiter runs on the fixed test clock.
	if _, ok := any(s.snap).(interface{ SetClock(func() time.Time) }); !ok {
		t.Fatal("*ps.Snapshotter must offer SetClock")
	}
	for i := 0; i < ps.MaxEntries+2000; i++ {
		pid := int32(100_000 + i)
		s.p.handle(&event.Event{Name: event.CreateProcess, Time: t0.Add(time.Duration(i) * time.Microsecond),
			Proc: &event.Proc{PID: pid, PPID: 1, PIDVersion: uint32(pid), Exe: "/private/tmp/flood", Name: "flood", StartTime: t0}}, false)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if st := s.snap.Stats(); st["evictions"] == 0 && st["evicted"] == 0 {
		t.Logf("process table stats: %v", st)
	}
	r, err := capture.Open(rcap)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var degraded []*event.Event
	for {
		e, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Name == event.SensorDegraded {
			degraded = append(degraded, e)
		}
	}
	if len(degraded) != 1 || degraded[0].Args["condition"] != ps.CondPressure || degraded[0].Source != "zaafvesper" {
		t.Fatalf("SensorDegraded records in the capture = %d %+v", len(degraded), degraded)
	}
	if n := strings.Count(out.String(), "Sensor degraded"); n != len(degraded) {
		t.Fatalf("alerts = %d, capture records %d\n%s", n, len(degraded), out.String())
	}
	if n := strings.Count(errb.String(), "sensor degraded: condition=proctable_pressure"); n != len(degraded) {
		t.Fatalf("stderr lines = %d\n%s", n, errb.String())
	}
}

// TestDegradedDecoyDoesNotHideReal: reports from components that limit
// themselves (yara, ps, eslogger) get a share per condition, so a decoy does
// not hide a different report and a flood of one condition does not starve
// another; es_events_dropped is never dropped; what is dropped is
// summarised by one degraded_suppressed event a minute.
func TestDegradedDecoyDoesNotHideReal(t *testing.T) {
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule})
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, jsonKeep: 8, captureKeep: 2}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.p.deg.clock = func() time.Time { return now }
	s.p.degradedFrom("yara_exec_replaced", "decoy /tmp/decoy")
	s.p.degradedFrom("yara_exec_replaced", "real /Users/a/.cache/agent")
	// The pipeline's own conditions stay limited to one a minute.
	s.p.degraded(condAlertsCapped, "one")
	s.p.degraded(condAlertsCapped, "two")
	// A flood of one condition is held to its share ...
	for i := 0; i < 100; i++ {
		s.p.degradedFrom("yara_exec_replaced", fmt.Sprintf("flood %d", i))
	}
	// ... and does not starve another condition; lost events always pass.
	s.p.degradedFrom("proctable_pressure", "real pressure")
	for i := 0; i < 100; i++ {
		s.p.degradedFrom("es_events_dropped", fmt.Sprintf("gap %d", i))
	}
	s.p.drainDegraded()
	// Inside the same minute no second summary.
	s.p.degradedFrom("yara_exec_replaced", "more")
	s.p.drainDegraded()
	_ = s.close()
	e := errb.String()
	count := func(sub string) int { return strings.Count(e, sub) }
	if count("condition=yara_exec_replaced") != degradedSharePerMinute || !strings.Contains(e, "real /Users/a/.cache/agent") {
		t.Fatalf("yara share: %d lines\n%s", count("condition=yara_exec_replaced"), e)
	}
	if count("condition=proctable_pressure") != 1 || count("condition=es_events_dropped") != 100 || count("condition=alerts_capped") != 1 {
		t.Fatalf("starved or dropped:\n%s", e)
	}
	if count("condition="+condSuppressed) != 1 || !strings.Contains(e, "alerts_capped=1 yara_exec_replaced=82") {
		t.Fatalf("summary:\n%s", e)
	}
	if !strings.Contains(out.String(), "degraded "+condSuppressed) || strings.Count(out.String(), "degraded yara_exec_replaced") != degradedSharePerMinute {
		t.Fatalf("alerts:\n%s", out.String())
	}
	// The next minute: the remaining suppressed report is summarised.
	now = now.Add(time.Minute)
	s.p.drainDegraded()
	if st := s.p.deg.stats(); st["rate_limited"] != 84 || st[condSuppressed] != 2 {
		t.Fatalf("stats = %v", st)
	}
	var w bytes.Buffer
	s.p.periodicStats(&w)
	if !strings.Contains(w.String(), "rate_limited=84") {
		t.Fatalf("periodic stats: %q", w.String())
	}
}

// TestResponseBudgetRaisesDegraded (F8): an 11th kill by one rule within a
// minute is refused and raises SensorDegraded response_rate_limited.
func TestResponseBudgetRaisesDegraded(t *testing.T) {
	killRule := strings.Replace(plistWriteRule, "severity: high\n", "severity: high\naction: [{name: kill}]\n", 1)
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule, "k.yml": killRule})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	kills := 0
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, enableResponse: true, jsonKeep: 8, captureKeep: 2,
		killFunc: func(int, syscall.Signal) error { kills++; return nil },
		identify: func(pid int32) (response.Identity, error) {
			return response.Identity{CSKnown: true, StartTime: t0, Exe: "/tmp/p", UniqueID: uint64(pid), UniqueKnown: true}, nil
		}}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	s.p.enricher = nil
	for i := 0; i < 12; i++ {
		s.p.handle(&event.Event{Name: event.CreateFile, Time: t0.Add(time.Duration(i) * time.Second),
			Proc: &event.Proc{PID: int32(3000 + i), Exe: "/tmp/p", StartTime: t0, UniqueID: uint64(3000 + i)}, File: &event.File{Path: "/Library/LaunchAgents/a.plist"}}, false)
	}
	_ = s.close()
	if kills != response.DefaultMaxPerRulePerMinute {
		t.Fatalf("kills = %d", kills)
	}
	if strings.Count(errb.String(), "condition="+response.CondRateLimited) != 1 || !strings.Contains(out.String(), "Sensor degraded") {
		t.Fatalf("budget not reported:\n%s", errb.String())
	}
}

func TestExtraStatsIncludeSourceCounters(t *testing.T) {
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: testRules, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, jsonKeep: 8, captureKeep: 2}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	src := s.extraStats()["source"]
	for _, k := range []string{"seq_gaps", "events_missed"} {
		if _, ok := src[k]; !ok {
			t.Fatalf("source stats lack %s: %v", k, src)
		}
	}
	var w bytes.Buffer
	s.p.printStats(&w, s.extraStats())
	if !strings.Contains(w.String(), "seq_gaps=") {
		t.Fatalf("stats output: %s", w.String())
	}
}

type recordingScanner struct{ got []string }

func (r *recordingScanner) Start(context.Context, chan<- *event.Event) error { return nil }
func (r *recordingScanner) Submit(e *event.Event)                            { r.got = append(r.got, e.Name) }
func (r *recordingScanner) Close() error                                     { return nil }

// TestMountReachesScanner: a Mount event reaches the YARA scanner (which
// invalidates its non-local mount cache) even when an exclusion matches
// it, and Mount is subscribed whenever YARA is active.
func TestMountReachesScanner(t *testing.T) {
	rs, err := rules.LoadDir(testRules)
	if err != nil {
		t.Fatal(err)
	}
	excl, err := config.CompileExclusions([]config.Exclusion{{Name: "all mounts", Events: []string{event.Mount}, Condition: "evt.name = 'Mount'"}}, rs.Macros)
	if err != nil {
		t.Fatal(err)
	}
	sc := &recordingScanner{}
	var errb bytes.Buffer
	p := &pipeline{engine: rules.NewEngine(rs, rules.Options{}), excl: excl, scanner: sc, errw: &errb}
	p.handle(&event.Event{Name: event.Mount, File: &event.File{Path: "/Volumes/share"}}, false)
	p.handle(&event.Event{Name: event.Mount, File: &event.File{Path: "/Volumes/x"}}, true) // from the scanner: not resubmitted
	if len(sc.got) != 1 || sc.got[0] != event.Mount || p.excluded != 2 {
		t.Fatalf("submitted %v, excluded %d", sc.got, p.excluded)
	}
	sub := strings.Join(subscription([]string{event.CreateProcess}, true), ",")
	if !strings.Contains(sub, event.Mount) {
		t.Fatalf("Mount not subscribed with YARA: %s", sub)
	}
	if strings.Contains(strings.Join(subscription([]string{event.CreateProcess}, false), ","), event.Mount) {
		t.Fatal("Mount subscribed without YARA")
	}
}
