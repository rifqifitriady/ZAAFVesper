package main

import (
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// shippedEvents loads every rule in rules/ and every event of every fixture
// scenario (match and nomatch), so the benchmark runs the real rule set over
// a mix of the event shapes those rules were written for, on all platforms.
func shippedEvents(tb testing.TB) (*rules.Ruleset, []*event.Event) {
	tb.Helper()
	rs, err := rules.LoadDir("../../rules")
	if err != nil {
		tb.Fatal(err)
	}
	var evs []*event.Event
	for _, r := range rs.Rules {
		path, ok := rules.FixturePath(rs.Dir, r.File)
		if !ok {
			tb.Fatalf("%s has no fixture", r.File)
		}
		ff, err := rules.LoadFixture(path)
		if err != nil {
			tb.Fatal(err)
		}
		for _, sc := range append(ff.Match, ff.NoMatch...) {
			if err := rules.NormalizeScenario(sc.Events); err != nil {
				tb.Fatal(err)
			}
			evs = append(evs, sc.Events...)
		}
	}
	return rs, evs
}

// BenchmarkShippedRules measures the rule engine with every shipped rule
// enabled (all platforms) at full speed: events/s is the number to report.
// Run: go test -run '^$' -bench BenchmarkShippedRules -benchtime 3s ./cmd/zaafvesper
func BenchmarkShippedRules(b *testing.B) {
	rs, evs := shippedEvents(b)
	base := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	en := rules.NewEngine(rs, rules.Options{Clock: func() time.Time { return base }})
	b.ReportAllocs()
	b.ResetTimer()
	alerts := 0
	for i := 0; i < b.N; i++ {
		e := *evs[i%len(evs)]
		e.Seq = uint64(i + 1)
		e.Time = base.Add(time.Duration(i) * time.Millisecond)
		alerts += len(en.Process(&e))
	}
	b.StopTimer()
	sec := b.Elapsed().Seconds()
	if sec > 0 {
		b.ReportMetric(float64(b.N)/sec, "events/s")
	}
	b.ReportMetric(float64(len(rs.Enabled())), "rules")
	b.ReportMetric(float64(len(evs)), "distinct-events")
	_ = alerts
}

// TestShippedRulesBenchSetup keeps the benchmark's inputs loadable in
// normal test runs (every rule has a fixture, every event normalises).
func TestShippedRulesBenchSetup(t *testing.T) {
	rs, evs := shippedEvents(t)
	if len(rs.Rules) == 0 || len(evs) == 0 {
		t.Fatalf("%d rules, %d events", len(rs.Rules), len(evs))
	}
}
