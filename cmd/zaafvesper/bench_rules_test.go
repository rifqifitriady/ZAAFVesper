package main

import (
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// shippedEvents loads every rule in rules/ and the events of every fixture
// scenario: all of them, or only the nomatch scenarios (benign lookalikes
// and near misses), which is closer to normal traffic where alerts are rare.
func shippedEvents(tb testing.TB, nomatchOnly bool) (*rules.Ruleset, []*event.Event) {
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
		scs := ff.NoMatch
		if !nomatchOnly {
			scs = append(append([]rules.Scenario{}, ff.Match...), ff.NoMatch...)
		}
		for _, sc := range scs {
			if err := rules.NormalizeScenario(sc.Events); err != nil {
				tb.Fatal(err)
			}
			evs = append(evs, sc.Events...)
		}
	}
	return rs, evs
}

// rulesPerEvent is the average number of rules the engine evaluates per
// event: rules indexed under the event's name plus rules with no evt.name
// constraint (the engine's byName index skips every other rule).
func rulesPerEvent(rs *rules.Ruleset, evs []*event.Event) float64 {
	byName := map[string]int{}
	anyRules := 0
	for _, r := range rs.Enabled() {
		names := r.EventNames()
		if names == nil {
			anyRules++
		}
		for _, n := range names {
			byName[n]++
		}
	}
	total := 0
	for _, e := range evs {
		total += byName[e.Name] + anyRules
	}
	return float64(total) / float64(len(evs))
}

// BenchmarkShippedRules measures the rule engine (engine only: no decoding,
// process table, YARA or output sinks) with every shipped rule enabled, all
// platforms, on one goroutine:
//
//   - benign: the events of every nomatch scenario (benign lookalikes and near
//     misses of the shipped rules). Few alerts; the realistic case.
//   - fixtures-all: every fixture event, about half of which raise an alert.
//   - benign-<platform>: what a sensor on that platform loads (its rules only)
//     over that platform's nomatch events. The like-for-like production case.
//
// The cost per event follows the number of rules indexed under the event's
// name (rules/event): most shipped rules are process-creation rules.
//
// Run: go test -run '^$' -bench BenchmarkShippedRules -benchtime 3s ./cmd/zaafvesper
func BenchmarkShippedRules(b *testing.B) {
	for _, c := range []struct {
		name        string
		nomatchOnly bool
		platform    string // "": every rule and event; else what a sensor on that platform loads
	}{
		{"benign", true, ""}, {"fixtures-all", false, ""},
		{"benign-macos", true, event.PlatformMacOS}, {"benign-windows", true, event.PlatformWindows}, {"benign-linux", true, event.PlatformLinux},
	} {
		b.Run(c.name, func(b *testing.B) {
			rs, evs := shippedEvents(b, c.nomatchOnly)
			if c.platform != "" {
				// run loads only the rules for its own platform; feed it that
				// platform's events (fixture events without a platform are macOS).
				rs.Platform = c.platform
				var keep []*event.Event
				for _, e := range evs {
					p := e.Platform
					if p == "" {
						p = event.PlatformMacOS
					}
					if p == c.platform {
						keep = append(keep, e)
					}
				}
				evs = keep
			}
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
			if sec := b.Elapsed().Seconds(); sec > 0 {
				b.ReportMetric(float64(b.N)/sec, "events/s")
			}
			b.ReportMetric(float64(alerts)/float64(b.N), "alerts/event")
			b.ReportMetric(rulesPerEvent(rs, evs), "rules/event")
			b.ReportMetric(float64(len(rs.Enabled())), "rules")
			b.ReportMetric(float64(len(evs)), "distinct-events")
		})
	}
}

// TestShippedRulesBenchSetup keeps the benchmark's inputs loadable in
// normal test runs (every rule has a fixture, every event normalises).
func TestShippedRulesBenchSetup(t *testing.T) {
	rs, evs := shippedEvents(t, false)
	if len(rs.Rules) == 0 || len(evs) == 0 {
		t.Fatalf("%d rules, %d events", len(rs.Rules), len(evs))
	}
}
