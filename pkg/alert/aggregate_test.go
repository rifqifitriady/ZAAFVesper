package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

func aggAlert(rule, sev, exe string, pid int32, at time.Time) *rules.Alert {
	return &rules.Alert{RuleID: rule, RuleName: "Rule " + rule, Severity: sev, Time: at, Output: "fired",
		Labels: map[string]string{"tactic.id": "TA0006"},
		Events: []*event.Event{{Name: event.CreateProcess, Time: at, Proc: &event.Proc{PID: pid, Exe: exe}}}}
}

// TestAggregatorFloodOneRule (owner decision 8 Nov 2026, R5-1): 100 alerts
// of one rule inside a minute give 20 written in full and, when the minute
// is over, one summary with count 80 that names at most five sources. A
// second rule firing meanwhile is unaffected.
func TestAggregatorFloodOneRule(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	now := t0
	g := NewAggregator(DefaultAggregateLimit, DefaultAggregateWindow, func() time.Time { return now })
	exes := []string{"/tmp/a", "/tmp/b", "/tmp/c", "/tmp/d", "/tmp/e", "/tmp/f", "/tmp/g"}
	written, other := 0, 0
	for i := 0; i < 100; i++ {
		now = t0.Add(time.Duration(i) * 500 * time.Millisecond) // 0 .. 49.5 s
		w, sums := g.Add(aggAlert("A", "high", exes[i%len(exes)], int32(1000+i), now))
		if len(sums) != 0 {
			t.Fatalf("summary inside the window at %d: %+v", i, sums)
		}
		if w {
			written++
		}
		if i%10 == 0 { // rule B: 10 alerts, all written
			if w, _ := g.Add(aggAlert("B", "low", "/usr/bin/curl", 50, now)); w {
				other++
			}
		}
	}
	if written != 20 || other != 10 {
		t.Fatalf("written A=%d (want 20), B=%d (want 10)", written, other)
	}
	now = t0.Add(59 * time.Second)
	if sums := g.Tick(now); len(sums) != 0 {
		t.Fatalf("summary before the minute is over: %+v", sums)
	}
	now = t0.Add(time.Minute)
	sums := g.Tick(now)
	if len(sums) != 1 {
		t.Fatalf("summaries = %d, want 1 (rule B held nothing): %+v", len(sums), sums)
	}
	s := sums[0]
	if s.RuleID != "A" || s.RuleName != "Rule A" || s.Severity != "high" || !s.Aggregated || s.Count != 80 || len(s.Events) != 3 || len(s.Actions) != 0 {
		t.Fatalf("summary = %+v", s)
	}
	if !strings.HasPrefix(s.Output, "rule fired 80 more times in the last minute; top sources: ") {
		t.Fatalf("output = %q", s.Output)
	}
	if n := strings.Count(s.Output, "×"); n != 5 {
		t.Fatalf("output lists %d sources, want 5: %q", n, s.Output)
	}
	// The last three held alerts (i = 97, 98, 99) are named by pid.
	for i, pid := range []int32{1097, 1098, 1099} {
		if s.Events[i].Proc == nil || s.Events[i].Proc.PID != pid || !strings.Contains(s.Output, fmt.Sprintf("pid %d ppid", pid)) {
			t.Fatalf("last held %d: %+v / %q", i, s.Events[i], s.Output)
		}
	}
	if g.Held()["Rule A"] != 80 || g.Held()["Rule B"] != 0 {
		t.Fatalf("held = %v", g.Held())
	}
	// The window is gone: the next alert of A is written in full again.
	if w, sums := g.Add(aggAlert("A", "high", "/tmp/a", 1, now)); !w || len(sums) != 0 {
		t.Fatalf("new window: write=%v sums=%v", w, sums)
	}
}

// TestAggregatorSummaryOnNextAlert: with no tick, the summary is returned
// by the first alert of the rule after the window, before that alert.
func TestAggregatorSummaryOnNextAlert(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	g := NewAggregator(2, time.Minute, nil) // nil clock: alert time
	for i := 0; i < 5; i++ {
		g.Add(aggAlert("A", "critical", "/tmp/x", 7, t0.Add(time.Duration(i)*time.Second)))
	}
	w, sums := g.Add(aggAlert("A", "critical", "/tmp/x", 7, t0.Add(61*time.Second)))
	if !w || len(sums) != 1 || sums[0].Count != 3 || sums[0].Severity != "critical" || !sums[0].Time.Equal(t0.Add(61*time.Second)) {
		t.Fatalf("write=%v sums=%+v", w, sums)
	}
	if !strings.Contains(sums[0].Output, "/tmp/x (parent (unknown parent)) ×3") {
		t.Fatalf("output = %q", sums[0].Output)
	}
	// Shutdown: Flush returns nothing for a window that held nothing back.
	if f := g.Flush(t0.Add(62 * time.Second)); len(f) != 0 {
		t.Fatalf("flush = %+v", f)
	}
	for i := 0; i < 4; i++ {
		g.Add(aggAlert("A", "critical", "/tmp/y", 8, t0.Add(62*time.Second)))
	}
	if f := g.Flush(t0.Add(63 * time.Second)); len(f) != 1 || f[0].Count != 2 {
		t.Fatalf("flush at shutdown = %+v", f)
	}
}

// TestAggregatorBoundedMemory: distinct sources per rule are capped (the
// rest are one "other" count), long paths are cut, and rules past the
// tracking bound are written in full, never dropped.
func TestAggregatorBoundedMemory(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	g := NewAggregator(1, time.Minute, func() time.Time { return t0 })
	long := "/tmp/" + strings.Repeat("x", 10000)
	g.Add(aggAlert("A", "high", "/tmp/first", 1, t0))
	for i := 0; i < 5000; i++ {
		exe := fmt.Sprintf("/tmp/p%d", i)
		if i == 0 {
			exe = long
		}
		g.Add(aggAlert("A", "high", exe, int32(i), t0))
	}
	w := g.rules["A"]
	if len(w.sources) > maxAggregateSources+1 {
		t.Fatalf("sources tracked = %d", len(w.sources))
	}
	// /tmp/first plus 63 new sources are written in full (the first alert
	// of each new source); the remaining 4937 sources are held as "other".
	if w.full != maxAggregateSources || w.sources[otherSources] != 5000-(maxAggregateSources-1) {
		t.Fatalf("full = %d, other = %d", w.full, w.sources[otherSources])
	}
	for k := range w.sources {
		if len(k) > maxSourceKey+64 {
			t.Fatalf("source key of %d bytes", len(k))
		}
	}
	s := g.Flush(t0)
	if len(s) != 1 || s[0].Count != 5000-(maxAggregateSources-1) || len(s[0].Output) > 4096 {
		t.Fatalf("summary: %d alerts, count %d, %d bytes", len(s), s[0].Count, len(s[0].Output))
	}
	g2 := NewAggregator(1, time.Minute, func() time.Time { return t0 })
	for i := 0; i < maxAggregateRules; i++ {
		g2.Add(aggAlert(fmt.Sprintf("r%d", i), "low", "/tmp/x", 1, t0))
	}
	for i := 0; i < 3; i++ {
		if w, _ := g2.Add(aggAlert("one-too-many", "low", "/tmp/x", 1, t0)); !w {
			t.Fatal("alert of an untracked rule held back")
		}
	}
	if len(g2.rules) != maxAggregateRules || g2.Held()["(rules over the tracking bound)"] != 3 {
		t.Fatalf("rules %d held %v", len(g2.rules), g2.Held())
	}
}

// TestSummaryEncoding: the JSONL line of a summary carries aggregated and
// count (also in the identity-only last resort), the console shows them.
func TestSummaryEncoding(t *testing.T) {
	s := &rules.Alert{RuleID: "A", RuleName: "Rule A", Severity: "high", Time: time.Unix(0, 0).UTC(),
		Output: "rule fired 80 more times in the last minute; top sources: /tmp/a ×80", Aggregated: true, Count: 80}
	line, _, err := EncodeAlert(s, DefaultMaxAlertBytes)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatal(err)
	}
	if m["aggregated"] != true || m["count"] != float64(80) || m["severity"] != "high" {
		t.Fatalf("encoded summary = %s", line)
	}
	if id := identityAlert(s); !id.Aggregated || id.Count != 80 {
		t.Fatalf("identity stub lost the aggregation: %+v", id)
	}
	if f := Format(s); !strings.Contains(f, "aggregated=80") || !strings.Contains(f, "×80") {
		t.Fatalf("console = %q", f)
	}
	// An ordinary alert carries neither field.
	plain, _, _ := EncodeAlert(aggAlert("A", "high", "/tmp/a", 1, time.Unix(0, 0)), DefaultMaxAlertBytes)
	if bytes.Contains(plain, []byte(`"aggregated"`)) || bytes.Contains(plain, []byte(`"count"`)) {
		t.Fatalf("plain alert = %s", plain)
	}
}

func promptAlert(parent string, pid int32, at time.Time) *rules.Alert {
	return &rules.Alert{RuleID: "6627fec8", RuleName: "Fake password prompt via osascript from untrusted origin", Severity: "critical", Time: at,
		Response: []rules.Action{{Name: rules.ActionKill, Target: rules.TargetParent}},
		Events: []*event.Event{{Name: event.CreateProcess, Time: at,
			Proc: &event.Proc{PID: pid, PPID: pid + 1, Exe: "/usr/bin/osascript", Parent: &event.Proc{PID: pid + 1, Exe: parent}}}}}
}

// TestAggregationDecoysDoNotHideRealPrompt (security review scenario A): 20
// decoy prompts of the critical kill-parent rule from /tmp/decoy, then the
// real prompt from a stealer in Downloads. The source of a kill-parent rule
// is the parent, so the real prompt is a new source and is written in full.
func TestAggregationDecoysDoNotHideRealPrompt(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := NewAggregator(0, 0, nil)
	for i := 0; i < 25; i++ {
		g.Add(promptAlert("/tmp/decoy", int32(1000+2*i), t0.Add(time.Duration(i)*time.Millisecond)))
	}
	stealer := "/Users/u/Downloads/Installer.app/Contents/MacOS/stealer"
	if w, _ := g.Add(promptAlert(stealer, 5000, t0.Add(time.Second))); !w {
		t.Fatal("real prompt held back behind decoys")
	}
	if SourceKey(promptAlert(stealer, 1, t0)) != "parent "+stealer {
		t.Fatalf("source key = %q", SourceKey(promptAlert(stealer, 1, t0)))
	}
	// A repeat of the real source after the limit is held, and the summary
	// still names it among the last held alerts.
	if w, _ := g.Add(promptAlert(stealer, 5002, t0.Add(2*time.Second))); w {
		t.Fatal("repeat of a seen source written past the limit")
	}
	sums := g.Flush(t0.Add(3 * time.Second))
	if len(sums) != 1 || sums[0].Count != 6 || !strings.Contains(sums[0].Output, "pid 5002 ppid 5003 /usr/bin/osascript parent "+stealer) {
		t.Fatalf("summary = %+v", sums)
	}
}

// TestAggregationDiversifiedDecoysDoNotHideSource (security review
// scenario B): 20 decoys from /bin/cp and two each from five more
// executables, then one alert from malware: written in full.
func TestAggregationDiversifiedDecoysDoNotHideSource(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := NewAggregator(0, 0, nil)
	for i := 0; i < 20; i++ {
		g.Add(aggAlert("B", "high", "/bin/cp", int32(1000+i), t0))
	}
	for _, x := range []string{"/bin/a1", "/bin/a2", "/bin/a3", "/bin/a4", "/bin/a5"} {
		if w, _ := g.Add(aggAlert("B", "high", x, 2000, t0)); !w {
			t.Fatalf("first alert of new source %s held", x)
		}
		if w, _ := g.Add(aggAlert("B", "high", x, 2001, t0)); w {
			t.Fatalf("repeat of %s written past the limit", x)
		}
	}
	if w, _ := g.Add(aggAlert("B", "high", "/Users/u/Library/Caches/x/malware", 3000, t0)); !w {
		t.Fatal("malware alert held back behind diversified decoys")
	}
	if sums := g.Flush(t0.Add(time.Minute)); len(sums) != 1 || sums[0].Count != 5 {
		t.Fatalf("summary = %+v", sums)
	}
}

// TestAggregationFullLinesBounded: a rule writes at most limit + 64 full
// alerts per window however many sources an attacker invents.
func TestAggregationFullLinesBounded(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := NewAggregator(0, 0, nil)
	full := 0
	for i := 0; i < 1000; i++ {
		exe := "/bin/cp"
		if i >= 20 {
			exe = fmt.Sprintf("/tmp/decoy%d", i)
		}
		if w, _ := g.Add(aggAlert("C", "high", exe, int32(i), t0)); w {
			full++
		}
	}
	if full != DefaultAggregateLimit+maxAggregateSources-1 {
		t.Fatalf("full alerts = %d, want %d", full, DefaultAggregateLimit+maxAggregateSources-1)
	}
}

// TestSourcesExhaustedReportedOnce: when a rule's source slots fill up in a
// window, the hook fires once for that window (security review finding 2).
func TestSourcesExhaustedReportedOnce(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	now := t0
	g := NewAggregator(DefaultAggregateLimit, DefaultAggregateWindow, func() time.Time { return now })
	var calls []string
	g.OnSourcesExhausted(func(id, name string) { calls = append(calls, id) })
	mk := func(parent string) *rules.Alert {
		return &rules.Alert{RuleID: "r1", RuleName: "R1", Severity: "critical", Time: now,
			Events: []*event.Event{{Name: event.CreateProcess, Proc: &event.Proc{PID: 9, Exe: "/usr/bin/osascript", Parent: &event.Proc{PID: 8, Exe: parent}}}}}
	}
	for i := 0; i < MaxAggregateSources; i++ {
		g.Add(mk(fmt.Sprintf("/tmp/d%02d", i)))
	}
	if len(calls) != 0 {
		t.Fatalf("hook fired before the slots were full: %v", calls)
	}
	g.Add(mk("/Users/x/Downloads/stealer"))
	g.Add(mk("/Users/x/Downloads/stealer2"))
	if len(calls) != 1 || calls[0] != "r1" {
		t.Fatalf("calls = %v, want one for r1", calls)
	}
	now = t0.Add(2 * time.Minute)
	g.Tick(now)
	for i := 0; i <= MaxAggregateSources; i++ {
		g.Add(mk(fmt.Sprintf("/tmp/e%02d", i)))
	}
	if len(calls) != 2 {
		t.Fatalf("new window must report again: %v", calls)
	}
}
