package alert

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// Per-rule alert aggregation (owner decision 8 Nov 2026, finding R5-1): one
// rule that fires in a flood must not fill the alert files, the high/critical
// series included.
//
// Within one window per rule:
//   - the first DefaultAggregateLimit alerts are written in full;
//   - after that, the FIRST alert of every source not yet seen in the window
//     is still written in full (security review of the aggregation: 20
//     decoys must not turn the real alert into a count), up to
//     maxAggregateSources sources, so a rule writes at most
//     DefaultAggregateLimit + maxAggregateSources full alerts per window;
//   - only repeats of an already-seen source (and new sources past the
//     bound) are held back and counted;
//   - when the window ends, one summary alert per rule replaces the held
//     ones. It names the top sources by count and carries the identity
//     (pid, ppid, exe, parent pid and exe) of the last aggregateLastHeld
//     held alerts as identity-only events.
//
// A source is the identity that matters for the rule: for a rule whose
// action kills the parent, the parent's executable; otherwise the
// executable plus the parent's executable.
const (
	DefaultAggregateLimit  = 20
	DefaultAggregateWindow = time.Minute
)

// Memory bounds. Rule ids come from the root-owned rules directory (41 rules
// today), so maxAggregateRules is far above any real rule set; an alert of a
// rule past the bound is written in full (never lost). Sources are the
// attacker-influenced part: at most maxAggregateSources distinct sources are
// tracked per rule and window, the rest are held as one "other" count.
const (
	maxAggregateRules   = 512
	maxAggregateSources = 64
	maxSourceKey        = 256 // bytes of an executable path kept in a source key
	aggregateTopSources = 5
	aggregateLastHeld   = 3
)

// otherSources is the source key of everything past maxAggregateSources.
const otherSources = "(other sources)"

// Aggregator decides, per rule and window, which alerts are written in full
// and builds the summary alerts for the ones it held back. Not safe for
// concurrent use; the pipeline calls it from its one goroutine.
type Aggregator struct {
	limit  int
	window time.Duration
	clock  func() time.Time // nil: the alert's own time (replay)
	rules  map[string]*aggWindow
	held   map[string]uint64 // alerts held back, by rule name (stats)
	over   uint64            // alerts written in full because maxAggregateRules was reached
	// exhausted, when set, is called once per rule window when a new source
	// arrives after maxAggregateSources sources were already seen: from then
	// on new sources are summarised, which an attacker can use to hide one.
	exhausted func(ruleID, ruleName string)
}

// MaxAggregateSources is the number of distinct sources a rule window tracks.
const MaxAggregateSources = maxAggregateSources

// OnSourcesExhausted sets the hook called when a rule's source slots fill up
// within a window (at most once per rule window). The pipeline turns it into
// a SensorDegraded event, aggregate_sources_exhausted, which is never
// aggregated.
func (g *Aggregator) OnSourcesExhausted(fn func(ruleID, ruleName string)) { g.exhausted = fn }

type aggWindow struct {
	start    time.Time
	full     int
	held     uint64
	sources  map[string]uint64 // every source seen in the window -> alerts held back from it
	lastHeld []*event.Event    // identity of the last aggregateLastHeld held alerts, oldest first
	reported bool              // source-slot exhaustion already reported for this window
	id, name string
	severity string
	labels   map[string]string
}

// NewAggregator returns an aggregator writing limit alerts per rule per
// window in full (limit <= 0: DefaultAggregateLimit; window <= 0:
// DefaultAggregateWindow), plus the first alert of each new source. clock
// supplies "now"; nil uses each alert's own time, which keeps a replay
// deterministic, and then Tick needs the caller's time.
func NewAggregator(limit int, window time.Duration, clock func() time.Time) *Aggregator {
	if limit <= 0 {
		limit = DefaultAggregateLimit
	}
	if window <= 0 {
		window = DefaultAggregateWindow
	}
	return &Aggregator{limit: limit, window: window, clock: clock, rules: map[string]*aggWindow{}, held: map[string]uint64{}}
}

func (g *Aggregator) now(fallback time.Time) time.Time {
	if g.clock != nil {
		return g.clock()
	}
	return fallback
}

// Add records a and reports whether a is to be written in full. summaries
// are the summary alerts of windows that ended before a (a's rule's own
// window, when a opens the next one); the caller writes them before a.
func (g *Aggregator) Add(a *rules.Alert) (write bool, summaries []*rules.Alert) {
	now := g.now(a.Time)
	w := g.rules[a.RuleID]
	if w != nil && !now.Before(w.start.Add(g.window)) {
		if s := g.summary(w, now); s != nil {
			summaries = append(summaries, s)
		}
		delete(g.rules, a.RuleID)
		w = nil
	}
	if w == nil {
		if len(g.rules) >= maxAggregateRules {
			g.over++
			return true, summaries
		}
		w = &aggWindow{start: now, id: a.RuleID, name: a.RuleName, severity: a.Severity, labels: a.Labels, sources: map[string]uint64{}}
		g.rules[a.RuleID] = w
	}
	key := SourceKey(a)
	_, seen := w.sources[key]
	if !seen && len(w.sources) < maxAggregateSources {
		// A new source inside the bound is always written in full, also
		// past the limit.
		w.sources[key] = 0
		w.full++
		return true, summaries
	}
	if w.full < g.limit {
		w.full++
		return true, summaries
	}
	if !seen {
		key = otherSources
		if len(w.sources) >= maxAggregateSources && !w.reported && g.exhausted != nil {
			w.reported = true
			g.exhausted(w.id, w.name)
		}
	}
	w.held++
	w.sources[key]++
	g.held[a.RuleName]++
	w.lastHeld = append(w.lastHeld, identityEvent(a.Last()))
	if len(w.lastHeld) > aggregateLastHeld {
		w.lastHeld = w.lastHeld[len(w.lastHeld)-aggregateLastHeld:]
	}
	return false, summaries
}

// Tick ends every window that is over at now (the caller's clock when the
// aggregator has none) and returns their summaries, in rule id order.
func (g *Aggregator) Tick(now time.Time) []*rules.Alert {
	if g.clock != nil {
		now = g.clock()
	}
	return g.end(func(w *aggWindow) bool { return !now.Before(w.start.Add(g.window)) }, now)
}

// Flush ends every window (shutdown, end of a replay) and returns the
// summaries of those that held alerts back, in rule id order. now is used
// as the summary time when the aggregator has no clock.
func (g *Aggregator) Flush(now time.Time) []*rules.Alert {
	if g.clock != nil {
		now = g.clock()
	}
	return g.end(func(*aggWindow) bool { return true }, now)
}

func (g *Aggregator) end(over func(*aggWindow) bool, now time.Time) []*rules.Alert {
	ids := make([]string, 0, len(g.rules))
	for id, w := range g.rules {
		if over(w) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []*rules.Alert
	for _, id := range ids {
		if s := g.summary(g.rules[id], now); s != nil {
			out = append(out, s)
		}
		delete(g.rules, id)
	}
	return out
}

// Held returns the alerts held back (counted in a summary instead of written
// in full), by rule name, plus "(rules over the tracking bound)" for alerts
// written in full because too many rules were tracked.
func (g *Aggregator) Held() map[string]uint64 {
	out := make(map[string]uint64, len(g.held)+1)
	for k, v := range g.held {
		out[k] = v
	}
	if g.over > 0 {
		out["(rules over the tracking bound)"] = g.over
	}
	return out
}

// summary builds the summary alert of w, or nil when w held nothing back.
// It keeps the rule's id, name, severity and labels (so it lands in the same
// alert file series), carries no actions (the response was already
// evaluated for every alert), lists at most aggregateTopSources sources by
// held count, and carries the last held alerts' identities as events.
func (g *Aggregator) summary(w *aggWindow, now time.Time) *rules.Alert {
	if w == nil || w.held == 0 {
		return nil
	}
	type src struct {
		key string
		n   uint64
	}
	srcs := make([]src, 0, len(w.sources))
	for k, n := range w.sources {
		if n > 0 {
			srcs = append(srcs, src{k, n})
		}
	}
	sort.Slice(srcs, func(i, j int) bool {
		if srcs[i].n != srcs[j].n {
			return srcs[i].n > srcs[j].n
		}
		return srcs[i].key < srcs[j].key
	})
	if len(srcs) > aggregateTopSources {
		srcs = srcs[:aggregateTopSources]
	}
	parts := make([]string, len(srcs))
	for i, s := range srcs {
		parts[i] = fmt.Sprintf("%s ×%d", s.key, s.n)
	}
	minutes := "the last minute"
	if g.window != time.Minute {
		minutes = "the last " + g.window.String()
	}
	last := make([]string, 0, len(w.lastHeld))
	for _, e := range w.lastHeld {
		if e == nil || e.Proc == nil {
			continue
		}
		p := e.Proc
		s := fmt.Sprintf("pid %d ppid %d %s", p.PID, p.PPID, p.Exe)
		if p.Parent != nil && p.Parent.Exe != "" {
			s += " parent " + p.Parent.Exe
		}
		last = append(last, s)
	}
	out := fmt.Sprintf("rule fired %d more times in %s; top sources: %s", w.held, minutes, strings.Join(parts, ", "))
	if len(last) > 0 {
		out += "; last held: " + strings.Join(last, "; ")
	}
	evs := make([]*event.Event, 0, len(w.lastHeld))
	for _, e := range w.lastHeld {
		if e != nil {
			evs = append(evs, e)
		}
	}
	return &rules.Alert{RuleID: w.id, RuleName: w.name, Severity: w.severity, Labels: w.labels,
		Time: now, Output: out, Events: evs, Aggregated: true, Count: w.held}
}

// SourceKey is the aggregation source of a: for a rule whose action kills
// the parent, the parent's executable (the process the rule is about); for
// any other rule, the executable of the completing event's process plus its
// parent's executable. Paths are cut to maxSourceKey bytes.
func SourceKey(a *rules.Alert) string {
	exe, parent := "(unknown executable)", "(unknown parent)"
	if e := a.Last(); e != nil && e.Proc != nil {
		if e.Proc.Exe != "" {
			exe = cutString(e.Proc.Exe, maxSourceKey)
		}
		if e.Proc.Parent != nil && e.Proc.Parent.Exe != "" {
			parent = cutString(e.Proc.Parent.Exe, maxSourceKey)
		}
	}
	for _, act := range a.Response {
		if act.Name == rules.ActionKill && act.KillTarget() == rules.TargetParent {
			return "parent " + parent
		}
	}
	return exe + " (parent " + parent + ")"
}

// identityEvent keeps the name, time, sequence number and process identity
// of e: pid, ppid, pidversion, unique id, exe, name, start time and the
// parent's pid, exe and name. Exe paths are cut to maxSourceKey bytes.
func identityEvent(e *event.Event) *event.Event {
	if e == nil {
		return nil
	}
	out := &event.Event{Seq: e.Seq, Time: e.Time, Name: e.Name, Source: e.Source}
	if p := e.Proc; p != nil {
		out.Proc = &event.Proc{PID: p.PID, PPID: p.PPID, PIDVersion: p.PIDVersion, UniqueID: p.UniqueID,
			Exe: cutString(p.Exe, maxSourceKey), Name: p.Name, StartTime: p.StartTime}
		if q := p.Parent; q != nil {
			out.Proc.Parent = &event.Proc{PID: q.PID, Exe: cutString(q.Exe, maxSourceKey), Name: q.Name}
		}
	}
	return out
}
