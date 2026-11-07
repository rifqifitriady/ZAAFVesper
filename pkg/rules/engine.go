package rules

import (
	"sort"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Alert is a rule match.
type Alert struct {
	RuleID   string            `json:"rule_id"`
	RuleName string            `json:"rule_name"`
	Severity string            `json:"severity"`
	Output   string            `json:"output"`
	Labels   map[string]string `json:"labels,omitempty"`
	Time     time.Time         `json:"time"`
	Events   []*event.Event    `json:"events"`
	Actions  []string          `json:"actions,omitempty"`
}

// Last returns the event that completed the match.
func (a *Alert) Last() *event.Event {
	if len(a.Events) == 0 {
		return nil
	}
	return a.Events[len(a.Events)-1]
}

// Options tunes the engine.
type Options struct {
	// Clock supplies "now" for an event without a timestamp. When nil (the
	// default) such an event takes the time of the last timestamped event, so
	// sequence windows are always measured on event time, never wall clock.
	Clock func() time.Time
	// MaxPartials caps partial sequences per rule (default 10 000); the
	// oldest partial is evicted first.
	MaxPartials int
	// MaxPartialBytes caps the estimated bytes held by partial sequences
	// across all rules (default 64 MiB); the oldest partial of any rule is
	// evicted first. Partials hold slim event copies: no environment,
	// cmdline/args/evt.arg values capped at 4 KiB.
	MaxPartialBytes int64
}

type ruleState struct {
	r       *Rule
	seq     *seqState
	matches uint64
}

// Engine evaluates enabled rules over events. It is not safe for concurrent
// use: the pipeline calls Process from a single goroutine, in event order.
type Engine struct {
	opts     Options
	rules    []*ruleState
	byName   map[string][]*ruleState
	anyRules []*ruleState
	required []string // nil = every event
	lastTime time.Time
	budget   *partialBudget
	events   uint64
	alerts   uint64
}

// NewEngine builds an engine over the enabled rules of rs.
func NewEngine(rs *Ruleset, opts Options) *Engine {
	if opts.MaxPartials <= 0 {
		opts.MaxPartials = DefaultMaxPartials
	}
	en := &Engine{opts: opts, byName: map[string][]*ruleState{}, budget: newPartialBudget(opts.MaxPartialBytes)}
	need := map[string]bool{}
	all := false
	for _, r := range rs.Enabled() {
		st := &ruleState{r: r}
		if r.seq != nil {
			st.seq = newSeqState(r.seq, opts.MaxPartials, en.budget)
		}
		en.rules = append(en.rules, st)
		names := r.EventNames()
		if names == nil {
			en.anyRules = append(en.anyRules, st)
			all = true
			continue
		}
		for _, n := range names {
			en.byName[n] = append(en.byName[n], st)
			need[n] = true
		}
	}
	if !all {
		en.required = make([]string, 0, len(need))
		for n := range need {
			en.required = append(en.required, n)
		}
		sort.Strings(en.required)
	}
	return en
}

// RequiredEvents returns the event names the loaded rules need, sorted. nil
// means at least one rule is not constrained by evt.name and needs every event.
func (en *Engine) RequiredEvents() []string {
	if en.required == nil {
		return nil
	}
	return append([]string{}, en.required...)
}

// Process evaluates one event and returns the alerts it completes.
func (en *Engine) Process(e *event.Event) []*Alert {
	if e == nil {
		return nil
	}
	en.events++
	now := e.Time
	switch {
	case !now.IsZero():
		en.lastTime = now
	case en.opts.Clock != nil:
		now = en.opts.Clock()
	default:
		now = en.lastTime
	}
	var out []*Alert
	for _, list := range [2][]*ruleState{en.byName[e.Name], en.anyRules} {
		for _, st := range list {
			if st.seq != nil {
				for _, evs := range st.seq.process(e, now) {
					out = append(out, en.alert(st, evs, now))
				}
				continue
			}
			if st.r.filter.Match(e) {
				out = append(out, en.alert(st, []*event.Event{e}, now))
			}
		}
	}
	return out
}

func (en *Engine) alert(st *ruleState, evs []*event.Event, now time.Time) *Alert {
	st.matches++
	en.alerts++
	r := st.r
	out := r.output.render(evs)
	if out == "" {
		out = r.Name
	}
	var labels map[string]string
	if len(r.Labels) > 0 {
		labels = make(map[string]string, len(r.Labels))
		for k, v := range r.Labels {
			labels[k] = v
		}
	}
	return &Alert{
		RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Output: out,
		Labels: labels, Time: now, Events: evs, Actions: r.Actions(),
	}
}

// Stats are engine counters.
type Stats struct {
	Events   uint64            `json:"events"`
	Alerts   uint64            `json:"alerts"`
	PerRule  map[string]uint64 `json:"per_rule"` // rule name -> matches (only rules that matched)
	Partials int               `json:"partials"` // live partial sequences
	Evicted  uint64            `json:"evicted"`  // partials evicted by the cap
	Expired  uint64            `json:"expired"`  // partials expired by maxspan
	// PartialBytes is the estimated memory held by partial sequences.
	PartialBytes int64 `json:"partial_bytes"`
}

// Stats returns a snapshot of the counters.
func (en *Engine) Stats() Stats {
	s := Stats{Events: en.events, Alerts: en.alerts, PerRule: map[string]uint64{}, PartialBytes: en.budget.used}
	for _, st := range en.rules {
		if st.matches > 0 {
			s.PerRule[st.r.Name] = st.matches
		}
		if st.seq != nil {
			s.Partials += st.seq.len()
			s.Evicted += st.seq.evicted
			s.Expired += st.seq.expired
		}
	}
	return s
}

// Rules returns the enabled rules the engine evaluates.
func (en *Engine) Rules() []*Rule {
	out := make([]*Rule, len(en.rules))
	for i, st := range en.rules {
		out[i] = st.r
	}
	return out
}
