package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
)

// pipeline is the single-goroutine event path shared by run and replay:
// enrich -> capture -> exclusions -> YARA submit -> rules -> sinks/response,
// then any SensorDegraded events raised meanwhile.
type pipeline struct {
	enricher  source.Enricher    // nil: events are already enriched
	excl      *config.Exclusions // nil: no exclusions
	engine    *rules.Engine
	sinks     []alert.Sink
	capture   *capture.Writer     // nil: no capture
	scanner   source.Scanner      // nil: no YARA
	responder *response.Responder // nil: response off (always nil in replay)
	dedup     *alert.Deduper      // nil: every alert is delivered
	agg       *alert.Aggregator   // nil: no per-rule aggregation
	errw      io.Writer
	deg       degradedState // SensorDegraded reports (see degraded.go)
	// taps see every event that passed the exclusions (ZAAFElegia and SIEM
	// event exports, netpoll exec nudges; see outputs.go). They must not
	// block or modify the event.
	taps []func(*event.Event)

	events, excluded, alerts, suppressed, sinkErrs, captureErrs, submitted uint64
	fallbackLines, aggregated, summaries                                   uint64
	captureStopped                                                         bool
}

// yaraTriggers are the event names handed to the YARA scanner.
var yaraTriggers = map[string]bool{event.CreateProcess: true, event.CreateFile: true, event.WriteFile: true}

func (p *pipeline) handle(e *event.Event, fromScanner bool) {
	if e == nil {
		return
	}
	p.events++
	if !fromScanner && p.enricher != nil {
		p.enricher.Enrich(e)
	}
	if p.capture != nil && !p.captureStopped {
		if err := p.capture.Write(e); err != nil {
			if errors.Is(err, capture.ErrLimit) {
				p.captureStopped = true
				say(p.errw, "capture: size limit reached after %d bytes (uncompressed); capture stopped, sensor keeps running", p.capture.Bytes())
				p.degraded(condCaptureCapped, fmt.Sprintf("capture reached its cap of %d uncompressed bytes; later events are not captured", p.capture.Bytes()))
			} else {
				p.captureErrs++
				if p.captureErrs == 1 {
					say(p.errw, "capture: write failed: %v", err)
				}
			}
		}
	}
	defer p.drainDegraded()
	// Mount events invalidate the YARA scanner's non-local mount cache. They
	// go to the scanner before the exclusions, so a configured exclusion
	// cannot keep a stale "local" verdict for a newly mounted path.
	if p.scanner != nil && !fromScanner && e.Name == event.Mount {
		p.scanner.Submit(e)
		p.submitted++
	}
	if _, drop := p.excl.Match(e); drop {
		p.excluded++
		return
	}
	for _, tap := range p.taps {
		tap(e)
	}
	if p.scanner != nil && !fromScanner && yaraTriggers[e.Name] {
		p.scanner.Submit(e)
		p.submitted++
	}
	for _, a := range p.engine.Process(e) {
		// Deduplication and aggregation only quiet the output: the response
		// decision is taken for every alert, repeat or not, held back or
		// not. SensorDegraded events are already rate-limited per condition
		// (20 a minute each, 120 in all, es_events_dropped never) and all
		// carry ZAAFVesper's own pid, so they are neither deduplicated nor
		// aggregated.
		switch {
		case p.dedup != nil && e.Name != event.SensorDegraded && !p.dedup.Allow(a):
			p.suppressed++ // same rule, same process, inside the window
		case p.agg != nil && e.Name != event.SensorDegraded:
			write, sums := p.agg.Add(a)
			for _, s := range sums {
				p.writeSummary(s)
			}
			if write {
				p.deliver(a)
			} else {
				p.aggregated++ // counted in the rule's next summary
			}
		default:
			p.deliver(a)
		}
		p.respond(a)
	}
}

// deliver writes a to every sink (and the stderr fallback line).
func (p *pipeline) deliver(a *rules.Alert) {
	p.alerts++
	for _, s := range p.sinks {
		if err := s.Send(a); err != nil {
			p.sinkErrs++
			if p.sinkErrs == 1 {
				say(p.errw, "alert sink: %v", err)
			}
		}
	}
	p.fallbackAlert(a)
}

// writeSummary delivers one per-rule summary alert of the aggregator.
func (p *pipeline) writeSummary(a *rules.Alert) {
	p.summaries++
	p.deliver(a)
}

// flushAggregates writes the summaries of aggregation windows that are over
// at now (all of them when final: shutdown, end of a replay). run calls it
// on its 2-second tick, so a summary follows the end of its minute closely
// even when the rule does not fire again.
func (p *pipeline) flushAggregates(now time.Time, final bool) {
	if p.agg == nil {
		return
	}
	var sums []*rules.Alert
	if final {
		sums = p.agg.Flush(now)
	} else {
		sums = p.agg.Tick(now)
	}
	for _, s := range sums {
		p.writeSummary(s)
	}
}

// maxFallbackLine bounds the stderr line written for a high or critical
// alert while an alert file is not being written.
const maxFallbackLine = 1024

// fallbackAlert writes a high or critical alert as one sanitized, bounded
// stderr line while any JSONL sink is stopped (cap or budget reached), so
// those alerts still reach the daemon's log.
func (p *pipeline) fallbackAlert(a *rules.Alert) {
	if !alert.HighOrCritical(a) {
		return
	}
	stopped := false
	for _, s := range p.sinks {
		j, ok := s.(*alert.JSONL)
		if f, isF := s.(*alert.Filtered); isF {
			j, ok = f.Sink.(*alert.JSONL)
		}
		if ok && j.Stopped() {
			stopped = true
			break
		}
	}
	if !stopped {
		return
	}
	// Identity first, attacker-influenced output last: only the output can
	// be cut by the length bound.
	line := fmt.Sprintf("alert not in alert file: %s %s rule=%s", a.Time.UTC().Format(time.RFC3339),
		strings.ToUpper(a.Severity), a.RuleID)
	if e := a.Last(); e != nil && e.Proc != nil {
		line += fmt.Sprintf(" pid=%d exe=%q", e.Proc.PID, e.Proc.Exe)
	}
	line += fmt.Sprintf(" %s: %s", a.RuleName, a.Output)
	line = alert.Sanitize(line)
	if len(line) > maxFallbackLine {
		cut := maxFallbackLine
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		line = line[:cut] + "...[truncated]"
	}
	p.fallbackLines++
	_, _ = io.WriteString(p.errw, line+"\n")
}

// respond applies the rule's response actions when response is on (see
// respondActions in response_actions.go).
func (p *pipeline) respond(a *rules.Alert) { p.respondActions(a) }

// printStats writes the end-of-run counters (sanitized, one group per line).
func (p *pipeline) printStats(w io.Writer, extra map[string]map[string]uint64) {
	st := p.engine.Stats()
	say(w, "stats: events=%d excluded=%d alerts=%d suppressed=%d yara_submitted=%d sink_errors=%d capture_errors=%d partial_sequences=%d partial_bytes=%d evicted=%d expired=%d",
		p.events, p.excluded, p.alerts, p.suppressed, p.submitted, p.sinkErrs, p.captureErrs, st.Partials, st.PartialBytes, st.Evicted, st.Expired)
	if p.capture != nil {
		say(w, "stats: captured=%d capture_bytes_uncompressed=%d capture_full=%v", p.capture.Count(), p.capture.Bytes(), p.capture.Full())
	}
	if p.dedup != nil {
		printCounter(w, "suppressed duplicates by rule", p.dedup.Suppressed())
	}
	if p.agg != nil {
		say(w, "stats: aggregated=%d aggregate_summaries=%d", p.aggregated, p.summaries)
		printCounter(w, "aggregated alerts by rule", p.agg.Held())
	}
	printCounter(w, "sensor degraded", p.deg.stats())
	for _, s := range p.sinks {
		if j, ok := s.(*alert.JSONL); ok {
			printCounter(w, "alert file", j.Stats())
		}
	}
	for _, s := range p.sinks {
		if as, ok := s.(*alert.Async); ok && as.Dropped() > 0 {
			say(w, "stats: console alerts dropped (terminal too slow)=%d", as.Dropped())
		}
	}
	printCounter(w, "alerts by rule", st.PerRule)
	printCounter(w, "exclusions hit", p.excl.Stats())
	if p.responder != nil {
		printCounter(w, "response", p.responder.Stats())
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		printCounter(w, k, extra[k])
	}
}

// periodicStats prints the counters a long-running daemon needs before
// shutdown: degraded reports (including what the limits suppressed),
// alert-file and response counters. run calls it every statsEvery.
func (p *pipeline) periodicStats(w io.Writer) {
	if p.agg != nil {
		printCounter(w, "aggregated alerts by rule", p.agg.Held())
	}
	printCounter(w, "sensor degraded", p.deg.stats())
	for _, s := range p.sinks {
		if j, ok := s.(*alert.JSONL); ok {
			printCounter(w, "alert file", j.Stats())
		}
	}
	if p.responder != nil {
		printCounter(w, "response", p.responder.Stats())
	}
}

func printCounter(w io.Writer, title string, m map[string]uint64) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", quoteSpace(k), m[k])
	}
	say(w, "stats: %s: %s", title, strings.Join(parts, " "))
}

func quoteSpace(s string) string {
	if strings.ContainsAny(s, " \t") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// say prints one sanitized line. Every terminal print of event- or
// rule-derived text goes through here or through alert.Console.
func say(w io.Writer, format string, args ...any) {
	_, _ = io.WriteString(w, alert.Sanitize(fmt.Sprintf(format, args...))+"\n")
}

// sayLines prints a possibly multi-line message (errors.Join), one sanitized
// line per input line.
func sayLines(w io.Writer, prefix string, msg string) {
	for _, line := range strings.Split(msg, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		say(w, "%s%s", prefix, line)
	}
}
