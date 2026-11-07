package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
)

// pipeline is the single-goroutine event path shared by run and replay:
// enrich -> capture -> exclusions -> YARA submit -> rules -> sinks/response.
type pipeline struct {
	enricher  source.Enricher    // nil: events are already enriched
	excl      *config.Exclusions // nil: no exclusions
	engine    *rules.Engine
	sinks     []alert.Sink
	capture   *capture.Writer     // nil: no capture
	scanner   source.Scanner      // nil: no YARA
	responder *response.Responder // nil: response off (always nil in replay)
	dedup     *alert.Deduper      // nil: every alert is delivered
	errw      io.Writer

	events, excluded, alerts, suppressed, sinkErrs, captureErrs, submitted uint64
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
			} else {
				p.captureErrs++
				if p.captureErrs == 1 {
					say(p.errw, "capture: write failed: %v", err)
				}
			}
		}
	}
	if _, drop := p.excl.Match(e); drop {
		p.excluded++
		return
	}
	if p.scanner != nil && !fromScanner && yaraTriggers[e.Name] {
		p.scanner.Submit(e)
		p.submitted++
	}
	for _, a := range p.engine.Process(e) {
		if p.dedup != nil && !p.dedup.Allow(a) {
			p.suppressed++ // same rule, same pid, inside the window: no alert, no response
			continue
		}
		p.alerts++
		for _, s := range p.sinks {
			if err := s.Send(a); err != nil {
				p.sinkErrs++
				if p.sinkErrs == 1 {
					say(p.errw, "alert sink: %v", err)
				}
			}
		}
		p.respond(a)
	}
}

// respond kills the process of the completing event when response is on and
// the rule asks for it. Guard rails live in pkg/response.
func (p *pipeline) respond(a *rules.Alert) {
	if p.responder == nil {
		return
	}
	wantKill := false
	for _, act := range a.Actions {
		if act == rules.ActionKill {
			wantKill = true
		}
	}
	if !wantKill {
		return
	}
	_ = p.responder.KillEvent(a.Last(), "rule "+a.RuleName+" ("+a.RuleID+")")
}

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
