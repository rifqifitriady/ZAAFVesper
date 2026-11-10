package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Conditions of SensorDegraded events raised by the pipeline itself
// (pkg/ps and pkg/yara report their own through OnDegraded).
const (
	condAlertsCapped  = "alerts_capped"
	condCaptureCapped = "capture_capped"
)

// degradedEvery is the minimum interval between two SensorDegraded events
// for the same condition raised by the pipeline itself.
const degradedEvery = time.Minute

// Ceilings on SensorDegraded events from components. Each condition has its
// own share per minute, so a flood of one condition cannot starve another;
// maxDegradedPerMinute bounds the sum over all conditions. Conditions in
// neverSuppressed (es_events_dropped: lost telemetry, already aggregated by
// the source) pass both limits.
const (
	degradedSharePerMinute = 20
	maxDegradedPerMinute   = 120
)

// elegia_dir_full: capture of the --elegia-dir segments has stopped (the
// directory is full of segments younger than the retention floor); the
// writer limits its own reports.
var neverSuppressed = map[string]bool{"es_events_dropped": true, condElegiaDirFull: true}

// condSuppressed is the summary SensorDegraded raised at most once a minute
// while reports are being suppressed; its detail lists the counts.
const condSuppressed = "degraded_suppressed"

// condSourcesExhausted is raised when a rule's alert aggregation runs out of
// source slots within a window (see alert.Aggregator.OnSourcesExhausted).
const condSourcesExhausted = "aggregate_sources_exhausted"

// maxDegradedDetail caps evt.arg[detail].
const maxDegradedDetail = 1024

// maxSuppressedConditions bounds the per-condition suppression counters.
const maxSuppressedConditions = 64

// degradedReporter is implemented by components that report degraded
// telemetry: *ps.Snapshotter, the YARA scanner and the eslogger source
// (workstream B). It is matched by type assertion.
type degradedReporter interface {
	OnDegraded(fn func(condition, detail string))
}

type degradedReport struct {
	condition, detail string
	at                time.Time
}

// degradedState queues SensorDegraded reports. report may be called from
// any goroutine (YARA workers); the pipeline goroutine drains the queue.
type degradedState struct {
	mu          sync.Mutex
	last        map[string]time.Time   // pipeline conditions: last passed
	share       map[string][]time.Time // component conditions: passed in the last minute
	window      []time.Time            // all limited reports passed in the last minute
	pending     []degradedReport
	counts      map[string]uint64 // every report, by condition
	suppressed  uint64            // reports dropped by a limit, total
	pendingSupp map[string]uint64 // dropped since the last summary, by condition
	lastSummary time.Time
	clock       func() time.Time
	draining    bool // pipeline goroutine only
}

func (d *degradedState) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

func lastMinute(ts []time.Time, now time.Time) []time.Time {
	cut := now.Add(-time.Minute)
	keep := ts[:0]
	for _, t := range ts {
		if t.After(cut) && !t.After(now) {
			keep = append(keep, t)
		}
	}
	return keep
}

// report queues one degraded report. perCondition applies the pipeline's
// own limit of one event per condition per minute. Components that limit
// themselves per (condition, key) (ps, yara, the eslogger source) pass
// false: they get degradedSharePerMinute per condition, so one decoy does
// not hide a different real report and a flood of one condition does not
// starve another. Everything except neverSuppressed counts against
// maxDegradedPerMinute. What a limit drops is counted and summarised by
// one degraded_suppressed event a minute.
func (d *degradedState) report(condition, detail string, perCondition bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last, d.counts, d.share, d.pendingSupp = map[string]time.Time{}, map[string]uint64{}, map[string][]time.Time{}, map[string]uint64{}
	}
	now := d.now()
	d.counts[condition]++
	if !neverSuppressed[condition] {
		d.window = lastMinute(d.window, now)
		drop := len(d.window) >= maxDegradedPerMinute
		if perCondition {
			if t, ok := d.last[condition]; ok && now.Sub(t) < degradedEvery && now.Sub(t) >= 0 {
				drop = true
			}
		} else {
			sh := lastMinute(d.share[condition], now)
			if len(sh) == 0 {
				delete(d.share, condition)
			} else {
				d.share[condition] = sh
			}
			if len(sh) >= degradedSharePerMinute {
				drop = true
			}
		}
		if drop {
			d.suppressed++
			if _, ok := d.pendingSupp[condition]; ok || len(d.pendingSupp) < maxSuppressedConditions {
				d.pendingSupp[condition]++
			} else {
				d.pendingSupp["other"]++
			}
			return
		}
		d.window = append(d.window, now)
		if perCondition {
			d.last[condition] = now
		} else if len(d.share) < maxSuppressedConditions || d.share[condition] != nil {
			d.share[condition] = append(d.share[condition], now)
		}
	}
	d.pending = append(d.pending, degradedReport{condition: condition, detail: detail, at: now})
}

// take returns the queued reports, plus one degraded_suppressed summary
// when reports were suppressed and the last summary is a minute old.
func (d *degradedState) take() []degradedReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.pending
	d.pending = nil
	if len(d.pendingSupp) > 0 {
		now := d.now()
		if d.lastSummary.IsZero() || now.Sub(d.lastSummary) >= time.Minute || now.Before(d.lastSummary) {
			keys := make([]string, 0, len(d.pendingSupp))
			for k := range d.pendingSupp {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, len(keys))
			for i, k := range keys {
				parts[i] = fmt.Sprintf("%s=%d", k, d.pendingSupp[k])
			}
			out = append(out, degradedReport{condition: condSuppressed, at: now,
				detail: "degraded reports suppressed by the per-minute limits: " + strings.Join(parts, " ")})
			d.counts[condSuppressed]++
			d.pendingSupp = map[string]uint64{}
			d.lastSummary = now
		}
	}
	return out
}

func (d *degradedState) stats() map[string]uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]uint64, len(d.counts)+1)
	for k, v := range d.counts {
		out[k] = v
	}
	if d.suppressed > 0 {
		out["rate_limited"] = d.suppressed
	}
	return out
}

// selfProc describes ZAAFVesper's own process for SensorDegraded events.
var selfProc = sync.OnceValue(func() event.Proc {
	exe, _ := os.Executable()
	return event.Proc{PID: int32(os.Getpid()), PPID: int32(os.Getppid()), Exe: exe, Name: filepath.Base(exe),
		UID: int64(os.Getuid()), EUID: int64(os.Geteuid())}
})

// degraded records that the sensor's telemetry is degraded (conditions
// raised by the pipeline itself: alerts_capped, capture_capped,
// response_rate_limited). Safe from any goroutine and never blocks on the
// pipeline; at most one report per condition per minute becomes a
// SensorDegraded event.
func (p *pipeline) degraded(condition, detail string) {
	p.deg.report(condition, detail, true)
}

// degradedFrom is the OnDegraded hook for components that rate-limit their
// own reports per (condition, key): only the global ceiling applies.
func (p *pipeline) degradedFrom(condition, detail string) {
	p.deg.report(condition, detail, false)
}

// drainDegraded turns queued reports into SensorDegraded events: one
// sanitized stderr line each, then the normal path (capture, rules, sinks,
// response). Pipeline goroutine only; re-entrant calls return at once.
func (p *pipeline) drainDegraded() {
	if p.deg.draining {
		return
	}
	p.deg.draining = true
	defer func() { p.deg.draining = false }()
	for {
		reports := p.deg.take()
		if len(reports) == 0 {
			return
		}
		for _, r := range reports {
			detail := r.detail
			if len(detail) > maxDegradedDetail {
				detail = detail[:maxDegradedDetail]
			}
			say(p.errw, "sensor degraded: condition=%s detail=%q", r.condition, detail)
			self := selfProc()
			p.handle(&event.Event{
				Time: r.at.UTC(), Name: event.SensorDegraded, Source: "zaafvesper", Proc: &self,
				Args: map[string]string{"condition": r.condition, "detail": detail},
			}, true)
		}
	}
}
