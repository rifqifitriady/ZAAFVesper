package output

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/sigmamap"
)

// SysmonTime is the format of Sysmon's UtcTime field (ZAAFElegia reads it as
// a timestamp).
const SysmonTime = "2006-01-02 15:04:05.000"

// genericFields are exported for events without a Sigma category (Fork,
// SetXattr, YaraMatch, ...): the process identity only, so that a Sigma rule
// written for one category is less likely to match another category's event.
var genericFields = func() map[string]string {
	out := map[string]string{}
	for _, f := range []struct{ cat, field string }{
		{"process_creation", "ps.exe"}, {"process_creation", "ps.pid"}, {"process_creation", "ps.username"},
		{"file_event", "file.path"},
	} {
		if name, ok := sigmamap.SigmaField(f.cat, f.field); ok {
			out[f.field] = name
		}
	}
	return out
}()

// ElegiaSchema names the record layout written by --elegia-out and
// --elegia-dir (integrations/zaafelegia/schema). Additive changes keep the
// version; a renamed, removed or retyped field makes a new one.
const ElegiaSchema = "zaafvesper.elegia/1"

// SigmaOptions completes a record with what the event does not carry.
type SigmaOptions struct {
	// DefaultProduct is logsource.product for events without a platform.
	DefaultProduct string
	// Host is written as Computer (the Sysmon field name); empty: omitted.
	Host string
}

// SigmaRecord converts e into a flat record with Sigma field names
// (pkg/sigmamap.ExportFields of the event's category), plus logsource.product
// and logsource.category (nested), a Sysmon-compatible EventID, UtcTime and
// a small "zaafvesper" object (event name, sequence number, source). Strings
// and lists are capped; values are strings, integers (pids, ports) or
// string lists; booleans become "true"/"false" as in Sysmon.
func SigmaRecord(e *event.Event, o SigmaOptions) map[string]any {
	return sigmaRecord(e, o, firstCaps)
}

func sigmaRecord(e *event.Event, o SigmaOptions, c caps) map[string]any {
	rec := map[string]any{}
	product := e.Platform
	if product == "" {
		product = o.DefaultProduct
	}
	ls := map[string]any{}
	if product != "" {
		ls["product"] = product
	}
	fields := genericFields
	cat := sigmamap.ForEvent(e.Name)
	if cat != nil {
		ls["category"] = cat.Name
		fields = sigmamap.ExportFields(cat.Name)
	}
	for zv, sf := range fields {
		if v := resolve(e, zv); v != nil && !emptyValue(v) {
			rec[sf] = exportValue(v, c)
		}
	}
	if cat != nil {
		// Reverse value mappings, e.g. net.direction outbound -> Initiated "true".
		names := make([]string, 0, len(cat.Values))
		for sf := range cat.Values {
			names = append(names, sf)
		}
		sort.Strings(names)
		for _, sf := range names {
			vals := make([]string, 0, len(cat.Values[sf]))
			for sv := range cat.Values[sf] {
				vals = append(vals, sv)
			}
			sort.Strings(vals)
			for _, sv := range vals {
				m := cat.Values[sf][sv]
				if got := resolve(e, m.Field); got != nil && fmt.Sprint(got) == m.Value {
					rec[sf] = sv
				}
			}
		}
	}
	rec["logsource"] = ls
	if id := sigmamap.SysmonEventIDs[e.Name]; id != 0 {
		rec["EventID"] = id
	}
	if !e.Time.IsZero() {
		rec["UtcTime"] = e.Time.UTC().Format(SysmonTime)
	}
	if o.Host != "" {
		rec["Computer"] = c.s(o.Host)
	}
	zv := map[string]any{"schema": ElegiaSchema, "name": e.Name}
	if e.Seq != 0 {
		zv["seq"] = e.Seq
	}
	if e.Source != "" {
		zv["source"] = c.s(e.Source)
	}
	if e.Platform != "" {
		zv["platform"] = e.Platform
	}
	if e.Args["identity"] == "unverified" {
		zv["identity"] = "unverified"
	}
	if p := e.Proc; p != nil {
		zv["proc"] = procIdentity(p, c, true)
		if p.Parent != nil {
			zv["parent"] = procIdentity(p.Parent, c, false)
		}
	}
	rec["zaafvesper"] = zv
	return rec
}

// procIdentity is the signing and kernel identity of a process that Sigma's
// field names do not cover (schema zaafvesper.elegia/1, zaafvesper.proc and
// zaafvesper.parent). The kernel unique id is what the zaafvesper pipeline
// preset maps ProcessGuid to on macOS, so correlations can group by process.
func procIdentity(p *event.Proc, c caps, full bool) map[string]any {
	m := map[string]any{"is_platform": p.IsPlatform}
	if p.UniqueID != 0 {
		m["unique_id"] = p.UniqueID
	}
	if p.PID != 0 {
		m["pid"] = p.PID
	}
	if p.SigningID != "" {
		m["signing_id"] = c.s(p.SigningID)
	}
	if p.TeamID != "" {
		m["team_id"] = c.s(p.TeamID)
	}
	if !full {
		return m
	}
	m["is_signed"] = p.IsSigned
	if p.PIDVersion != 0 {
		m["pidversion"] = p.PIDVersion
	}
	if p.CSCategory != "" {
		m["cs_category"] = p.CSCategory
	}
	if p.Seeded {
		m["seeded"] = true
	}
	return m
}

// resolve reads a static field or an indexed one ("evt.arg[key]").
func resolve(e *event.Event, field string) event.Value {
	if i := strings.IndexByte(field, '['); i > 0 && strings.HasSuffix(field, "]") {
		return e.GetIndexed(field[:i], field[i+1:len(field)-1])
	}
	return e.Get(field)
}

// emptyValue: an empty string, a zero integer (pid, port) or an empty list
// is not reported, so it is left out rather than exported as "" or 0.
func emptyValue(v event.Value) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case int64:
		return x == 0
	case []string:
		return len(x) == 0
	}
	return false
}

func exportValue(v event.Value, c caps) any {
	switch x := v.(type) {
	case string:
		return c.s(x)
	case bool:
		return strconv.FormatBool(x)
	case []string:
		return c.strs(x)
	default:
		return x
	}
}

// EncodeSigma returns e as one sanitised NDJSON line (without the newline),
// at most max bytes unless even the tightly capped form is larger.
func EncodeSigma(e *event.Event, o SigmaOptions, max int) ([]byte, error) {
	if max <= 0 {
		max = DefaultMaxRecordBytes
	}
	c, cut := firstCaps.tracked()
	rec := sigmaRecord(e, o, c)
	if *cut {
		rec["truncated"] = true
	}
	b, err := encodeCapped(rec, max, func() any {
		r := sigmaRecord(e, o, caps{str: 256, list: 8})
		r["truncated"] = true
		return r
	})
	return b, err
}

// ---- OCSF Detection Finding (class 2004) ----

// OCSFVersion is the OCSF schema version of the findings (as ZAAFElegia).
const OCSFVersion = "1.5.0"

var ocsfSeverity = map[string]struct {
	id   int
	name string
}{"info": {1, "Informational"}, "low": {2, "Low"}, "medium": {3, "Medium"}, "high": {4, "High"}, "critical": {5, "Critical"}}

// OCSFFinding converts an alert into an OCSF Detection Finding shaped like
// ZAAFElegia's output: class 2004, finding_info with the rule as analytic and
// ATT&CK tags as types, metadata.product, one evidence per event (its
// Sigma-named record) and the ZAAFVesper rule details under
// unmapped.zaafvesper.
func OCSFFinding(a *rules.Alert, version string, o SigmaOptions, seq uint64) map[string]any {
	return ocsfFinding(a, version, o, seq, firstCaps, true)
}

func ocsfFinding(a *rules.Alert, version string, o SigmaOptions, seq uint64, c caps, withEvidence bool) map[string]any {
	sev, ok := ocsfSeverity[a.Severity]
	if !ok {
		sev = ocsfSeverity["info"]
	}
	var types []string
	for _, k := range []string{"tactic.id", "technique.id"} {
		if v := a.Labels[k]; v != "" {
			types = append(types, "attack."+strings.ToLower(c.s(v)))
		}
	}
	var evidences []any
	if withEvidence {
		for _, e := range a.Events {
			if e != nil {
				evidences = append(evidences, map[string]any{"data": sigmaRecord(e, o, c)})
			}
		}
	}
	zv := map[string]any{"rule_id": c.s(a.RuleID), "output": c.s(a.Output)}
	if len(a.Labels) > 0 {
		zv["labels"] = c.m(a.Labels)
	}
	if len(a.Actions) > 0 {
		zv["actions"] = c.strs(a.Actions)
	}
	if a.Aggregated {
		zv["aggregated"], zv["count"] = true, a.Count
	}
	if a.Truncated || !withEvidence {
		zv["truncated"] = true
	}
	f := map[string]any{
		"class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
		"activity_id": 1, "activity_name": "Create", "type_uid": 200401,
		"severity_id": sev.id, "severity": sev.name, "status_id": 1, "status": "New",
		"time":    a.Time.UnixMilli(),
		"message": c.s(a.RuleName),
		"finding_info": map[string]any{
			"uid":      c.s(a.RuleID) + ":" + strconv.FormatUint(seq, 10),
			"title":    c.s(a.RuleName),
			"desc":     c.s(a.Output),
			"types":    types,
			"analytic": map[string]any{"uid": c.s(a.RuleID), "name": c.s(a.RuleName), "type_id": 1, "type": "Rule"},
		},
		"metadata": map[string]any{"version": OCSFVersion,
			"product": map[string]any{"name": "ZAAFVesper", "vendor_name": "ZAAFVesper project", "version": version}},
		"unmapped": map[string]any{"source": "zaafvesper", "zaafvesper": zv},
	}
	if withEvidence {
		f["evidences"] = evidences
	}
	return f
}

// EncodeOCSF returns the alert as one sanitised OCSF line (without newline):
// first with the normal caps, then with tight caps, then without evidences.
func EncodeOCSF(a *rules.Alert, version string, o SigmaOptions, seq uint64, max int) ([]byte, error) {
	if max <= 0 {
		max = DefaultMaxRecordBytes
	}
	b, err := marshal(ocsfFinding(a, version, o, seq, firstCaps, true))
	if err != nil {
		return nil, err
	}
	if len(b) <= max {
		return sanitizeJSON(b), nil
	}
	return encodeCapped(ocsfFinding(a, version, o, seq, caps{str: 256, list: 16}, true), max, func() any {
		return ocsfFinding(a, version, o, seq, caps{str: 256, list: 16}, false)
	})
}

// ---- bounded asynchronous NDJSON writer ----

// LineWriter writes lines to w from its own goroutine through a bounded
// queue, so a slow reader (a pipe into zaaf, a full disk) never stalls the
// sensor: lines that do not fit in the queue are dropped and counted. With
// MaxBytes > 0 it stops at that many bytes (a file cap).
type LineWriter struct {
	name     string
	w        io.Writer
	ch       chan []byte
	done     chan struct{}
	max      int64
	onCapped func(detail string)
	onDrop   func(detail string)

	mu      sync.Mutex
	written int64
	stopped bool

	lines, dropped, capped, errs atomic.Uint64
	queued, maxQueued            int64 // bytes waiting (atomic) and their bound
	closeOnce                    sync.Once
	// sendMu guards ch against a send after Close.
	sendMu sync.RWMutex
	closed bool
}

// LineWriterConfig configures a LineWriter.
type LineWriterConfig struct {
	Name  string // for reports
	Queue int    // lines, default 8192
	// QueueBytes bounds the bytes waiting (default 32 MiB).
	QueueBytes int64
	MaxBytes   int64 // 0: no cap
	// Written is the size the file already has (an append after a
	// restart); it counts against MaxBytes.
	Written int64
	// OnCapped is called once when the cap is reached; OnDrop for drops
	// (both rate-limited by the pipeline).
	OnCapped, OnDrop func(detail string)
}

// NewLineWriter starts the writer.
func NewLineWriter(w io.Writer, cfg LineWriterConfig) *LineWriter {
	if cfg.Queue <= 0 {
		cfg.Queue = 8192
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = 32 << 20
	}
	lw := &LineWriter{name: cfg.Name, w: w, ch: make(chan []byte, cfg.Queue), done: make(chan struct{}),
		max: cfg.MaxBytes, onCapped: cfg.OnCapped, onDrop: cfg.OnDrop, maxQueued: cfg.QueueBytes, written: cfg.Written}
	go lw.loop()
	return lw
}

// WriteLine queues one line (a newline is appended). It never blocks.
func (lw *LineWriter) WriteLine(b []byte) {
	line := make([]byte, 0, len(b)+1)
	line = append(append(line, b...), '\n')
	lw.sendMu.RLock()
	defer lw.sendMu.RUnlock()
	if lw.closed {
		lw.capped.Add(1)
		return
	}
	if atomic.LoadInt64(&lw.queued)+int64(len(line)) <= lw.maxQueued {
		select {
		case lw.ch <- line:
			atomic.AddInt64(&lw.queued, int64(len(line)))
			return
		default:
		}
	}
	{
		n := lw.dropped.Add(1)
		if lw.onDrop != nil && (n == 1 || n%1000 == 0) {
			lw.onDrop(fmt.Sprintf("%s: the reader is too slow; %d lines dropped so far", lw.name, n))
		}
	}
}

// rotator is a destination that starts a new file between lines
// (Segments): Due says when, Rotate does it.
type rotator interface {
	Due() bool
	Rotate() error
}

// rotateCheck is how often an idle LineWriter asks its rotator.
const rotateCheck = time.Second

func (lw *LineWriter) loop() {
	defer close(lw.done)
	bw := bufio.NewWriterSize(lw.w, 64<<10)
	rot, _ := lw.w.(rotator)
	rotate := func() {
		if rot == nil || !rot.Due() {
			return
		}
		if err := bw.Flush(); err != nil {
			lw.errs.Add(1)
		}
		if err := rot.Rotate(); err != nil {
			lw.errs.Add(1)
		}
	}
	var tick <-chan time.Time
	if rot != nil {
		t := time.NewTicker(rotateCheck)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case line, ok := <-lw.ch:
			if !ok {
				_ = bw.Flush()
				return
			}
			atomic.AddInt64(&lw.queued, -int64(len(line)))
			lw.write(bw, line)
			if len(lw.ch) == 0 {
				if err := bw.Flush(); err != nil {
					lw.errs.Add(1)
				}
			}
			rotate()
		case <-tick:
			rotate() // an idle segment still closes at its age limit
		}
	}
}

func (lw *LineWriter) write(bw *bufio.Writer, line []byte) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.stopped {
		lw.capped.Add(1)
		return
	}
	if lw.max > 0 && lw.written+int64(len(line)) > lw.max {
		lw.stopped = true
		lw.capped.Add(1)
		if lw.onCapped != nil {
			lw.onCapped(fmt.Sprintf("%s reached its cap of %d bytes; further lines are not written", lw.name, lw.max))
		}
		return
	}
	n, err := bw.Write(line)
	lw.written += int64(n)
	if err != nil {
		lw.errs.Add(1)
		return
	}
	lw.lines.Add(1)
}

// Close drains the queue (within timeout), flushes and closes w when it is
// an io.Closer.
func (lw *LineWriter) Close(timeout time.Duration) error {
	var err error
	lw.closeOnce.Do(func() {
		lw.sendMu.Lock()
		lw.closed = true
		close(lw.ch)
		lw.sendMu.Unlock()
		select {
		case <-lw.done:
		case <-time.After(timeout):
			err = fmt.Errorf("%s: writer did not finish within %v", lw.name, timeout)
			return
		}
		if c, ok := lw.w.(io.Closer); ok {
			err = c.Close()
		}
	})
	return err
}

// Stats returns the writer's counters.
func (lw *LineWriter) Stats() map[string]uint64 {
	lw.mu.Lock()
	w := lw.written
	lw.mu.Unlock()
	return map[string]uint64{"lines": lw.lines.Load(), "bytes": uint64(w), "dropped_slow_reader": lw.dropped.Load(),
		"dropped_after_cap": lw.capped.Load(), "write_errors": lw.errs.Load()}
}

// ElegiaSink streams every event as a Sigma-named NDJSON line.
type ElegiaSink struct {
	W        *LineWriter
	Options  SigmaOptions
	MaxBytes int
	errs     atomic.Uint64
}

// Event writes one event.
func (s *ElegiaSink) Event(e *event.Event) {
	if e == nil {
		return
	}
	line, err := EncodeSigma(e, s.Options, s.MaxBytes)
	if err != nil {
		s.errs.Add(1)
		return
	}
	s.W.WriteLine(line)
}

// OCSFSink writes alerts as OCSF Detection Findings (alert.Sink).
type OCSFSink struct {
	W        *LineWriter
	Version  string
	Options  SigmaOptions
	MaxBytes int
	seq      atomic.Uint64
}

// Send writes one finding.
func (s *OCSFSink) Send(a *rules.Alert) error {
	line, err := EncodeOCSF(a, s.Version, s.Options, s.seq.Add(1), s.MaxBytes)
	if err != nil {
		return err
	}
	s.W.WriteLine(line)
	return nil
}
