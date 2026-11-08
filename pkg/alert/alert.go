// Package alert delivers rule alerts to sinks (console, JSONL file) and owns
// Sanitize, which every terminal print of event- or rule-derived text passes
// through.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// Sanitize makes s safe to print on a terminal: invalid UTF-8 becomes U+FFFD;
// tab, newline and carriage return become a space; every other C0 control,
// ESC, DEL, C1 control (U+0080–U+009F) and bidirectional control (U+200E,
// U+200F, U+061C, U+202A–U+202E, U+2066–U+2069) is removed.
func Sanitize(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		i += w
		switch {
		case r == utf8.RuneError && w == 1:
			b.WriteRune(utf8.RuneError)
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		case r == 0x200e, r == 0x200f, r == 0x061c:
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Sink receives alerts.
type Sink interface {
	Send(a *rules.Alert) error
}

// ---- console ----

// Console writes one line per alert plus indented detail lines.
type Console struct {
	mu    sync.Mutex
	w     io.Writer
	color bool
}

// NewConsole returns a console sink. color enables ANSI severity colours
// (the only escape sequences ZAAFVesper itself emits).
func NewConsole(w io.Writer, color bool) *Console { return &Console{w: w, color: color} }

var sevColor = map[string]string{
	"critical": "\x1b[1;35m",
	"high":     "\x1b[1;31m",
	"medium":   "\x1b[33m",
	"low":      "\x1b[36m",
	"info":     "\x1b[90m",
}

// Format renders an alert as console text (without colour). Every piece of
// event- or rule-derived text is sanitized.
func Format(a *rules.Alert) string { return format(a, false) }

func format(a *rules.Alert, color bool) string {
	var b strings.Builder
	sev := strings.ToUpper(Sanitize(a.Severity))
	if color {
		if c, ok := sevColor[a.Severity]; ok {
			sev = c + fmt.Sprintf("%-8s", sev) + "\x1b[0m"
		}
	} else {
		sev = fmt.Sprintf("%-8s", sev)
	}
	fmt.Fprintf(&b, "%s %s %s: %s\n", a.Time.UTC().Format(time.RFC3339), sev, Sanitize(a.RuleName), Sanitize(a.Output))
	var meta []string
	meta = append(meta, "rule="+Sanitize(a.RuleID))
	keys := make([]string, 0, len(a.Labels))
	for k := range a.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		meta = append(meta, Sanitize(k)+"="+quoteIfSpace(Sanitize(a.Labels[k])))
	}
	if len(a.Actions) > 0 {
		meta = append(meta, "actions="+Sanitize(strings.Join(a.Actions, ",")))
	}
	if a.Aggregated {
		meta = append(meta, fmt.Sprintf("aggregated=%d", a.Count))
	}
	fmt.Fprintf(&b, "    %s\n", strings.Join(meta, " "))
	for i, e := range a.Events {
		prefix := "    "
		if len(a.Events) > 1 {
			prefix = fmt.Sprintf("    [%d] ", i+1)
		}
		fmt.Fprintf(&b, "%s%s\n", prefix, describeEvent(e))
	}
	return b.String()
}

func quoteIfSpace(s string) string {
	if strings.ContainsRune(s, ' ') {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func describeEvent(e *event.Event) string {
	if e == nil {
		return "<nil event>"
	}
	parts := []string{Sanitize(e.Name), "seq=" + fmt.Sprint(e.Seq)}
	if p := e.Proc; p != nil {
		parts = append(parts, fmt.Sprintf("pid=%d ppid=%d exe=%s", p.PID, p.PPID, quoteIfSpace(Sanitize(p.Exe))))
		if p.Cmdline != "" {
			parts = append(parts, "cmdline="+fmt.Sprintf("%q", Sanitize(p.Cmdline)))
		}
		if p.SigningID != "" {
			parts = append(parts, "signing_id="+Sanitize(p.SigningID))
		}
		if p.Parent != nil && p.Parent.Exe != "" {
			parts = append(parts, "parent="+quoteIfSpace(Sanitize(p.Parent.Exe)))
		}
	}
	if t := e.Target; t != nil {
		parts = append(parts, fmt.Sprintf("target.pid=%d target.exe=%s", t.PID, quoteIfSpace(Sanitize(t.Exe))))
	}
	if f := e.File; f != nil {
		parts = append(parts, "file="+quoteIfSpace(Sanitize(f.Path)))
		if f.Dest != "" {
			parts = append(parts, "dest="+quoteIfSpace(Sanitize(f.Dest)))
		}
	}
	if y := e.Yara; y != nil {
		parts = append(parts, "yara="+Sanitize(y.Rule), "target="+quoteIfSpace(Sanitize(y.Target)))
	}
	return strings.Join(parts, " ")
}

// Send writes the alert.
func (c *Console) Send(a *rules.Alert) error {
	s := format(a, c.color)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := io.WriteString(c.w, s)
	return err
}

// ---- JSONL ----

// DefaultMaxAlertBytes caps one serialized alert (one JSONL line). Larger
// alerts have their longest string fields shortened and carry
// "truncated": true.
const DefaultMaxAlertBytes = 64 << 10

// DefaultMaxFileBytes is the default size cap of one JSONL alert file.
const DefaultMaxFileBytes = 256 << 20

// JSONLOptions configures a JSONL sink.
type JSONLOptions struct {
	// KeepEnv stores full environment values (default: names only, plus
	// DYLD_* values).
	KeepEnv bool
	// MaxBytes caps the bytes written to one file (<= 0: no cap). An alert
	// that would cross the cap is not written to the current file: the sink
	// rotates (Rotate set) or stops writing (Rotate nil).
	MaxBytes int64
	// MaxAlertBytes caps one line (<= 0: DefaultMaxAlertBytes).
	MaxAlertBytes int
	// Rotate returns the next file when MaxBytes is reached; the sink closes
	// the previous one (if it is an io.Closer). nil: stop at the cap.
	Rotate func() (io.Writer, error)
	// OnCapped is called, outside the sink's lock, each time the file cap
	// is reached (rotation or stop) and for every alert dropped while
	// stopped, with a short description.
	OnCapped func(detail string)
	// StartStopped starts the sink without a file (w may be nil): every
	// alert is dropped until Rotate succeeds (tried every RotateRetryEvery).
	StartStopped bool
	// StopReason describes why the sink starts stopped.
	StopReason string
	// Now is the clock for retries (default time.Now).
	Now func() time.Time
}

// JSONL writes one JSON object per alert per line. JSON encoding escapes
// control characters, so no sanitizing is needed (or wanted: the file keeps
// the exact evidence). Environment values are redacted unless keepEnv.
type JSONL struct {
	mu         sync.Mutex
	w          io.Writer
	opts       JSONLOptions
	written    int64
	stopped    bool
	stopReason string
	lastTry    time.Time
	dropped    uint64
	rotations  uint64
	truncated  uint64
}

// NewJSONL returns a JSONL sink writing to w with environment values
// redacted (names kept, DYLD_* values kept). Close closes w if it is an
// io.Closer.
func NewJSONL(w io.Writer) *JSONL { return NewJSONLWith(w, false) }

// NewJSONLWith is NewJSONL with an explicit keepEnv choice (--keep-env).
func NewJSONLWith(w io.Writer, keepEnv bool) *JSONL {
	return NewJSONLOptions(w, JSONLOptions{KeepEnv: keepEnv})
}

// NewJSONLOptions returns a JSONL sink with size caps (and rotation).
func NewJSONLOptions(w io.Writer, o JSONLOptions) *JSONL {
	if o.MaxAlertBytes <= 0 {
		o.MaxAlertBytes = DefaultMaxAlertBytes
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	j := &JSONL{w: w, opts: o}
	if o.StartStopped {
		j.stopped, j.stopReason, j.lastTry = true, o.StopReason, o.Now()
	}
	return j
}

// RotateRetryEvery is how often a stopped sink with a Rotate function tries
// to open a new file again (for example once old files have aged enough to
// be pruned).
const RotateRetryEvery = time.Minute

// Send writes the alert as one line. When the file cap is reached and no
// new file can be opened (no Rotate, or Rotate fails), the sink stops:
// alerts are dropped and counted, every drop is reported through OnCapped
// (the pipeline rate-limits the resulting SensorDegraded), Send returns nil,
// and with Rotate set a new file is tried again every RotateRetryEvery.
func (j *JSONL) Send(a *rules.Alert) error {
	if !j.opts.KeepEnv {
		a = RedactAlert(a)
	}
	line, cut, err := EncodeAlert(a, j.opts.MaxAlertBytes)
	if err != nil {
		return err
	}
	var notice string
	defer func() {
		if notice != "" && j.opts.OnCapped != nil {
			j.opts.OnCapped(notice)
		}
	}()
	j.mu.Lock()
	defer j.mu.Unlock()
	if cut {
		j.truncated++
	}
	now := j.opts.Now()
	if j.stopped && j.opts.Rotate != nil && !now.Before(j.lastTry.Add(RotateRetryEvery)) {
		j.lastTry = now
		if nw, err := j.opts.Rotate(); err == nil {
			j.closeCurrent()
			j.w, j.written, j.stopped = nw, 0, false
			j.rotations++
		} else {
			j.stopReason = err.Error()
		}
	}
	if j.stopped {
		j.dropped++
		notice = fmt.Sprintf("alert file not writable (%s); alert dropped, %d dropped so far", j.stopReason, j.dropped)
		return nil
	}
	if max := j.opts.MaxBytes; max > 0 && j.written > 0 && j.written+int64(len(line)) > max {
		if j.opts.Rotate == nil {
			j.stop(now, fmt.Sprintf("the file reached its cap of %d bytes", max))
			notice = fmt.Sprintf("alert file reached its cap of %d bytes; further alerts are not written to it", max)
			return nil
		}
		nw, err := j.opts.Rotate()
		if err != nil {
			j.stop(now, fmt.Sprintf("the file reached its cap of %d bytes and no new file can be opened: %v", max, err))
			notice = fmt.Sprintf("alert file reached its cap of %d bytes and no new file can be opened (%v); alerts are not written until one can", max, err)
			return nil
		}
		cerr := j.closeCurrent()
		j.w, j.written = nw, 0
		j.rotations++
		notice = fmt.Sprintf("alert file reached its cap of %d bytes; rotated to a new file", max)
		if cerr != nil {
			notice += fmt.Sprintf(" (closing the previous file failed: %v)", cerr)
		}
	}
	n, err := j.w.Write(line)
	j.written += int64(n)
	return err
}

// stop marks the sink stopped (one drop counted). Caller holds mu.
func (j *JSONL) stop(now time.Time, why string) {
	j.stopped, j.stopReason, j.lastTry = true, why, now
	j.dropped++
}

// closeCurrent closes the current writer when it is an io.Closer (once).
// Caller holds mu.
func (j *JSONL) closeCurrent() error {
	c, ok := j.w.(io.Closer)
	j.w = nil
	if !ok {
		return nil
	}
	return c.Close()
}

// Stopped reports whether the sink is currently not writing alerts (file
// cap reached without a new file, or started without one).
func (j *JSONL) Stopped() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stopped
}

// Filtered passes to Sink only the alerts Allow accepts.
type Filtered struct {
	Sink  Sink
	Allow func(*rules.Alert) bool
}

// Send forwards a when Allow accepts it.
func (f *Filtered) Send(a *rules.Alert) error {
	if f.Allow(a) {
		return f.Sink.Send(a)
	}
	return nil
}

// HighOrCritical accepts alerts of severity high or critical.
func HighOrCritical(a *rules.Alert) bool { return a.Severity == "high" || a.Severity == "critical" }

// Stats returns the sink's counters.
func (j *JSONL) Stats() map[string]uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return map[string]uint64{"bytes_current_file": uint64(j.written), "dropped_after_cap": j.dropped,
		"rotations": j.rotations, "truncated_alerts": j.truncated}
}

// Close closes the underlying writer when it supports it.
func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.closeCurrent()
}

func marshalLine(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil // Encode appends the newline
}
