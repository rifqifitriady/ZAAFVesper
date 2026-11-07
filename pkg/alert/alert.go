// Package alert delivers rule alerts to sinks (console, JSONL file) and owns
// Sanitize, which every terminal print of event- or rule-derived text passes
// through.
package alert

import (
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

// JSONL writes one JSON object per alert per line. JSON encoding escapes
// control characters, so no sanitizing is needed (or wanted: the file keeps
// the exact evidence). Environment values are redacted unless keepEnv.
type JSONL struct {
	mu      sync.Mutex
	w       io.Writer
	enc     *json.Encoder
	keepEnv bool
}

// NewJSONL returns a JSONL sink writing to w with environment values
// redacted (names kept, DYLD_* values kept). Close closes w if it is an
// io.Closer.
func NewJSONL(w io.Writer) *JSONL { return NewJSONLWith(w, false) }

// NewJSONLWith is NewJSONL with an explicit keepEnv choice (--keep-env).
func NewJSONLWith(w io.Writer, keepEnv bool) *JSONL {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONL{w: w, enc: enc, keepEnv: keepEnv}
}

// Send writes the alert as one line.
func (j *JSONL) Send(a *rules.Alert) error {
	if !j.keepEnv {
		a = RedactAlert(a)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(a)
}

// Close closes the underlying writer when it supports it.
func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if c, ok := j.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
