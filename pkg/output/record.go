// Package output ships alerts (and, optionally, events) to SIEMs and to
// ZAAFElegia:
//
//   - syslog RFC 5424 over TCP with TLS (RFC 5425 octet-counted framing),
//     trusting only a pinned CA bundle;
//   - an HTTPS webhook (JSON batches, bearer token) and its Splunk HTTP
//     Event Collector mode;
//   - a root-owned, size-capped disk spool used while an endpoint is down;
//   - ZAAFElegia NDJSON events with Sigma field names, and OCSF Detection
//     Finding (class 2004) alerts.
//
// Every record passes the per-alert (per-event) size cap and alert.Sanitize
// before it leaves the process, environment values are redacted unless
// --keep-env, and no secret (token, key) is ever logged or written to the
// spool.
package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// Record kinds.
const (
	KindAlert = "alert"
	KindEvent = "event"
)

// DefaultMaxRecordBytes caps one encoded record (alert or event).
const DefaultMaxRecordBytes = alert.DefaultMaxAlertBytes

// Record is one alert or event ready to ship: Body is a JSON object that has
// been capped and sanitised. Records are also the spool's line format.
type Record struct {
	Kind     string          `json:"kind"`
	Time     time.Time       `json:"time"`
	Severity string          `json:"severity,omitempty"`
	RuleID   string          `json:"rule_id,omitempty"`
	RuleName string          `json:"rule_name,omitempty"`
	Body     json.RawMessage `json:"body"`
}

// Encoder turns alerts and events into Records.
type Encoder struct {
	// KeepEnv keeps environment values (default: names only, DYLD_* values).
	KeepEnv bool
	// MaxBytes caps one record's body (<= 0: DefaultMaxRecordBytes).
	MaxBytes int
}

func (en Encoder) max() int {
	if en.MaxBytes <= 0 {
		return DefaultMaxRecordBytes
	}
	return en.MaxBytes
}

// Alert encodes a through the JSONL sink's cap (alert.EncodeAlert) and the
// sanitiser.
func (en Encoder) Alert(a *rules.Alert) (Record, error) {
	if !en.KeepEnv {
		a = alert.RedactAlert(a)
	}
	line, _, err := alert.EncodeAlert(a, en.max())
	if err != nil {
		return Record{}, err
	}
	return Record{Kind: KindAlert, Time: a.Time.UTC(), Severity: a.Severity,
		RuleID: clean(a.RuleID, 128), RuleName: clean(a.RuleName, 512), Body: sanitizeJSON(line)}, nil
}

// Event encodes e with the same string and list caps as alerts; an event
// still over the cap is reduced to its identity.
func (en Encoder) Event(e *event.Event) (Record, error) {
	if !en.KeepEnv {
		e = alert.RedactEvent(e)
	}
	body, err := encodeCapped(capEvent(e, firstCaps), en.max(), func() any { return identityEvent(e) })
	if err != nil {
		return Record{}, err
	}
	return Record{Kind: KindEvent, Time: e.Time.UTC(), Severity: "info", Body: body}, nil
}

// encodeCapped marshals v; when the result is over max it marshals
// fallback() instead (with "truncated": true when it is an object).
func encodeCapped(v any, max int, fallback func() any) (json.RawMessage, error) {
	b, err := marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) <= max {
		return sanitizeJSON(b), nil
	}
	b, err = marshal(fallback())
	if err != nil {
		return nil, err
	}
	return sanitizeJSON(b), nil
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// sanitizeJSON applies alert.Sanitize to encoded JSON. encoding/json already
// escapes control characters and replaces invalid UTF-8, so what Sanitize
// still removes are bidirectional and C1 controls (raw in JSON strings);
// removing them keeps the JSON valid.
func sanitizeJSON(b []byte) json.RawMessage {
	b = bytes.TrimRight(b, "\n")
	return json.RawMessage(alert.Sanitize(string(b)))
}

// clean sanitises s and bounds it to n bytes on a rune boundary.
func clean(s string, n int) string {
	s = alert.Sanitize(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// caps bound attacker-sized strings and lists in an exported event.
type caps struct{ str, list int }

var firstCaps = caps{str: 2 << 10, list: 64}

func (c caps) s(v string) string {
	if len(v) <= c.str {
		return v
	}
	n := c.str
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n] + "...[truncated]"
}

func (c caps) strs(in []string) []string {
	if in == nil {
		return nil
	}
	if len(in) > c.list {
		in = in[:c.list]
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = c.s(v)
	}
	return out
}

func (c caps) m(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if len(out) >= c.list {
			break
		}
		out[c.s(k)] = c.s(v)
	}
	return out
}

func (c caps) proc(p *event.Proc, depth int) *event.Proc {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Exe, cp.Name, cp.Cmdline, cp.Cwd = c.s(p.Exe), c.s(p.Name), c.s(p.Cmdline), c.s(p.Cwd)
	cp.Username, cp.TTY, cp.SigningID, cp.TeamID = c.s(p.Username), c.s(p.TTY), c.s(p.SigningID), c.s(p.TeamID)
	cp.Args, cp.Ancestors, cp.Env = c.strs(p.Args), c.strs(p.Ancestors), c.m(p.Env)
	cp.Hashes, cp.Company, cp.Product, cp.Description, cp.OriginalName = c.s(p.Hashes), c.s(p.Company), c.s(p.Product), c.s(p.Description), c.s(p.OriginalName)
	if depth > 0 {
		cp.Parent = c.proc(p.Parent, depth-1)
	} else {
		cp.Parent = nil
	}
	return &cp
}

func capEvent(e *event.Event, c caps) *event.Event {
	cp := *e
	cp.Proc, cp.Target = c.proc(e.Proc, 1), c.proc(e.Target, 0)
	cp.Args = c.m(e.Args)
	if e.File != nil {
		f := *e.File
		f.Path, f.Dest = c.s(f.Path), c.s(f.Dest)
		cp.File = &f
	}
	if e.Yara != nil {
		y := *e.Yara
		y.Rule, y.Namespace, y.Target, y.Tags, y.Meta = c.s(y.Rule), c.s(y.Namespace), c.s(y.Target), c.strs(y.Tags), c.m(y.Meta)
		cp.Yara = &y
	}
	if e.Net != nil {
		n := *e.Net
		n.DstHost = c.s(n.DstHost)
		cp.Net = &n
	}
	if e.DNS != nil {
		d := *e.DNS
		d.Query, d.Type, d.Status, d.Answers = c.s(d.Query), c.s(d.Type), c.s(d.Status), c.strs(d.Answers)
		cp.DNS = &d
	}
	if e.Registry != nil {
		r := *e.Registry
		r.Key, r.Value, r.Data, r.NewKey = c.s(r.Key), c.s(r.Value), c.s(r.Data), c.s(r.NewKey)
		cp.Registry = &r
	}
	if e.Module != nil {
		m := *e.Module
		m.Path, m.Signature, m.SignatureStatus, m.Hashes = c.s(m.Path), c.s(m.Signature), c.s(m.SignatureStatus), c.s(m.Hashes)
		cp.Module = &m
	}
	return &cp
}

// identityEvent is the last resort for an event over the cap.
func identityEvent(e *event.Event) any {
	c := caps{str: 256, list: 8}
	stub := &event.Event{Seq: e.Seq, Time: e.Time, Name: e.Name, Source: e.Source, Platform: e.Platform, Net: e.Net}
	if e.Proc != nil {
		stub.Proc = &event.Proc{PID: e.Proc.PID, PPID: e.Proc.PPID, PIDVersion: e.Proc.PIDVersion, UniqueID: e.Proc.UniqueID,
			Exe: c.s(e.Proc.Exe), Name: c.s(e.Proc.Name), UID: e.Proc.UID, EUID: e.Proc.EUID,
			SigningID: c.s(e.Proc.SigningID), TeamID: c.s(e.Proc.TeamID), IsPlatform: e.Proc.IsPlatform, IsSigned: e.Proc.IsSigned}
	}
	if e.File != nil {
		stub.File = &event.File{Path: c.s(e.File.Path)}
	}
	if stub.Net != nil {
		n := *stub.Net
		n.DstHost = c.s(n.DstHost)
		stub.Net = &n
	}
	return struct {
		*event.Event
		Truncated bool `json:"truncated"`
	}{stub, true}
}

// Host returns a hostname safe for syslog's HOSTNAME field and JSON: printable
// ASCII without spaces, at most 255 bytes, "-" when empty.
func Host(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > 32 && r < 127 && b.Len() < 255 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
