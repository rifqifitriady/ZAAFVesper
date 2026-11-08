package alert

import (
	"sort"
	"unicode/utf8"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// truncMarker is appended to every shortened string.
const truncMarker = "...[truncated]"

// maxSigningField caps signing_id and team_id: the only identity fields
// the signer (an attacker for self-signed code) chooses freely. Real Team
// IDs are 10 characters and signing IDs are bundle-id-like.
const maxSigningField = 256

// capLimits bound the attacker-sized parts of an alert: every free-text
// string and every list or map.
type capLimits struct {
	str  int // bytes per string
	list int // entries per list or map
}

var (
	// firstPass is applied to every alert before it is marshalled; an alert
	// within these limits is written unchanged.
	firstPass = capLimits{str: 2 << 10, list: 64}
	// secondPass is used only when the first result is still over the
	// per-alert cap (many events, each near the first-pass limits).
	secondPass = capLimits{str: 256, list: 16}
)

// EncodeAlert returns a as one JSON line (newline included), normally of at
// most max bytes, and whether anything was shortened ("truncated": true in
// the line). Work is bounded: a single copy-and-cap pass over the alert
// (strings to 2 KiB, argument, environment and other lists to 64 entries),
// one marshal, and at most two more (tighter caps, then an identity-only
// stub). Process identity is not cut: pid, ppid, pidversion, unique id,
// exe, name, cdhash, cs_category, start time and the parent's pid and exe
// stay exact; signing_id and team_id are capped at 256 bytes. Only a stub
// whose identity fields alone exceed max can produce a longer line.
func EncodeAlert(a *rules.Alert, max int) ([]byte, bool, error) {
	for _, lim := range []capLimits{firstPass, secondPass} {
		c := capper{lim: lim}
		ca := c.alert(a)
		line, err := marshalLine(ca)
		if err != nil {
			return nil, false, err
		}
		if len(line) <= max {
			return line, c.cut, nil
		}
	}
	line, err := marshalLine(identityAlert(a))
	return line, true, err
}

type capper struct {
	lim capLimits
	cut bool
}

func (c *capper) str(s string) string {
	if len(s) <= c.lim.str {
		return s
	}
	c.cut = true
	return cutString(s, c.lim.str)
}

func (c *capper) signing(s string) string {
	if len(s) <= maxSigningField {
		return s
	}
	c.cut = true
	return cutString(s, maxSigningField)
}

func (c *capper) strs(in []string) []string {
	if in == nil {
		return nil
	}
	n := len(in)
	if n > c.lim.list {
		n = c.lim.list
		c.cut = true
	}
	out := make([]string, n)
	for i := range out {
		out[i] = c.str(in[i])
	}
	return out
}

// strMap keeps the first lim.list keys in sorted order (DYLD_* and other
// evidence keys are not special-cased: the environment is already redacted
// or kept by policy before this point).
func (c *capper) strMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	if len(keys) > c.lim.list {
		sort.Strings(keys)
		keys = keys[:c.lim.list]
		c.cut = true
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[c.str(k)] = c.str(in[k])
	}
	return out
}

// proc copies p with its free-text fields capped; identity fields are kept.
func (c *capper) proc(p *event.Proc) *event.Proc {
	if p == nil {
		return nil
	}
	cp := *p
	cp.SigningID, cp.TeamID = c.signing(p.SigningID), c.signing(p.TeamID)
	cp.Cmdline = c.str(p.Cmdline)
	cp.Args = c.strs(p.Args)
	cp.Cwd = c.str(p.Cwd)
	cp.Username = c.str(p.Username)
	cp.TTY = c.str(p.TTY)
	cp.Env = c.strMap(p.Env)
	cp.Ancestors = c.strs(p.Ancestors)
	cp.Parent = c.proc(p.Parent)
	return &cp
}

func (c *capper) event(e *event.Event) *event.Event {
	if e == nil {
		return nil
	}
	cp := *e
	cp.Proc = c.proc(e.Proc)
	cp.Target = c.proc(e.Target)
	cp.Args = c.strMap(e.Args)
	if e.File != nil {
		f := *e.File
		f.Path, f.Dest = c.str(f.Path), c.str(f.Dest)
		cp.File = &f
	}
	if e.Yara != nil {
		y := *e.Yara
		y.Rule, y.Namespace, y.Target = c.str(y.Rule), c.str(y.Namespace), c.str(y.Target)
		y.Tags = c.strs(y.Tags)
		y.Meta = c.strMap(y.Meta)
		cp.Yara = &y
	}
	return &cp
}

// alert copies a with every event capped; Labels and Actions come from the
// root-owned rule and are kept.
func (c *capper) alert(a *rules.Alert) *rules.Alert {
	cp := *a
	cp.Output = c.str(a.Output)
	cp.Events = make([]*event.Event, len(a.Events))
	for i, e := range a.Events {
		cp.Events[i] = c.event(e)
	}
	cp.Truncated = a.Truncated || c.cut
	return &cp
}

// identityProc keeps only the identity of p (and its parent's pid and exe).
func identityProc(p *event.Proc) *event.Proc {
	if p == nil {
		return nil
	}
	out := &event.Proc{PID: p.PID, PPID: p.PPID, PIDVersion: p.PIDVersion, UUID: p.UUID, UniqueID: p.UniqueID, Exe: p.Exe, Name: p.Name,
		UID: p.UID, EUID: p.EUID, SigningID: cutString(p.SigningID, maxSigningField), TeamID: cutString(p.TeamID, maxSigningField),
		CDHash: p.CDHash, CSCategory: p.CSCategory,
		IsPlatform: p.IsPlatform, IsSigned: p.IsSigned, Seeded: p.Seeded, StartTime: p.StartTime,
		ExeDev: p.ExeDev, ExeIno: p.ExeIno, ExeCtimeNs: p.ExeCtimeNs}
	if p.Parent != nil {
		out.Parent = &event.Proc{PID: p.Parent.PID, PIDVersion: p.Parent.PIDVersion, UniqueID: p.Parent.UniqueID, Exe: p.Parent.Exe, Name: p.Parent.Name, StartTime: p.Parent.StartTime}
	}
	return out
}

// identityAlert is the last resort: rule identity, shortened output and the
// identity of every event's processes.
func identityAlert(a *rules.Alert) *rules.Alert {
	c := capper{lim: secondPass}
	stub := &rules.Alert{RuleID: a.RuleID, RuleName: a.RuleName, Severity: a.Severity, Time: a.Time,
		Output: c.str(a.Output), Labels: a.Labels, Actions: a.Actions, Truncated: true}
	for _, e := range a.Events {
		if e == nil {
			continue
		}
		stub.Events = append(stub.Events, &event.Event{Seq: e.Seq, Time: e.Time, Name: e.Name, Source: e.Source,
			Proc: identityProc(e.Proc), Target: identityProc(e.Target)})
	}
	return stub
}

// cutString shortens s to at most n bytes on a UTF-8 boundary and appends
// the truncation marker.
func cutString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 0 {
		n = 0
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + truncMarker
}
