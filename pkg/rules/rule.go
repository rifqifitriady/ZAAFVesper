// Package rules loads detection rules (YAML), compiles their conditions with
// pkg/filter/ql, and evaluates them over events, including sequence rules.
package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

// EngineVersion is compared with each rule's min-engine-version.
const EngineVersion = "0.1.0"

// Severities in ascending order.
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Response action names (v0.2 contract: reserved names; validation and
// behaviour belong to workstream W1, see pkg/response). Every action is off
// unless the sensor runs with --enable-response or --dry-run-response.
const (
	ActionKill              = "kill"               // SIGKILL the process
	ActionSuspend           = "suspend"            // SIGSTOP the process, resumed after a bounded time unless killed
	ActionQuarantineFile    = "quarantine_file"    // move the file into the root-only vault
	ActionRequarantine      = "requarantine"       // re-add com.apple.quarantine to the file
	ActionRemovePersistence = "remove_persistence" // launchctl bootout of a launch item's label, then quarantine its plist
	ActionIsolateProcess    = "isolate_process"    // block the process's remote peers in a pf anchor
)

// Action targets. TargetProcess (or an empty target) acts on the process of
// the event that completed the match; TargetParent on that process's parent;
// TargetFile on the event's file. For quarantine_file, TargetProcess means
// the executable file of the event's process.
const (
	TargetProcess = "process"
	TargetParent  = "parent"
	TargetFile    = "file"
)

// actionTargets lists, per action, the accepted targets; the first is the
// default used when the rule gives none.
var actionTargets = map[string][]string{
	ActionKill:              {TargetProcess, TargetParent},
	ActionSuspend:           {TargetProcess, TargetParent},
	ActionIsolateProcess:    {TargetProcess, TargetParent},
	ActionQuarantineFile:    {TargetFile, TargetProcess},
	ActionRequarantine:      {TargetFile},
	ActionRemovePersistence: {TargetFile},
}

// ActionNames returns every supported action name, sorted.
func ActionNames() []string {
	return []string{ActionIsolateProcess, ActionKill, ActionQuarantineFile, ActionRemovePersistence, ActionRequarantine, ActionSuspend}
}

// Action is a response requested by a rule.
type Action struct {
	Name   string `yaml:"name" json:"name"`
	Target string `yaml:"target" json:"target,omitempty"`
}

// KillTarget returns TargetProcess or TargetParent ("" means process). It
// is meaningful for the process actions (kill, suspend, isolate_process).
func (a Action) KillTarget() string {
	if a.Target == TargetParent {
		return TargetParent
	}
	return TargetProcess
}

// EffectiveTarget returns the action's target, or its default when the rule
// gives none ("" for an unknown action).
func (a Action) EffectiveTarget() string {
	if a.Target != "" {
		return a.Target
	}
	if ts := actionTargets[a.Name]; len(ts) > 0 {
		return ts[0]
	}
	return ""
}

// String renders the action for display: the name, plus ":target" when the
// target is not the action's default ("kill", "kill:parent",
// "quarantine_file:process").
func (a Action) String() string {
	if ts := actionTargets[a.Name]; len(ts) > 0 && a.Target != "" && a.Target != ts[0] {
		return a.Name + ":" + a.Target
	}
	return a.Name
}

// Tests links a rule to the atomic tests that prove it.
type Tests struct {
	Atomic []string `yaml:"atomic" json:"atomic,omitempty"`
}

// Rule is one detection rule as written in rules/<file>.yml plus its
// compiled form.
type Rule struct {
	Name             string            `yaml:"name"`
	ID               string            `yaml:"id"`
	Version          string            `yaml:"version"`
	Description      string            `yaml:"description"`
	Labels           map[string]string `yaml:"labels"`
	References       []string          `yaml:"references"`
	Condition        string            `yaml:"condition"`
	Output           string            `yaml:"output"`
	Severity         string            `yaml:"severity"`
	Action           []Action          `yaml:"action"`
	Tests            Tests             `yaml:"tests"`
	MinEngineVersion string            `yaml:"min-engine-version"`
	Enabled          *bool             `yaml:"enabled"`
	// Platforms limits the rule to these platforms (macos, windows, linux);
	// empty means every platform.
	Platforms []string `yaml:"platforms"`
	Notes     string   `yaml:"notes"`

	// File is the path the rule was loaded from.
	File string `yaml:"-"`

	filter *ql.Filter // single-event rule
	seq    *Sequence  // sequence rule
	output *template
}

// IsEnabled reports whether the rule is active (default true).
func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// AppliesTo reports whether the rule runs on platform (event.Platform*).
func (r *Rule) AppliesTo(platform string) bool {
	if len(r.Platforms) == 0 {
		return true
	}
	for _, p := range r.Platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// IsSequence reports whether the rule is a sequence rule.
func (r *Rule) IsSequence() bool { return r.seq != nil }

// Sequence returns the compiled sequence (nil for single-event rules).
func (r *Rule) Sequence() *Sequence { return r.seq }

// EventNames returns the event names the rule can fire on (nil = any).
func (r *Rule) EventNames() []string {
	if r.seq != nil {
		return r.seq.EventNames()
	}
	if r.filter == nil {
		return nil
	}
	return r.filter.EventNames()
}

// Actions returns the actions for display ("kill", "kill:parent").
func (r *Rule) Actions() []string {
	out := make([]string, 0, len(r.Action))
	for _, a := range r.Action {
		out = append(out, a.String())
	}
	return out
}

// TechniqueIDs returns the ATT&CK technique ids in labels (technique.id,
// which may hold several comma-separated ids).
func (r *Rule) TechniqueIDs() []string {
	v := strings.TrimSpace(r.Labels["technique.id"])
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var (
	uuidV4Re    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	uuidAnyRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	techniqueRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	tacticRe    = regexp.MustCompile(`^TA\d{4}$`)
	semverRe    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
)

// parseSemver returns the three components of a MAJOR.MINOR.PATCH version.
func parseSemver(v string) ([3]int, bool) {
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func semverLess(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// quoteOr renders ["a","b"] as `"a" or "b"` and ["a"] as `"a"`.
func quoteOr(ts []string) string {
	q := make([]string, len(ts))
	for i, t := range ts {
		q[i] = strconv.Quote(t)
	}
	if len(q) == 1 {
		return q[0]
	}
	return strings.Join(q[:len(q)-1], ", ") + " or " + q[len(q)-1]
}

// validate checks the static schema (everything except the condition).
func (r *Rule) validate() []error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if strings.TrimSpace(r.Name) == "" {
		bad("name is required")
	}
	if !uuidV4Re.MatchString(r.ID) {
		bad("id %q is not a UUID v4", r.ID)
	}
	if _, ok := parseSemver(r.Version); !ok {
		bad("version %q is not MAJOR.MINOR.PATCH", r.Version)
	}
	if strings.TrimSpace(r.Condition) == "" {
		bad("condition is required")
	}
	sevOK := false
	for _, s := range Severities {
		if r.Severity == s {
			sevOK = true
		}
	}
	if !sevOK {
		bad("severity %q must be one of %s", r.Severity, strings.Join(Severities, ", "))
	}
	for k, v := range r.Labels {
		switch k {
		case "technique.id":
			ids := r.TechniqueIDs()
			if len(ids) == 0 {
				bad("labels.technique.id is empty")
			}
			for _, id := range ids {
				if !techniqueRe.MatchString(id) {
					bad("labels.technique.id %q does not match T1234 or T1234.567", id)
				}
			}
		case "tactic.id":
			for _, id := range strings.Split(v, ",") {
				if id = strings.TrimSpace(id); !tacticRe.MatchString(id) {
					bad("labels.tactic.id %q does not match TA1234", id)
				}
			}
		}
	}
	for _, p := range r.Platforms {
		if p != event.PlatformMacOS && p != event.PlatformWindows && p != event.PlatformLinux {
			bad("platforms: %q is not macos, windows or linux", p)
		}
	}
	seen := map[string]bool{}
	for _, a := range r.Action {
		ts, ok := actionTargets[a.Name]
		if !ok {
			bad("action %q is not supported (one of %s)", a.Name, strings.Join(ActionNames(), ", "))
			continue
		}
		if a.Target != "" {
			okT := false
			for _, t := range ts {
				okT = okT || a.Target == t
			}
			if !okT {
				bad("action %q target %q must be %s", a.Name, a.Target, quoteOr(ts))
				continue
			}
		}
		key := a.Name + ":" + a.EffectiveTarget()
		if seen[key] {
			bad("action %q with target %q is listed twice", a.Name, a.EffectiveTarget())
		}
		seen[key] = true
	}
	for _, g := range r.Tests.Atomic {
		if !uuidAnyRe.MatchString(g) {
			bad("tests.atomic %q is not a GUID", g)
		}
	}
	if r.MinEngineVersion == "" {
		bad("min-engine-version is required")
	} else if mv, ok := parseSemver(r.MinEngineVersion); !ok {
		bad("min-engine-version %q is not MAJOR.MINOR.PATCH", r.MinEngineVersion)
	} else if ev, _ := parseSemver(EngineVersion); semverLess(ev, mv) {
		bad("rule needs engine %s, this engine is %s", r.MinEngineVersion, EngineVersion)
	}
	return errs
}
