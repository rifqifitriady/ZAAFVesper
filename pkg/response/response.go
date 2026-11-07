// Package response implements the kill action with guard rails. Response is
// off unless the operator passes --enable-response (or --dry-run-response);
// see cmd/zaafvesper. replay never builds a Responder.
package response

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
)

// Outcomes of a kill decision.
const (
	OutcomeKilled      = "killed"
	OutcomeDryRun      = "dry-run"
	OutcomeProtected   = "refused-protected"
	OutcomeRateLimited = "refused-rate-limit"
	OutcomeUnknown     = "refused-unknown-process"
	OutcomeMismatch    = "refused-identity-mismatch"
	OutcomeError       = "error"
)

// Errors returned by Kill.
var (
	ErrProtected   = errors.New("response: process is protected")
	ErrRateLimited = errors.New("response: kill rate limit reached")
	ErrUnknownProc = errors.New("response: process identity unknown or unverified")
	ErrMismatch    = errors.New("response: pid no longer belongs to the process that matched")
)

// ProtectedNames are process names that are never killed. Names are an extra
// layer only; the platform-binary flag and the path prefixes are the main gate.
var ProtectedNames = []string{"kernel_task", "launchd", "WindowServer", "loginwindow", "eslogger"}

// ProtectedExePrefixes are executable path prefixes that are never killed.
var ProtectedExePrefixes = []string{"/System/", "/usr/libexec/", "/sbin/", "/usr/sbin/"}

// ProtectedExes are exact executable paths that are never killed.
var ProtectedExes = []string{"/usr/bin/eslogger"}

// DefaultMaxPerMinute is the kill rate limit.
const DefaultMaxPerMinute = 10

// StartTolerance is the allowed difference between the start time in the
// event and the start time the kernel reports for the pid now.
const StartTolerance = time.Second

// Identity is what the kernel says about a pid right before the kill.
type Identity struct {
	StartTime time.Time
	Exe       string // as recorded by the kernel (kern.procargs2); may be relative
}

// Decision records one kill decision.
type Decision struct {
	Time    time.Time `json:"time"`
	PID     int32     `json:"pid"`
	Name    string    `json:"name,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	Reason  string    `json:"reason"`
	Outcome string    `json:"outcome"`
	Detail  string    `json:"detail,omitempty"`
}

// String renders the decision for a log line (sanitized).
func (d Decision) String() string {
	s := fmt.Sprintf("%s response %s pid=%d name=%s exe=%s reason=%q",
		d.Time.UTC().Format(time.RFC3339), d.Outcome, d.PID, alert.Sanitize(d.Name), alert.Sanitize(d.Exe), alert.Sanitize(d.Reason))
	if d.Detail != "" {
		s += " detail=" + fmt.Sprintf("%q", alert.Sanitize(d.Detail))
	}
	return s
}

// Config configures a Responder.
type Config struct {
	DryRun       bool                                    // log what would be killed, kill nothing
	MaxPerMinute int                                     // default 10
	ProtectPIDs  []int32                                 // extra protected pids (own pid and ppid are always protected)
	DynamicPIDs  func() []int32                          // pids protected at decision time (e.g. the current eslogger child)
	Log          func(Decision)                          // default: one line on stderr
	Now          func() time.Time                        // default time.Now
	KillFunc     func(pid int, sig syscall.Signal) error // default syscall.Kill
	Identify     func(pid int32) (Identity, error)       // default: kernel lookup (sysctl), see identify_darwin.go
	Lookup       func(pid int32) (*event.Proc, bool)     // process table, for Kill(pid); optional
}

// Responder kills processes within the guard rails. Safe for concurrent use.
type Responder struct {
	mu        sync.Mutex
	cfg       Config
	protected map[int32]bool
	recent    []time.Time // kills (or dry-run kills) inside the last minute
	stats     map[string]uint64
}

// New returns a responder.
func New(cfg Config) *Responder {
	if cfg.MaxPerMinute <= 0 {
		cfg.MaxPerMinute = DefaultMaxPerMinute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.KillFunc == nil {
		cfg.KillFunc = syscall.Kill
	}
	if cfg.Identify == nil {
		cfg.Identify = identify
	}
	if cfg.Log == nil {
		cfg.Log = func(d Decision) { _, _ = io.WriteString(os.Stderr, d.String()+"\n") }
	}
	r := &Responder{cfg: cfg, protected: map[int32]bool{}, stats: map[string]uint64{}}
	r.protected[int32(os.Getpid())] = true
	r.protected[int32(os.Getppid())] = true
	for _, p := range cfg.ProtectPIDs {
		r.protected[p] = true
	}
	return r
}

// Protect adds a pid to the protected set (e.g. an eslogger child).
func (r *Responder) Protect(pid int32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.protected[pid] = true
}

// Stats returns decision counters by outcome.
func (r *Responder) Stats() map[string]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]uint64, len(r.stats))
	for k, v := range r.stats {
		out[k] = v
	}
	return out
}

// Kill kills pid using the identity from Config.Lookup. Without a lookup the
// identity cannot be checked, so the kill is refused.
func (r *Responder) Kill(pid int32, reason string) error {
	if r.cfg.Lookup != nil {
		if p, ok := r.cfg.Lookup(pid); ok && p != nil {
			cp := *p
			cp.PID = pid
			return r.KillProc(&cp, reason)
		}
	}
	return r.decide(&event.Proc{PID: pid}, reason, "identity unknown")
}

// KillEvent kills the process of e (normally the event that completed an
// alert). A process whose identity the snapshotter marked unverified
// (evt.arg[identity]=unverified, seeded from kern.procargs2) is never killed.
func (r *Responder) KillEvent(e *event.Event, reason string) error {
	if e == nil || e.Proc == nil {
		return r.decide(&event.Proc{}, reason, "event has no process")
	}
	if e.Args[ps.ArgIdentity] == ps.Unverified {
		return r.decide(e.Proc, reason, "process identity is unverified (seeded at start from kern.procargs2)")
	}
	return r.KillProc(e.Proc, reason)
}

// KillProc kills the process described by p unless a guard rail refuses.
func (r *Responder) KillProc(p *event.Proc, reason string) error {
	if p == nil {
		return r.decide(&event.Proc{}, reason, "no process")
	}
	return r.decide(p, reason, "")
}

func nameOf(p *event.Proc) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Exe != "" {
		return filepath.Base(p.Exe)
	}
	return ""
}

func protectedExe(exe string) string {
	for _, x := range ProtectedExes {
		if exe == x {
			return "protected executable"
		}
	}
	for _, pre := range ProtectedExePrefixes {
		if strings.HasPrefix(exe, pre) {
			return "protected path " + pre
		}
	}
	return ""
}

// protectedReason returns why p must not be killed, or "". Caller holds mu.
func (r *Responder) protectedReason(p *event.Proc) string {
	if p.PID <= 1 {
		return "pid <= 1"
	}
	if r.protected[p.PID] {
		return "protected pid"
	}
	if r.cfg.DynamicPIDs != nil {
		for _, d := range r.cfg.DynamicPIDs() {
			if d == p.PID {
				return "protected pid (eslogger)"
			}
		}
	}
	if p.IsPlatform {
		return "Apple platform binary"
	}
	if why := protectedExe(p.Exe); why != "" {
		return why
	}
	name := nameOf(p)
	for _, n := range ProtectedNames {
		if name == n {
			return "protected name " + n
		}
	}
	return ""
}

// verify compares the event's process with what the kernel reports for the
// pid now: same start time (within StartTolerance) and same executable name.
// The start time catches pid reuse; the name catches an exec in between.
func (r *Responder) verify(p *event.Proc) (outcome, detail string, err error) {
	if p.StartTime.IsZero() {
		return OutcomeUnknown, "event has no process start time", ErrUnknownProc
	}
	id, ierr := r.cfg.Identify(p.PID)
	if ierr != nil {
		return OutcomeUnknown, "cannot read the process from the kernel: " + ierr.Error(), ErrUnknownProc
	}
	d := id.StartTime.Sub(p.StartTime)
	if d < 0 {
		d = -d
	}
	if id.StartTime.IsZero() || d > StartTolerance {
		return OutcomeMismatch, fmt.Sprintf("start time now %s, event %s (pid reused)",
			id.StartTime.UTC().Format(time.RFC3339Nano), p.StartTime.UTC().Format(time.RFC3339Nano)), ErrMismatch
	}
	if id.Exe == "" || filepath.Base(id.Exe) != filepath.Base(p.Exe) {
		return OutcomeMismatch, fmt.Sprintf("executable now %q, event %q", id.Exe, p.Exe), ErrMismatch
	}
	if why := protectedExe(id.Exe); why != "" {
		return OutcomeProtected, why + " (current image)", ErrProtected
	}
	return "", "", nil
}

// decide applies every guard rail in order and logs the decision. A
// non-empty unknown means the identity is already known to be unusable.
func (r *Responder) decide(p *event.Proc, reason, unknown string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	d := Decision{Time: now, PID: p.PID, Name: p.Name, Exe: p.Exe, Reason: reason}
	finish := func(outcome, detail string, err error) error {
		d.Outcome, d.Detail = outcome, detail
		r.stats[outcome]++
		r.cfg.Log(d)
		return err
	}
	if why := r.protectedReason(p); why != "" {
		return finish(OutcomeProtected, why, fmt.Errorf("%w: %s", ErrProtected, why))
	}
	if unknown != "" {
		return finish(OutcomeUnknown, unknown, ErrUnknownProc)
	}
	if p.Exe == "" {
		return finish(OutcomeUnknown, "no executable path to check against the protected list", ErrUnknownProc)
	}
	if outcome, detail, err := r.verify(p); err != nil {
		return finish(outcome, detail, err)
	}
	// Sliding one-minute window.
	cut := now.Add(-time.Minute)
	keep := r.recent[:0]
	for _, t := range r.recent {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	r.recent = keep
	if len(r.recent) >= r.cfg.MaxPerMinute {
		return finish(OutcomeRateLimited, fmt.Sprintf("%d kills in the last minute", len(r.recent)), ErrRateLimited)
	}
	r.recent = append(r.recent, now)
	if r.cfg.DryRun {
		return finish(OutcomeDryRun, "", nil)
	}
	if err := r.cfg.KillFunc(int(p.PID), syscall.SIGKILL); err != nil {
		return finish(OutcomeError, err.Error(), fmt.Errorf("response: kill %d: %w", p.PID, err))
	}
	return finish(OutcomeKilled, "", nil)
}
