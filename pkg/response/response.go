// Package response implements the response actions with guard rails: kill
// and suspend (signals, response.go and suspend.go), quarantine_file and
// requarantine (files, quarantine.go), remove_persistence (persistence.go)
// and isolate_process (isolate.go). Response is off unless the operator
// passes --enable-response (or --dry-run-response); see cmd/zaafvesper.
// replay never builds a Responder. Every action happens after the event that
// triggered it: none of them prevents anything (no Endpoint Security AUTH).
package response

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	// OutcomeSigningUnknown: the process has a Team ID but its signing
	// validation category was not reported, so it is alert-only.
	OutcomeSigningUnknown = "refused-signing-category-unknown"
	OutcomeError          = "error"
)

// Errors returned by Kill.
var (
	ErrProtected   = errors.New("response: process is protected")
	ErrRateLimited = errors.New("response: response rate limit reached")
	ErrUnknownProc = errors.New("response: process identity unknown or unverified")
	ErrMismatch    = errors.New("response: pid no longer belongs to the process that matched")
)

// ProtectedNames are process names that are never killed. Names are an extra
// layer only; the platform-binary flag at event time and the path prefixes are
// the main gate. A current image that is an Apple platform binary with one of
// these base names is refused too.
var ProtectedNames = []string{"kernel_task", "launchd", "WindowServer", "loginwindow", "eslogger"}

// ProtectedExePrefixes are executable path prefixes that are never killed.
var ProtectedExePrefixes = []string{"/System/", "/usr/libexec/", "/sbin/", "/usr/sbin/"}

// ProtectedExes are exact executable paths that are never killed.
var ProtectedExes = []string{"/usr/bin/eslogger"}

// Kill budgets: per rule, and a global safety cap over all rules.
const (
	DefaultMaxPerRulePerMinute = 10
	DefaultMaxPerMinute        = 30
)

// CondRateLimited is the SensorDegraded condition reported (through
// Config.OnDegraded) when a kill budget refuses a kill.
const CondRateLimited = "response_rate_limited"

// LogRepeatEvery is the minimum interval between two logged refusals with
// the same rule, target, pid and outcome; repeats inside it are counted only.
const LogRepeatEvery = time.Minute

const maxLogKeys = 4096

// StartTolerance is the allowed difference between the start time in the
// event and the start time the kernel reports for the pid now. pids are
// handed out sequentially, so a pid is not reused within a millisecond: the
// pid plus its start time to the millisecond binds one process incarnation.
const StartTolerance = time.Millisecond

// ESSource is event.Event.Source of events decoded from eslogger. Every
// es_process_t carries is_platform_binary, so for such an event (and for
// process-table entries learned from such events) Proc.IsPlatform == false
// is a positive statement, not a Go zero value. The eslogger decoder sets
// this value (TestESSourceMatchesDecoder).
const ESSource = "eslogger"

// csPlatformBinary is CS_PLATFORM_BINARY from <kern/cs_blobs.h>.
const csPlatformBinary = 0x04000000

// ErrExeUnlinked marks an Identity whose running image has no path any more
// (proc_pidpath ENOENT: the file was deleted after exec). SIP-protected
// system files cannot be unlinked, so such an image is not on a protected
// path; the code-signing status still decides whether it is a platform
// binary.
var ErrExeUnlinked = errors.New("executable file was unlinked after exec")

// Identity is what the kernel says about a pid right before the kill.
type Identity struct {
	StartTime time.Time
	// Exe is the kernel's path of the process's executable vnode
	// (proc_pidpath): absolute, symbolic links resolved, like the path
	// Endpoint Security reports. Empty when ExeErr is set.
	Exe    string
	ExeErr error
	// Dev and Ino identify the file found at Exe now (valid when HasFileID).
	Dev, Ino  uint64
	HasFileID bool
	// CSFlags are the code-signing status flags of the running image
	// (csops CS_OPS_STATUS), valid when CSKnown.
	CSFlags uint32
	CSKnown bool
	// UniqueID is the kernel's per-boot unique process id (p_uniqueid),
	// valid when UniqueKnown.
	UniqueID    uint64
	UniqueKnown bool
}

// Kill targets recorded in a Decision.
const (
	TargetProcess = "process"
	TargetParent  = "parent"
)

// Decision records one response decision.
type Decision struct {
	Time time.Time `json:"time"`
	// Action is the rule action (ActionSuspend, ActionQuarantineFile, ...);
	// empty for kill, whose log line format predates the other actions.
	Action  string `json:"action,omitempty"`
	PID     int32  `json:"pid"`
	Target  string `json:"target"` // TargetProcess, TargetParent or TargetFile
	Name    string `json:"name,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Path    string `json:"path,omitempty"` // file actions: the file acted on
	Reason  string `json:"reason"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// String renders the decision for a log line (sanitized).
func (d Decision) String() string {
	target := d.Target
	if target == "" {
		target = TargetProcess
	}
	s := d.Time.UTC().Format(time.RFC3339) + " response " + alert.Sanitize(d.Outcome)
	if d.Action != "" {
		s += " action=" + alert.Sanitize(d.Action)
	}
	s += fmt.Sprintf(" target=%s pid=%d name=%s exe=%s", alert.Sanitize(target), d.PID, alert.Sanitize(d.Name), alert.Sanitize(d.Exe))
	if d.Path != "" {
		s += fmt.Sprintf(" path=%q", alert.Sanitize(d.Path))
	}
	s += fmt.Sprintf(" reason=%q", alert.Sanitize(d.Reason))
	if d.Detail != "" {
		s += " detail=" + fmt.Sprintf("%q", alert.Sanitize(d.Detail))
	}
	return s
}

// Config configures a Responder.
type Config struct {
	DryRun              bool                                    // log what would be killed, kill nothing
	MaxPerRulePerMinute int                                     // kills per rule per minute, default 10
	MaxPerMinute        int                                     // kills over all rules per minute, default 30
	ProtectPIDs         []int32                                 // extra protected pids (own pid and ppid are always protected)
	DynamicPIDs         func() []int32                          // pids protected at decision time (e.g. the current eslogger child)
	Log                 func(Decision)                          // default: one line on stderr
	Now                 func() time.Time                        // default time.Now
	KillFunc            func(pid int, sig syscall.Signal) error // default defaultKill: syscall.Kill; Windows and Linux re-check the identity on the handle they kill (identify_windows.go, identify_linux.go)
	Identify            func(pid int32) (Identity, error)       // default: kernel lookup (sysctl, proc_pidpath, csops), see identify_darwin.go
	Lookup              func(pid int32) (*event.Proc, bool)     // process table, for Kill(pid); optional
	// OnDegraded is called, outside the responder's lock, when a response
	// budget refuses an action (condition CondRateLimited).
	OnDegraded func(condition, detail string)

	// Settings of the actions other than kill (zero values take the
	// defaults; see actions.go).

	// VaultDir is the quarantine vault (default DefaultVaultDir), StateDir
	// holds the isolation state (default DefaultStateDir). With
	// RequireRootOwned (production, as root) both must be owned by root and
	// closed to group and others.
	VaultDir, StateDir string
	RequireRootOwned   bool
	// MaxQuarantineBytes caps the size of a quarantined file
	// (default DefaultMaxQuarantineBytes).
	MaxQuarantineBytes int64
	// ProtectPaths are ZAAFVesper's own files and directories (binary,
	// configuration, rules, output, vault): never quarantined or changed.
	ProtectPaths []string
	// Runner runs pfctl, launchctl and codesign (default RunPinned).
	Runner Runner
	// AppleSigned reports whether a bundle directory carries Apple's own
	// signature (default: codesign -R "anchor apple" through Runner).
	AppleSigned func(bundle string) (bool, error)
	// ConsoleUID returns the uid of the console user (default: owner of
	// /dev/console), for the gui/<uid> domain of /Library/LaunchAgents.
	ConsoleUID func() (uint32, error)
	// IsolationTTL is how long an isolation lasts (default
	// DefaultIsolationTTL); IsolationAllow are networks never blocked (the
	// management allow-list); LocalAddrs returns this host's addresses
	// (default: the interface addresses), which are never blocked either.
	IsolationTTL   time.Duration
	IsolationAllow []netip.Prefix
	LocalAddrs     func() ([]netip.Addr, error)
	// Resolvers returns the DNS resolvers that are never blocked either
	// (default: the nameservers of /etc/resolv.conf); Gateways the default
	// gateways (default: /sbin/route -n get default, IPv4 and IPv6, through
	// Runner). A gateway lookup that fails refuses the isolation.
	Resolvers func() []netip.Addr
	Gateways  func() ([]netip.Addr, error)
	// SuspendFor is how long a suspended process stays stopped before it is
	// resumed unless killed (default DefaultSuspendFor, at most
	// MaxSuspendFor).
	SuspendFor time.Duration
}

// Responder applies response actions within the guard rails. Safe for
// concurrent use.
type Responder struct {
	mu        sync.Mutex
	cfg       Config
	protected map[int32]bool
	// budgets: [budgetSignal] for kill and suspend, [budgetAction] for the
	// file and network actions (owner decision 9 Nov 2026: decoy file
	// actions must not spend the kill budget). Each: Max* per rule and in
	// all per minute.
	budgets [2]*budget
	logged  map[string]time.Time // last logged refusal by rule|target|pid|outcome
	stats   map[string]uint64

	// actMu serialises the file and network actions and guards their state
	// (isolated, saved, fwToken, fwLoaded). It is held across their slow
	// steps (copies, pfctl, launchctl, codesign); mu is only taken inside it
	// for budgets, stats and logs, so kill and suspend never wait for them.
	// Lock order: actMu before mu.
	actMu sync.Mutex
	work  atomic.Pointer[worker] // background worker of the slow actions (worker.go), nil until StartWorker

	suspended map[int32]*suspension  // stopped processes waiting for their resume (suspend.go)
	retries   map[string]*retryEntry // slow actions refused by the budget, to try again (retry.go)
	isolated  map[string]*Isolation  // blocked peers by address (isolate.go)
	saved     map[string]bool        // addresses in the state file at the last save
	fwToken   string                 // macOS: pfctl -E reference token, released at Close
	fwLoaded  bool                   // the firewall objects (pf anchor, nftables table) are loaded
	// lastNeverCheck is when isolated addresses were last checked against
	// the never-block set (isolate.go recheckNeverBlock).
	lastNeverCheck time.Time

	// launchRoot, set only by tests, is a fake root for the persistence
	// directories of remove_persistence (launch items, systemd, cron, rc).
	launchRoot string

	netMu sync.Mutex
	peers map[string]*peerSet // remote peers seen per process (isolate.go)
}

// New returns a responder.
func New(cfg Config) *Responder {
	if cfg.MaxPerMinute <= 0 {
		cfg.MaxPerMinute = DefaultMaxPerMinute
	}
	if cfg.MaxPerRulePerMinute <= 0 {
		cfg.MaxPerRulePerMinute = DefaultMaxPerRulePerMinute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.KillFunc == nil {
		cfg.KillFunc = defaultKill
	}
	if cfg.Identify == nil {
		cfg.Identify = identify
	}
	if cfg.Log == nil {
		cfg.Log = func(d Decision) { _, _ = io.WriteString(os.Stderr, d.String()+"\n") }
	}
	if cfg.VaultDir == "" {
		cfg.VaultDir = DefaultVaultDir
	}
	if cfg.StateDir == "" {
		cfg.StateDir = DefaultStateDir
	}
	if cfg.MaxQuarantineBytes <= 0 {
		cfg.MaxQuarantineBytes = DefaultMaxQuarantineBytes
	}
	if cfg.Runner == nil {
		cfg.Runner = RunPinned
	}
	if cfg.AppleSigned == nil {
		cfg.AppleSigned = appleSignedByCodesign(cfg.Runner)
	}
	if cfg.ConsoleUID == nil {
		cfg.ConsoleUID = consoleUID
	}
	if cfg.IsolationTTL <= 0 {
		cfg.IsolationTTL = DefaultIsolationTTL
	}
	if cfg.LocalAddrs == nil {
		cfg.LocalAddrs = interfaceAddrs
	}
	if cfg.Resolvers == nil {
		cfg.Resolvers = defaultResolvers
	}
	if cfg.Gateways == nil {
		cfg.Gateways = defaultGateways(cfg.Runner)
	}
	if cfg.SuspendFor <= 0 {
		cfg.SuspendFor = DefaultSuspendFor
	}
	if cfg.SuspendFor > MaxSuspendFor {
		cfg.SuspendFor = MaxSuspendFor
	}
	// The vault and the state directory are ZAAFVesper's own files.
	cfg.ProtectPaths = append(append([]string(nil), cfg.ProtectPaths...), cfg.VaultDir, cfg.StateDir)
	r := &Responder{cfg: cfg, protected: map[int32]bool{},
		budgets: [2]*budget{{name: "kill/suspend", perRule: map[string][]time.Time{}}, {name: "file/network action", perRule: map[string][]time.Time{}}},
		logged:  map[string]time.Time{}, stats: map[string]uint64{},
		suspended: map[int32]*suspension{}, retries: map[string]*retryEntry{}, isolated: map[string]*Isolation{}, peers: map[string]*peerSet{}}
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
	return r.decide(&event.Proc{PID: pid}, TargetProcess, "", reason, "identity unknown", false, syscall.SIGKILL)
}

// KillEvent kills the process of e (normally the event that completed an
// alert). A process whose identity is unverified (seeded at start-up from
// kern.procargs2: Proc.Seeded or evt.arg[identity]=unverified) is never
// killed. rule (the rule id) selects the per-rule kill budget.
func (r *Responder) KillEvent(e *event.Event, rule, reason string) error {
	return r.signalEvent(e, rule, reason, syscall.SIGKILL)
}

func (r *Responder) signalEvent(e *event.Event, rule, reason string, sig syscall.Signal) error {
	if e == nil || e.Proc == nil {
		return r.decide(&event.Proc{}, TargetProcess, rule, reason, "event has no process", false, sig)
	}
	if e.Proc.Seeded || e.Args[ps.ArgIdentity] == ps.Unverified {
		return r.decide(e.Proc, TargetProcess, rule, reason, "process identity is unverified (seeded at start from kern.procargs2)", false, sig)
	}
	return r.decide(e.Proc, TargetProcess, rule, reason, "", e.Source == ESSource, sig)
}

// KillParent kills the parent of e's process (rules with action
// {name: kill, target: parent}). It refuses when the parent is unknown (not
// in the process table), was seeded at start-up, or is marked unverified
// (evt.arg[parent_identity]=unverified). Every other guard rail of KillProc
// applies to the parent. rule selects the per-rule kill budget.
func (r *Responder) KillParent(e *event.Event, rule, reason string) error {
	return r.signalParent(e, rule, reason, syscall.SIGKILL)
}

func (r *Responder) signalParent(e *event.Event, rule, reason string, sig syscall.Signal) error {
	if e == nil || e.Proc == nil {
		return r.decide(&event.Proc{}, TargetParent, rule, reason, "event has no process", false, sig)
	}
	par := e.Proc.Parent
	if par == nil {
		return r.decide(&event.Proc{PID: e.Proc.PPID}, TargetParent, rule, reason, "parent process is unknown (not in the process table)", false, sig)
	}
	cp := *par
	if cp.PID == 0 {
		cp.PID = e.Proc.PPID
	}
	if cp.PID != e.Proc.PPID {
		return r.decide(&cp, TargetParent, rule, reason, fmt.Sprintf("parent pid %d does not match ppid %d", cp.PID, e.Proc.PPID), false, sig)
	}
	if cp.Seeded || e.Args[ps.ArgParentIdentity] == ps.Unverified {
		return r.decide(&cp, TargetParent, rule, reason, "parent identity is unverified (seeded at start from kern.procargs2)", false, sig)
	}
	// The parent comes from the process table. With an eslogger event, the
	// table was built from eslogger events (exec, fork and every other event
	// carry is_platform_binary; fork and observe copy it with the image), and
	// seeded entries were refused above, so its IsPlatform is known.
	return r.decide(&cp, TargetParent, rule, reason, "", e.Source == ESSource, sig)
}

// KillProc kills the process described by p unless a guard rail refuses.
// It is not tied to a rule: only the global kill budget applies. p carries
// no event source, so whether it was a platform binary at detection is not
// known: a current platform image is refused (no exec-into-platform kill).
func (r *Responder) KillProc(p *event.Proc, reason string) error {
	if p == nil {
		return r.decide(&event.Proc{}, TargetProcess, "", reason, "no process", false, syscall.SIGKILL)
	}
	return r.decide(p, TargetProcess, "", reason, "", false, syscall.SIGKILL)
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

// verify reads the process from the kernel and decides whether pid still
// is the process of the event and whether its CURRENT image may be killed.
//
//   - Identity: the kernel unique id (p_uniqueid, never reused before a
//     reboot) must equal the one recorded when the process table learned
//     the process; no recorded id, or one that cannot be read now, refuses
//     the kill. The start time must also match within StartTolerance (1 ms).
//   - Protection of the current image: refused when proc_pidpath names a
//     protected path, when the current image's base name is a protected
//     name while it is an Apple platform binary, or when the code-signing
//     status or the path cannot be read (unknown protection: fail closed).
//     An unlinked image (proc_pidpath ENOENT) is not on a protected path.
//   - Exec into an Apple platform binary after detection (owner decision
//     8 Nov 2026, finding New-3): when csops says the current image is a
//     platform binary but the image at event time was not (p.IsPlatform is
//     false; a platform image at event time is refused earlier by
//     protectedReason), the kill is allowed, but only when platformKnown
//     says p.IsPlatform came from Endpoint Security (security note N1: a
//     false from the Go zero value proves nothing). The kernel unique id and the
//     start time above already proved it is the same process that matched,
//     so the malware is not saved by exec'ing into /bin/zsh or osascript.
//     The decision's detail records it. Protected paths and names of the
//     current image still refuse.
//   - A different path, a renamed, deleted or replaced file is NOT a
//     refusal (malware must not escape by renaming itself); it is returned
//     as a note for the decision's detail.
func (r *Responder) verify(p *event.Proc, platformKnown bool) (outcome, detail, note string, err error) {
	if p.UniqueID == 0 {
		return OutcomeUnknown, "kernel unique id not recorded for this process", "", ErrUnknownProc
	}
	if p.StartTime.IsZero() {
		return OutcomeUnknown, "event has no process start time", "", ErrUnknownProc
	}
	id, ierr := r.cfg.Identify(p.PID)
	if ierr != nil {
		return OutcomeUnknown, "cannot read the process from the kernel: " + ierr.Error(), "", ErrUnknownProc
	}
	if !id.UniqueKnown {
		return OutcomeUnknown, "cannot read the kernel unique id of the process", "", ErrUnknownProc
	}
	if id.UniqueID != p.UniqueID {
		return OutcomeMismatch, fmt.Sprintf("kernel unique id now %d, event %d (another process)", id.UniqueID, p.UniqueID), "", ErrMismatch
	}
	d := id.StartTime.Sub(p.StartTime)
	if d < 0 {
		d = -d
	}
	if id.StartTime.IsZero() || d > StartTolerance {
		return OutcomeMismatch, fmt.Sprintf("start time now %s, event %s (pid reused)",
			id.StartTime.UTC().Format(time.RFC3339Nano), p.StartTime.UTC().Format(time.RFC3339Nano)), "", ErrMismatch
	}
	if !id.CSKnown {
		return OutcomeUnknown, "cannot read the code-signing status of the current image (csops); protection unknown", "", ErrUnknownProc
	}
	platformNow := id.CSFlags&csPlatformBinary != 0
	if platformNow && p.IsPlatform {
		// Backup only: decide never gets here (protectedReason refuses a
		// platform image at event time first). Kept so verify alone never
		// allows it; TestVerifyPlatformAtEventBackup calls verify directly.
		return OutcomeProtected, "Apple platform binary (current image and at event time)", "", ErrProtected
	}
	if platformNow && !platformKnown {
		return OutcomeProtected, "Apple platform binary (current image); whether it was one at detection is not known from Endpoint Security", "", ErrProtected
	}
	var notes []string
	switch {
	case errors.Is(id.ExeErr, ErrExeUnlinked):
		notes = append(notes, "running image was unlinked after exec")
	case id.ExeErr != nil || id.Exe == "":
		return OutcomeUnknown, fmt.Sprintf("cannot read the executable path of the current image (%v); protection unknown", id.ExeErr), "", ErrUnknownProc
	default:
		if why := protectedExe(id.Exe); why != "" {
			return OutcomeProtected, why + " (current image)", "", ErrProtected
		}
		if platformNow {
			base := filepath.Base(id.Exe)
			for _, n := range ProtectedNames {
				if base == n {
					return OutcomeProtected, "protected name " + n + " (current image, Apple platform binary)", "", ErrProtected
				}
			}
		}
		if id.Exe != p.Exe {
			notes = append(notes, fmt.Sprintf("executable now %q, event %q", id.Exe, p.Exe))
		}
	}
	if platformNow {
		notes = append(notes, "process exec'd into an Apple platform binary after detection (not a platform binary at event time; kernel unique id and start time match the event)")
	}
	if (p.ExeDev != 0 || p.ExeIno != 0) && id.ExeErr == nil {
		// dev_t is 32 bits on macOS; compare the low 32 bits.
		if !id.HasFileID || uint32(id.Dev) != uint32(p.ExeDev) || id.Ino != p.ExeIno {
			notes = append(notes, fmt.Sprintf("file at the path now dev=%d ino=%d (readable=%v), event dev=%d ino=%d",
				uint32(id.Dev), id.Ino, id.HasFileID, uint32(p.ExeDev), p.ExeIno))
		}
	}
	return "", "", strings.Join(notes, "; "), nil
}

// pruneWindow drops times older than one minute before now.
func pruneWindow(ts []time.Time, now time.Time) []time.Time {
	cut := now.Add(-time.Minute)
	keep := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	return keep
}

// decide applies every guard rail in order and logs the decision. A
// non-empty unknown means the identity is already known to be unusable.
// platformKnown says p.IsPlatform comes from Endpoint Security (see
// ESSource); only then may a process that exec'd into a platform binary
// after detection be signalled. sig is SIGKILL (kill) or SIGSTOP (suspend):
// both go through exactly the same guard rails and the same budgets.
func (r *Responder) decide(p *event.Proc, target, rule, reason, unknown string, platformKnown bool, sig syscall.Signal) error {
	var notice string
	defer func() { // after the unlock below
		if notice != "" && r.cfg.OnDegraded != nil {
			r.cfg.OnDegraded(CondRateLimited, notice)
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	d := Decision{Time: now, PID: p.PID, Target: target, Name: p.Name, Exe: p.Exe, Reason: reason}
	statKey := ""
	if sig == sigStop {
		d.Action = ActionSuspend
		statKey = ActionSuspend + " "
	}
	finish := func(outcome, detail string, err error) error {
		d.Outcome, d.Detail = outcome, detail
		r.stats[statKey+outcome]++
		if target == TargetParent {
			r.stats[statKey+outcome+" (parent)"]++
		}
		if r.repeatRefusal(d.Action+"|"+rule, target, p.PID, outcome, now) {
			r.stats["log_suppressed"]++
			return err
		}
		r.cfg.Log(d)
		return err
	}
	if why := r.protectedReason(p); why != "" {
		return finish(OutcomeProtected, why, fmt.Errorf("%w: %s", ErrProtected, why))
	}
	if unknown != "" {
		return finish(OutcomeUnknown, unknown, ErrUnknownProc)
	}
	if p.Seeded {
		return finish(OutcomeUnknown, "process identity is unverified (seeded at start from kern.procargs2)", ErrUnknownProc)
	}
	if p.Exe == "" {
		return finish(OutcomeUnknown, "no executable path to check against the protected list", ErrUnknownProc)
	}
	if p.TeamID != "" && p.CSCategory == "" {
		return finish(OutcomeSigningUnknown, "signing category unreported; kill disabled (a Team ID without a validation category cannot be told from a forged one)", ErrUnknownProc)
	}
	outcome, detail, note, err := r.verify(p, platformKnown)
	if err != nil {
		return finish(outcome, detail, err)
	}
	// A kill that follows this responder's own suspend of the same process
	// (same kernel unique id) completes that response: it does not spend a
	// second unit of the budget.
	free := false
	if s, ok := r.suspended[p.PID]; ok && sig == syscall.SIGKILL && s.proc.UniqueID == p.UniqueID {
		free = true
	}
	if !free {
		if outcome, detail, err := r.spend(budgetSignal, rule, reason, now, &notice); err != nil {
			return finish(outcome, detail, err)
		}
	}
	if r.cfg.DryRun {
		return finish(OutcomeDryRun, note, nil)
	}
	if err := r.cfg.KillFunc(int(p.PID), sig); err != nil {
		return finish(OutcomeError, err.Error(), fmt.Errorf("response: signal %d to %d: %w", sig, p.PID, err))
	}
	if sig == sigStop {
		r.holdSuspended(p, rule, reason, now)
		return finish(OutcomeSuspended, note, nil)
	}
	r.forgetSuspended(p)
	return finish(OutcomeKilled, note, nil)
}

// Budgets (Responder.budgets).
const (
	budgetSignal = 0 // kill and suspend
	budgetAction = 1 // quarantine_file, requarantine, remove_persistence, isolate_process
)

// budget is one response budget: the actions (or dry-run actions) inside
// the last minute, in all and by rule.
type budget struct {
	name    string
	recent  []time.Time
	perRule map[string][]time.Time
}

// spend takes one unit of the per-rule and of the global budget kind at
// now, or refuses. kill and suspend share one budget; the file and network
// actions share the other, of the same size, so decoy file actions cannot
// spend the kill budget. On a refusal, *notice is set to the
// response_rate_limited detail, which names the budget; the caller raises it
// after unlocking. Caller holds mu.
func (r *Responder) spend(kind int, rule, reason string, now time.Time, notice *string) (string, string, error) {
	b := r.budgets[kind]
	b.recent = pruneWindow(b.recent, now)
	ruleTimes := pruneWindow(b.perRule[rule], now)
	if len(ruleTimes) == 0 {
		delete(b.perRule, rule)
	}
	if len(ruleTimes) >= r.cfg.MaxPerRulePerMinute {
		b.perRule[rule] = ruleTimes
		*notice = fmt.Sprintf("%s budget of %d per minute reached for %s", b.name, r.cfg.MaxPerRulePerMinute, reason)
		return OutcomeRateLimited, fmt.Sprintf("%d %s responses by this rule in the last minute", len(ruleTimes), b.name), ErrRateLimited
	}
	if len(b.recent) >= r.cfg.MaxPerMinute {
		b.perRule[rule] = ruleTimes
		*notice = fmt.Sprintf("global %s budget of %d per minute reached (last: %s)", b.name, r.cfg.MaxPerMinute, reason)
		return OutcomeRateLimited, fmt.Sprintf("%d %s responses in the last minute (all rules)", len(b.recent), b.name), ErrRateLimited
	}
	b.recent = append(b.recent, now)
	b.perRule[rule] = append(ruleTimes, now)
	return "", "", nil
}

// repeatRefusal reports whether a refusal with the same rule, target, pid
// and outcome was logged less than LogRepeatEvery ago (and records this
// one otherwise). Kills, dry-runs and errors are always logged. Caller
// holds mu.
func (r *Responder) repeatRefusal(rule, target string, pid int32, outcome string, now time.Time) bool {
	if !strings.HasPrefix(outcome, "refused-") {
		return false
	}
	key := rule + "|" + target + "|" + fmt.Sprint(pid) + "|" + outcome
	if t, ok := r.logged[key]; ok && now.Sub(t) < LogRepeatEvery && !now.Before(t) {
		return true
	}
	if len(r.logged) >= maxLogKeys {
		r.logged = map[string]time.Time{}
	}
	r.logged[key] = now
	return false
}
