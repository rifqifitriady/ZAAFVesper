package response

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
)

// Action names, the same strings as pkg/rules (TestActionNamesMatchRules).
const (
	ActionKill              = "kill"
	ActionSuspend           = "suspend"
	ActionQuarantineFile    = "quarantine_file"
	ActionRequarantine      = "requarantine"
	ActionRemovePersistence = "remove_persistence"
	ActionIsolateProcess    = "isolate_process"
)

// TargetFile is the target of the file actions.
const TargetFile = "file"

// Outcomes of the actions other than kill. Every refusal starts with
// "refused-" (repeats are then logged once a minute).
const (
	OutcomeSuspended          = "suspended"
	OutcomeResumed            = "resumed"
	OutcomeResumeSkipped      = "resume-skipped"
	OutcomeQuarantined        = "quarantined"
	OutcomeRequarantined      = "requarantined"
	OutcomeAlreadyQuarantined = "already-quarantined"
	OutcomePersistenceRemoved = "persistence-removed"
	OutcomePartial            = "partial" // some steps done, one failed: see detail
	OutcomeIsolated           = "isolated"
	OutcomeReleased           = "released"
	OutcomeProtectedPath      = "refused-protected-path"
	OutcomeFileCheck          = "refused-file-check"
	OutcomeNoPeers            = "refused-no-peers"
	OutcomeLabel              = "refused-label"
	OutcomeIsolationFull      = "refused-isolation-full"
	OutcomeUnsupported        = "refused-unsupported"
	OutcomeWriterNotUntrusted = "refused-writer-not-untrusted"
	OutcomeUnknownTarget      = "refused-unknown-target"
)

// Errors of the actions other than kill.
var (
	ErrProtectedPath = errors.New("response: path is protected")
	ErrFileCheck     = errors.New("response: file does not pass the checks")
	ErrNoPeers       = errors.New("response: no remote peer to isolate")
	ErrLabel         = errors.New("response: launch item label refused")
)

// Defaults of the action settings.
const (
	DefaultMaxQuarantineBytes = 128 << 20
	DefaultIsolationTTL       = time.Hour
	DefaultSuspendFor         = 30 * time.Second
	// MaxSuspendFor bounds Config.SuspendFor: a suspended process is
	// always resumed (unless killed) within this time.
	MaxSuspendFor = 10 * time.Minute
	// commandTimeout bounds every pfctl, launchctl and codesign run;
	// codesignTimeout bounds one bundle signature check (a timeout refuses).
	commandTimeout  = 10 * time.Second
	codesignTimeout = 5 * time.Second
	// maxBundleDepth is the deepest bundle nesting a file action accepts.
	maxBundleDepth = 3
)

// The macOS binaries the actions run. Only binaries in pinnedBins (per
// platform: paths_<os>.go) are ever run, with fixed argument vectors and an
// empty environment (Windows: SystemRoot only).
const (
	PfctlBin     = "/sbin/pfctl"
	LaunchctlBin = "/bin/launchctl"
	CodesignBin  = "/usr/bin/codesign"
	RouteBin     = "/sbin/route"
)

// ExitError is a command that ran and exited with a non-zero status.
type ExitError struct {
	Code   int
	Output string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d: %s", e.Code, strings.TrimSpace(e.Output))
}

// Runner runs one pinned command with stdin and returns its combined
// output. A non-zero exit is an *ExitError. Tests replace it; the default
// (RunPinned) refuses any binary that is not pinned.
type Runner func(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, error)

// RunPinned is the production Runner: exec of a pinned absolute path, no
// shell, empty environment, bounded output, killed after commandTimeout.
func RunPinned(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
	if !pinnedBins[bin] {
		return nil, fmt.Errorf("response: %q is not a pinned binary", bin)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = pinnedEnv()
	cmd.Dir = pinnedDir()
	hideWindow(cmd)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out limitedBuffer
	out.max = 64 << 10
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Bytes(), &ExitError{Code: ee.ExitCode(), Output: out.String()}
	}
	return out.Bytes(), err
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// bundleSuffixes mark bundle directories; a file inside an Apple-signed
// bundle is never acted on.
var bundleSuffixes = []string{".app", ".framework", ".bundle", ".kext", ".plugin", ".xpc", ".appex",
	".dext", ".systemextension", ".qlgenerator", ".prefpane", ".saver", ".mdimporter"}

// hasPrefixFold reports whether s starts with prefix under Unicode simple
// case folding (so "/ſystem/" and "/SYSTEM/" match "/System/").
func hasPrefixFold(s, prefix string) bool {
	for prefix != "" {
		if s == "" {
			return false
		}
		pr, pn := utf8.DecodeRuneInString(prefix)
		sr, sn := utf8.DecodeRuneInString(s)
		if !strings.EqualFold(string(pr), string(sr)) {
			return false
		}
		prefix, s = prefix[pn:], s[sn:]
	}
	return true
}

// hasSuffixFold is hasPrefixFold for suffixes (ASCII suffixes only).
func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

// protectedPath returns why the file at p must not be touched, or "".
// extra are the sensor's own files and directories (Config.ProtectPaths).
func protectedPath(p string, extra []string) string {
	if err := checkCleanAbs(p); err != nil {
		return err.Error()
	}
	for _, x := range extra {
		if x == "" {
			continue
		}
		x = filepath.Clean(x)
		if strings.EqualFold(p, x) || hasPrefixFold(p, strings.TrimSuffix(x, sep)+sep) {
			return "ZAAFVesper's own file or directory " + x
		}
	}
	for _, ok := range unprotectedUnder {
		if hasPrefixFold(p, ok) {
			return ""
		}
	}
	for _, pre := range ProtectedFilePrefixes {
		if hasPrefixFold(p, pre) || strings.EqualFold(p+sep, pre) {
			return "protected path " + pre
		}
	}
	return ""
}

// dirOf returns the directory of the clean absolute path p ("/" or a
// drive root "C:\" at the top).
func dirOf(p string) string {
	i := strings.LastIndex(p, sep)
	if i <= 0 {
		return sep
	}
	if p[i-1] == ':' {
		return p[:i+1]
	}
	return p[:i]
}

// bundlesOf returns the bundle directories that contain p, outermost first.
func bundlesOf(p string) []string {
	var out []string
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts)-1; i++ { // the file itself is not its own bundle
		for _, suf := range bundleSuffixes {
			if hasSuffixFold(parts[i], suf) {
				out = append(out, strings.Join(parts[:i+1], "/"))
				break
			}
		}
	}
	return out
}

// appleSignedByCodesign is the default Config.AppleSigned: codesign checks
// the bundle against the requirement "anchor apple" (Apple's own signature,
// not Developer ID). Exit 0 means Apple-signed; a non-zero exit means not;
// a failure to run it is returned (the caller then refuses).
func appleSignedByCodesign(run Runner) func(string) (bool, error) {
	return func(bundle string) (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), codesignTimeout)
		defer cancel()
		_, err := run(ctx, CodesignBin, []string{"--verify", "-R=anchor apple", bundle}, nil)
		var ee *ExitError
		switch {
		case err == nil:
			return true, nil
		case ctx.Err() != nil:
			return false, fmt.Errorf("codesign timed out after %s", codesignTimeout)
		case errors.As(err, &ee) && (ee.Code == 1 || ee.Code == 3):
			// 1: not signed or signature invalid; 3: requirement "anchor
			// apple" not satisfied. Any other status (a signal, -1 after a
			// kill) is not an answer: the caller refuses.
			return false, nil
		}
		return false, err
	}
}

// userWritableBundles are locations where an Apple-signed bundle can only
// be a copy a user made (temp folders, home folders, mounted volumes): acting
// on a file there cannot damage the system, so their signature is not
// checked. That also keeps malware from stalling the slow-action worker with
// fake bundles it builds there (codesign on a bundle whose executable is a
// FIFO waits for its timeout).
var userWritableBundles = []string{"/private/tmp/", "/private/var/tmp/", "/private/var/folders/", "/Users/", "/Volumes/"}

func userWritableBundle(b string) bool {
	for _, pre := range userWritableBundles {
		if hasPrefixFold(b, pre) {
			return true
		}
	}
	return false
}

// checkBundles refuses a path inside an Apple-signed bundle, and a path
// nested in more than maxBundleDepth bundles (each needs a codesign run, so
// deep nesting would be a cheap way to stall the actions).
func (r *Responder) checkBundles(p string) string {
	bs := bundlesOf(p)
	if len(bs) > maxBundleDepth {
		return fmt.Sprintf("nested in %d bundles (more than %d)", len(bs), maxBundleDepth)
	}
	for _, b := range bs {
		if userWritableBundle(b) {
			continue
		}
		apple, err := r.cfg.AppleSigned(b)
		if err != nil {
			return fmt.Sprintf("cannot check the signature of bundle %s (%v); refusing", b, err)
		}
		if apple {
			return "inside the Apple-signed bundle " + b
		}
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on macOS
	}
	return hex.EncodeToString(b)
}

// result is the end of one action: outcome, detail and error.
type result struct {
	outcome, detail string
	err             error
}

func refused(outcome string, err error, format string, args ...any) result {
	detail := fmt.Sprintf(format, args...)
	return result{outcome, detail, fmt.Errorf("%w: %s", err, detail)}
}

// act runs one action other than kill and suspend under actMu (never
// under mu, so kill and suspend do not wait for it): perform applies the guard rails, calls budget (the file and network per-rule
// and global budgets) right before the first side effect, honours DryRun,
// and returns the result, which act counts and logs.
func (r *Responder) act(d Decision, rule string, perform func(budget func() *result) result) error {
	var notice string
	defer func() { // after the unlock below
		if notice != "" && r.cfg.OnDegraded != nil {
			r.cfg.OnDegraded(CondRateLimited, notice)
		}
	}()
	r.actMu.Lock()
	defer r.actMu.Unlock()
	now := r.cfg.Now()
	d.Time = now
	budget := func() *result {
		r.mu.Lock()
		defer r.mu.Unlock()
		if o, det, err := r.spend(budgetAction, rule, d.Reason, now, &notice); err != nil {
			return &result{o, det, err}
		}
		return nil
	}
	res := perform(budget)
	r.mu.Lock()
	defer r.mu.Unlock()
	d.Outcome, d.Detail = res.outcome, res.detail
	r.stats[d.Action+" "+res.outcome]++
	if d.Target == TargetParent {
		r.stats[d.Action+" "+res.outcome+" (parent)"]++
	}
	key := d.Path
	if key == "" {
		key = fmt.Sprint(d.PID)
	}
	if r.repeatRefusal(d.Action+"|"+rule, d.Target, d.PID, res.outcome+"|"+key, now) {
		r.stats["log_suppressed"]++
		return res.err
	}
	r.cfg.Log(d)
	return res.err
}

// logLocked logs a decision that is not tied to a rule (resume, release,
// expiry). Caller holds mu.
func (r *Responder) logLocked(d Decision) {
	r.stats[d.Action+" "+d.Outcome]++
	r.cfg.Log(d)
}

// targetProc returns the process an action with target process or parent
// acts on, or a refusal detail. The identity rules are those of KillEvent
// and KillParent: an event without a process, a seeded or unverified
// process, an unknown parent and a parent whose pid does not match the
// event's ppid are refused.
func targetProc(e *event.Event, target string) (*event.Proc, string) {
	if e == nil || e.Proc == nil {
		return &event.Proc{}, "event has no process"
	}
	if target != TargetParent {
		if e.Proc.Seeded || e.Args[ps.ArgIdentity] == ps.Unverified {
			return e.Proc, "process identity is unverified (seeded at start from kern.procargs2)"
		}
		return e.Proc, ""
	}
	par := e.Proc.Parent
	if par == nil {
		return &event.Proc{PID: e.Proc.PPID}, "parent process is unknown (not in the process table)"
	}
	cp := *par
	if cp.PID == 0 {
		cp.PID = e.Proc.PPID
	}
	if cp.PID != e.Proc.PPID {
		return &cp, fmt.Sprintf("parent pid %d does not match ppid %d", cp.PID, e.Proc.PPID)
	}
	if cp.Seeded || e.Args[ps.ArgParentIdentity] == ps.Unverified {
		return &cp, "parent identity is unverified (seeded at start from kern.procargs2)"
	}
	return &cp, ""
}

// platformKnown reports whether p.IsPlatform is a positive statement rather
// than a Go zero value (security note N1): the event came from eslogger,
// whose every process carries is_platform_binary, or the process came from
// the process table, which learned it from eslogger events and recorded its
// kernel unique id, and was not seeded at start-up from kern.procargs2.
// Network events from the socket poller (S2) are in the second case.
func platformKnown(e *event.Event, p *event.Proc) bool {
	return e != nil && p != nil && !p.Seeded && (e.Source == ESSource || p.UniqueID != 0)
}

// verifiedVendor reports a Team ID with a verified signing category.
func verifiedVendor(p *event.Proc) bool {
	return p.TeamID != "" && (p.CSCategory == event.CSDeveloperID || p.CSCategory == event.CSAppStore)
}

// What an action's preflight checks.
const (
	// preProcess: the action acts on a process (isolate_process). The
	// process (or its parent) gets kill's identity and protection rules:
	// protected pids, names and paths, Apple platform binaries, seeded or
	// unverified identity, a Team ID without signing category, and a
	// platform flag that must be known.
	preProcess = iota
	// preWriter: the action acts on the event's file and relies on the
	// rule's judgement of the event's process (quarantine_file target file,
	// requarantine): that process must not be seeded or unverified, and its
	// platform flag must be known.
	preWriter
	// preUntrustedWriter: preWriter, and the writer must be untrusted
	// (trustedWriter, per platform) (remove_persistence).
	preUntrustedWriter
	// preExecutable: the file is the executable of the event's process
	// (quarantine_file target process): preWriter, and never an Apple
	// platform binary.
	preExecutable
)

// preflight applies the identity and platform guard rails every action
// shares, in one place, and returns the process the action is about or a
// refusal. Caller holds actMu, not mu.
func (r *Responder) preflight(e *event.Event, target string, kind int) (*event.Proc, *result) {
	if kind != preProcess {
		target = TargetProcess // the file actions judge the event's process
	}
	p, unknown := targetProc(e, target)
	ref := func(rr result) (*event.Proc, *result) { return p, &rr }
	if kind == preProcess {
		r.mu.Lock()
		why := r.protectedReason(p)
		r.mu.Unlock()
		if why != "" {
			return ref(refused(OutcomeProtected, ErrProtected, "%s", why))
		}
	}
	if unknown != "" {
		return ref(refused(OutcomeUnknown, ErrUnknownProc, "%s", unknown))
	}
	if !platformKnown(e, p) {
		return ref(refused(OutcomeUnknown, ErrUnknownProc, "whether the process is an Apple platform binary is not known (not from eslogger and not from the process table)"))
	}
	switch kind {
	case preProcess:
		if p.TeamID != "" && p.CSCategory == "" {
			return ref(refused(OutcomeSigningUnknown, ErrUnknownProc, "signing category unreported"))
		}
	case preUntrustedWriter:
		if why := trustedWriter(p); why != "" {
			return ref(refused(OutcomeWriterNotUntrusted, ErrProtected, "%s", why))
		}
	case preExecutable:
		if p.IsPlatform {
			return ref(refused(OutcomeProtectedPath, ErrProtectedPath, "Apple platform binary"))
		}
	}
	return p, nil
}

// untrustedChain reports whether the chain above p is untrusted: its parent
// is unknown, seeded, or has no trusted identity (neither an Apple platform
// binary nor a verified vendor), or the process table found an ancestor up
// to launchd without a trusted identity (ps.ancestors_untrusted).
func untrustedChain(p *event.Proc) bool {
	if p.AncestorsUntrusted {
		return true
	}
	par := p.Parent
	return par == nil || par.Seeded || !(par.IsPlatform || verifiedVendor(par))
}
