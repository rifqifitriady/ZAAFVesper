package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// daemonPlistPath is where the package installs the LaunchDaemon plist.
const daemonPlistPath = "/Library/LaunchDaemons/" + daemonLabel + ".plist"

// responseQueue is how many slow actions may wait for the response worker.
const responseQueue = 64

// respondActions applies every action of a when response is on, in the
// rule's order. kill and suspend run here (a few system calls each), so
// "suspend then kill" stops the process before the kill decision. The slow
// actions (quarantine_file, requarantine, remove_persistence,
// isolate_process: file copies, codesign, launchctl, pfctl) run on the
// responder's worker with a copy of the event, so they never hold up the
// event loop; when its queue is full the action is listed for a retry and
// reported as response_rate_limited. Guard rails live in pkg/response.
func (p *pipeline) respondActions(a *rules.Alert) {
	if p.responder == nil {
		return
	}
	r := p.responder
	ev := a.Last()
	rule, reason := a.RuleID, "rule "+a.RuleName+" ("+a.RuleID+")"
	for _, act := range a.Response {
		if act.Name == rules.ActionQuarantineFile && act.EffectiveTarget() == rules.TargetProcess {
			// Bind the executable while the process runs (Linux, Sysmon
			// events carry no inode): a kill of the same rule may end it
			// before the quarantine runs on the worker.
			ev = r.BindExecutable(ev)
			break
		}
	}
	for _, act := range a.Response {
		parent := act.KillTarget() == rules.TargetParent
		target := act.EffectiveTarget()
		if why := unsupportedAction(act.Name); why != "" {
			pid := int32(0)
			if ev != nil && ev.Proc != nil {
				pid = ev.Proc.PID
			}
			r.RefuseUnsupported(act.Name, target, pid, rule, reason, why)
			continue
		}
		var slow func(e *event.Event)
		switch act.Name {
		case rules.ActionKill:
			if parent {
				_ = r.KillParent(ev, rule, reason)
			} else {
				_ = r.KillEvent(ev, rule, reason)
			}
		case rules.ActionSuspend:
			if parent {
				_ = r.SuspendParent(ev, rule, reason)
			} else {
				_ = r.SuspendEvent(ev, rule, reason)
			}
		case rules.ActionQuarantineFile:
			slow = func(e *event.Event) { _ = r.QuarantineFile(e, target, rule, reason) }
		case rules.ActionRequarantine:
			slow = func(e *event.Event) { _ = r.Requarantine(e, rule, reason) }
		case rules.ActionRemovePersistence:
			slow = func(e *event.Event) { _ = r.RemovePersistence(e, rule, reason) }
		case rules.ActionIsolateProcess:
			slow = func(e *event.Event) { _ = r.IsolateProcess(e, target, rule, reason) }
		}
		if slow == nil {
			continue
		}
		e := cloneEvent(ev)
		if !r.Go(func() { slow(e) }) {
			// Not skipped: listed for a retry like a budget refusal.
			r.Defer(rule, reason, func() { slow(e) })
			p.degraded(response.CondRateLimited, fmt.Sprintf("response queue full (%d actions waiting); %s for %s will be retried", responseQueue, act.Name, reason))
		}
	}
}

// cloneEvent copies what the slow actions read of an event (process and
// parent, file, network, arguments), so the worker never shares memory with
// the event loop.
func cloneEvent(e *event.Event) *event.Event {
	if e == nil {
		return nil
	}
	c := *e
	if e.Proc != nil {
		p := *e.Proc
		if e.Proc.Parent != nil {
			par := *e.Proc.Parent
			p.Parent = &par
		}
		c.Proc = &p
	}
	if e.File != nil {
		f := *e.File
		c.File = &f
	}
	if e.Net != nil {
		n := *e.Net
		c.Net = &n
	}
	if e.Args != nil {
		c.Args = make(map[string]string, len(e.Args))
		for k, v := range e.Args {
			c.Args[k] = v
		}
	}
	return &c
}

// responseTick runs the timed parts of the actions (resume of suspended
// processes, expiry of isolations).
func (p *pipeline) responseTick(now time.Time) {
	if p.responder != nil {
		p.responder.Tick(now)
	}
}

// responseActionConfig fills the action settings of a response.Config from
// the configuration and the run options.
func responseActionConfig(rc *response.Config, o runOptions, cfg *config.Config, rulesDir string) error {
	for _, s := range cfg.Response.IsolationAllow {
		pfx, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("response.isolation_allow: %w", err)
		}
		rc.IsolationAllow = append(rc.IsolationAllow, pfx)
	}
	if cfg.Response.IsolationTTL < 0 || cfg.Response.SuspendFor < 0 || cfg.Response.QuarantineMaxBytes < 0 {
		return fmt.Errorf("response: isolation_ttl, suspend_for and quarantine_max_bytes must not be negative")
	}
	if cfg.Response.SuspendFor > response.MaxSuspendFor {
		return fmt.Errorf("response.suspend_for %s is over the maximum of %s", cfg.Response.SuspendFor, response.MaxSuspendFor)
	}
	rc.IsolationTTL = cfg.Response.IsolationTTL
	rc.SuspendFor = cfg.Response.SuspendFor
	rc.MaxQuarantineBytes = cfg.Response.QuarantineMaxBytes
	rc.RequireRootOwned = o.asRoot
	rc.Runner = o.responseRunner
	if rc.Runner == nil && !o.asRoot {
		// Not root and no test runner: pfctl, launchctl and codesign are
		// never run (they could not change anything anyway).
		rc.Runner = func(_ context.Context, bin string, _ []string, _ []byte) ([]byte, error) {
			return nil, fmt.Errorf("%s not run: response commands run only as root", bin)
		}
	}
	if o.responseStateDir != "" {
		rc.StateDir = o.responseStateDir
		rc.VaultDir = filepath.Join(o.responseStateDir, "quarantine")
	}
	if o.responseAppleSigned != nil {
		rc.AppleSigned = o.responseAppleSigned
	}
	if o.responseConsoleUID != nil {
		rc.ConsoleUID = o.responseConsoleUID
	}
	if o.responseLocalAddrs != nil {
		rc.LocalAddrs = o.responseLocalAddrs
	}
	// ZAAFVesper's own files: the binary, rules, configuration, output, the
	// LaunchDaemon plist and its log directory. The vault and the state
	// directory are added by response.New.
	own := append([]string{rulesDir, daemonPlistPath, "/private/var/log/zaafvesper", "/var/log/zaafvesper"}, ownServicePaths...)
	if exe, err := os.Executable(); err == nil {
		own = append(own, exe)
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			own = append(own, r)
		}
	}
	for _, f := range cfg.Dirs {
		own = append(own, f)
	}
	if o.outputDir != "" {
		own = append(own, o.outputDir)
	}
	for _, x := range own {
		if x == "" {
			continue
		}
		if abs, err := filepath.Abs(x); err == nil {
			rc.ProtectPaths = append(rc.ProtectPaths, abs)
		}
	}
	return nil
}

// parsePrefix accepts an address ("10.0.0.53") or a network ("10.0.0.0/8").
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// startResponse prepares the pf anchor and the isolation state as root
// (production) or with a test runner, and arranges the clean shutdown
// (resume of suspended processes, flush of the anchor). Without root and
// without a test runner, nothing outside the process is touched.
func (s *sensor) startResponse(o runOptions, stderr io.Writer) {
	r := s.p.responder
	if r == nil {
		return
	}
	// The host firewall (pf, nftables, Windows Firewall) is driven only as
	// root (an elevated administrator) or with a test runner.
	useFW := o.responseRunner != nil || (o.asRoot && firewallAvailable)
	if useFW {
		if err := r.StartResponse(); err != nil {
			say(stderr, "response: preparing %s: %v (isolate_process may fail)", response.FirewallName, err)
		}
	}
	r.StartWorker(responseQueue)
	// Remote peers per process, for isolate_process: every event that
	// passed the exclusions (Observe keeps only network events).
	s.p.taps = append(s.p.taps, r.Observe)
	s.closers = append(s.closers, func() error {
		if !useFW {
			r.StopWorker()
			r.ResumeAll()
			return nil
		}
		if err := r.Close(); err != nil {
			say(stderr, "response: shutdown: %v", err)
		}
		return nil
	})
}

// warnIsolation warns when an enabled rule uses isolate_process while the
// management allow-list is empty: only the built-in never-block set
// (loopback, link-local, multicast, this host's addresses, its gateways and
// DNS resolvers, and on macOS Apple's 17.0.0.0/8) is then protected.
func warnIsolation(rs *rules.Ruleset, cfg *config.Config, stderr io.Writer) {
	if len(cfg.Response.IsolationAllow) > 0 {
		return
	}
	for _, r := range rs.Enabled() {
		for _, a := range r.Action {
			if a.Name == rules.ActionIsolateProcess {
				say(stderr, "warning: rule %q uses isolate_process but response.isolation_allow is empty; the gateways and DNS resolvers (and on macOS Apple's 17.0.0.0/8) are never blocked, but add your proxy, management server and log collector, or the rule can block them for the whole host", r.Name)
				return
			}
		}
	}
}

// responseSummary is the start-up line describing the response mode.
func responseSummary(mode string) string {
	return fmt.Sprintf("response: %s (actions only for rules that request them: %s; at most %d per rule and %d in all per minute; every action happens after the event, none prevents it)",
		mode, strings.Join(rules.ActionNames(), ", "), response.DefaultMaxPerRulePerMinute, response.DefaultMaxPerMinute)
}
