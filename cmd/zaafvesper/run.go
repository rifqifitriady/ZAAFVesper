package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/eslogger"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/netpoll"
	"github.com/rifqifitriady/ZAAFVesper/pkg/yara"
)

// snapshotEvents keep the process table correct; run always subscribes them
// because the snapshotter is always on.
var snapshotEvents = ps.RequiredEvents()

// syntheticEvents are produced inside ZAAFVesper, never subscribed at the source.
var syntheticEvents = map[string]bool{event.YaraMatch: true, event.SensorDegraded: true}

// statsEvery is how often run prints the degraded, alert-file and response
// counters to stderr (the daemon's log), not only at shutdown.
const statsEvery = 10 * time.Minute

// daemonLabel is the LaunchDaemon label and package identifier.
const daemonLabel = "com.rifqifitriady.zaafvesper"

// Defaults of the output caps.
const (
	defaultJSONKeep     = 8
	defaultJSONHighKeep = 4
	defaultCaptureKeep  = 2
)

type runOptions struct {
	rulesDir, configPath, capturePath, jsonPath string
	rulesGiven, configGiven                     bool
	enableResponse, dryRunResponse, noColor     bool
	noYara, keepEnv, noConsole                  bool
	captureMaxBytes                             int64
	// outputDir (--output-dir): alerts-<UTC>.jsonl (and, with captureInDir,
	// capture-<UTC>.rcap) are created there on each start; alert files
	// rotate at jsonMaxBytes and at most jsonKeep (captureKeep) are kept.
	outputDir             string
	captureInDir          bool
	jsonMaxBytes          int64
	jsonKeep, captureKeep int
	jsonHighKeep          int // alerts-high-*.jsonl files kept (a separate budget)
	dedupWindow           time.Duration
	// asRoot applies the root-only checks (executable, config/rules
	// ownership, eslogger pinning, YARA image check). It is os.Geteuid()==0
	// in production; tests set it to exercise those paths.
	asRoot bool
	// clock, when set (tests), replaces the wall clock of the degraded
	// limiter, the output directory's 7-day prune age, the alert sinks'
	// retry timer and, if it offers SetClock, the process table.
	clock func() time.Time
	// Test hooks for the responder (nil in production).
	killFunc func(pid int, sig syscall.Signal) error
	identify func(pid int32) (response.Identity, error)
	// Test hooks of the other actions (response_actions.go): a stub runner
	// for pfctl/launchctl/codesign, a state directory instead of
	// /private/var/db/zaafvesper, and the codesign, console-user and
	// interface-address lookups.
	responseRunner      response.Runner
	responseStateDir    string
	responseAppleSigned func(string) (bool, error)
	responseConsoleUID  func() (uint32, error)
	responseLocalAddrs  func() ([]netip.Addr, error)
	// netout holds the W2 flags (network polling, SIEM and ZAAFElegia
	// outputs; see outputs.go).
	netout netOutOptions
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("run")
	var o runOptions
	fs.StringVar(&o.rulesDir, "rules", defaultRulesDir, "rules directory")
	fs.StringVar(&o.configPath, "config", defaultConfigPath, "configuration file")
	fs.StringVar(&o.capturePath, "capture", "", "write every event to this new .rcap file")
	fs.StringVar(&o.jsonPath, "json", "", "also write alerts to this new JSONL file (stops at --json-max-bytes)")
	fs.StringVar(&o.outputDir, "output-dir", "", "write alerts-<UTC time>.jsonl into this directory (created 0700; root-owned when run as root); rotates at --json-max-bytes")
	fs.BoolVar(&o.captureInDir, "capture-in-dir", false, "also write capture-<UTC time>.rcap into --output-dir")
	fs.Int64Var(&o.jsonMaxBytes, "json-max-bytes", alert.DefaultMaxFileBytes, "cap of one JSONL alert file in bytes")
	fs.IntVar(&o.jsonKeep, "json-keep", defaultJSONKeep, "alert files kept in --output-dir (oldest deleted)")
	fs.IntVar(&o.jsonHighKeep, "json-high-keep", defaultJSONHighKeep, "high/critical alert files (alerts-high-*.jsonl) kept in --output-dir; a separate budget")
	fs.IntVar(&o.captureKeep, "capture-keep", defaultCaptureKeep, "capture files kept in --output-dir with --capture-in-dir (oldest deleted)")
	fs.BoolVar(&o.noConsole, "no-console", false, "do not print alerts on stdout (the LaunchDaemon uses --output-dir instead)")
	fs.BoolVar(&o.enableResponse, "enable-response", false, "allow the response actions of rules that request them (kill, suspend, quarantine_file, requarantine, remove_persistence, isolate_process)")
	fs.BoolVar(&o.dryRunResponse, "dry-run-response", false, "log what the response actions would do, do nothing")
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured severities")
	fs.BoolVar(&o.noYara, "no-yara", false, "run without the YARA scanner")
	fs.BoolVar(&o.keepEnv, "keep-env", false, "store full environment values in captures and JSONL alerts (default: names only, plus DYLD_* values)")
	fs.Int64Var(&o.captureMaxBytes, "capture-max-bytes", capture.DefaultMaxBytes, "stop capturing after this many uncompressed bytes")
	fs.DurationVar(&o.dedupWindow, "dedup-window", alert.DefaultDedupWindow, "suppress repeats of the same rule for the same pid within this window")
	o.netout.register(fs)
	registerSourceFlag(fs) // --source on Linux (run_<os>.go)
	if !parseFlags(fs, args, stderr) {
		return 2
	}
	if fs.NArg() != 0 {
		say(stderr, "zaafvesper run: unexpected argument %q", fs.Arg(0))
		return 2
	}
	o.rulesGiven, o.configGiven = flagSet(fs, "rules"), flagSet(fs, "config")
	if err := o.checkOutputFlags(); err != nil {
		say(stderr, "zaafvesper run: %v", err)
		return 2
	}
	if err := checkPrivileges(); err != nil {
		say(stderr, "zaafvesper run: %v", err)
		return 1
	}
	o.asRoot = true
	config.RequireOwner(0)
	if code, handled := runAsService(o, stdout, stderr); handled {
		return code // Windows service (run_windows.go)
	}
	ignoreJobControlSignals()
	if stdinIsTerminal() {
		say(stderr, "warning: zaafvesper is running in a terminal: development only, the normal account can stop or pause it there. %s", liveHint)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runSensor(ctx, o, stdout, stderr); err != nil {
		sayLines(stderr, "zaafvesper run: ", err.Error())
		return 1
	}
	return 0
}

// checkOutputFlags rejects contradictory or out-of-range output flags.
func (o *runOptions) checkOutputFlags() error {
	switch {
	case o.outputDir != "" && o.jsonPath != "":
		return errors.New("--json and --output-dir are exclusive (--output-dir names its alert files itself)")
	case o.captureInDir && o.outputDir == "":
		return errors.New("--capture-in-dir needs --output-dir")
	case o.captureInDir && o.capturePath != "":
		return errors.New("--capture and --capture-in-dir are exclusive")
	case o.jsonMaxBytes <= 0:
		return errors.New("--json-max-bytes must be positive")
	case o.jsonKeep < 1 || o.captureKeep < 1 || o.jsonHighKeep < 1:
		return errors.New("--json-keep, --json-high-keep and --capture-keep must be at least 1")
	}
	return o.netout.check()
}

// subscription computes the canonical events to subscribe at the source.
// nil means every supported event.
func subscription(required []string, withYara bool) []string {
	if required == nil {
		return nil
	}
	set := map[string]bool{}
	for _, n := range required {
		if !syntheticEvents[n] {
			set[n] = true
		}
	}
	for _, n := range snapshotEvents {
		set[n] = true
	}
	if withYara {
		set[event.CreateFile] = true
		set[event.WriteFile] = true
		set[event.Mount] = true // invalidates the scanner's mount cache
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func colorFor(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// sensor holds what runSensor builds, so that wiring can be tested without
// starting eslogger.
type sensor struct {
	p       *pipeline
	snap    *ps.Snapshotter
	src     source.Source
	events  []string
	closers []func() error
	net     *netpoll.Source                     // nil: no socket polling (outputs.go)
	extra   map[string]func() map[string]uint64 // W2 counters printed at shutdown
}

// sourcePIDs returns the pid of the running eslogger child when the source
// exposes it (eslogger.Source.PID, added by the sensor workstream).
func (s *sensor) sourcePIDs() []int32 {
	if pp, ok := s.src.(interface{ PID() int32 }); ok {
		if pid := pp.PID(); pid > 0 {
			return []int32{pid}
		}
	}
	return nil
}

func (s *sensor) close() error {
	var errs []error
	for i := len(s.closers) - 1; i >= 0; i-- {
		errs = append(errs, s.closers[i]())
	}
	return errors.Join(errs...)
}

// buildSensor wires config, rules, exclusions, engine, sinks, capture,
// response, the eslogger source, the snapshotter and YARA.
func buildSensor(o runOptions, stdout, stderr io.Writer) (*sensor, error) {
	if o.asRoot {
		// Before anything is parsed: the binary, then the config location.
		if err := checkExecutable(); err != nil {
			return nil, err
		}
		if err := checkConfigLocation(o.configPath, o.configGiven); err != nil {
			return nil, err
		}
		if !o.noYara {
			if err := checkYaraImages(); err != nil {
				return nil, fmt.Errorf("yara: %w; refusing to run YARA as root (fix the library ownership or pass --no-yara)", err)
			}
		}
	}
	cfg, err := loadConfig(o.configPath, o.configGiven)
	if err != nil {
		return nil, err
	}
	rulesDir := resolveRulesDir(o.rulesDir, o.rulesGiven, cfg)
	yaraDir := cfg.Yara.RulesDir
	if yaraDir == "" {
		yaraDir = filepath.Join(rulesDir, "yara")
	}
	if o.asRoot {
		if err := checkRulesLocation(rulesDir, yaraDir); err != nil {
			return nil, err
		}
		if err := checkSourceBinary(cfg); err != nil {
			return nil, err
		}
	}
	rs, err := rules.LoadDir(rulesDir)
	if err != nil {
		return nil, err
	}
	rs.Platform = hostPlatform() // rules declaring other platforms stay off
	excl, err := config.CompileExclusions(cfg.Exclude, rs.Macros)
	if err != nil {
		return nil, err
	}
	engine := rules.NewEngine(rs, rules.Options{})
	snap := ps.NewSnapshotter(true)
	if seeded, err := snap.BootstrapStats(); err != nil {
		say(stderr, "process snapshot: bootstrap failed (%v); parents of already-running processes will be unknown", err)
	} else {
		say(stderr, "process snapshot: %d running processes seeded", seeded)
	}
	s := &sensor{snap: snap}
	p := &pipeline{
		engine:   engine,
		excl:     excl,
		enricher: snap,
		dedup:    alert.NewDeduper(o.dedupWindow),
		// Per rule and minute: the first 20 alerts, and the first alert of
		// every new source (up to 64), are written in full; repeats are
		// summarised (owner decision R5-1, refined after the security
		// review). Wall clock (or the test clock), so the 2-second tick can
		// end a window.
		agg:  alert.NewAggregator(alert.DefaultAggregateLimit, alert.DefaultAggregateWindow, wallClock(o.clock)),
		errw: stderr,
	}
	s.p = p
	// A rule whose 64 source slots fill up in a minute may be hiding a
	// real alert behind decoys: say so, as a SensorDegraded event that is
	// never aggregated (security review, finding 2).
	p.agg.OnSourcesExhausted(func(ruleID, ruleName string) {
		p.degradedFrom(condSourcesExhausted, fmt.Sprintf("rule %q (%s) saw %d alert sources in one window; alerts from further new sources are only summarised", ruleName, ruleID, alert.MaxAggregateSources))
	})
	if o.clock != nil {
		p.deg.clock = o.clock
		if c, ok := any(snap).(interface{ SetClock(func() time.Time) }); ok {
			c.SetClock(o.clock)
		}
	}
	// Process-table pressure (and, below, YARA conditions) become
	// SensorDegraded events.
	if d, ok := any(snap).(degradedReporter); ok {
		d.OnDegraded(p.degradedFrom)
	}
	fail := func(err error) (*sensor, error) {
		_ = s.close()
		return nil, err
	}
	if !o.noConsole {
		// The console is fed from its own goroutine through a bounded queue,
		// so a stuck terminal drops alerts (counted) instead of stalling the
		// sensor.
		cw := o.netout.consoleWriter(stdout, stderr) // stderr when --elegia-out - owns stdout
		console := alert.NewAsync(alert.NewConsole(cw, colorFor(cw, o.noColor)), alert.DefaultQueue)
		p.sinks = append(p.sinks, console)
		s.closers = append(s.closers, func() error { return console.Close(2 * time.Second) })
	}
	jsonOpts := alert.JSONLOptions{KeepEnv: o.keepEnv, MaxBytes: o.jsonMaxBytes, Now: o.clock,
		OnCapped: func(detail string) { p.degraded(condAlertsCapped, detail) }}
	if o.jsonPath != "" {
		f, err := config.CreatePrivate(o.jsonPath)
		if err != nil {
			return fail(err)
		}
		j := alert.NewJSONLOptions(f, jsonOpts) // stops at the cap
		p.sinks = append(p.sinks, j)
		s.closers = append(s.closers, j.Close)
	}
	if o.capturePath != "" {
		w, err := capture.Create(o.capturePath)
		if err != nil {
			return fail(err)
		}
		s.setCapture(w, o)
	}
	if o.outputDir != "" {
		if err := s.openOutputDir(o, jsonOpts, stderr); err != nil {
			return fail(err)
		}
	}
	if o.enableResponse || o.dryRunResponse {
		rc := response.Config{
			DryRun: o.dryRunResponse, // dry-run wins over enable-response
			Log:    func(d response.Decision) { say(stderr, "%s", d.String()) },
			Lookup: func(pid int32) (*event.Proc, bool) {
				pr, ok := snap.Lookup(pid)
				return &pr, ok
			},
			// The eslogger child is protected by pid, whatever pid each
			// (re)start gets.
			DynamicPIDs: func() []int32 { return s.sourcePIDs() },
			KillFunc:    o.killFunc,
			Identify:    o.identify,
			// A refused action because a budget is spent is a degraded
			// response, raised as SensorDegraded response_rate_limited.
			OnDegraded: p.degraded,
		}
		if err := responseActionConfig(&rc, o, cfg, rulesDir); err != nil {
			return fail(err)
		}
		p.responder = response.New(rc)
		s.startResponse(o, stderr)
		warnIsolation(rs, cfg, stderr)
		warnUnsupportedActions(rs, stderr)
		mode := "ENABLED"
		if o.dryRunResponse {
			mode = "DRY-RUN"
		}
		say(stderr, "%s", responseSummary(mode))
	}

	if err := s.wireNetOut(o, engine, snap, stdout, stderr); err != nil {
		return fail(err)
	}

	required := engine.RequiredEvents()
	withYara := false
	if o.noYara {
		say(stderr, "yara: disabled by --no-yara")
	}
	if !cfg.Yara.Disabled && !o.noYara {
		sc, err := yara.New(yara.Config{
			RulesDir: yaraDir, Workers: cfg.Yara.Workers, MaxFileSize: cfg.Yara.MaxFileSize,
			TimeoutSec: cfg.Yara.TimeoutSec, WatchDirs: cfg.Yara.WatchDirs,
		})
		switch {
		case errors.Is(err, yara.ErrDisabled):
			say(stderr, "yara: %v; continuing without YARA", err)
		case err != nil:
			return fail(err)
		default:
			p.scanner = sc
			withYara = true
			s.closers = append(s.closers, sc.Close)
			if d, ok := any(sc).(degradedReporter); ok {
				d.OnDegraded(p.degradedFrom)
			}
		}
	}
	if !withYara {
		for _, n := range required {
			if n == event.YaraMatch {
				say(stderr, "warning: some rules use YaraMatch events but YARA is not active")
				break
			}
		}
	}
	s.events = subscription(required, withYara)
	if s.events == nil {
		say(stderr, "warning: a rule is not limited by evt.name, so every event type is subscribed (high volume)")
	}
	s.src = newSource(cfg, p, stderr) // eslogger, Windows event log or journald (run_<os>.go)
	// Dropped events at the source (es_events_dropped, workstream B;
	// sysmon_events_dropped on Windows and Linux).
	if d, ok := any(s.src).(degradedReporter); ok {
		d.OnDegraded(p.degradedFrom)
	}
	say(stderr, "zaafvesper %s: %d rules enabled of %d, %d exclusions, events: %v", version, len(rs.Enabled()), len(rs.Rules), excl.Len(), s.events)
	return s, nil
}

// wallClock returns c, or time.Now when c is nil.
func wallClock(c func() time.Time) func() time.Time {
	if c != nil {
		return c
	}
	return time.Now
}

func runSensor(ctx context.Context, o runOptions, stdout, stderr io.Writer) error {
	s, err := buildSensor(o, stdout, stderr)
	if err != nil {
		return err
	}
	p := s.p
	srcCh := make(chan *event.Event, 4096)
	yaraCh := make(chan *event.Event, 256)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if p.scanner != nil {
		if err := p.scanner.Start(runCtx, yaraCh); err != nil {
			_ = s.close()
			return err
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.src.Run(runCtx, s.events, srcCh) }()
	netCh := s.startNet(runCtx, stderr) // nil when socket polling is off

	flush := time.NewTicker(2 * time.Second)
	defer flush.Stop()
	statsTick := time.NewTicker(statsEvery)
	defer statsTick.Stop()
	var srcErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-errCh:
			errCh = nil
			if err != nil && ctx.Err() == nil {
				srcErr = err
			}
			break loop
		case e := <-srcCh:
			p.handle(e, false)
		case e := <-yaraCh:
			p.handle(e, true)
		case e := <-netCh:
			p.handleNetwork(e)
		case <-statsTick.C:
			p.periodicStats(stderr)
		case <-flush.C:
			p.flushAggregates(time.Now(), false) // summaries of windows that ended
			p.responseTick(time.Now())           // resume suspended processes, expire isolations
			p.drainDegraded()                    // reports from YARA workers while idle
			if p.capture != nil {
				_ = p.capture.Flush()
			}
		}
	}
	// Shutdown: stop the source, keep handling what it already produced for
	// a short grace period, then close capture and sinks so files are valid.
	cancel()
	grace := time.NewTimer(2 * time.Second)
	defer grace.Stop()
drain:
	for errCh != nil {
		select {
		case e := <-srcCh:
			p.handle(e, false)
		case <-errCh:
			break drain
		case <-grace.C:
			break drain
		}
	}
	for {
		select {
		case e := <-srcCh:
			p.handle(e, false)
			continue
		default:
		}
		break
	}
	p.flushAggregates(time.Now(), true) // one summary per rule still holding alerts
	p.drainDegraded()
	closeErr := s.close()
	p.printStats(stderr, s.extraStats())
	return errors.Join(srcErr, closeErr)
}

// extraStats gathers the component counters printed at shutdown: the
// source (including eslogger seq_gaps and events_missed), the process table
// and YARA (including exec_unbound and file_changed).
func (s *sensor) extraStats() map[string]map[string]uint64 {
	extra := map[string]map[string]uint64{"source": s.src.Stats(), "process table": s.snap.Stats()}
	for name, stats := range s.extra {
		extra[name] = stats()
	}
	if st, ok := s.p.scanner.(interface{ Stats() map[string]uint64 }); ok {
		extra["yara"] = st.Stats()
	}
	return extra
}

func (s *sensor) setCapture(w *capture.Writer, o runOptions) {
	w.SetMaxBytes(o.captureMaxBytes)
	w.SetKeepEnv(o.keepEnv)
	s.p.capture = w
	s.closers = append(s.closers, w.Close)
}

// errBudgetFull: the keep budget holds only files that may not be deleted
// (younger than minPruneAge, or open).
var errBudgetFull = errors.New("keep budget full")

// openOutputDir wires --output-dir: a new alerts-<UTC>.jsonl on every start
// (KeepAlive restarts never reuse a file), rotation at the size cap, and
// optionally a capture file. Old files are deleted only to stay within
// --json-keep / --capture-keep and only when older than 7 days (or empty);
// when the budget is full of younger files the sensor keeps running without
// writing that file (alerts_capped / capture_capped), preserving what is on
// disk.
func (s *sensor) openOutputDir(o runOptions, jsonOpts alert.JSONLOptions, stderr io.Writer) error {
	od, err := openOutputDir(o.outputDir, o.asRoot)
	if err != nil {
		return err
	}
	if o.clock != nil {
		od.now = o.clock
	}
	if o.jsonHighKeep < 1 {
		o.jsonHighKeep = defaultJSONHighKeep
	}
	s.closers = append(s.closers, od.close)
	open := map[string]bool{} // files being written: never pruned
	newFile := func(prefix, ext string, keep int) (*os.File, error) {
		room, removed, perr := od.makeRoom(prefix, ext, keep, open)
		if len(removed) > 0 {
			say(stderr, "output: removed %d %s file(s) older than 7 days or empty (keeping %d)", len(removed), prefix, keep)
		}
		if perr != nil {
			say(stderr, "output: pruning old %s files: %v", prefix, perr)
		}
		if !room {
			return nil, fmt.Errorf("%w: %d %s files younger than 7 days in %s; delete or move some to resume", errBudgetFull, keep, prefix, od.path)
		}
		f, err := od.create(prefix, ext)
		if err != nil {
			return nil, err
		}
		open[filepath.Base(f.Name())] = true
		return f, nil
	}
	// rotating builds one alert file series: alerts-<UTC>.jsonl for every
	// alert, and alerts-high-<UTC>.jsonl, a reserved budget for high and
	// critical alerts that a flood of lower alerts cannot use up.
	rotating := func(prefix string, keep int, opts alert.JSONLOptions) (*alert.JSONL, error) {
		current := ""
		opts.Rotate = func() (io.Writer, error) {
			nf, err := newFile(prefix, alertsExt, keep)
			if err != nil {
				return nil, err
			}
			delete(open, current) // the sink closes it once Rotate returns
			current = filepath.Base(nf.Name())
			say(stderr, "output: %s to %s", prefix, nf.Name())
			return nf, nil
		}
		f, err := newFile(prefix, alertsExt, keep)
		var w io.Writer
		switch {
		case errors.Is(err, errBudgetFull):
			opts.StartStopped, opts.StopReason = true, err.Error()
			say(stderr, "output: %s are NOT written: %v", prefix, err)
			s.p.degraded(condAlertsCapped, err.Error())
		case err != nil:
			return nil, err
		default:
			w, current = f, filepath.Base(f.Name())
			say(stderr, "output: %s to %s (rotate at %d bytes, keep %d)", prefix, f.Name(), o.jsonMaxBytes, keep)
		}
		j := alert.NewJSONLOptions(w, opts)
		s.closers = append(s.closers, j.Close)
		return j, nil
	}
	j, err := rotating(alertsPrefix, o.jsonKeep, jsonOpts)
	if err != nil {
		return err
	}
	s.p.sinks = append(s.p.sinks, j)
	jh, err := rotating(alertsHighPrefix, o.jsonHighKeep, jsonOpts)
	if err != nil {
		return err
	}
	s.p.sinks = append(s.p.sinks, &alert.Filtered{Sink: jh, Allow: alert.HighOrCritical})
	if o.captureInDir {
		cf, err := newFile(capturePrefix, captureExt, o.captureKeep)
		switch {
		case errors.Is(err, errBudgetFull):
			say(stderr, "output: capture is NOT written: %v", err)
			s.p.degraded(condCaptureCapped, err.Error())
		case err != nil:
			return err
		default:
			say(stderr, "output: capture to %s (stops at %d uncompressed bytes, keep %d)", cf.Name(), o.captureMaxBytes, o.captureKeep)
			s.setCapture(capture.NewFileWriter(cf), o)
		}
	}
	return nil
}

// pinnedEslogger refuses any eslogger binary but the system one as root.
func pinnedEslogger(bin string) error {
	if bin != "" && bin != eslogger.DefaultBinary {
		return fmt.Errorf("eslogger.binary %q is refused when running as root; only %s is used", bin, eslogger.DefaultBinary)
	}
	return nil
}
