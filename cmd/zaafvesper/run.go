package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/rifqifitriady/ZAAFVesper/pkg/yara"
)

// snapshotEvents keep the process table correct; run always subscribes them
// because the snapshotter is always on.
var snapshotEvents = ps.RequiredEvents()

// syntheticEvents are produced inside ZAAFVesper, never subscribed at the source.
var syntheticEvents = map[string]bool{event.YaraMatch: true}

type runOptions struct {
	rulesDir, configPath, capturePath, jsonPath string
	rulesGiven, configGiven                     bool
	enableResponse, dryRunResponse, noColor     bool
	noYara, keepEnv                             bool
	captureMaxBytes                             int64
	dedupWindow                                 time.Duration
	// asRoot applies the root-only checks (executable, config/rules
	// ownership, eslogger pinning, YARA image check). It is os.Geteuid()==0
	// in production; tests set it to exercise those paths.
	asRoot bool
	// Test hooks for the responder (nil in production).
	killFunc func(pid int, sig syscall.Signal) error
	identify func(pid int32) (response.Identity, error)
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("run")
	var o runOptions
	fs.StringVar(&o.rulesDir, "rules", defaultRulesDir, "rules directory")
	fs.StringVar(&o.configPath, "config", defaultConfigPath, "configuration file")
	fs.StringVar(&o.capturePath, "capture", "", "write every event to this new .rcap file")
	fs.StringVar(&o.jsonPath, "json", "", "also write alerts to this new JSONL file")
	fs.BoolVar(&o.enableResponse, "enable-response", false, "allow the kill action of rules that request it")
	fs.BoolVar(&o.dryRunResponse, "dry-run-response", false, "log what would be killed, kill nothing")
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured severities")
	fs.BoolVar(&o.noYara, "no-yara", false, "run without the YARA scanner")
	fs.BoolVar(&o.keepEnv, "keep-env", false, "store full environment values in captures and JSONL alerts (default: names only, plus DYLD_* values)")
	fs.Int64Var(&o.captureMaxBytes, "capture-max-bytes", capture.DefaultMaxBytes, "stop capturing after this many uncompressed bytes")
	fs.DurationVar(&o.dedupWindow, "dedup-window", alert.DefaultDedupWindow, "suppress repeats of the same rule for the same pid within this window")
	if !parseFlags(fs, args, stderr) {
		return 2
	}
	if fs.NArg() != 0 {
		say(stderr, "zaafvesper run: unexpected argument %q", fs.Arg(0))
		return 2
	}
	o.rulesGiven, o.configGiven = flagSet(fs, "rules"), flagSet(fs, "config")
	if os.Geteuid() != 0 {
		say(stderr, "zaafvesper run: needs root, because eslogger does (sudo zaafvesper run). Use 'zaafvesper replay' to test rules without root.")
		return 1
	}
	o.asRoot = true
	config.RequireOwner(0)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runSensor(ctx, o, stdout, stderr); err != nil {
		sayLines(stderr, "zaafvesper run: ", err.Error())
		return 1
	}
	return 0
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
		if err := pinnedEslogger(cfg.Eslogger.Binary); err != nil {
			return nil, err
		}
	}
	rs, err := rules.LoadDir(rulesDir)
	if err != nil {
		return nil, err
	}
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
		errw:     stderr,
	}
	s.p = p
	// The console is fed from its own goroutine through a bounded queue, so a
	// stuck terminal drops alerts (counted) instead of stalling the sensor.
	console := alert.NewAsync(alert.NewConsole(stdout, colorFor(stdout, o.noColor)), alert.DefaultQueue)
	p.sinks = append(p.sinks, console)
	s.closers = append(s.closers, func() error { return console.Close(2 * time.Second) })
	fail := func(err error) (*sensor, error) {
		_ = s.close()
		return nil, err
	}
	if o.jsonPath != "" {
		f, err := config.CreatePrivate(o.jsonPath)
		if err != nil {
			return fail(err)
		}
		j := alert.NewJSONLWith(f, o.keepEnv)
		p.sinks = append(p.sinks, j)
		s.closers = append(s.closers, j.Close)
	}
	if o.capturePath != "" {
		w, err := capture.Create(o.capturePath)
		if err != nil {
			return fail(err)
		}
		w.SetMaxBytes(o.captureMaxBytes)
		w.SetKeepEnv(o.keepEnv)
		p.capture = w
		s.closers = append(s.closers, w.Close)
	}
	if o.enableResponse || o.dryRunResponse {
		p.responder = response.New(response.Config{
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
		})
		mode := "ENABLED"
		if o.dryRunResponse {
			mode = "DRY-RUN"
		}
		say(stderr, "response: %s (kill only for rules with action kill; max %d per minute)", mode, response.DefaultMaxPerMinute)
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
	s.src = eslogger.New(eslogger.Config{
		Binary:         cfg.Eslogger.Binary,
		ExcludePaths:   cfg.Eslogger.ExcludePaths,
		ExcludeSigning: cfg.Eslogger.ExcludeSigning,
		SubscribeWrite: cfg.Source.SubscribeWrite,
		// Protect each eslogger child by pid as soon as it (re)starts.
		OnStart: func(pid int32) {
			if p.responder != nil {
				p.responder.Protect(pid)
			}
		},
		Logf: func(format string, args ...any) {
			say(stderr, "eslogger: %s", fmt.Sprintf(format, args...))
		},
	})
	say(stderr, "zaafvesper %s: %d rules enabled of %d, %d exclusions, events: %v", version, len(rs.Enabled()), len(rs.Rules), excl.Len(), s.events)
	return s, nil
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

	flush := time.NewTicker(2 * time.Second)
	defer flush.Stop()
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
		case <-flush.C:
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
	closeErr := s.close()
	extra := map[string]map[string]uint64{"source": s.src.Stats(), "process table": s.snap.Stats()}
	if st, ok := p.scanner.(interface{ Stats() map[string]uint64 }); ok {
		extra["yara"] = st.Stats()
	}
	p.printStats(stderr, extra)
	return errors.Join(srcErr, closeErr)
}

// pinnedEslogger refuses any eslogger binary but the system one as root.
func pinnedEslogger(bin string) error {
	if bin != "" && bin != eslogger.DefaultBinary {
		return fmt.Errorf("eslogger.binary %q is refused when running as root; only %s is used", bin, eslogger.DefaultBinary)
	}
	return nil
}
