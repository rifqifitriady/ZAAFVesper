package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/output"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// cmdReplay feeds a capture through the same pipeline as run. It needs no
// root and can never kill: the pipeline is built without a responder.
func cmdReplay(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("replay")
	rulesDir := fs.String("rules", defaultRulesDir, "rules directory")
	configPath := fs.String("config", defaultConfigPath, "configuration file (exclusions)")
	jsonPath := fs.String("json", "", "also write alerts to this new JSONL file")
	noColor := fs.Bool("no-color", false, "disable coloured severities")
	keepEnv := fs.Bool("keep-env", false, "store full environment values in JSONL alerts")
	platform := fs.String("platform", hostPlatform(), "run only rules for this platform: macos, windows, linux, or all")
	var ex elegiaOptions // --elegia-out / --elegia-dir (elegia.go)
	ex.register(fs)
	if !parseFlags(fs, args, stderr) {
		return 2
	}
	if fs.NArg() != 1 {
		say(stderr, "zaafvesper replay: expected exactly one capture file")
		return 2
	}
	if err := ex.check(); err != nil {
		say(stderr, "zaafvesper replay: %v", err)
		return 2
	}
	replayElegia = ex
	defer func() { replayElegia = elegiaOptions{} }()
	switch *platform {
	case "all":
		*platform = ""
	case event.PlatformMacOS, event.PlatformWindows, event.PlatformLinux:
	default:
		say(stderr, "zaafvesper replay: --platform must be macos, windows, linux or all")
		return 2
	}
	if err := replay(fs.Arg(0), *rulesDir, flagSet(fs, "rules"), *configPath, flagSet(fs, "config"), *jsonPath, *platform, *noColor, *keepEnv, stdout, stderr); err != nil {
		sayLines(stderr, "zaafvesper replay: ", err.Error())
		return 1
	}
	return 0
}

// replayElegia holds replay's --elegia-out/--elegia-dir options (set by
// cmdReplay; the zero value writes nothing).
var replayElegia elegiaOptions

// replay runs a capture through the pipeline. platform limits it to one
// platform's rules ("" = every platform; --platform defaults to the host).
func replay(file, rulesFlag string, rulesGiven bool, configPath string, configGiven bool, jsonPath, platform string, noColor, keepEnv bool, stdout, stderr io.Writer) error {
	asRoot := os.Geteuid() == 0
	if asRoot {
		if err := checkConfigLocation(configPath, configGiven); err != nil {
			return err
		}
	}
	cfg, err := loadConfig(configPath, configGiven)
	if err != nil {
		return err
	}
	rulesDir := resolveRulesDir(rulesFlag, rulesGiven, cfg)
	if asRoot {
		if err := checkRulesLocation(rulesDir, ""); err != nil {
			return err
		}
	}
	rs, err := rules.LoadDir(rulesDir)
	if err != nil {
		return err
	}
	rs.Platform = platform
	excl, err := config.CompileExclusions(cfg.Exclude, rs.Macros)
	if err != nil {
		return err
	}
	r, err := capture.Open(file)
	if err != nil {
		return err
	}
	defer r.Close()
	p := &pipeline{
		engine: rules.NewEngine(rs, rules.Options{}),
		excl:   excl,
		sinks:  []alert.Sink{alert.NewConsole(replayElegia.consoleWriter(stdout, stderr), colorFor(replayElegia.consoleWriter(stdout, stderr), noColor))},
		dedup:  alert.NewDeduper(alert.DefaultDedupWindow),
		// Event time, so a replay aggregates as the live run would have.
		agg:  alert.NewAggregator(alert.DefaultAggregateLimit, alert.DefaultAggregateWindow, nil),
		errw: stderr,
		// responder stays nil: replay never kills.
	}
	// Replay has no sensor-health pipeline; say on stderr when a rule's
	// source slots filled up, as the live sensor would raise
	// aggregate_sources_exhausted.
	p.agg.OnSourcesExhausted(func(ruleID, ruleName string) {
		say(stderr, "%s", alert.Sanitize(fmt.Sprintf("replay: %s: rule %q (%s) saw %d alert sources in one window; alerts from further new sources are only summarised",
			condSourcesExhausted, ruleName, ruleID, alert.MaxAggregateSources)))
	})
	if r.Format() == capture.FormatEslogger {
		// Raw eslogger output is not enriched yet. No bootstrap: the live
		// process list says nothing about the recorded machine.
		p.enricher = ps.NewSnapshotter(false)
	}
	extraStats := func() map[string]map[string]uint64 {
		m := map[string]map[string]uint64{"reader": r.Stats()}
		if snap, ok := p.enricher.(*ps.Snapshotter); ok {
			m["process table"] = snap.Stats()
		}
		return m
	}
	// ZAAFElegia outputs: the capture's events as Sigma-named NDJSON.
	// Computer is left out (the capture does not record the host).
	var closeElegia []func() error
	if replayElegia.active() {
		ew, err := replayElegia.wire(asRoot, output.SigmaOptions{DefaultProduct: platform}, 30*time.Second, stdout, stderr, p.degraded)
		if err != nil {
			return err
		}
		p.taps = append(p.taps, ew.taps...)
		closeElegia = ew.closers
		prev := extraStats
		extraStats = func() map[string]map[string]uint64 {
			m := prev()
			for k, f := range ew.stats {
				m[k] = f()
			}
			return m
		}
	}
	var closeJSON func() error
	if jsonPath != "" {
		f, err := config.CreatePrivate(jsonPath)
		if err != nil {
			return err
		}
		j := alert.NewJSONLOptions(f, alert.JSONLOptions{KeepEnv: keepEnv, MaxBytes: alert.DefaultMaxFileBytes,
			OnCapped: func(detail string) { p.degraded(condAlertsCapped, detail) }})
		p.sinks = append(p.sinks, j)
		closeJSON = j.Close
	}
	var readErr error
	var last time.Time // event time of the last timestamped event
	for {
		e, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			readErr = err
			break
		}
		p.handle(e, false)
		if e != nil && !e.Time.IsZero() {
			last = e.Time
			p.flushAggregates(last, false) // windows that ended by event time
		}
	}
	p.flushAggregates(last, true)
	if closeJSON != nil {
		readErr = errors.Join(readErr, closeJSON())
	}
	for _, c := range closeElegia {
		readErr = errors.Join(readErr, c())
	}
	if last := r.LastError(); last != nil {
		say(stderr, "replay: some lines could not be decoded, last: %v", last)
	}
	say(stderr, "replay: %s format=%s", file, r.Format())
	p.printStats(stderr, extraStats())
	_ = os.Stdout.Sync()
	return readErr
}
