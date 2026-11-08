package main

import (
	"errors"
	"io"
	"os"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
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
	if !parseFlags(fs, args, stderr) {
		return 2
	}
	if fs.NArg() != 1 {
		say(stderr, "zaafvesper replay: expected exactly one capture file")
		return 2
	}
	if err := replay(fs.Arg(0), *rulesDir, flagSet(fs, "rules"), *configPath, flagSet(fs, "config"), *jsonPath, *noColor, *keepEnv, stdout, stderr); err != nil {
		sayLines(stderr, "zaafvesper replay: ", err.Error())
		return 1
	}
	return 0
}

func replay(file, rulesFlag string, rulesGiven bool, configPath string, configGiven bool, jsonPath string, noColor, keepEnv bool, stdout, stderr io.Writer) error {
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
		sinks:  []alert.Sink{alert.NewConsole(stdout, colorFor(stdout, noColor))},
		dedup:  alert.NewDeduper(alert.DefaultDedupWindow),
		errw:   stderr,
		// responder stays nil: replay never kills.
	}
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
	}
	if closeJSON != nil {
		readErr = errors.Join(readErr, closeJSON())
	}
	if last := r.LastError(); last != nil {
		say(stderr, "replay: some lines could not be decoded, last: %v", last)
	}
	say(stderr, "replay: %s format=%s", file, r.Format())
	p.printStats(stderr, extraStats())
	_ = os.Stdout.Sync()
	return readErr
}
