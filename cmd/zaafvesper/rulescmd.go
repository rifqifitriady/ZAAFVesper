package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

func cmdRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "zaafvesper rules: expected list, validate or test")
		return 2
	}
	sub := args[0]
	fs := newFlagSet("rules " + sub)
	rulesDir := fs.String("rules", defaultRulesDir, "rules directory")
	configPath := fs.String("config", "", "also validate this configuration's exclusions")
	verbose := fs.Bool("v", false, "verbose")
	if !parseFlags(fs, args[1:], stderr) {
		return 2
	}
	dir := *rulesDir
	switch fs.NArg() {
	case 0:
	case 1:
		dir = fs.Arg(0)
	default:
		say(stderr, "zaafvesper rules %s: expected at most one directory", sub)
		return 2
	}
	asRoot := os.Geteuid() == 0
	if asRoot {
		if err := checkConfigLocation(*configPath, true); err != nil {
			sayLines(stderr, "zaafvesper rules: ", err.Error())
			return 1
		}
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		sayLines(stderr, "zaafvesper rules: ", err.Error())
		return 1
	}
	if asRoot {
		if err := checkRulesLocation(dir, ""); err != nil {
			sayLines(stderr, "zaafvesper rules: ", err.Error())
			return 1
		}
	}
	switch sub {
	case "list":
		return rulesList(dir, stdout, stderr)
	case "validate":
		return rulesValidate(dir, cfg, stdout, stderr)
	case "test":
		return rulesTest(dir, *verbose, stdout, stderr)
	}
	say(stderr, "zaafvesper rules: unknown subcommand %q (list, validate, test)", sub)
	return 2
}

func rulesList(dir string, stdout, stderr io.Writer) int {
	rs, err := rules.LoadDir(dir)
	if err != nil {
		sayLines(stderr, "", err.Error())
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tTYPE\tENABLED\tTECHNIQUE\tACTION\tNAME")
	for _, r := range rs.Rules {
		typ := "single"
		if r.IsSequence() {
			typ = fmt.Sprintf("seq/%d", len(r.Sequence().Steps))
		}
		action := "-"
		if a := r.Actions(); len(a) > 0 {
			action = strings.Join(a, ",")
		}
		tech := strings.Join(r.TechniqueIDs(), ",")
		if tech == "" {
			tech = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\t%s\n",
			alert.Sanitize(r.Severity), typ, r.IsEnabled(), alert.Sanitize(tech), alert.Sanitize(action), alert.Sanitize(r.Name))
	}
	_ = tw.Flush()
	say(stdout, "%d rules (%d enabled)", len(rs.Rules), len(rs.Enabled()))
	return 0
}

func rulesValidate(dir string, cfg *config.Config, stdout, stderr io.Writer) int {
	rs, err := rules.LoadDir(dir)
	if err != nil {
		sayLines(stderr, "error: ", err.Error())
		say(stderr, "validation failed")
		return 1
	}
	if _, err := config.CompileExclusions(cfg.Exclude, rs.Macros); err != nil {
		sayLines(stderr, "error: config: ", err.Error())
		return 1
	}
	seqs, warnings := 0, 0
	for _, r := range rs.Rules {
		if r.IsSequence() {
			seqs++
		}
		if r.EventNames() == nil {
			say(stderr, "warning: %s: rule %q is not limited by evt.name; it will force a subscription to every event type", r.File, r.Name)
			warnings++
		}
		if len(r.TechniqueIDs()) == 0 {
			say(stderr, "warning: %s: rule %q has no labels.technique.id", r.File, r.Name)
			warnings++
		}
		if _, ok := rules.FixturePath(dir, r.File); !ok {
			say(stderr, "warning: %s: rule %q has no fixture in testdata/", r.File, r.Name)
			warnings++
		}
	}
	say(stdout, "OK: %d rules (%d enabled, %d sequences), %d macros, %d warnings",
		len(rs.Rules), len(rs.Enabled()), seqs, len(rs.Macros.Names()), warnings)
	return 0
}

func rulesTest(dir string, verbose bool, stdout, stderr io.Writer) int {
	res, err := rules.RunFixtures(dir)
	if err != nil {
		sayLines(stderr, "error: ", err.Error())
		return 1
	}
	pass, fail := 0, 0
	for _, r := range res {
		name := r.RuleName
		if name == "" {
			name = r.FixtureFile
		}
		if r.Passed {
			pass++
			if verbose {
				say(stdout, "PASS  %-7s %s: %s", r.Kind, name, r.Desc)
			}
			continue
		}
		fail++
		desc := r.Desc
		if desc != "" {
			desc = " " + fmt.Sprintf("%q", desc)
		}
		say(stdout, "FAIL  %-7s %s%s: %s", r.Kind, name, desc, r.Err)
	}
	say(stdout, "%d passed, %d failed", pass, fail)
	if fail > 0 {
		return 1
	}
	return 0
}
