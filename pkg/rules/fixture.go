package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

// FixtureBaseTime is the timestamp given to the first fixture event that has
// no time; each following event is one second later.
var FixtureBaseTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Minimum scenarios per fixture file.
const (
	MinMatchScenarios   = 1
	MinNoMatchScenarios = 2
)

// Fixture kinds.
const (
	KindMatch   = "match"
	KindNoMatch = "nomatch"
	KindFixture = "fixture" // problems with the fixture file itself
)

// FixtureResult is the outcome of one fixture scenario (or a file-level problem).
type FixtureResult struct {
	RuleID      string `json:"rule_id,omitempty"`
	RuleName    string `json:"rule_name,omitempty"`
	RuleFile    string `json:"rule_file,omitempty"`
	FixtureFile string `json:"fixture_file,omitempty"`
	Kind        string `json:"kind"`
	Desc        string `json:"desc,omitempty"`
	Passed      bool   `json:"passed"`
	Fired       int    `json:"fired"`
	Err         string `json:"error,omitempty"`
}

// Scenario is a list of events fed to one rule.
type Scenario struct {
	Desc   string         `yaml:"desc"`
	Events []*event.Event `yaml:"events"`
}

// FixtureFile is rules/testdata/<rule-file-stem>.yml.
type FixtureFile struct {
	Match   []Scenario `yaml:"match"`
	NoMatch []Scenario `yaml:"nomatch"`
}

// FixturePath returns the fixture path for a rule file, and whether it exists.
func FixturePath(rulesDir, ruleFile string) (string, bool) {
	stem := strings.TrimSuffix(filepath.Base(ruleFile), filepath.Ext(ruleFile))
	for _, ext := range []string{".yml", ".yaml"} {
		p := filepath.Join(rulesDir, "testdata", stem+ext)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, true
		}
	}
	return filepath.Join(rulesDir, "testdata", stem+".yml"), false
}

// LoadFixture reads a fixture file strictly (unknown keys are errors, so a
// misspelt event field cannot silently make a nomatch scenario pass).
func LoadFixture(path string) (*FixtureFile, error) {
	data, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	ff := &FixtureFile{}
	if err := decodeStrict(data, ff); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return ff, nil
}

// NormalizeScenario fills defaults on scenario events in place: time
// (FixtureBaseTime + i·1s when zero), seq (auto-increment when zero),
// source "fixture", and process names derived from exe.
func NormalizeScenario(evs []*event.Event) error {
	known := map[string]bool{}
	for _, n := range ql.KnownEvents() {
		known[n] = true
	}
	var seq uint64
	for i, e := range evs {
		if e == nil {
			return fmt.Errorf("event %d is empty", i+1)
		}
		if !known[e.Name] {
			return fmt.Errorf("event %d: unknown event name %q", i+1, e.Name)
		}
		if e.Time.IsZero() {
			e.Time = FixtureBaseTime.Add(time.Duration(i) * time.Second)
		}
		if e.Seq == 0 {
			seq++
			e.Seq = seq
		} else {
			seq = e.Seq
		}
		if e.Source == "" {
			e.Source = "fixture"
		}
		for _, p := range []*event.Proc{e.Proc, e.Target} {
			fillProc(p)
			if p != nil {
				fillProc(p.Parent)
			}
		}
	}
	return nil
}

func fillProc(p *event.Proc) {
	if p == nil {
		return
	}
	if p.Name == "" && p.Exe != "" {
		p.Name = filepath.Base(p.Exe)
	}
	if p.Cmdline == "" && len(p.Args) > 0 {
		p.Cmdline = strings.Join(p.Args, " ")
	}
}

// RunScenario feeds events to a fresh engine holding only r (enabled for the
// test even if disabled in the ruleset) and returns how many alerts fired.
func RunScenario(r *Rule, evs []*event.Event) (int, error) {
	if len(evs) == 0 {
		return 0, errors.New("scenario has no events")
	}
	if err := NormalizeScenario(evs); err != nil {
		return 0, err
	}
	rc := *r
	rc.Enabled = nil
	en := NewEngine(&Ruleset{Rules: []*Rule{&rc}}, Options{Clock: func() time.Time { return FixtureBaseTime }})
	fired := 0
	for _, e := range evs {
		fired += len(en.Process(e))
	}
	return fired, nil
}

// RunFixtures loads the rules in rulesDir and runs every rule's fixture file.
// It returns an error only when the rules themselves fail to load.
func RunFixtures(rulesDir string) ([]FixtureResult, error) {
	rs, err := LoadDir(rulesDir)
	if err != nil {
		return nil, err
	}
	var out []FixtureResult
	used := map[string]bool{}
	for _, r := range rs.Rules {
		base := FixtureResult{RuleID: r.ID, RuleName: r.Name, RuleFile: r.File}
		path, ok := FixturePath(rulesDir, r.File)
		base.FixtureFile = path
		if !ok {
			res := base
			res.Kind, res.Err = KindFixture, "missing fixture file "+path
			out = append(out, res)
			continue
		}
		used[filepath.Clean(path)] = true
		ff, err := LoadFixture(path)
		if err != nil {
			res := base
			res.Kind, res.Err = KindFixture, err.Error()
			out = append(out, res)
			continue
		}
		if len(ff.Match) < MinMatchScenarios || len(ff.NoMatch) < MinNoMatchScenarios {
			res := base
			res.Kind = KindFixture
			res.Err = fmt.Sprintf("needs >= %d match and >= %d nomatch scenarios, has %d and %d",
				MinMatchScenarios, MinNoMatchScenarios, len(ff.Match), len(ff.NoMatch))
			out = append(out, res)
		}
		for _, sc := range ff.Match {
			out = append(out, runOne(base, KindMatch, sc, r))
		}
		for _, sc := range ff.NoMatch {
			out = append(out, runOne(base, KindNoMatch, sc, r))
		}
	}
	// Fixture files without a rule are reported, they usually mean a rename.
	if files, err := yamlFiles(filepath.Join(rulesDir, "testdata")); err == nil {
		for _, f := range files {
			if !used[filepath.Clean(f)] {
				out = append(out, FixtureResult{FixtureFile: f, Kind: KindFixture, Err: "fixture has no rule file with the same name"})
			}
		}
	}
	return out, nil
}

func runOne(base FixtureResult, kind string, sc Scenario, r *Rule) FixtureResult {
	res := base
	res.Kind, res.Desc = kind, sc.Desc
	if strings.TrimSpace(sc.Desc) == "" {
		res.Err = "scenario has no desc"
		return res
	}
	fired, err := RunScenario(r, sc.Events)
	res.Fired = fired
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if kind == KindMatch {
		res.Passed = fired >= 1
		if !res.Passed {
			res.Err = "rule did not fire"
		}
	} else {
		res.Passed = fired == 0
		if !res.Passed {
			res.Err = fmt.Sprintf("rule fired %d time(s)", fired)
		}
	}
	return res
}
