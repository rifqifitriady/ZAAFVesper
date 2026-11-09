package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

type alertLine struct {
	RuleID   string    `json:"rule_id"`
	RuleName string    `json:"rule_name"`
	Output   string    `json:"output"`
	Count    uint64    `json:"count"`
	Time     time.Time `json:"time"`
}

// Alerts are attributed to a test when their event time falls between the
// test's start and its end plus this grace (the 2 s gap between tests keeps
// the windows apart).
const (
	windowBefore = 500 * time.Millisecond
	windowAfter  = 1500 * time.Millisecond
)

// Row is one rule's line in the validation document.
type Row struct {
	Rule   string
	File   string
	Status string // fired, did not fire, not tested
	Tests  []string
	Detail string
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	planPath := fs.String("plan", "", "test plan")
	resultsPath := fs.String("results", "", "results of artrun run")
	alertsDir := fs.String("alerts", "", "folder with the sensor's alerts-*.jsonl")
	rulesDir := fs.String("rules", "rules", "rules folder")
	platform := fs.String("platform", "", "windows or linux")
	runURL := fs.String("run-url", "", "workflow run link")
	out := fs.String("out", "", "markdown output (also printed)")
	jsonOut := fs.String("json", "", "optional JSON summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadPlan(*planPath)
	if err != nil {
		return err
	}
	var results []Result
	var broken string
	if b, err := os.ReadFile(*resultsPath); err != nil {
		broken = "the results file could not be read: " + err.Error()
	} else if err := json.Unmarshal(b, &results); err != nil {
		broken = "the results file is not valid JSON: " + err.Error()
	} else if len(results) != len(p.Tests) {
		broken = fmt.Sprintf("the test run stopped early: %d of %d tests have results", len(results), len(p.Tests))
	}
	fired, firstOutput, alerts, err := readAlerts(*alertsDir)
	if err != nil {
		return err
	}
	rs, err := rules.LoadDir(*rulesDir)
	if err != nil {
		return err
	}
	rows := buildRows(p, results, fired, firstOutput, alerts, rs, *platform)
	if broken == "" {
		broken = canaryProblem(p, results, alerts)
	}
	md := render(rows, p, results, *platform, *runURL, fired)
	if broken != "" {
		md = "> **INCOMPLETE RUN:** " + broken + ". The rows below are not a valid result.\n\n" + md
	}
	fmt.Print(md)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil {
			return err
		}
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rows, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			return err
		}
	}
	if broken != "" {
		return fmt.Errorf("incomplete run: %s", broken)
	}
	return nil
}

func readAlerts(dir string) (map[string]uint64, map[string]string, []alertLine, error) {
	fired, first := map[string]uint64{}, map[string]string{}
	var all []alertLine
	files, err := filepath.Glob(filepath.Join(dir, "alerts-*.jsonl"))
	if err != nil {
		return nil, nil, nil, err
	}
	for _, f := range files {
		if strings.Contains(filepath.Base(f), "alerts-high-") {
			continue // the same alerts as the main file
		}
		fh, err := os.Open(f)
		if err != nil {
			return nil, nil, nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var a alertLine
			if json.Unmarshal(sc.Bytes(), &a) != nil || a.RuleName == "" {
				continue
			}
			n := a.Count
			if n == 0 {
				n = 1
			}
			fired[a.RuleName] += n
			if _, ok := first[a.RuleName]; !ok {
				first[a.RuleName] = a.Output
			}
			all = append(all, a)
		}
		fh.Close()
	}
	return fired, first, all, nil
}

// firedIn returns the first alert of rule inside the test's time window.
func firedIn(alerts []alertLine, rule string, r Result) (alertLine, bool) {
	if r.Start.IsZero() {
		return alertLine{}, false
	}
	from, to := r.Start.Add(-windowBefore), r.End.Add(windowAfter)
	for _, a := range alerts {
		if a.RuleName == rule && !a.Time.Before(from) && !a.Time.After(to) {
			return a, true
		}
	}
	return alertLine{}, false
}

// canaryProblem reports a canary test that did not raise its alert: the
// sensor was not receiving events at that point, so no result is valid.
func canaryProblem(p *Plan, results []Result, alerts []alertLine) string {
	res := map[string]Result{}
	for _, r := range results {
		res[r.ID] = r
	}
	for _, t := range p.Tests {
		if !t.Canary {
			continue
		}
		r, ok := res[t.ID]
		if !ok || r.Start.IsZero() {
			return "canary " + t.ID + " did not run"
		}
		for _, rule := range t.Expect {
			if _, ok := firedIn(alerts, rule, r); !ok {
				return "canary " + t.ID + " raised no alert (" + rule + "): the sensor was not receiving events"
			}
		}
	}
	return ""
}

func stamp(t time.Time) string { return t.UTC().Format("15:04:05.000") }

func buildRows(p *Plan, results []Result, fired map[string]uint64, first map[string]string, alerts []alertLine, rs *rules.Ruleset, platform string) []Row {
	byRule := map[string][]string{}
	for _, t := range p.Tests {
		for _, e := range t.Expect {
			byRule[e] = append(byRule[e], t.ID)
		}
	}
	res := map[string]Result{}
	for _, r := range results {
		res[r.ID] = r
	}
	untestable := map[string]string{}
	for _, u := range p.Untestable {
		untestable[u.Rule] = u.Reason
	}
	var rows []Row
	for _, r := range rs.Rules {
		if len(r.Platforms) != 1 || r.Platforms[0] != platform {
			continue
		}
		row := Row{Rule: r.Name, File: filepath.ToSlash(r.File)}
		if i := strings.Index(row.File, "rules/"); i >= 0 {
			row.File = row.File[i:]
		}
		hit, miss, notRun := 0, 0, 0
		var notes []string
		for _, id := range byRule[r.Name] {
			tr, ran := res[id]
			switch {
			case !ran:
				row.Tests = append(row.Tests, id+": not run")
				notes = append(notes, id+": not run")
				notRun++
			case tr.NotRun != "":
				row.Tests = append(row.Tests, id+": not run")
				notes = append(notes, id+": "+tr.NotRun)
				notRun++
			case tr.Command == "" && tr.Error != "":
				row.Tests = append(row.Tests, id+": not run")
				notes = append(notes, id+": "+tr.Error)
				notRun++
			default:
				if a, ok := firedIn(alerts, r.Name, tr); ok {
					row.Tests = append(row.Tests, fmt.Sprintf("%s: fired (alert %s, test %s–%s)", id, stamp(a.Time), stamp(tr.Start), stamp(tr.End)))
					if row.Detail == "" {
						row.Detail = a.Output
					}
					hit++
					continue
				}
				row.Tests = append(row.Tests, fmt.Sprintf("%s: did not fire (test %s–%s)", id, stamp(tr.Start), stamp(tr.End)))
				miss++
			}
		}
		firstHit := row.Detail
		switch {
		case hit > 0 && miss == 0:
			row.Status = "fired"
			row.Detail = strings.Join(append(notes, firstHit), "; ")
		case hit > 0:
			row.Status = "fired for some tests"
			row.Detail = strings.Join(append(notes, firstHit), "; ")
		case miss > 0:
			row.Status = "did not fire"
			if fired[r.Name] > 0 {
				notes = append(notes, fmt.Sprintf("fired %d time(s) outside the test windows", fired[r.Name]))
			}
			row.Detail = strings.Join(notes, "; ")
		case notRun > 0:
			row.Status = "not tested"
			row.Detail = strings.Join(notes, "; ")
		case untestable[r.Name] != "":
			row.Status = "not tested"
			row.Detail = untestable[r.Name]
		default:
			row.Status = "not tested"
			row.Detail = "no test in the plan"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Status != rows[j].Status {
			return order(rows[i].Status) < order(rows[j].Status)
		}
		return rows[i].Rule < rows[j].Rule
	})
	return rows
}

func order(s string) int {
	switch s {
	case "fired":
		return 0
	case "fired for some tests":
		return 1
	case "did not fire":
		return 2
	}
	return 3
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

func render(rows []Row, p *Plan, results []Result, platform, runURL string, fired map[string]uint64) string {
	var b strings.Builder
	count := map[string]int{}
	for _, r := range rows {
		count[r.Status]++
	}
	fmt.Fprintf(&b, "Run: %s\n\n", runURL)
	fmt.Fprintf(&b, "%d rules for %s: **%d fired**, **%d fired for some tests only**, **%d did not fire**, **%d not tested**.\n\n",
		len(rows), platform, count["fired"], count["fired for some tests"], count["did not fire"], count["not tested"])
	b.WriteString("| Rule | Result | Tests | Detail |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s<br>`%s` | %s | %s | %s |\n", cell(r.Rule), r.File, r.Status, cell(strings.Join(r.Tests, ", ")), cell(r.Detail))
	}
	b.WriteString("\n### Tests run\n\n| Test | Kind | Exit | Note |\n|---|---|---|---|\n")
	notes := map[string]string{}
	for _, t := range p.Tests {
		notes[t.ID] = t.Note
	}
	for _, r := range results {
		note := notes[r.ID]
		if len(r.Prereqs) > 0 {
			note = strings.TrimSpace(note + " Prerequisites not fetched: " + strings.Join(r.Prereqs, "; "))
		}
		if r.NotRun != "" {
			note = strings.TrimSpace(note + " Not run: " + r.NotRun)
		}
		if r.Error != "" {
			note = strings.TrimSpace(note + " Error: " + r.Error)
		}
		fmt.Fprintf(&b, "| %s %s | %s | %d | %s |\n", r.ID, cell(r.Name), r.Kind, r.ExitCode, cell(note))
	}
	if len(p.SkippedAtomics) > 0 {
		b.WriteString("\n## Linked Atomic tests not run as they are\n\n| Atomic test | Why |\n|---|---|\n")
		for _, sk := range p.SkippedAtomics {
			fmt.Fprintf(&b, "| `%s` | %s |\n", sk.GUID, cell(sk.Reason))
		}
	}
	expected := map[string]bool{}
	for _, r := range rows {
		expected[r.Rule] = true
	}
	var other []string
	for name, n := range fired {
		if !expected[name] {
			other = append(other, fmt.Sprintf("%s (%d)", name, n))
		}
	}
	sort.Strings(other)
	if len(other) > 0 {
		b.WriteString("\n### Other alerts during the run\n\n")
		for _, o := range other {
			b.WriteString("- " + cell(o) + "\n")
		}
	}
	return b.String()
}
