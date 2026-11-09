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
	if b, err := os.ReadFile(*resultsPath); err == nil {
		_ = json.Unmarshal(b, &results)
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
	md := render(rows, p, results, *platform, *runURL, fired)
	fmt.Print(md)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil {
			return err
		}
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(rows, "", "  ")
		return os.WriteFile(*jsonOut, b, 0o644)
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

// firedIn reports whether rule has an alert inside the test's time window.
func firedIn(alerts []alertLine, rule string, r Result) bool {
	if r.Start.IsZero() {
		return false
	}
	from, to := r.Start.Add(-windowBefore), r.End.Add(windowAfter)
	for _, a := range alerts {
		if a.RuleName == rule && !a.Time.Before(from) && !a.Time.After(to) {
			return true
		}
	}
	return false
}

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
		hit, miss := 0, 0
		var notes []string
		for _, id := range byRule[r.Name] {
			tr, ran := res[id]
			switch {
			case !ran:
				row.Tests = append(row.Tests, id+": not run")
				miss++
			case tr.Command == "" && tr.Error != "":
				row.Tests = append(row.Tests, id+": not run")
				notes = append(notes, id+": "+tr.Error)
				miss++
			case firedIn(alerts, r.Name, tr):
				row.Tests = append(row.Tests, id+": fired")
				hit++
			default:
				row.Tests = append(row.Tests, id+": did not fire")
				miss++
			}
		}
		switch {
		case hit > 0 && miss == 0:
			row.Status = "fired"
			row.Detail = first[r.Name]
		case hit > 0:
			row.Status = "fired for some tests"
			row.Detail = strings.Join(append(notes, first[r.Name]), "; ")
		case len(byRule[r.Name]) > 0:
			row.Status = "did not fire"
			if fired[r.Name] > 0 {
				notes = append(notes, fmt.Sprintf("fired %d time(s) outside the test windows", fired[r.Name]))
			}
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
		if r.Error != "" {
			note = strings.TrimSpace(note + " Error: " + r.Error)
		}
		fmt.Fprintf(&b, "| %s %s | %s | %d | %s |\n", r.ID, cell(r.Name), r.Kind, r.ExitCode, cell(note))
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
