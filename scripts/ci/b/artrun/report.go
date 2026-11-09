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

	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

type alertLine struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Output   string `json:"output"`
	Count    uint64 `json:"count"`
}

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
	fired, firstOutput, err := readAlerts(*alertsDir)
	if err != nil {
		return err
	}
	rs, err := rules.LoadDir(*rulesDir)
	if err != nil {
		return err
	}
	rows := buildRows(p, results, fired, firstOutput, rs, *platform)
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

func readAlerts(dir string) (map[string]uint64, map[string]string, error) {
	fired, first := map[string]uint64{}, map[string]string{}
	files, err := filepath.Glob(filepath.Join(dir, "alerts-*.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		if strings.Contains(filepath.Base(f), "alerts-high-") {
			continue // the same alerts as the main file
		}
		fh, err := os.Open(f)
		if err != nil {
			return nil, nil, err
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
		}
		fh.Close()
	}
	return fired, first, nil
}

func buildRows(p *Plan, results []Result, fired map[string]uint64, first map[string]string, rs *rules.Ruleset, platform string) []Row {
	byRule := map[string][]string{}
	for _, t := range p.Tests {
		for _, e := range t.Expect {
			byRule[e] = append(byRule[e], t.ID)
		}
	}
	errs := map[string]string{}
	for _, r := range results {
		if r.Error != "" && r.Command == "" {
			errs[r.ID] = r.Error
		}
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
		row := Row{Rule: r.Name, File: filepath.ToSlash(r.File), Tests: byRule[r.Name]}
		if i := strings.Index(row.File, "rules/"); i >= 0 {
			row.File = row.File[i:]
		}
		switch {
		case fired[r.Name] > 0:
			row.Status = "fired"
			row.Detail = first[r.Name]
		case len(row.Tests) > 0:
			row.Status = "did not fire"
			var why []string
			for _, id := range row.Tests {
				if e := errs[id]; e != "" {
					why = append(why, id+": "+e)
				}
			}
			row.Detail = strings.Join(why, "; ")
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
	case "did not fire":
		return 1
	}
	return 2
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
	fmt.Fprintf(&b, "%d rules for %s: **%d fired**, **%d did not fire**, **%d not tested**.\n\n", len(rows), platform, count["fired"], count["did not fire"], count["not tested"])
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
