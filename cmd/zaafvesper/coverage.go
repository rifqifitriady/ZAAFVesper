package main

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// navigatorLayer is an ATT&CK Navigator layer (format 4.5).
type navigatorLayer struct {
	Name                          string              `json:"name"`
	Versions                      map[string]string   `json:"versions"`
	Domain                        string              `json:"domain"`
	Description                   string              `json:"description"`
	Filters                       map[string][]string `json:"filters"`
	Sorting                       int                 `json:"sorting"`
	Layout                        map[string]any      `json:"layout"`
	HideDisabled                  bool                `json:"hideDisabled"`
	Techniques                    []navTechnique      `json:"techniques"`
	Gradient                      navGradient         `json:"gradient"`
	LegendItems                   []any               `json:"legendItems"`
	Metadata                      []any               `json:"metadata"`
	ShowTacticRowBackground       bool                `json:"showTacticRowBackground"`
	SelectTechniquesAcrossTactics bool                `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool                `json:"selectSubtechniquesWithParent"`
}

type navTechnique struct {
	TechniqueID       string `json:"techniqueID"`
	Score             int    `json:"score"`
	Comment           string `json:"comment"`
	Enabled           bool   `json:"enabled"`
	ShowSubtechniques bool   `json:"showSubtechniques"`
}

type navGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

// buildLayer scores each technique by the number of enabled rules that carry it.
func buildLayer(rs *rules.Ruleset) navigatorLayer {
	byTech := map[string][]string{}
	for _, r := range rs.Enabled() {
		for _, id := range r.TechniqueIDs() {
			byTech[id] = append(byTech[id], r.Name)
		}
	}
	ids := make([]string, 0, len(byTech))
	for id := range byTech {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	max := 1
	techs := make([]navTechnique, 0, len(ids))
	for _, id := range ids {
		names := byTech[id]
		sort.Strings(names)
		if len(names) > max {
			max = len(names)
		}
		techs = append(techs, navTechnique{
			TechniqueID: id, Score: len(names), Comment: strings.Join(names, "; "),
			Enabled: true, ShowSubtechniques: strings.Contains(id, "."),
		})
	}
	return navigatorLayer{
		Name:                          "ZAAFVesper rule coverage",
		Versions:                      map[string]string{"layer": "4.5", "navigator": "4.9.5"},
		Domain:                        "enterprise-attack",
		Description:                   "Techniques covered by enabled ZAAFVesper rules; score = number of rules (zaafvesper " + version + ")",
		Filters:                       map[string][]string{"platforms": {"macOS"}},
		Sorting:                       3,
		Layout:                        map[string]any{"layout": "side", "showID": true, "showName": true},
		Techniques:                    techs,
		Gradient:                      navGradient{Colors: []string{"#ffffffff", "#66b1ffff"}, MinValue: 0, MaxValue: max},
		LegendItems:                   []any{},
		Metadata:                      []any{},
		SelectTechniquesAcrossTactics: true,
	}
}

func cmdCoverage(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("coverage")
	out := fs.String("navigator", "", "write an ATT&CK Navigator layer (v4.5) to this new file, or - for stdout")
	rulesDir := fs.String("rules", defaultRulesDir, "rules directory")
	if !parseFlags(fs, args, stderr) {
		return 2
	}
	if *out == "" || fs.NArg() != 0 {
		say(stderr, "usage: zaafvesper coverage --navigator layer.json [--rules dir]")
		return 2
	}
	rs, err := rules.LoadDir(*rulesDir)
	if err != nil {
		sayLines(stderr, "zaafvesper coverage: ", err.Error())
		return 1
	}
	layer := buildLayer(rs)
	data, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		say(stderr, "zaafvesper coverage: %v", err)
		return 1
	}
	summary := stdout
	data = append(data, '\n')
	if *out == "-" {
		if _, err := stdout.Write(data); err != nil {
			say(stderr, "zaafvesper coverage: %v", err)
			return 1
		}
		summary = stderr
	} else {
		f, err := config.CreatePrivate(*out)
		if err != nil {
			say(stderr, "zaafvesper coverage: %v (the file must not exist yet; use --navigator - for stdout)", err)
			return 1
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			say(stderr, "zaafvesper coverage: %v", werr)
			return 1
		}
	}
	for _, t := range layer.Techniques {
		say(summary, "%-10s %d  %s", t.TechniqueID, t.Score, t.Comment)
	}
	say(summary, "%d techniques covered by %d enabled rules; layer written to %s", len(layer.Techniques), len(rs.Enabled()), *out)
	return 0
}
