package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/nofollow"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// coverageReport summarises a rule set: ATT&CK techniques per platform and
// per tactic, and the rules without a linked atomic test.
type coverageReport struct {
	Rules            int            `json:"rules"`
	Techniques       int            `json:"techniques"`
	PerPlatform      map[string]int `json:"techniques_per_platform"`
	PerTactic        map[string]int `json:"techniques_per_tactic"`
	RulesWithAtomics int            `json:"rules_with_atomics"`
	RulesNoAtomics   []string       `json:"rules_without_atomics"`
	// NoAtomicsByPlat lists, per platform, the rules that apply there and
	// link no atomic test (a rule without platforms is listed under all).
	NoAtomicsByPlat   map[string][]string `json:"rules_without_atomics_by_platform"`
	TechniquesByPlat  map[string][]string `json:"techniques_by_platform"`
	AttackProblems    []string            `json:"attack_problems,omitempty"`
	AttackWarnings    []string            `json:"attack_warnings,omitempty"`
	AttackDataVersion string              `json:"attack_data,omitempty"`
}

var allPlatforms = []string{event.PlatformMacOS, event.PlatformWindows, event.PlatformLinux}

func buildCoverageReport(rs *rules.Ruleset) *coverageReport {
	rep := &coverageReport{PerPlatform: map[string]int{}, PerTactic: map[string]int{}, TechniquesByPlat: map[string][]string{}, NoAtomicsByPlat: map[string][]string{}}
	all := map[string]bool{}
	byPlat := map[string]map[string]bool{}
	byTactic := map[string]map[string]bool{}
	for _, p := range allPlatforms {
		byPlat[p] = map[string]bool{}
	}
	for _, r := range rs.Enabled() {
		rep.Rules++
		plats := r.Platforms
		if len(plats) == 0 {
			plats = allPlatforms
		}
		if len(r.Tests.Atomic) > 0 {
			rep.RulesWithAtomics++
		} else {
			rel := alert.Sanitize(ruleRel(rs.Dir, r.File))
			rep.RulesNoAtomics = append(rep.RulesNoAtomics, rel)
			for _, p := range plats {
				rep.NoAtomicsByPlat[p] = append(rep.NoAtomicsByPlat[p], rel)
			}
		}
		tactics := splitIDs(r.Labels["tactic.name"])
		for _, t := range r.TechniqueIDs() {
			all[t] = true
			for _, p := range plats {
				byPlat[p][t] = true
			}
			for _, ta := range tactics {
				if byTactic[ta] == nil {
					byTactic[ta] = map[string]bool{}
				}
				byTactic[ta][t] = true
			}
		}
	}
	rep.Techniques = len(all)
	for p, set := range byPlat {
		rep.PerPlatform[p] = len(set)
		rep.TechniquesByPlat[p] = sortedKeys(set)
	}
	for ta, set := range byTactic {
		rep.PerTactic[alert.Sanitize(ta)] = len(set)
	}
	sort.Strings(rep.RulesNoAtomics)
	for _, p := range allPlatforms {
		sort.Strings(rep.NoAtomicsByPlat[p])
	}
	return rep
}

func ruleRel(dir, file string) string {
	if strings.HasPrefix(file, dir+"/") {
		return strings.TrimPrefix(file, dir+"/")
	}
	return file
}

func splitIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// attackData is the part of an ATT&CK STIX bundle (enterprise-attack.json)
// the check needs.
type attackData struct {
	techniques map[string]attackTechnique
	tactics    map[string]string // TA id -> name
	version    string
}

type attackTechnique struct {
	name       string
	tactics    map[string]bool // TA ids
	revoked    bool
	deprecated bool
}

// Bounds on the ATT&CK bundle (the real one is ~50 MB with ~25 000 objects).
// Objects are decoded one at a time from a stream, so memory follows the
// largest single object and the kept techniques, not the file size.
const (
	maxAttackBytes   = 256 << 20
	maxAttackObjects = 500000
)

type stixObject struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Shortname  string `json:"x_mitre_shortname"`
	Revoked    bool   `json:"revoked"`
	Deprecated bool   `json:"x_mitre_deprecated"`
	Version    string `json:"x_mitre_version"`
	ExtRefs    []struct {
		Source string `json:"source_name"`
		ID     string `json:"external_id"`
	} `json:"external_references"`
	Phases []struct {
		Chain string `json:"kill_chain_name"`
		Phase string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

// keptTechnique is what the check keeps of an attack-pattern object.
type keptTechnique struct {
	id, name            string
	revoked, deprecated bool
	phases              []string
}

func (o *stixObject) attackID() string {
	for _, r := range o.ExtRefs {
		if r.Source == "mitre-attack" {
			return r.ID
		}
	}
	return ""
}

func loadAttackData(path string) (*attackData, error) {
	f, err := nofollow.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	dec := json.NewDecoder(io.LimitReader(f, maxAttackBytes))
	bad := func(what string) error { return fmt.Errorf("%s: not an ATT&CK STIX bundle (%s)", path, what) }
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, bad("expected an object")
	}
	var techs []keptTechnique
	short := map[string]string{} // tactic shortname -> TA id
	ad := &attackData{techniques: map[string]attackTechnique{}, tactics: map[string]string{}}
	n := 0
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, bad(err.Error())
		}
		if k != "objects" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, bad(err.Error())
			}
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			return nil, bad("objects is not a list")
		}
		for dec.More() {
			if n++; n > maxAttackObjects {
				return nil, bad(fmt.Sprintf("more than %d objects", maxAttackObjects))
			}
			var o stixObject
			if err := dec.Decode(&o); err != nil {
				return nil, bad(err.Error())
			}
			switch o.Type {
			case "x-mitre-tactic":
				id := o.attackID()
				ad.tactics[id] = o.Name
				short[o.Shortname] = id
			case "x-mitre-collection":
				if ad.version == "" {
					ad.version = o.Name + " " + o.Version
				}
			case "attack-pattern":
				if id := o.attackID(); id != "" {
					k := keptTechnique{id: id, name: o.Name, revoked: o.Revoked, deprecated: o.Deprecated}
					for _, p := range o.Phases {
						if p.Chain == "mitre-attack" {
							k.phases = append(k.phases, p.Phase)
						}
					}
					techs = append(techs, k)
				}
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, bad(err.Error())
		}
	}
	for _, k := range techs {
		t := attackTechnique{name: k.name, tactics: map[string]bool{}, revoked: k.revoked, deprecated: k.deprecated}
		for _, p := range k.phases {
			t.tactics[short[p]] = true
		}
		ad.techniques[k.id] = t
	}
	if len(ad.techniques) == 0 {
		return nil, fmt.Errorf("%s: no ATT&CK techniques found", path)
	}
	return ad, nil
}

// checkAttack reports technique and tactic ids that are unknown, revoked or
// deprecated (problems), and tactic labels that none of a rule's
// techniques belongs to (warnings).
func checkAttack(rs *rules.Ruleset, ad *attackData) (problems, warnings []string) {
	for _, r := range rs.Rules {
		name := alert.Sanitize(ruleRel(rs.Dir, r.File))
		ruleTactics := map[string]bool{}
		for _, ta := range r.TechniqueIDs() {
			t, ok := ad.techniques[ta]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: technique %s is not in the ATT&CK data", name, alert.Sanitize(ta)))
			case t.revoked:
				problems = append(problems, fmt.Sprintf("%s: technique %s is revoked", name, ta))
			case t.deprecated:
				problems = append(problems, fmt.Sprintf("%s: technique %s is deprecated", name, ta))
			}
			for k := range t.tactics {
				ruleTactics[k] = true
			}
		}
		for _, ta := range splitIDs(r.Labels["tactic.id"]) {
			if _, ok := ad.tactics[ta]; !ok {
				problems = append(problems, fmt.Sprintf("%s: tactic %s is not in the ATT&CK data", name, alert.Sanitize(ta)))
				continue
			}
			if len(r.TechniqueIDs()) > 0 && !ruleTactics[ta] {
				warnings = append(warnings, fmt.Sprintf("%s: tactic %s (%s) is not a tactic of its techniques", name, ta, ad.tactics[ta]))
			}
		}
	}
	sort.Strings(problems)
	sort.Strings(warnings)
	return problems, warnings
}

func printCoverageReport(w io.Writer, rep *coverageReport) {
	say(w, "%d enabled rules cover %d ATT&CK techniques", rep.Rules, rep.Techniques)
	for _, p := range allPlatforms {
		say(w, "  %-8s %3d techniques", p, rep.PerPlatform[p])
	}
	tactics := make([]string, 0, len(rep.PerTactic))
	for t := range rep.PerTactic {
		tactics = append(tactics, t)
	}
	sort.Slice(tactics, func(i, j int) bool {
		if rep.PerTactic[tactics[i]] != rep.PerTactic[tactics[j]] {
			return rep.PerTactic[tactics[i]] < rep.PerTactic[tactics[j]]
		}
		return tactics[i] < tactics[j]
	})
	say(w, "techniques per tactic (thinnest first):")
	for _, t := range tactics {
		say(w, "  %3d  %s", rep.PerTactic[t], t)
	}
	say(w, "rules without an atomic test, per platform (a rule for several platforms counts in each):")
	for _, p := range allPlatforms {
		say(w, "  %-8s %3d", p, len(rep.NoAtomicsByPlat[p]))
	}
	say(w, "%d rules link an atomic test; %d do not:", rep.RulesWithAtomics, len(rep.RulesNoAtomics))
	for _, r := range rep.RulesNoAtomics {
		say(w, "  %s", r)
	}
	if rep.AttackDataVersion != "" {
		say(w, "ATT&CK check against %s: %d problems, %d warnings", alert.Sanitize(rep.AttackDataVersion), len(rep.AttackProblems), len(rep.AttackWarnings))
		for _, p := range rep.AttackProblems {
			say(w, "  PROBLEM %s", p)
		}
		for _, p := range rep.AttackWarnings {
			say(w, "  warning %s", p)
		}
	}
}

// cmdCoverageReport implements `coverage --report`.
func cmdCoverageReport(rulesDir, attackPath string, asJSON bool, stdout, stderr io.Writer) int {
	rs, err := rules.LoadDir(rulesDir)
	if err != nil {
		sayLines(stderr, "zaafvesper coverage: ", err.Error())
		return 1
	}
	rep := buildCoverageReport(rs)
	if attackPath != "" {
		ad, err := loadAttackData(attackPath)
		if err != nil {
			sayLines(stderr, "zaafvesper coverage: ", err.Error())
			return 1
		}
		rep.AttackDataVersion = ad.version
		if rep.AttackDataVersion == "" {
			rep.AttackDataVersion = "enterprise-attack"
		}
		rep.AttackProblems, rep.AttackWarnings = checkAttack(rs, ad)
	}
	if asJSON {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			say(stderr, "zaafvesper coverage: %v", err)
			return 1
		}
		if _, err := stdout.Write(append(data, '\n')); err != nil {
			return 1
		}
	} else {
		printCoverageReport(stdout, rep)
	}
	if len(rep.AttackProblems) > 0 {
		return 1
	}
	return 0
}
