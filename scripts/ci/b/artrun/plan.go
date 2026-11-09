package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Plan is one platform's test plan (scripts/ci/b/<platform>-plan.json).
type Plan struct {
	Platform string `json:"platform"`
	// Tests run in order.
	Tests []Test `json:"tests"`
	// Untestable lists rules that are deliberately not exercised, and why.
	Untestable []Untestable `json:"untestable"`
	// SkippedAtomics lists the Atomic tests the rules link (tests.atomic)
	// that are not run as they are, and why (each is replaced by an inline
	// equivalent or left out).
	SkippedAtomics []SkippedAtomic `json:"skipped_atomics"`
	// RuleNotes explain known reasons a rule may not fire on some images;
	// the report adds the note to a "did not fire" row (the row stays a miss).
	RuleNotes []Untestable `json:"rule_notes,omitempty"`
}

// SkippedAtomic is a linked Atomic test that is not run as is.
type SkippedAtomic struct {
	GUID   string `json:"guid"`
	Reason string `json:"reason"`
}

// Test is one Atomic Red Team test or one inline equivalent.
type Test struct {
	ID     string  `json:"id"`
	Atomic *Atomic `json:"atomic,omitempty"`
	Inline *Inline `json:"inline,omitempty"`
	// Setup runs before the test (for example creating the file an Atomic
	// test deletes); same executor as Inline.
	Setup *Inline `json:"setup,omitempty"`
	// Expect names the rules (by name) this test should make fire.
	Expect []string `json:"expect"`
	Note   string   `json:"note,omitempty"`
	// Requires names programs the test needs; when one is not on the
	// runner image the test is recorded as not run (not as a miss).
	Requires []string `json:"requires,omitempty"`
	// Canary tests run first and last: if one does not raise its expected
	// alert the sensor was not receiving events, and the whole run is
	// invalid.
	Canary bool `json:"canary,omitempty"`
}

// Atomic names one test in the atomics folder.
type Atomic struct {
	Technique string `json:"technique"`
	GUID      string `json:"guid"`
}

// Inline is a command run with an executor.
type Inline struct {
	Executor string `json:"executor"` // command_prompt, powershell, sh, bash
	Command  string `json:"command"`
	Cleanup  string `json:"cleanup,omitempty"`
}

// Untestable is a rule left out of the run.
type Untestable struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

func loadPlan(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, t := range p.Tests {
		if (t.Atomic == nil) == (t.Inline == nil) {
			return nil, fmt.Errorf("%s: test %d (%s) needs exactly one of atomic and inline", path, i, t.ID)
		}
		if len(t.Expect) == 0 {
			return nil, fmt.Errorf("%s: test %s expects no rule", path, t.ID)
		}
	}
	return &p, nil
}

// atomicDoc is the part of an atomics YAML file artrun reads.
type atomicDoc struct {
	AttackTechnique string       `yaml:"attack_technique"`
	Tests           []atomicTest `yaml:"atomic_tests"`
}

type atomicTest struct {
	Name      string                   `yaml:"name"`
	GUID      string                   `yaml:"auto_generated_guid"`
	Platforms []string                 `yaml:"supported_platforms"`
	Inputs    map[string]atomicInput   `yaml:"input_arguments"`
	Deps      []map[string]interface{} `yaml:"dependencies"`
	Executor  struct {
		Name    string `yaml:"name"`
		Command string `yaml:"command"`
		Cleanup string `yaml:"cleanup_command"`
	} `yaml:"executor"`
}

type atomicInput struct {
	Default interface{} `yaml:"default"`
}

var placeholder = regexp.MustCompile(`#\{([A-Za-z0-9_]+)\}`)

// resolveAtomic finds the test and returns its command and cleanup with
// every #{input} replaced by its default and PathToAtomicsFolder by the
// atomics folder. Prerequisites are never fetched: a test that declares
// dependencies runs as is, and its dependencies are recorded.
func resolveAtomic(atomicsDir string, a *Atomic, platform string) (*Inline, string, []string, error) {
	path := filepath.Join(atomicsDir, a.Technique+".yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, err
	}
	var doc atomicDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, "", nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, t := range doc.Tests {
		if !strings.EqualFold(t.GUID, a.GUID) {
			continue
		}
		ok := false
		for _, p := range t.Platforms {
			ok = ok || p == platform
		}
		if !ok {
			return nil, "", nil, fmt.Errorf("%s %s does not support %s", a.Technique, a.GUID, platform)
		}
		sub := func(s string) string {
			s = strings.ReplaceAll(s, "PathToAtomicsFolder", atomicsDir)
			return placeholder.ReplaceAllStringFunc(s, func(m string) string {
				name := placeholder.FindStringSubmatch(m)[1]
				if in, ok := t.Inputs[name]; ok && in.Default != nil {
					return fmt.Sprint(in.Default)
				}
				return m
			})
		}
		var deps []string
		for _, d := range t.Deps {
			deps = append(deps, fmt.Sprint(d["description"]))
		}
		return &Inline{Executor: t.Executor.Name, Command: sub(t.Executor.Command), Cleanup: sub(t.Executor.Cleanup)}, t.Name, deps, nil
	}
	return nil, "", nil, fmt.Errorf("%s: no test %s", path, a.GUID)
}
