package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
	"gopkg.in/yaml.v3"
)

// MaxRuleFileSize bounds a rule or fixture file read from disk.
const MaxRuleFileSize = 1 << 20

// Ruleset is the set of rules and macros loaded from a rules directory.
type Ruleset struct {
	Dir string
	// Platform, when set (event.Platform* value), limits Enabled to rules
	// that apply to that platform. Empty means every platform.
	Platform   string
	Rules      []*Rule // all rules, sorted by file name; see Enabled
	Macros     *ql.Macros
	MacroFiles []string
}

// Enabled returns the enabled rules.
func (rs *Ruleset) Enabled() []*Rule {
	var out []*Rule
	for _, r := range rs.Rules {
		if r.IsEnabled() && (rs.Platform == "" || r.AppliesTo(rs.Platform)) {
			out = append(out, r)
		}
	}
	return out
}

// Files returns every file the ruleset was read from.
func (rs *Ruleset) Files() []string {
	out := append([]string{}, rs.MacroFiles...)
	for _, r := range rs.Rules {
		out = append(out, r.File)
	}
	return out
}

// yamlFiles lists *.yml and *.yaml directly inside dir, sorted.
func yamlFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, ".") {
			continue
		}
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out, nil
}

// readLimited reads a rule or fixture file through config.SecureRead: one
// O_NOFOLLOW open, checks on that descriptor (root ownership when ZAAFVesper runs
// as root), and the bytes parsed are the bytes checked.
func readLimited(path string) ([]byte, error) {
	return config.SecureRead(path, MaxRuleFileSize)
}

// decodeStrict decodes exactly one YAML document, rejecting unknown keys.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("file is empty")
		}
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("more than one YAML document (one rule per file)")
	}
	return nil
}

// skipRuleDir reports whether a subdirectory of a rules tree holds something
// other than rules.
func skipRuleDir(name string) bool {
	return name == "macros" || name == "testdata" || name == "yara" || strings.HasPrefix(name, ".")
}

// ruleFiles lists rule files in dir and, recursively, in its subdirectories
// (e.g. rules/windows/, rules/sigma/macos/), skipping macros/, testdata/,
// yara/ and dot directories. Symbolic links are not followed. Sorted.
func ruleFiles(dir string) ([]string, error) {
	out, err := yamlFiles(dir)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() || skipRuleDir(e.Name()) {
			continue
		}
		sub, err := ruleFiles(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	sort.Strings(out)
	return out, nil
}

// LoadDir loads macros from dir/macros/*.yml and rules from dir/*.yml and
// from rule subdirectories (see ruleFiles); macros/, testdata/ and yara/ are
// not rules. All problems are reported together.
func LoadDir(dir string) (*Ruleset, error) {
	rs := &Ruleset{Dir: dir}
	macroFiles, err := yamlFiles(filepath.Join(dir, "macros"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	rs.MacroFiles = macroFiles
	m, err := ql.LoadMacrosWith(config.SecureRead, macroFiles...)
	if err != nil {
		return nil, err
	}
	rs.Macros = m

	files, err := ruleFiles(dir)
	if err != nil {
		return nil, err
	}
	var errs []error
	ids := map[string]string{}
	for _, f := range files {
		r, err := LoadRuleFile(f, m)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, ok := ids[strings.ToLower(r.ID)]; ok {
			errs = append(errs, fmt.Errorf("%s: id %s already used by %s", f, r.ID, prev))
			continue
		}
		ids[strings.ToLower(r.ID)] = f
		rs.Rules = append(rs.Rules, r)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return rs, nil
}

// LoadRuleFile reads, validates and compiles one rule file.
func LoadRuleFile(path string, m *ql.Macros) (*Rule, error) {
	data, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	r := &Rule{}
	if err := decodeStrict(data, r); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	r.File = path
	if err := r.Compile(m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// Compile validates the rule's schema and compiles its condition and output.
func (r *Rule) Compile(m *ql.Macros) error {
	errs := r.validate()
	label := r.Name
	if label == "" {
		label = r.ID
	}
	if strings.TrimSpace(r.Condition) != "" {
		if isSequence(r.Condition) {
			seq, err := parseSequence(r.Condition, m)
			if err != nil {
				errs = append(errs, fmt.Errorf("condition: sequence: %w", err))
			} else {
				r.seq = seq
			}
		} else {
			f, err := ql.Compile(r.Condition, m)
			if err != nil {
				errs = append(errs, fmt.Errorf("condition: %w", err))
			} else {
				r.filter = f
			}
		}
	}
	steps := 0
	if r.seq != nil {
		steps = len(r.seq.Steps)
	}
	if isSequence(r.Condition) && r.seq == nil {
		steps = maxSteps // still check the output template sensibly
	}
	t, err := parseTemplate(r.Output, steps)
	if err != nil {
		errs = append(errs, err)
	} else {
		r.output = t
	}
	if len(errs) > 0 {
		return fmt.Errorf("rule %q: %w", label, errors.Join(errs...))
	}
	return nil
}
