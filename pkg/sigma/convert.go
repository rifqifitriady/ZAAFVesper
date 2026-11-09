package sigma

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/sigmamap"
	"gopkg.in/yaml.v3"
)

// CategoryMapper maps fields through one pkg/sigmamap category.
type CategoryMapper struct {
	Cat *sigmamap.Category
}

// Field implements FieldMapper.
func (m CategoryMapper) Field(f string) (string, bool) {
	zv, ok := m.Cat.Fields[f]
	return zv, ok
}

// Value implements FieldMapper.
func (m CategoryMapper) Value(f, v string) (string, string, bool) {
	vm, ok := m.Cat.Values[f]
	if !ok {
		return "", "", false
	}
	for k, t := range vm {
		if strings.EqualFold(k, strings.TrimSpace(v)) {
			return t.Field, t.Value, true
		}
	}
	return "", "", false
}

// HasValues implements FieldMapper.
func (m CategoryMapper) HasValues(f string) bool {
	_, ok := m.Cat.Values[f]
	return ok
}

// KeywordFields implements FieldMapper: every string field the category
// maps to, sorted.
func (m CategoryMapper) KeywordFields() []string {
	set := map[string]bool{}
	for _, zv := range m.Cat.Fields {
		if k, ok := fieldKind(zv); ok && (k == event.KindString || k == event.KindStrings) {
			set[zv] = true
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Name implements FieldMapper.
func (m CategoryMapper) Name() string { return "category " + m.Cat.Name }

// Options control a conversion.
type Options struct {
	// Source names the Sigma file (relative path) in labels and messages.
	Source string
}

// Result is one converted rule.
type Result struct {
	// YAML is the ZAAFVesper rule file.
	YAML []byte
	// ID is the ZAAFVesper rule id; SigmaID the original Sigma id.
	ID      string
	SigmaID string
	Title   string
	// Platform is the evt.platform value of the Sigma product.
	Platform string
	Category string
	// Condition is the generated ZAAFVesper condition.
	Condition string
	// Notes are decisions taken during conversion worth reporting.
	Notes []string
}

var levelSeverity = map[string]string{
	"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}

var uuidV4 = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// deriveID makes a stable UUID-v4-shaped id from a Sigma id (or title)
// that is not itself a UUID v4, so the same Sigma rule always converts to
// the same ZAAFVesper id.
func deriveID(seed string) string {
	h := sha256.Sum256([]byte("zaafvesper/sigma/" + seed))
	h[6] = h[6]&0x0f | 0x40
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// outputs are the alert texts per category; the Sigma author is appended
// (DRL 1.1 requires it in messages based on matches).
var outputs = map[string]string{
	"process_creation":   "%ps.exe (pid %ps.pid, parent %ps.parent.exe) ran: %ps.cmdline",
	"file_event":         "%ps.exe (pid %ps.pid) wrote %file.path",
	"file_delete":        "%ps.exe (pid %ps.pid) deleted %file.path",
	"file_rename":        "%ps.exe (pid %ps.pid) renamed %file.path to %file.dest",
	"network_connection": "%ps.exe (pid %ps.pid) %net.direction connection %net.sip:%net.sport -> %net.dip:%net.dport",
	"dns_query":          "%ps.exe (pid %ps.pid) looked up %dns.query",
}

const defaultOutput = "%ps.exe (pid %ps.pid) matched on %evt.name"

// Convert converts a parsed Sigma rule into a ZAAFVesper rule file. It
// returns a *SkipError when the rule cannot be converted exactly.
func Convert(r *Rule, opt Options) (*Result, error) {
	switch r.Status {
	case "deprecated", "unsupported":
		return nil, unsupported("status %q: SigmaHQ does not maintain this rule", r.Status)
	}
	ls := r.Logsource
	if ls.Service != "" {
		return nil, unsupported("logsource service %q is not supported (only product and category)", ls.Service)
	}
	if ls.Product == "" {
		return nil, unsupported("logsource product is missing (macos, windows or linux needed)")
	}
	platform, ok := sigmamap.Products[ls.Product]
	if !ok {
		return nil, unsupported("logsource product %q is not supported (macos, windows, linux)", ls.Product)
	}
	if ls.Category == "" {
		return nil, unsupported("logsource category is missing")
	}
	cat, ok := sigmamap.Categories[ls.Category]
	if !ok {
		return nil, unsupported("logsource category %q is not supported", ls.Category)
	}
	det, err := CompileDetection(r, CategoryMapper{Cat: cat})
	if err != nil {
		return nil, err
	}
	events := append([]string(nil), cat.Events...)
	sort.Strings(events)
	cond := "evt.name in (" + strings.Join(quoteAll(events), ", ") + ") and " + det
	if !strings.HasPrefix(det, "(") || !closesAtEnd(det) {
		cond = "evt.name in (" + strings.Join(quoteAll(events), ", ") + ") and (" + det + ")"
	}

	res := &Result{SigmaID: r.ID, Title: r.Title, Platform: platform, Category: ls.Category, Condition: cond}
	switch {
	case uuidV4.MatchString(r.ID):
		res.ID = strings.ToLower(r.ID)
	case r.ID != "":
		res.ID = deriveID("id:" + r.ID)
		res.Notes = append(res.Notes, fmt.Sprintf("Sigma id %q is not a UUID v4; ZAAFVesper id %s derived from it", r.ID, res.ID))
	default:
		res.ID = deriveID("title:" + r.Title)
		res.Notes = append(res.Notes, "Sigma rule has no id; ZAAFVesper id derived from the title")
	}
	sev, ok := levelSeverity[r.Level]
	if !ok {
		sev = "low"
		res.Notes = append(res.Notes, "Sigma rule has no level; severity set to low")
	}

	labels := map[string]string{"sigma.title": r.Title}
	if r.ID != "" {
		labels["sigma.id"] = r.ID
	}
	if r.Author != "" {
		labels["sigma.author"] = r.Author
	}
	if r.Status != "" {
		labels["sigma.status"] = r.Status
	}
	if r.Level != "" {
		labels["sigma.level"] = r.Level
	}
	if r.License != "" {
		labels["sigma.license"] = r.License
	}
	if opt.Source != "" {
		labels["sigma.source"] = opt.Source
	}
	if len(r.Tags) > 0 {
		labels["sigma.tags"] = strings.Join(r.Tags, ", ")
	}
	att := attackLabels(r.Tags)
	for k, v := range att.labels {
		labels[k] = v
	}
	res.Notes = append(res.Notes, att.notes...)

	desc := strings.TrimSpace(r.Description)
	if desc != "" {
		desc += "\n\n"
	}
	desc += "Converted from Sigma"
	if r.ID != "" {
		desc += " rule " + r.ID
	}
	desc += " by zaafvesper sigma convert."
	if r.Author != "" {
		desc += " Sigma author: " + r.Author + "."
	}
	if r.License != "" {
		desc += " License: " + r.License + "."
	}

	out := outputs[ls.Category]
	if out == "" {
		out = defaultOutput
	}
	if r.Author != "" {
		out += " (Sigma rule by " + strings.ReplaceAll(r.Author, "%", "%%") + ")"
	}

	var notes string
	if len(r.FalsePositives) > 0 {
		notes = "Sigma false positives: " + strings.Join(r.FalsePositives, "; ")
	}

	doc := ruleDoc{
		Name:             r.Title,
		ID:               res.ID,
		Version:          "1.0.0",
		Platforms:        []string{platform},
		Description:      desc,
		Labels:           labels,
		References:       r.References,
		Condition:        cond,
		Output:           out,
		Severity:         sev,
		Action:           []rules.Action{},
		MinEngineVersion: rules.EngineVersion,
		Notes:            notes,
	}
	var buf bytes.Buffer
	buf.WriteString(Header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, invalid("rendering the rule: %v", err)
	}
	if err := enc.Close(); err != nil {
		return nil, invalid("rendering the rule: %v", err)
	}
	if buf.Len() > rules.MaxRuleFileSize {
		return nil, unsupported("converted rule is %d bytes, over the rule loader's %d-byte limit", buf.Len(), rules.MaxRuleFileSize)
	}
	if err := Check(buf.Bytes()); err != nil {
		return nil, unsupported("converted rule does not load in ZAAFVesper: %v", oneLine(err.Error()))
	}
	res.YAML = buf.Bytes()
	return res, nil
}

// Header starts every rule file the converter writes. `sigma convert
// --force` replaces only files that start with it.
const Header = "# Converted from Sigma by zaafvesper sigma convert. Do not edit by hand;\n# re-run the converter instead.\n"

// ruleDoc is the on-disk shape of a ZAAFVesper rule, in the field order of
// the built-in rules.
type ruleDoc struct {
	Name             string            `yaml:"name"`
	ID               string            `yaml:"id"`
	Version          string            `yaml:"version"`
	Platforms        []string          `yaml:"platforms,flow"`
	Description      string            `yaml:"description"`
	Labels           map[string]string `yaml:"labels"`
	References       []string          `yaml:"references,omitempty"`
	Condition        string            `yaml:"condition"`
	Output           string            `yaml:"output"`
	Severity         string            `yaml:"severity"`
	Action           []rules.Action    `yaml:"action,flow"`
	MinEngineVersion string            `yaml:"min-engine-version"`
	Notes            string            `yaml:"notes,omitempty"`
}

// Check loads a rule file the way the rule loader does (strict YAML, schema,
// condition and output) without macros.
func Check(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	r := &rules.Rule{}
	if err := dec.Decode(r); err != nil {
		return err
	}
	return r.Compile(nil)
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = lit(s)
	}
	return out
}
