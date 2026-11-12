// Package sigma converts Sigma detection rules (Sigma 2.1 rule format) into
// ZAAFVesper rules. It parses a rule strictly, compiles its detection into a
// ZAAFVesper condition (pkg/filter/ql) through a FieldMapper, normally the
// pkg/sigmamap tables, and renders the result as a ZAAFVesper rule file.
//
// Everything a rule needs that ZAAFVesper cannot express exactly is refused
// with a *SkipError instead of being approximated.
//
// Sigma rule files are untrusted input: parsing is bounded in size, depth,
// node count and value count, YAML anchors and aliases are refused, and
// regular expressions are RE2 only.
package sigma

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Bounds on untrusted input.
const (
	// MaxRuleBytes bounds one Sigma rule file.
	MaxRuleBytes = 1 << 20
	// MaxDepth bounds YAML nesting.
	MaxDepth = 32
	// MaxNodes bounds the number of YAML nodes in one rule.
	MaxNodes = 20000
	// MaxConditionLen bounds a Sigma condition expression.
	MaxConditionLen = 4096
	// MaxValueLen bounds one detection value (string or regex).
	MaxValueLen = 4096
	// MaxOutputCondition bounds the generated ZAAFVesper condition, so the
	// rule file stays well under the rule loader's 1 MiB limit.
	MaxOutputCondition = 256 << 10
)

// Kinds of SkipError.
const (
	// KindInvalid: the rule is not valid Sigma (or uses a modifier
	// combination the Sigma specification makes meaningless).
	KindInvalid = "invalid"
	// KindUnsupported: valid Sigma that ZAAFVesper cannot express exactly.
	KindUnsupported = "unsupported"
)

// SkipError explains why a rule was not converted.
type SkipError struct {
	Kind   string // KindInvalid or KindUnsupported
	Reason string
}

func (e *SkipError) Error() string { return e.Kind + ": " + e.Reason }

func invalid(format string, args ...any) error {
	return &SkipError{Kind: KindInvalid, Reason: fmt.Sprintf(format, args...)}
}

func unsupported(format string, args ...any) error {
	return &SkipError{Kind: KindUnsupported, Reason: fmt.Sprintf(format, args...)}
}

// AsSkip returns err as a *SkipError, wrapping any other error as invalid.
func AsSkip(err error) *SkipError {
	if err == nil {
		return nil
	}
	var se *SkipError
	if errors.As(err, &se) {
		return se
	}
	return &SkipError{Kind: KindInvalid, Reason: err.Error()}
}

// Logsource is a Sigma rule's logsource.
type Logsource struct {
	Product  string
	Category string
	Service  string
}

// Rule is a parsed Sigma rule. Detection keeps the YAML nodes; Compile reads
// them.
type Rule struct {
	Title          string
	ID             string
	Status         string
	Description    string
	License        string
	Author         string
	References     []string
	Date           string
	Modified       string
	Tags           []string
	Level          string
	FalsePositives []string
	Logsource      Logsource

	// Searches are the detection's search identifiers, in file order.
	Searches []Search
	// Conditions are the condition expressions (a list is OR-ed).
	Conditions []string
}

// Search is one named search identifier of the detection section.
type Search struct {
	Name string
	Node *yaml.Node
}

var knownTop = map[string]bool{
	"title": true, "id": true, "name": true, "related": true, "taxonomy": true, "status": true,
	"description": true, "license": true, "author": true, "references": true, "date": true,
	"modified": true, "logsource": true, "detection": true, "fields": true, "falsepositives": true,
	"level": true, "tags": true, "scope": true,
}

var statuses = map[string]bool{"stable": true, "test": true, "experimental": true, "deprecated": true, "unsupported": true}

var levels = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}

// Parse reads one Sigma rule strictly: exactly one YAML document, a mapping
// at the top, no anchors or aliases, no duplicate keys, the documented type
// for every known attribute, and the bounds above. Unknown top-level
// attributes are allowed (Sigma permits custom attributes) and ignored.
func Parse(data []byte) (*Rule, error) {
	if len(data) > MaxRuleBytes {
		return nil, invalid("rule file larger than %d bytes", MaxRuleBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, invalid("file is empty")
		}
		return nil, invalid("YAML: %v", oneLine(err.Error()))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, unsupported("more than one YAML document (Sigma rule collections are not supported)")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, invalid("not a YAML document")
	}
	count := 0
	if err := checkTree(doc.Content[0], 0, &count); err != nil {
		return nil, err
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, invalid("a Sigma rule must be a YAML mapping")
	}
	r := &Rule{}
	var detection *yaml.Node
	var logsource *yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i], top.Content[i+1]
		key := k.Value
		var err error
		switch key {
		case "title":
			r.Title, err = scalarString(key, v)
		case "id":
			r.ID, err = scalarString(key, v)
		case "status":
			r.Status, err = scalarString(key, v)
			if err == nil && !statuses[r.Status] {
				err = invalid("status %q is not one of stable, test, experimental, deprecated, unsupported", r.Status)
			}
		case "description":
			r.Description, err = scalarString(key, v)
		case "license":
			r.License, err = scalarString(key, v)
		case "author":
			r.Author, err = scalarString(key, v)
		case "date":
			r.Date, err = scalarString(key, v)
		case "modified":
			r.Modified, err = scalarString(key, v)
		case "level":
			r.Level, err = scalarString(key, v)
			if err == nil && !levels[r.Level] {
				err = invalid("level %q is not one of informational, low, medium, high, critical", r.Level)
			}
		case "references":
			r.References, err = stringList(key, v, false)
		case "tags":
			r.Tags, err = stringList(key, v, false)
		case "falsepositives":
			r.FalsePositives, err = stringList(key, v, true)
		case "logsource":
			logsource = v
		case "detection":
			detection = v
		case "correlation":
			return nil, unsupported("correlation rules are not supported")
		case "filter":
			return nil, unsupported("Sigma filter (meta) rules are not supported")
		default:
			if !knownTop[key] {
				continue // custom attribute
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(r.Title) == "" {
		return nil, invalid("title is required")
	}
	if len(r.Title) > 256 {
		return nil, invalid("title longer than 256 characters")
	}
	if logsource == nil {
		return nil, invalid("logsource is required")
	}
	if err := parseLogsource(r, logsource); err != nil {
		return nil, err
	}
	if detection == nil {
		return nil, invalid("detection is required")
	}
	if err := parseDetection(r, detection); err != nil {
		return nil, err
	}
	return r, nil
}

// checkTree enforces depth and node-count bounds and refuses anchors,
// aliases, merge keys and duplicate mapping keys anywhere in the document.
func checkTree(n *yaml.Node, depth int, count *int) error {
	*count++
	if *count > MaxNodes {
		return invalid("more than %d YAML nodes", MaxNodes)
	}
	if depth > MaxDepth {
		return invalid("YAML nested deeper than %d levels", MaxDepth)
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return invalid("YAML anchors and aliases are not allowed in Sigma rules (line %d)", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return invalid("mapping key at line %d is not a scalar", k.Line)
			}
			if k.Tag == "!!merge" || (k.Value == "<<" && k.Style == 0) {
				return invalid("YAML merge keys are not allowed (line %d)", k.Line)
			}
			if seen[k.Value] {
				return invalid("duplicate key %q at line %d", k.Value, k.Line)
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := checkTree(c, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func scalarString(key string, v *yaml.Node) (string, error) {
	if v.Kind != yaml.ScalarNode || v.Tag == "!!null" {
		return "", invalid("%s must be a string", key)
	}
	if len(v.Value) > 64<<10 {
		return "", invalid("%s is too long", key)
	}
	return v.Value, nil
}

func stringList(key string, v *yaml.Node, allowScalar bool) ([]string, error) {
	if allowScalar && v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
		return []string{v.Value}, nil
	}
	if v.Kind != yaml.SequenceNode {
		return nil, invalid("%s must be a list of strings", key)
	}
	out := make([]string, 0, len(v.Content))
	for _, c := range v.Content {
		if c.Kind != yaml.ScalarNode || c.Tag == "!!null" {
			return nil, invalid("%s must be a list of strings", key)
		}
		out = append(out, c.Value)
	}
	return out, nil
}

func parseLogsource(r *Rule, n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return invalid("logsource must be a mapping")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		s, err := scalarString("logsource."+k, v)
		if err != nil {
			return err
		}
		switch k {
		case "product":
			r.Logsource.Product = s
		case "category":
			r.Logsource.Category = s
		case "service":
			r.Logsource.Service = s
		case "definition":
		default:
			// Custom logsource attributes are allowed by Sigma but change
			// what the rule applies to, so they cannot be ignored.
			return unsupported("logsource attribute %q is not supported", k)
		}
	}
	return nil
}

func parseDetection(r *Rule, n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return invalid("detection must be a mapping")
	}
	var cond *yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		switch k {
		case "condition":
			cond = v
		case "timeframe":
			return unsupported("detection.timeframe (aggregation window) is not supported")
		default:
			if k == "" {
				return invalid("empty search identifier")
			}
			r.Searches = append(r.Searches, Search{Name: k, Node: v})
		}
	}
	if cond == nil {
		return invalid("detection.condition is required")
	}
	switch cond.Kind {
	case yaml.ScalarNode:
		if cond.Tag == "!!null" || strings.TrimSpace(cond.Value) == "" {
			return invalid("detection.condition is empty")
		}
		r.Conditions = []string{cond.Value}
	case yaml.SequenceNode:
		if len(cond.Content) == 0 {
			return invalid("detection.condition is an empty list")
		}
		for _, c := range cond.Content {
			if c.Kind != yaml.ScalarNode || c.Tag == "!!null" || strings.TrimSpace(c.Value) == "" {
				return invalid("detection.condition list must hold non-empty strings")
			}
			r.Conditions = append(r.Conditions, c.Value)
		}
	default:
		return invalid("detection.condition must be a string or a list of strings")
	}
	for _, c := range r.Conditions {
		if len(c) > MaxConditionLen {
			return invalid("condition longer than %d bytes", MaxConditionLen)
		}
	}
	if len(r.Searches) == 0 {
		return invalid("detection has no search identifiers")
	}
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
