package sigma

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
	"gopkg.in/yaml.v3"
)

// FieldMapper resolves Sigma field names for one log source.
type FieldMapper interface {
	// Field maps a Sigma field to a ZAAFVesper field: a static field
	// (event.LookupField) or an indexed one such as "evt.arg[x]".
	Field(sigmaField string) (string, bool)
	// Value maps a special value of a Sigma field (for example Initiated
	// "true") to a comparison on another ZAAFVesper field.
	Value(sigmaField, value string) (field, val string, ok bool)
	// HasValues reports whether the Sigma field is handled by Value.
	HasValues(sigmaField string) bool
	// KeywordFields are the string fields a keyword search looks in.
	KeywordFields() []string
	// Name names the log source in messages.
	Name() string
}

// Modifiers ZAAFVesper converts.
var supportedModifiers = map[string]bool{
	"contains": true, "startswith": true, "endswith": true, "all": true,
	"re": true, "i": true, "m": true, "s": true, "cidr": true, "windash": true,
	"exists": true, "cased": true, "neq": true,
}

// Valid Sigma modifiers ZAAFVesper does not convert.
var knownUnsupported = map[string]bool{
	"base64": true, "base64offset": true, "wide": true, "utf16": true, "utf16le": true,
	"utf16be": true, "fieldref": true, "expand": true, "lt": true, "lte": true, "gt": true,
	"gte": true, "minute": true, "hour": true, "day": true, "week": true, "month": true, "year": true,
}

// modifiers is the parsed modifier chain of one field.
type modifiers struct {
	str     string // "", "contains", "startswith" or "endswith"
	all     bool
	re      bool
	reFlags string // subset of "ims"
	cidr    bool
	windash bool
	exists  bool
	cased   bool
	neq     bool
}

func parseModifiers(field string, mods []string) (modifiers, error) {
	var m modifiers
	seen := map[string]bool{}
	var unsup []string
	for _, mod := range mods {
		if seen[mod] {
			return m, invalid("field %q: modifier %q given twice", field, mod)
		}
		seen[mod] = true
		switch {
		case supportedModifiers[mod]:
		case knownUnsupported[mod]:
			unsup = append(unsup, mod)
			continue
		default:
			return m, invalid("field %q: unknown modifier %q", field, mod)
		}
		switch mod {
		case "contains", "startswith", "endswith":
			if m.str != "" {
				return m, invalid("field %q: more than one of contains, startswith, endswith", field)
			}
			m.str = mod
		case "all":
			m.all = true
		case "re":
			m.re = true
		case "i", "m", "s":
			m.reFlags += mod
		case "cidr":
			m.cidr = true
		case "windash":
			m.windash = true
		case "exists":
			m.exists = true
		case "cased":
			m.cased = true
		case "neq":
			m.neq = true
		}
	}
	// Combinations whose effect would be silently ignored are rule errors
	// (ZAAFElegia conformance interpretations 10 and 15).
	numericOrTime := false
	for _, u := range unsup {
		switch u {
		case "lt", "lte", "gt", "gte", "minute", "hour", "day", "week", "month", "year":
			numericOrTime = true
		}
	}
	strTransform := m.str != "" || m.windash || m.cased || seen["base64"] || seen["base64offset"] ||
		seen["wide"] || seen["utf16"] || seen["utf16le"] || seen["utf16be"]
	switch {
	case m.reFlags != "" && !m.re:
		return m, invalid("field %q: regex flag modifier without re", field)
	case m.exists && len(mods) > 1:
		return m, invalid("field %q: exists cannot be combined with other modifiers", field)
	case m.re && (strTransform || m.cidr):
		return m, invalid("field %q: re cannot be combined with string or cidr modifiers", field)
	case m.cidr && (strTransform || m.re):
		return m, invalid("field %q: cidr cannot be combined with string modifiers", field)
	case numericOrTime && (strTransform || m.re || m.cidr):
		return m, invalid("field %q: numeric or time modifiers cannot be combined with string modifiers", field)
	}
	if len(unsup) > 0 {
		return m, unsupported("field %q: modifier %s is not supported", field, strings.Join(unsup, ", "))
	}
	return m, nil
}

// compiler turns a rule's detection into a ZAAFVesper condition.
type compiler struct {
	r      *Rule
	m      FieldMapper
	byName map[string]*yaml.Node
	cache  map[string]string
}

// CompileDetection compiles the rule's detection and condition into a
// ZAAFVesper condition (without any evt.name constraint).
func CompileDetection(r *Rule, m FieldMapper) (string, error) {
	c := &compiler{r: r, m: m, byName: map[string]*yaml.Node{}, cache: map[string]string{}}
	names := make([]string, 0, len(r.Searches))
	for _, s := range r.Searches {
		c.byName[s.Name] = s.Node
		names = append(names, s.Name)
	}
	var parts []string
	total := 0
	for _, expr := range r.Conditions {
		n, err := parseCondition(expr, names)
		if err != nil {
			return "", err
		}
		q, err := c.cond(n)
		if err != nil {
			return "", err
		}
		if total += len(q) + 4; total > MaxOutputCondition {
			return "", tooLong()
		}
		parts = append(parts, q)
	}
	// Every search identifier must compile, even one the condition does not
	// use: a broken search means a broken rule.
	for _, n := range names {
		if _, err := c.search(n); err != nil {
			return "", err
		}
	}
	return checkedJoin(parts, " or ")
}

// tooLong is the error for a condition over MaxOutputCondition. Every join
// checks the size of its result before building it, so a small rule that
// would expand into a huge condition is refused early and cheaply.
func tooLong() error {
	return unsupported("converted condition is longer than %d bytes", MaxOutputCondition)
}

// checkedJoin joins like andJoin/orJoin, refusing a result over the limit
// before it is built.
func checkedJoin(parts []string, sep string) (string, error) {
	n := 2
	for _, p := range parts {
		n += len(p) + len(sep)
		if n > MaxOutputCondition {
			return "", tooLong()
		}
	}
	return join(parts, sep), nil
}

func (c *compiler) cond(n condNode) (string, error) {
	switch n := n.(type) {
	case condAnd:
		l, err := c.cond(n.l)
		if err != nil {
			return "", err
		}
		r, err := c.cond(n.r)
		if err != nil {
			return "", err
		}
		return checkedJoin([]string{l, r}, " and ")
	case condOr:
		l, err := c.cond(n.l)
		if err != nil {
			return "", err
		}
		r, err := c.cond(n.r)
		if err != nil {
			return "", err
		}
		return checkedJoin([]string{l, r}, " or ")
	case condNot:
		x, err := c.cond(n.x)
		if err != nil {
			return "", err
		}
		if len(x)+8 > MaxOutputCondition {
			return "", tooLong()
		}
		return notOf(x), nil
	case condRef:
		return c.search(n.name)
	case condOf:
		parts := make([]string, 0, len(n.names))
		for _, name := range n.names {
			q, err := c.search(name)
			if err != nil {
				return "", err
			}
			parts = append(parts, q)
		}
		if n.all {
			return checkedJoin(parts, " and ")
		}
		return checkedJoin(parts, " or ")
	}
	return "", invalid("condition: internal error")
}

func (c *compiler) search(name string) (string, error) {
	if q, ok := c.cache[name]; ok {
		return q, nil
	}
	node := c.byName[name]
	var q string
	var err error
	switch node.Kind {
	case yaml.MappingNode:
		q, err = c.fieldMap(name, node)
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return "", invalid("search %q is an empty list", name)
		}
		if node.Content[0].Kind == yaml.MappingNode {
			parts := make([]string, 0, len(node.Content))
			for _, el := range node.Content {
				if el.Kind != yaml.MappingNode {
					return "", invalid("search %q mixes maps and values in one list", name)
				}
				p, err := c.fieldMap(name, el)
				if err != nil {
					return "", err
				}
				parts = append(parts, p)
			}
			q, err = checkedJoin(parts, " or ")
		} else {
			q, err = c.keywords(name, modifiers{}, node.Content)
		}
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			return "", invalid("search %q is empty", name)
		}
		q, err = c.keywords(name, modifiers{}, []*yaml.Node{node})
	default:
		return "", invalid("search %q has an unexpected YAML type", name)
	}
	if err != nil {
		return "", err
	}
	if len(q) > MaxOutputCondition {
		return "", tooLong()
	}
	c.cache[name] = q
	return q, nil
}

func (c *compiler) fieldMap(name string, node *yaml.Node) (string, error) {
	if len(node.Content) == 0 {
		return "", invalid("search %q is an empty map", name)
	}
	parts := make([]string, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, val := node.Content[i].Value, node.Content[i+1]
		segs := strings.Split(key, "|")
		field, mods := segs[0], segs[1:]
		m, err := parseModifiers(field, mods)
		if err != nil {
			return "", err
		}
		vals, isNull, err := values(name, key, val, m)
		if err != nil {
			return "", err
		}
		var q string
		if field == "" {
			if isNull {
				return "", invalid("search %q: keyword search cannot be null", name)
			}
			q, err = c.keywords(name, m, vals)
		} else {
			q, err = c.field(field, m, vals, isNull)
		}
		if err != nil {
			return "", err
		}
		parts = append(parts, q)
	}
	return checkedJoin(parts, " and ")
}

// values returns the scalar value nodes of a field. isNull is a single null.
func values(search, key string, n *yaml.Node, m modifiers) ([]*yaml.Node, bool, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			if m != (modifiers{}) {
				return nil, false, invalid("search %q: %s: null cannot take modifiers", search, key)
			}
			return nil, true, nil
		}
		if m.all {
			return nil, false, invalid("search %q: %s: all needs a list of values", search, key)
		}
		if err := checkValueLen(n); err != nil {
			return nil, false, err
		}
		return []*yaml.Node{n}, false, nil
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			return nil, false, invalid("search %q: %s: empty value list", search, key)
		}
		for _, v := range n.Content {
			if v.Kind != yaml.ScalarNode {
				return nil, false, invalid("search %q: %s: values must be scalars", search, key)
			}
			if v.Tag == "!!null" {
				return nil, false, invalid("search %q: %s: null is not allowed inside a value list", search, key)
			}
			if err := checkValueLen(v); err != nil {
				return nil, false, err
			}
		}
		return n.Content, false, nil
	}
	return nil, false, invalid("search %q: %s: value must be a scalar or a list", search, key)
}

func checkValueLen(n *yaml.Node) error {
	if len(n.Value) > MaxValueLen {
		return invalid("value at line %d is longer than %d bytes", n.Line, MaxValueLen)
	}
	return nil
}

// fieldKind returns the kind of a ZAAFVesper field (indexed fields are strings).
func fieldKind(zv string) (event.FieldKind, bool) {
	if i := strings.IndexByte(zv, '['); i > 0 && strings.HasSuffix(zv, "]") {
		root := zv[:i]
		for _, r := range event.IndexedRoots {
			if r == root {
				return event.KindString, true
			}
		}
		return 0, false
	}
	return event.LookupField(zv)
}

// presence is true when the field is reported on the event.
func presence(zv string, k event.FieldKind) string {
	switch k {
	case event.KindInt:
		return "(" + zv + " >= 0 or " + zv + " < 0)"
	case event.KindBool:
		return "(" + zv + " = true or " + zv + " = false)"
	}
	return zv + " imatches '*'"
}

func (c *compiler) field(field string, m modifiers, vals []*yaml.Node, isNull bool) (string, error) {
	if c.m.HasValues(field) {
		if _, ok := c.m.Field(field); !ok {
			return c.valueMapped(field, m, vals, isNull)
		}
	}
	zv, ok := c.m.Field(field)
	if !ok {
		return "", unsupported("field %q has no ZAAFVesper mapping for %s", field, c.m.Name())
	}
	kind, ok := fieldKind(zv)
	if !ok {
		return "", unsupported("field %q maps to %q, which is not a ZAAFVesper field", field, zv)
	}
	if isNull {
		return notOf(presence(zv, kind)), nil
	}
	if m.exists {
		if len(vals) != 1 || vals[0].Tag != "!!bool" {
			return "", invalid("field %q: exists needs true or false", field)
		}
		b, _ := strconv.ParseBool(vals[0].Value)
		if b {
			return presence(zv, kind), nil
		}
		return notOf(presence(zv, kind)), nil
	}
	if m.neq && len(vals) > 1 {
		return "", unsupported("field %q: neq with a list of values is not supported", field)
	}
	var q string
	var err error
	switch kind {
	case event.KindString, event.KindStrings:
		q, err = stringField(zv, field, m, vals)
	case event.KindInt:
		q, err = intField(zv, field, m, vals)
	case event.KindBool:
		q, err = boolField(zv, field, m, vals)
	default:
		err = unsupported("field %q: unsupported field type", field)
	}
	if err != nil {
		return "", err
	}
	if m.neq {
		return notOf(q), nil
	}
	return q, nil
}

func (c *compiler) valueMapped(field string, m modifiers, vals []*yaml.Node, isNull bool) (string, error) {
	if isNull || m != (modifiers{}) {
		return "", unsupported("field %q only supports plain values on %s", field, c.m.Name())
	}
	var parts []string
	for _, v := range vals {
		zf, zval, ok := c.m.Value(field, v.Value)
		if !ok {
			return "", unsupported("field %q: value %q has no ZAAFVesper mapping", field, v.Value)
		}
		kind, ok := fieldKind(zf)
		if !ok || (kind != event.KindString && kind != event.KindStrings) {
			return "", unsupported("field %q maps to %q, which is not a string field", field, zf)
		}
		parts = append(parts, zf+" iin ("+lit(zval)+")")
	}
	return orJoin(parts), nil
}

// ---- string values ----

// patTok is a piece of a Sigma string value: literal text or a wildcard.
type patTok struct {
	wild byte // 0 literal, '*' or '?'
	s    string
}

// parsePattern splits a Sigma string into literals and wildcards. "\*",
// "\?" and "\\" are escapes; a backslash before any other character is a
// literal backslash (Sigma 2.1 escaping, conformance case 005).
func parsePattern(s string) []patTok {
	var out []patTok
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, patTok{s: b.String()})
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteByte(s[i+1])
			i++
		case ch == '*' || ch == '?':
			flush()
			if ch == '*' && len(out) > 0 && out[len(out)-1].wild == '*' {
				continue
			}
			out = append(out, patTok{wild: ch})
		default:
			b.WriteByte(ch)
		}
	}
	flush()
	return out
}

func hasWild(p []patTok) bool {
	for _, t := range p {
		if t.wild != 0 {
			return true
		}
	}
	return false
}

func literal(p []patTok) string {
	var b strings.Builder
	for _, t := range p {
		b.WriteString(t.s)
	}
	return b.String()
}

// strMatch is one ZAAFVesper string comparison: op and pattern.
type strMatch struct {
	op  string
	val string
}

// stringMatch converts one Sigma string value with a string modifier into a
// ZAAFVesper comparison.
func stringMatch(s, strMod string, cased bool) strMatch {
	p := parsePattern(s)
	pre := func(op string) string {
		if cased {
			return op
		}
		return "i" + op
	}
	if !hasWild(p) {
		v := literal(p)
		switch strMod {
		case "contains", "startswith", "endswith":
			return strMatch{pre(strMod), v}
		}
		if cased {
			return strMatch{"in", v}
		}
		return strMatch{"iin", v}
	}
	star := patTok{wild: '*'}
	switch strMod {
	case "contains":
		p = append(append([]patTok{star}, p...), star)
	case "startswith":
		p = append(p, star)
	case "endswith":
		p = append([]patTok{star}, p...)
	}
	globOK := true
	for _, t := range p {
		if t.wild == 0 && strings.ContainsAny(t.s, "*?") {
			globOK = false
		}
	}
	if globOK {
		var b strings.Builder
		for i, t := range p {
			if t.wild == '*' && i > 0 && p[i-1].wild == '*' {
				continue
			}
			if t.wild != 0 {
				b.WriteByte(t.wild)
			} else {
				b.WriteString(t.s)
			}
		}
		return strMatch{pre("matches"), b.String()}
	}
	var b strings.Builder
	b.WriteString("(?s")
	if !cased {
		b.WriteString("i")
	}
	b.WriteString(")^")
	for _, t := range p {
		switch t.wild {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(t.s))
		}
	}
	b.WriteString("$")
	return strMatch{"regex", b.String()}
}

// renderMatches ORs comparisons, grouping values that share an operator.
func renderMatches(zv string, ms []strMatch) string {
	var order []string
	groups := map[string][]string{}
	for _, m := range ms {
		if _, ok := groups[m.op]; !ok {
			order = append(order, m.op)
		}
		groups[m.op] = append(groups[m.op], m.val)
	}
	parts := make([]string, 0, len(order))
	for _, op := range order {
		vals := litList(groups[op])
		if (op == "in" || op == "iin") && len(groups[op]) == 1 {
			vals = "(" + vals + ")"
		}
		parts = append(parts, zv+" "+op+" "+vals)
	}
	return orJoin(parts)
}

const maxWindashVariants = 625

var windashChars = []string{"-", "/", "–", "—", "―"}

func isWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

// windashPositions returns the indexes of flag dashes in s.
func windashPositions(s string) []int {
	var pos []int
	for i := 0; i < len(s); i++ {
		if (s[i] == '-' || s[i] == '/') && (i == 0 || !isWordByte(s[i-1])) && i+1 < len(s) && isWordByte(s[i+1]) {
			pos = append(pos, i)
		}
	}
	return pos
}

// windashCount is the number of variants windashVariants returns for s,
// saturated just above maxWindashVariants.
func windashCount(s string) int {
	n := 1
	for range windashPositions(s) {
		if n *= len(windashChars); n > maxWindashVariants {
			return maxWindashVariants + 1
		}
	}
	return n
}

// windashVariants expands every flag dash ('-' or '/' at the start of a
// word, as pySigma's regex \B[-/]\b) into -, /, en dash, em dash and
// horizontal bar.
func windashVariants(s string) ([]string, error) {
	pos := windashPositions(s)
	if len(pos) == 0 {
		return []string{s}, nil
	}
	n := 1
	for range pos {
		n *= len(windashChars)
		if n > maxWindashVariants {
			return nil, unsupported("windash value %q has too many dashes", s)
		}
	}
	out := []string{""}
	last := 0
	for _, p := range pos {
		seg := s[last:p]
		next := make([]string, 0, len(out)*len(windashChars))
		for _, o := range out {
			for _, d := range windashChars {
				next = append(next, o+seg+d)
			}
		}
		out = next
		last = p + 1
	}
	for i := range out {
		out[i] += s[last:]
	}
	return out, nil
}

func stringField(zv, field string, m modifiers, vals []*yaml.Node) (string, error) {
	switch {
	case m.re:
		return regexField(zv, field, m, vals)
	case m.cidr:
		return cidrField(zv, field, m, vals)
	}
	// Each original value becomes a group of variants (windash); values are
	// OR-ed, or AND-ed with all, and variants are always OR-ed. The size of
	// the expansion is estimated before anything is built.
	est := 0
	for _, v := range vals {
		n := 1
		if m.windash {
			n = windashCount(v.Value)
		}
		est += n * (len(zv) + 2*len(v.Value) + 16)
		if n > maxWindashVariants {
			return "", unsupported("windash value %q has too many dashes", v.Value)
		}
		if est > MaxOutputCondition {
			return "", tooLong()
		}
	}
	groups := make([][]strMatch, 0, len(vals))
	for _, v := range vals {
		variants := []string{v.Value}
		if m.windash {
			var err error
			if variants, err = windashVariants(v.Value); err != nil {
				return "", err
			}
		}
		g := make([]strMatch, 0, len(variants))
		for _, s := range variants {
			g = append(g, stringMatch(s, m.str, m.cased))
		}
		groups = append(groups, g)
	}
	if m.all {
		parts := make([]string, 0, len(groups))
		for _, g := range groups {
			parts = append(parts, renderMatches(zv, g))
		}
		return checkedJoin(parts, " and ")
	}
	var flat []strMatch
	for _, g := range groups {
		flat = append(flat, g...)
	}
	return renderMatches(zv, flat), nil
}

func regexField(zv, field string, m modifiers, vals []*yaml.Node) (string, error) {
	flags := ""
	for _, f := range "ims" {
		if strings.ContainsRune(m.reFlags, f) {
			flags += string(f)
		}
	}
	pats := make([]string, 0, len(vals))
	for _, v := range vals {
		if v.Tag != "!!str" {
			return "", invalid("field %q: re needs string values", field)
		}
		p := v.Value
		if flags != "" {
			p = "(?" + flags + ")" + p
		}
		if _, err := regexp.Compile(p); err != nil {
			return "", unsupported("field %q: regular expression %q is not RE2 syntax: %v", field, v.Value, err)
		}
		pats = append(pats, p)
	}
	if m.all {
		parts := make([]string, 0, len(pats))
		for _, p := range pats {
			parts = append(parts, zv+" regex "+lit(p))
		}
		return andJoin(parts), nil
	}
	return zv + " regex " + litList(pats), nil
}

const octetRE = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`

// cidrRegex returns an anchored regular expression matching the canonical
// dotted-quad text of every IPv4 address in the prefix, also written as an
// IPv4-mapped IPv6 address (::ffff:a.b.c.d).
func cidrRegex(pfx netip.Prefix) string {
	a := pfx.Addr().As4()
	bits := pfx.Bits()
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		lo := i * 8
		switch {
		case bits >= lo+8:
			parts[i] = strconv.Itoa(int(a[i]))
		case bits <= lo:
			parts[i] = octetRE
		default:
			block := 1 << (lo + 8 - bits)
			start := int(a[i]) &^ (block - 1)
			alts := make([]string, 0, block)
			for v := start; v < start+block; v++ {
				alts = append(alts, strconv.Itoa(v))
			}
			parts[i] = "(?:" + strings.Join(alts, "|") + ")"
		}
	}
	return `^(?i:::ffff:)?` + strings.Join(parts, `\.`) + `$`
}

func cidrField(zv, field string, m modifiers, vals []*yaml.Node) (string, error) {
	res := make([]string, 0, len(vals))
	size := 0
	for _, v := range vals {
		s := strings.TrimSpace(v.Value)
		var pfx netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			pfx, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(s)
			if err == nil {
				pfx = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return "", invalid("field %q: %q is not an IP address or CIDR range", field, v.Value)
		}
		if pfx.Addr().Is4In6() && pfx.Bits() >= 96 {
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
		}
		if !pfx.Addr().Is4() {
			return "", unsupported("field %q: IPv6 cidr %q is not supported (ZAAFVesper has no address-range operator yet)", field, v.Value)
		}
		r := cidrRegex(pfx.Masked())
		if size += len(r) + len(zv) + 16; size > MaxOutputCondition {
			return "", tooLong()
		}
		res = append(res, r)
	}
	if m.all {
		parts := make([]string, 0, len(res))
		for _, r := range res {
			parts = append(parts, zv+" regex "+lit(r))
		}
		return andJoin(parts), nil
	}
	return zv + " regex " + litList(res), nil
}

// ---- integer and boolean fields ----

func intField(zv, field string, m modifiers, vals []*yaml.Node) (string, error) {
	if m.str != "" || m.re || m.cidr || m.windash || m.cased {
		return "", unsupported("field %q is a number in ZAAFVesper; string modifiers are not supported on it", field)
	}
	nums := make([]string, 0, len(vals))
	for _, v := range vals {
		n, err := strconv.ParseInt(strings.TrimSpace(v.Value), 10, 64)
		if err != nil {
			return "", unsupported("field %q is a number in ZAAFVesper; value %q is not an integer", field, v.Value)
		}
		nums = append(nums, strconv.FormatInt(n, 10))
	}
	if m.all {
		parts := make([]string, 0, len(nums))
		for _, n := range nums {
			parts = append(parts, zv+" = "+n)
		}
		return andJoin(parts), nil
	}
	return zv + " in (" + strings.Join(nums, ", ") + ")", nil
}

func boolField(zv, field string, m modifiers, vals []*yaml.Node) (string, error) {
	if m.str != "" || m.re || m.cidr || m.windash || m.cased || m.all {
		return "", unsupported("field %q is a boolean in ZAAFVesper; modifiers are not supported on it", field)
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		switch strings.ToLower(strings.TrimSpace(v.Value)) {
		case "true":
			parts = append(parts, zv+" = true")
		case "false":
			parts = append(parts, zv+" = false")
		default:
			return "", unsupported("field %q is a boolean in ZAAFVesper; value %q is not true or false", field, v.Value)
		}
	}
	return orJoin(parts), nil
}

// ---- keywords ----

// keywords compiles a keyword search: every value is a case-insensitive
// substring search over every string field of the log source (ZAAFElegia
// conformance interpretation 1). Values are OR-ed, or AND-ed with all.
func (c *compiler) keywords(search string, m modifiers, vals []*yaml.Node) (string, error) {
	if m.str != "" || m.re || m.cidr || m.windash || m.exists || m.neq || m.cased {
		return "", unsupported("search %q: keyword searches only support the all modifier", search)
	}
	fields := c.m.KeywordFields()
	if len(fields) == 0 {
		return "", unsupported("search %q: keyword search has no fields to search on %s", search, c.m.Name())
	}
	est := 0
	for _, v := range vals {
		if v.Tag == "!!null" {
			return "", invalid("search %q: null keyword", search)
		}
		for _, f := range fields {
			est += len(f) + 2*len(v.Value) + 24
		}
		if est > MaxOutputCondition {
			return "", tooLong()
		}
	}
	one := func(ms []strMatch) string {
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			parts = append(parts, renderMatches(f, ms))
		}
		return orJoin(parts)
	}
	if m.all {
		parts := make([]string, 0, len(vals))
		for _, v := range vals {
			parts = append(parts, one([]strMatch{stringMatch(v.Value, "contains", false)}))
		}
		return checkedJoin(parts, " and ")
	}
	ms := make([]strMatch, 0, len(vals))
	for _, v := range vals {
		ms = append(ms, stringMatch(v.Value, "contains", false))
	}
	return one(ms), nil
}

// ---- rendering ----

func lit(s string) string { return ql.Lit{Kind: ql.LitString, S: s}.String() }

func litList(vals []string) string {
	if len(vals) == 1 {
		return lit(vals[0])
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = lit(v)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func andJoin(parts []string) string { return join(parts, " and ") }
func orJoin(parts []string) string  { return join(parts, " or ") }

func join(parts []string, sep string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, sep) + ")"
}

func notOf(x string) string {
	if strings.HasPrefix(x, "(") && closesAtEnd(x) {
		return "not " + x
	}
	return "not (" + x + ")"
}

// closesAtEnd reports whether the '(' at x[0] is closed by the last byte.
func closesAtEnd(x string) bool {
	depth := 0
	inStr := false
	for i := 0; i < len(x); i++ {
		ch := x[i]
		if inStr {
			if ch == '\\' {
				i++
				continue
			}
			if ch == '\'' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '\'':
			inStr = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(x)-1 {
				return false
			}
		}
	}
	return depth == 0
}
