package sigma

import "strings"

// Condition grammar (Sigma 2.1), lowest to highest precedence:
//
//	expr    := and ( "or" and )*
//	and     := not ( "and" not )*
//	not     := "not" not | primary
//	primary := "(" expr ")" | quant | IDENT
//	quant   := ( "1" | "any" | "all" ) "of" ( PATTERN | "them" )
//
// A "|" starts an aggregation, which is not supported. Keywords are lower
// case, as in the specification.

type condNode interface{ isCond() }

type condAnd struct{ l, r condNode }
type condOr struct{ l, r condNode }
type condNot struct{ x condNode }
type condRef struct{ name string }

// condOf is "1 of" / "all of" over the named searches.
type condOf struct {
	all   bool
	names []string
}

func (condAnd) isCond() {}
func (condOr) isCond()  {}
func (condNot) isCond() {}
func (condRef) isCond() {}
func (condOf) isCond()  {}

const maxCondTokens = 1000
const maxCondDepth = 64

type condTok struct {
	text string
	kind int // 0 word, 1 '(', 2 ')'
}

func lexCondition(s string) ([]condTok, error) {
	var out []condTok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, condTok{"(", 1})
			i++
		case c == ')':
			out = append(out, condTok{")", 2})
			i++
		case isCondWordChar(c):
			j := i
			for j < len(s) && isCondWordChar(s[j]) {
				j++
			}
			out = append(out, condTok{s[i:j], 0})
			i = j
		default:
			return nil, invalid("condition: unexpected character %q", rune(c))
		}
		if len(out) > maxCondTokens {
			return nil, invalid("condition has more than %d tokens", maxCondTokens)
		}
	}
	return out, nil
}

func isCondWordChar(c byte) bool {
	return c == '_' || c == '*' || c == '-' || c == '.' || c == '?' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

type condParser struct {
	toks   []condTok
	pos    int
	depth  int
	search []string // search identifier names, in file order
}

// parseCondition parses one condition expression against the rule's search
// identifiers.
func parseCondition(expr string, searches []string) (condNode, error) {
	if strings.Contains(expr, "|") {
		return nil, unsupported("aggregation in condition (%q) is not supported", strings.TrimSpace(expr))
	}
	toks, err := lexCondition(expr)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, invalid("condition is empty")
	}
	p := &condParser{toks: toks, search: searches}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, invalid("condition: unexpected %q", p.toks[p.pos].text)
	}
	return n, nil
}

func (p *condParser) peek() (condTok, bool) {
	if p.pos >= len(p.toks) {
		return condTok{}, false
	}
	return p.toks[p.pos], true
}

func (p *condParser) isWord(w string) bool {
	t, ok := p.peek()
	return ok && t.kind == 0 && t.text == w
}

func (p *condParser) enter() error {
	p.depth++
	if p.depth > maxCondDepth {
		return invalid("condition nested deeper than %d levels", maxCondDepth)
	}
	return nil
}

func (p *condParser) parseOr() (condNode, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isWord("or") {
		p.pos++
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = condOr{l, r}
	}
	return l, nil
}

func (p *condParser) parseAnd() (condNode, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.isWord("and") {
		p.pos++
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = condAnd{l, r}
	}
	return l, nil
}

func (p *condParser) parseNot() (condNode, error) {
	if p.isWord("not") {
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer func() { p.depth-- }()
		p.pos++
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return condNot{x}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condNode, error) {
	t, ok := p.peek()
	if !ok {
		return nil, invalid("condition ends unexpectedly")
	}
	switch t.kind {
	case 1:
		p.pos++
		x, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if c, ok := p.peek(); !ok || c.kind != 2 {
			return nil, invalid("condition: missing ')'")
		}
		p.pos++
		return x, nil
	case 2:
		return nil, invalid("condition: unexpected ')'")
	}
	switch t.text {
	case "and", "or", "not", "of", "them":
		return nil, invalid("condition: unexpected %q", t.text)
	}
	if p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == 0 && p.toks[p.pos+1].text == "of" {
		return p.parseOf(t.text)
	}
	p.pos++
	if strings.ContainsAny(t.text, "*?") {
		return nil, invalid("condition: wildcard %q needs '1 of' or 'all of'", t.text)
	}
	for _, s := range p.search {
		if s == t.text {
			return condRef{t.text}, nil
		}
	}
	return nil, invalid("condition: search identifier %q is not defined", t.text)
}

func (p *condParser) parseOf(quant string) (condNode, error) {
	all := false
	switch quant {
	case "1", "any":
	case "all":
		all = true
	default:
		return nil, unsupported("condition: %q of is not supported (only 1 of, any of, all of)", quant)
	}
	p.pos += 2
	t, ok := p.peek()
	if !ok || t.kind != 0 {
		return nil, invalid("condition: '%s of' needs a pattern or 'them'", quant)
	}
	p.pos++
	var names []string
	if t.text == "them" {
		for _, s := range p.search {
			if !strings.HasPrefix(s, "_") {
				names = append(names, s)
			}
		}
	} else {
		for _, s := range p.search {
			if identMatch(t.text, s) {
				names = append(names, s)
			}
		}
	}
	if len(names) == 0 {
		return nil, invalid("condition: '%s of %s' matches no search identifier", quant, t.text)
	}
	return condOf{all: all, names: names}, nil
}

// identMatch matches a search identifier against a condition pattern where
// '*' is any run of characters and '?' one character.
func identMatch(pat, s string) bool {
	px, sx, starPx, starSx := 0, 0, -1, -1
	for px < len(pat) || sx < len(s) {
		if px < len(pat) {
			switch pat[px] {
			case '*':
				starPx, starSx = px, sx
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			default:
				if sx < len(s) && s[sx] == pat[px] {
					px++
					sx++
					continue
				}
			}
		}
		if starPx >= 0 && starSx < len(s) {
			starSx++
			px, sx = starPx+1, starSx
			continue
		}
		return false
	}
	return true
}
