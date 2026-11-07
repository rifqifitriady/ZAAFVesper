package ql

import (
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

const (
	maxNesting    = 128 // parentheses / not / function nesting
	maxMacroDepth = 32  // macro-in-macro expansion depth
)

// opKeywords are the word operators.
var opKeywords = map[string]bool{
	"in": true, "iin": true,
	"contains": true, "icontains": true,
	"startswith": true, "istartswith": true,
	"endswith": true, "iendswith": true,
	"matches": true, "imatches": true,
	"regex": true,
}

// functions are the field functions, all of arity 1.
var functions = map[string]bool{"base": true, "dir": true, "ext": true, "lower": true, "length": true}

func isReserved(word string) bool {
	switch word {
	case "and", "or", "not", "true", "false", "sequence", "maxspan", "by":
		return true
	}
	return opKeywords[word] || functions[word]
}

type parser struct {
	toks  []token
	i     int
	m     *Macros
	depth int
	stack []string // macro expansion stack, for cycle detection
}

// Parse parses expr into an AST, inlining macros from m (which may be nil).
// It checks syntax and field names; types are checked by Compile.
func Parse(expr string, m *Macros) (Node, error) {
	return parseWith(expr, m, nil)
}

func parseWith(expr string, m *Macros, stack []string) (Node, error) {
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, m: m, stack: stack}
	if p.peek().kind == tEOF {
		return nil, errAt(p.peek().pos, "empty expression")
	}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, errAt(t.pos, "unexpected %s %s", t.kind, t.describe())
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) peekAt(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func keyword(t token) string {
	if t.kind != tIdent {
		return ""
	}
	w := strings.ToLower(t.text)
	if isReserved(w) {
		return w
	}
	return ""
}

func (p *parser) enter(pos Pos) error {
	p.depth++
	if p.depth > maxNesting {
		return errAt(pos, "expression nested deeper than %d levels", maxNesting)
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

func (p *parser) parseOr() (Node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for keyword(p.peek()) == "or" {
		t := p.next()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &BoolExpr{Op: "or", L: l, R: r, P: t.pos}
	}
	return l, nil
}

func (p *parser) parseAnd() (Node, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for keyword(p.peek()) == "and" {
		t := p.next()
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = &BoolExpr{Op: "and", L: l, R: r, P: t.pos}
	}
	return l, nil
}

func (p *parser) parseNot() (Node, error) {
	if keyword(p.peek()) == "not" {
		t := p.next()
		if err := p.enter(t.pos); err != nil {
			return nil, err
		}
		defer p.leave()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &NotExpr{X: x, P: t.pos}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	t := p.peek()
	switch t.kind {
	case tLParen:
		p.next()
		if err := p.enter(t.pos); err != nil {
			return nil, err
		}
		defer p.leave()
		x, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if c := p.next(); c.kind != tRParen {
			return nil, errAt(c.pos, "expected ')', found %s", c.describe())
		}
		return x, nil
	case tIdent:
		kw := keyword(t)
		switch {
		case kw == "true" || kw == "false":
			p.next()
			return &ConstExpr{V: kw == "true", P: t.pos}, nil
		case kw != "" && !functions[kw]:
			return nil, errAt(t.pos, "unexpected keyword %q, expected a condition", t.text)
		case functions[kw] && p.peekAt(1).kind == tLParen:
			lhs, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			return p.parseComparison(lhs)
		}
		if p.m != nil {
			if _, ok := p.m.exprs[t.text]; ok {
				p.next()
				return p.expandMacro(t.text, t.pos)
			}
			if _, ok := p.m.lists[t.text]; ok {
				return nil, errAt(t.pos, "list macro %q cannot be used as a condition", t.text)
			}
		}
		if !isFieldSyntax(t.text) {
			return nil, errAt(t.pos, "unknown field or macro %q", t.text)
		}
		lhs, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return p.parseComparison(lhs)
	}
	return nil, errAt(t.pos, "expected a condition, found %s", t.describe())
}

// isFieldSyntax reports whether an identifier names a field (static or indexed).
func isFieldSyntax(s string) bool {
	if i := strings.IndexByte(s, '['); i >= 0 {
		return true
	}
	_, ok := event.LookupField(s)
	return ok
}

func (p *parser) expandMacro(name string, pos Pos) (Node, error) {
	for _, s := range p.stack {
		if s == name {
			return nil, errAt(pos, "macro %q references itself (cycle %s -> %s)", name, strings.Join(p.stack, " -> "), name)
		}
	}
	if len(p.stack) >= maxMacroDepth {
		return nil, errAt(pos, "macro expansion deeper than %d levels", maxMacroDepth)
	}
	stack := make([]string, len(p.stack), len(p.stack)+1)
	copy(stack, p.stack)
	stack = append(stack, name)
	x, err := parseWith(p.m.exprs[name].expr, p.m, stack)
	if err != nil {
		return nil, errAt(pos, "in macro %q: %v", name, err)
	}
	return &MacroExpr{Name: name, X: x, P: pos}, nil
}

// parseOperand parses a field or a function call on a field.
func (p *parser) parseOperand() (*Operand, error) {
	t := p.next()
	if t.kind != tIdent {
		return nil, errAt(t.pos, "expected a field, found %s", t.describe())
	}
	if fn := strings.ToLower(t.text); functions[fn] {
		if c := p.next(); c.kind != tLParen {
			return nil, errAt(c.pos, "expected '(' after function %s", fn)
		}
		if err := p.enter(t.pos); err != nil {
			return nil, err
		}
		defer p.leave()
		arg, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		if c := p.next(); c.kind != tRParen {
			return nil, errAt(c.pos, "function %s takes one field argument; expected ')', found %s", fn, c.describe())
		}
		return &Operand{Func: fn, Arg: arg, P: t.pos}, nil
	}
	if keyword(t) != "" {
		return nil, errAt(t.pos, "expected a field, found keyword %q", t.text)
	}
	return resolveField(t.text, t.pos)
}

func resolveField(name string, pos Pos) (*Operand, error) {
	if i := strings.IndexByte(name, '['); i >= 0 {
		root := name[:i]
		key := name[i+1 : len(name)-1]
		if len(key) >= 2 && key[0] == '\'' && key[len(key)-1] == '\'' {
			key = key[1 : len(key)-1]
		}
		ok := false
		for _, r := range event.IndexedRoots {
			if r == root {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errAt(pos, "field %q does not accept an index (indexed fields: %s)", root, strings.Join(event.IndexedRoots, ", "))
		}
		if key == "" {
			return nil, errAt(pos, "empty index in field %q", name)
		}
		return &Operand{Field: root, Key: key, Index: true, P: pos}, nil
	}
	if _, ok := event.LookupField(name); !ok {
		return nil, errAt(pos, "unknown field %q", name)
	}
	return &Operand{Field: name, P: pos}, nil
}

func (p *parser) parseComparison(lhs *Operand) (Node, error) {
	start := lhs.P
	neg := false
	t := p.peek()
	if keyword(t) == "not" {
		nt := p.peekAt(1)
		if nt.kind == tOp || opKeywords[keyword(nt)] {
			p.next()
			neg = true
			t = p.peek()
		}
	}
	var op string
	switch {
	case t.kind == tOp:
		op = t.text
	case opKeywords[keyword(t)]:
		op = keyword(t)
	default:
		// Bare predicate (boolean field); the type checker enforces the kind.
		return &CmpExpr{LHS: lhs, P: start}, nil
	}
	if neg && t.kind == tOp {
		return nil, errAt(t.pos, "'not %s' is not allowed; use the opposite operator", op)
	}
	p.next()
	rhs, err := p.parseRHS()
	if err != nil {
		return nil, err
	}
	return &CmpExpr{LHS: lhs, Op: op, Neg: neg, RHS: rhs, P: start}, nil
}

func (p *parser) parseLit() (Lit, error) {
	t := p.next()
	switch t.kind {
	case tString:
		return Lit{Kind: LitString, S: t.text, P: t.pos}, nil
	case tInt:
		return Lit{Kind: LitInt, I: t.num, P: t.pos}, nil
	case tIdent:
		if kw := keyword(t); kw == "true" || kw == "false" {
			return Lit{Kind: LitBool, B: kw == "true", P: t.pos}, nil
		}
	}
	return Lit{}, errAt(t.pos, "expected a literal, found %s", t.describe())
}

func (p *parser) parseRHS() (*RHS, error) {
	t := p.peek()
	switch t.kind {
	case tLParen:
		p.next()
		r := &RHS{List: true, P: t.pos}
		for {
			l, err := p.parseLit()
			if err != nil {
				return nil, err
			}
			r.Lits = append(r.Lits, l)
			c := p.next()
			if c.kind == tRParen {
				return r, nil
			}
			if c.kind != tComma {
				return nil, errAt(c.pos, "expected ',' or ')' in list, found %s", c.describe())
			}
		}
	case tString, tInt:
		l, err := p.parseLit()
		if err != nil {
			return nil, err
		}
		return &RHS{Lits: []Lit{l}, P: t.pos}, nil
	case tIdent:
		if kw := keyword(t); kw == "true" || kw == "false" {
			l, _ := p.parseLit()
			return &RHS{Lits: []Lit{l}, P: t.pos}, nil
		}
		if p.m != nil {
			if items, ok := p.m.lists[t.text]; ok {
				p.next()
				lits := make([]Lit, len(items))
				for i, it := range items {
					it.P = t.pos
					lits[i] = it
				}
				return &RHS{Lits: lits, List: true, Macro: t.text, P: t.pos}, nil
			}
			if _, ok := p.m.exprs[t.text]; ok {
				return nil, errAt(t.pos, "expression macro %q cannot be used as a value", t.text)
			}
		}
		if !isFieldSyntax(t.text) && !functions[strings.ToLower(t.text)] {
			return nil, errAt(t.pos, "unknown field or list macro %q", t.text)
		}
		f, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return &RHS{Field: f, P: t.pos}, nil
	}
	return nil, errAt(t.pos, "expected a value, found %s", t.describe())
}
