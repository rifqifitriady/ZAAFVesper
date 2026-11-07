package ql

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// knownEvents are the canonical event names; a literal compared with evt.name
// must be one of these, so a typo is a compile error instead of a silent miss.
var knownEvents = []string{
	event.CreateProcess, event.Fork, event.TerminateProcess, event.OpenFile,
	event.CreateFile, event.WriteFile, event.RenameFile, event.DeleteFile,
	event.SetXattr, event.DeleteXattr, event.SetMode, event.SetOwner,
	event.OpenProcess, event.Signal, event.Ptrace, event.CreateRemoteThread,
	event.AddLaunchItem, event.Mount, event.LoadKext, event.Authenticate,
	event.Sudo, event.ModifyTCC, event.XProtectDetect, event.YaraMatch,
}

// KnownEvents returns the canonical event names, sorted.
func KnownEvents() []string {
	out := append([]string(nil), knownEvents...)
	sort.Strings(out)
	return out
}

func canonicalEvent(name string, fold bool) (string, bool) {
	for _, k := range knownEvents {
		if k == name || (fold && strings.EqualFold(k, name)) {
			return k, true
		}
	}
	return "", false
}

// Filter is a compiled condition.
type Filter struct {
	expr  string
	ast   Node
	root  evaluator
	names []string // nil = any event
}

// Compile parses, type-checks and compiles expr. m may be nil.
func Compile(expr string, m *Macros) (*Filter, error) {
	ast, err := Parse(expr, m)
	if err != nil {
		return nil, err
	}
	ev, ns, err := compileNode(ast)
	if err != nil {
		return nil, err
	}
	f := &Filter{expr: expr, ast: ast, root: ev}
	if !ns.any {
		f.names = make([]string, 0, len(ns.set))
		for n := range ns.set {
			f.names = append(f.names, n)
		}
		sort.Strings(f.names)
	}
	return f, nil
}

// Match reports whether the event satisfies the condition.
func (f *Filter) Match(e *event.Event) bool {
	if e == nil {
		return false
	}
	return f.root.eval(e)
}

// EventNames returns the event names the condition is constrained to on every
// true path, sorted; nil means the condition can match any event.
func (f *Filter) EventNames() []string {
	if f.names == nil {
		return nil
	}
	return append([]string{}, f.names...)
}

// String returns the source expression.
func (f *Filter) String() string { return f.expr }

// AST returns the parsed tree with macros inlined.
func (f *Filter) AST() Node { return f.ast }

// ---- event-name analysis ----

type nameSet struct {
	any bool
	set map[string]bool
}

var anyNames = nameSet{any: true}

func setOf(names ...string) nameSet {
	s := nameSet{set: map[string]bool{}}
	for _, n := range names {
		s.set[n] = true
	}
	return s
}

func (a nameSet) and(b nameSet) nameSet {
	switch {
	case a.any:
		return b
	case b.any:
		return a
	}
	out := setOf()
	for n := range a.set {
		if b.set[n] {
			out.set[n] = true
		}
	}
	return out
}

func (a nameSet) or(b nameSet) nameSet {
	if a.any || b.any {
		return anyNames
	}
	out := setOf()
	for n := range a.set {
		out.set[n] = true
	}
	for n := range b.set {
		out.set[n] = true
	}
	return out
}

// ---- evaluators ----

type evaluator interface {
	eval(e *event.Event) bool
}

type andEval []evaluator

func (a andEval) eval(e *event.Event) bool {
	for _, x := range a {
		if !x.eval(e) {
			return false
		}
	}
	return true
}

type orEval []evaluator

func (o orEval) eval(e *event.Event) bool {
	for _, x := range o {
		if x.eval(e) {
			return true
		}
	}
	return false
}

type notEval struct{ x evaluator }

func (n notEval) eval(e *event.Event) bool { return !n.x.eval(e) }

type constEval bool

func (c constEval) eval(*event.Event) bool { return bool(c) }

type cmpEval struct {
	get func(*event.Event) event.Value
	str func(string, *event.Event) bool
	num func(int64, *event.Event) bool
	bl  func(bool, *event.Event) bool
	neg bool
}

// eval applies the comparison. An absent (nil) field makes every comparison
// false, including the infix negations (`not in`, `not imatches`, ...): only a
// prefix `not (...)` turns that false into true.
func (c *cmpEval) eval(e *event.Event) bool {
	v := c.get(e)
	if v == nil {
		return false
	}
	r := c.match(v, e)
	if c.neg {
		return !r
	}
	return r
}

func (c *cmpEval) match(v event.Value, e *event.Event) bool {
	switch v := v.(type) {
	case string:
		return c.str != nil && c.str(v, e)
	case []string:
		if c.str == nil {
			return false
		}
		for _, s := range v {
			if c.str(s, e) {
				return true
			}
		}
	case int64:
		return c.num != nil && c.num(v, e)
	case bool:
		return c.bl != nil && c.bl(v, e)
	}
	return false // nil (absent) or unexpected
}

func compileNode(n Node) (evaluator, nameSet, error) {
	switch n := n.(type) {
	case *BoolExpr:
		l, ln, err := compileNode(n.L)
		if err != nil {
			return nil, nameSet{}, err
		}
		r, rn, err := compileNode(n.R)
		if err != nil {
			return nil, nameSet{}, err
		}
		if n.Op == "and" {
			out := andEval{}
			out = appendFlat(out, l)
			out = appendFlat(out, r)
			return out, ln.and(rn), nil
		}
		out := orEval{}
		out = appendFlatOr(out, l)
		out = appendFlatOr(out, r)
		return out, ln.or(rn), nil
	case *NotExpr:
		x, _, err := compileNode(n.X)
		if err != nil {
			return nil, nameSet{}, err
		}
		return notEval{x}, anyNames, nil
	case *ConstExpr:
		if n.V {
			return constEval(true), anyNames, nil
		}
		return constEval(false), setOf(), nil
	case *MacroExpr:
		return compileNode(n.X)
	case *CmpExpr:
		return compileCmp(n)
	}
	return nil, nameSet{}, fmt.Errorf("ql: unknown node %T", n)
}

func appendFlat(out andEval, x evaluator) andEval {
	if a, ok := x.(andEval); ok {
		return append(out, a...)
	}
	return append(out, x)
}

func appendFlatOr(out orEval, x evaluator) orEval {
	if o, ok := x.(orEval); ok {
		return append(out, o...)
	}
	return append(out, x)
}

// ---- operands ----

type valuer struct {
	kind event.FieldKind
	get  func(*event.Event) event.Value
}

func kindName(k event.FieldKind) string {
	switch k {
	case event.KindString:
		return "string"
	case event.KindInt:
		return "integer"
	case event.KindBool:
		return "boolean"
	case event.KindStrings:
		return "string list"
	}
	return "unknown"
}

func compileOperand(o *Operand) (valuer, error) {
	if o.Func != "" {
		return compileFunc(o)
	}
	if o.Index {
		root, key := o.Field, o.Key
		return valuer{event.KindString, func(e *event.Event) event.Value { return e.GetIndexed(root, key) }}, nil
	}
	kind, ok := event.LookupField(o.Field)
	if !ok {
		return valuer{}, errAt(o.P, "unknown field %q", o.Field)
	}
	name := o.Field
	return valuer{kind, func(e *event.Event) event.Value { return e.Get(name) }}, nil
}

func baseOf(s string) string {
	if s == "" {
		return ""
	}
	return filepath.Base(s)
}

func dirOf(s string) string {
	if s == "" {
		return ""
	}
	return filepath.Dir(s)
}

func extOf(s string) string { return strings.ToLower(filepath.Ext(s)) }

func compileFunc(o *Operand) (valuer, error) {
	arg, err := compileOperand(o.Arg)
	if err != nil {
		return valuer{}, err
	}
	if arg.kind != event.KindString && arg.kind != event.KindStrings {
		return valuer{}, errAt(o.P, "function %s needs a string field, %s is %s", o.Func, o.Arg, kindName(arg.kind))
	}
	inner := arg.get
	if o.Func == "length" {
		return valuer{event.KindInt, func(e *event.Event) event.Value {
			switch v := inner(e).(type) {
			case string:
				return int64(utf8.RuneCountInString(v))
			case []string:
				return int64(len(v))
			}
			return nil
		}}, nil
	}
	var f func(string) string
	switch o.Func {
	case "base":
		f = baseOf
	case "dir":
		f = dirOf
	case "ext":
		f = extOf
	case "lower":
		f = strings.ToLower
	default:
		return valuer{}, errAt(o.P, "unknown function %q", o.Func)
	}
	return valuer{arg.kind, func(e *event.Event) event.Value {
		switch v := inner(e).(type) {
		case string:
			return f(v)
		case []string:
			out := make([]string, len(v))
			for i, s := range v {
				out[i] = f(s)
			}
			return out
		}
		return nil
	}}, nil
}

// ---- comparisons ----

var listOps = map[string]bool{
	"in": true, "iin": true, "contains": true, "icontains": true,
	"startswith": true, "istartswith": true, "endswith": true, "iendswith": true,
	"matches": true, "imatches": true, "regex": true,
}

func compileCmp(n *CmpExpr) (evaluator, nameSet, error) {
	lhs, err := compileOperand(n.LHS)
	if err != nil {
		return nil, nameSet{}, err
	}
	if n.RHS == nil {
		if lhs.kind != event.KindBool {
			return nil, nameSet{}, errAt(n.P, "%s is a %s field; expected an operator after it", n.LHS, kindName(lhs.kind))
		}
		return &cmpEval{get: lhs.get, bl: func(b bool, _ *event.Event) bool { return b }}, anyNames, nil
	}
	c := &cmpEval{get: lhs.get, neg: n.Neg}
	if n.RHS.List && !listOps[n.Op] {
		return nil, nameSet{}, errAt(n.RHS.P, "operator %s does not accept a list; use in", n.Op)
	}
	switch lhs.kind {
	case event.KindString, event.KindStrings:
		c.str, err = stringPred(n)
	case event.KindInt:
		c.num, err = intPred(n)
	case event.KindBool:
		c.bl, err = boolPred(n)
	}
	if err != nil {
		return nil, nameSet{}, err
	}
	ns, err := cmpNames(n)
	if err != nil {
		return nil, nameSet{}, err
	}
	return c, ns, nil
}

// cmpNames validates evt.name literals and derives the event-name constraint.
func cmpNames(n *CmpExpr) (nameSet, error) {
	if n.LHS.Func != "" || n.LHS.Index || n.RHS.Field != nil {
		return anyNames, nil
	}
	switch n.LHS.Field {
	case "evt.name":
		fold := n.Op == "iin"
		var names []string
		for _, l := range n.RHS.Lits {
			if n.Op != "=" && n.Op != "!=" && n.Op != "in" && n.Op != "iin" {
				break
			}
			c, ok := canonicalEvent(l.S, fold)
			if !ok {
				return nameSet{}, errAt(l.P, "unknown event name %q (known: %s)", l.S, strings.Join(KnownEvents(), ", "))
			}
			names = append(names, c)
		}
		if !n.Neg && (n.Op == "=" || n.Op == "in" || n.Op == "iin") {
			return setOf(names...), nil
		}
	case "evt.category":
		if !n.Neg && (n.Op == "=" || n.Op == "in") {
			var names []string
			for _, l := range n.RHS.Lits {
				for _, k := range knownEvents {
					if event.Category(k) == l.S {
						names = append(names, k)
					}
				}
			}
			return setOf(names...), nil
		}
	}
	return anyNames, nil
}

func litStrings(n *CmpExpr) ([]string, error) {
	out := make([]string, len(n.RHS.Lits))
	for i, l := range n.RHS.Lits {
		if l.Kind != LitString {
			return nil, errAt(l.P, "%s is a string field; expected a string, found %s", n.LHS, l)
		}
		out[i] = l.S
	}
	return out, nil
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func anyOf(vals []string, f func(string) bool) bool {
	for _, v := range vals {
		if f(v) {
			return true
		}
	}
	return false
}

type strPredFn = func(string, *event.Event) bool

func stringPred(n *CmpExpr) (strPredFn, error) {
	switch n.Op {
	case "<", "<=", ">", ">=":
		return nil, errAt(n.P, "operator %s is not defined for string field %s", n.Op, n.LHS)
	}
	if n.RHS.Field != nil {
		return stringFieldPred(n)
	}
	vals, err := litStrings(n)
	if err != nil {
		return nil, err
	}
	switch n.Op {
	case "=":
		v := vals[0]
		return func(s string, _ *event.Event) bool { return s == v }, nil
	case "!=":
		v := vals[0]
		return func(s string, _ *event.Event) bool { return s != v }, nil
	case "in":
		set := make(map[string]struct{}, len(vals))
		for _, v := range vals {
			set[v] = struct{}{}
		}
		return func(s string, _ *event.Event) bool { _, ok := set[s]; return ok }, nil
	case "iin":
		set := make(map[string]struct{}, len(vals))
		for _, v := range lowerAll(vals) {
			set[v] = struct{}{}
		}
		return func(s string, _ *event.Event) bool { _, ok := set[strings.ToLower(s)]; return ok }, nil
	case "contains", "startswith", "endswith":
		f := map[string]func(string, string) bool{"contains": strings.Contains, "startswith": strings.HasPrefix, "endswith": strings.HasSuffix}[n.Op]
		return func(s string, _ *event.Event) bool {
			return anyOf(vals, func(v string) bool { return f(s, v) })
		}, nil
	case "icontains", "istartswith", "iendswith":
		f := map[string]func(string, string) bool{"icontains": strings.Contains, "istartswith": strings.HasPrefix, "iendswith": strings.HasSuffix}[n.Op]
		lv := lowerAll(vals)
		return func(s string, _ *event.Event) bool {
			ls := strings.ToLower(s)
			return anyOf(lv, func(v string) bool { return f(ls, v) })
		}, nil
	case "matches", "imatches":
		fold := n.Op == "imatches"
		globs := make([]*glob, len(vals))
		for i, v := range vals {
			if fold {
				v = strings.ToLower(v)
			}
			globs[i] = compileGlob(v)
		}
		return func(s string, _ *event.Event) bool {
			if fold {
				s = strings.ToLower(s)
			}
			for _, g := range globs {
				if g.match(s) {
					return true
				}
			}
			return false
		}, nil
	case "regex":
		res := make([]*regexp.Regexp, len(vals))
		for i, v := range vals {
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, errAt(n.RHS.Lits[i].P, "invalid regex %q: %v", v, err)
			}
			res[i] = re
		}
		return func(s string, _ *event.Event) bool {
			for _, re := range res {
				if re.MatchString(s) {
					return true
				}
			}
			return false
		}, nil
	}
	return nil, errAt(n.P, "operator %s is not defined for string field %s", n.Op, n.LHS)
}

func anyStr(v event.Value, f func(string) bool) bool {
	switch x := v.(type) {
	case string:
		return f(x)
	case []string:
		for _, s := range x {
			if f(s) {
				return true
			}
		}
	}
	return false
}

func stringFieldPred(n *CmpExpr) (strPredFn, error) {
	rv, err := compileOperand(n.RHS.Field)
	if err != nil {
		return nil, err
	}
	if rv.kind != event.KindString && rv.kind != event.KindStrings {
		return nil, errAt(n.RHS.P, "cannot compare string field %s with %s field %s", n.LHS, kindName(rv.kind), n.RHS.Field)
	}
	var f func(s, r string) bool
	switch n.Op {
	case "=", "in":
		f = func(s, r string) bool { return s == r }
	case "!=":
		f = func(s, r string) bool { return s != r }
	case "iin":
		f = strings.EqualFold
	case "contains":
		f = strings.Contains
	case "startswith":
		f = strings.HasPrefix
	case "endswith":
		f = strings.HasSuffix
	case "icontains":
		f = func(s, r string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(r)) }
	case "istartswith":
		f = func(s, r string) bool { return strings.HasPrefix(strings.ToLower(s), strings.ToLower(r)) }
	case "iendswith":
		f = func(s, r string) bool { return strings.HasSuffix(strings.ToLower(s), strings.ToLower(r)) }
	default:
		return nil, errAt(n.P, "operator %s needs a literal pattern on the right, not a field", n.Op)
	}
	get := rv.get
	return func(s string, e *event.Event) bool {
		return anyStr(get(e), func(r string) bool { return f(s, r) })
	}, nil
}

func intCmp(op string) (func(a, b int64) bool, bool) {
	switch op {
	case "=":
		return func(a, b int64) bool { return a == b }, true
	case "!=":
		return func(a, b int64) bool { return a != b }, true
	case "<":
		return func(a, b int64) bool { return a < b }, true
	case "<=":
		return func(a, b int64) bool { return a <= b }, true
	case ">":
		return func(a, b int64) bool { return a > b }, true
	case ">=":
		return func(a, b int64) bool { return a >= b }, true
	}
	return nil, false
}

func intPred(n *CmpExpr) (func(int64, *event.Event) bool, error) {
	if n.RHS.Field != nil {
		rv, err := compileOperand(n.RHS.Field)
		if err != nil {
			return nil, err
		}
		if rv.kind != event.KindInt {
			return nil, errAt(n.RHS.P, "cannot compare integer field %s with %s field %s", n.LHS, kindName(rv.kind), n.RHS.Field)
		}
		op := n.Op
		if op == "in" {
			op = "="
		}
		cmp, ok := intCmp(op)
		if !ok {
			return nil, errAt(n.P, "operator %s is not defined for integer field %s", n.Op, n.LHS)
		}
		get := rv.get
		return func(a int64, e *event.Event) bool {
			b, ok := get(e).(int64)
			return ok && cmp(a, b)
		}, nil
	}
	vals := make([]int64, len(n.RHS.Lits))
	for i, l := range n.RHS.Lits {
		if l.Kind != LitInt {
			return nil, errAt(l.P, "%s is an integer field; expected an integer, found %s", n.LHS, l)
		}
		vals[i] = l.I
	}
	if n.Op == "in" {
		return func(a int64, _ *event.Event) bool {
			for _, v := range vals {
				if a == v {
					return true
				}
			}
			return false
		}, nil
	}
	cmp, ok := intCmp(n.Op)
	if !ok {
		return nil, errAt(n.P, "operator %s is not defined for integer field %s", n.Op, n.LHS)
	}
	b := vals[0]
	return func(a int64, _ *event.Event) bool { return cmp(a, b) }, nil
}

func boolPred(n *CmpExpr) (func(bool, *event.Event) bool, error) {
	if n.Op != "=" && n.Op != "!=" {
		return nil, errAt(n.P, "operator %s is not defined for boolean field %s", n.Op, n.LHS)
	}
	eq := n.Op == "="
	if n.RHS.Field != nil {
		rv, err := compileOperand(n.RHS.Field)
		if err != nil {
			return nil, err
		}
		if rv.kind != event.KindBool {
			return nil, errAt(n.RHS.P, "cannot compare boolean field %s with %s field %s", n.LHS, kindName(rv.kind), n.RHS.Field)
		}
		get := rv.get
		return func(a bool, e *event.Event) bool {
			b, ok := get(e).(bool)
			return ok && (a == b) == eq
		}, nil
	}
	l := n.RHS.Lits[0]
	if l.Kind != LitBool {
		return nil, errAt(l.P, "%s is a boolean field; expected true or false, found %s", n.LHS, l)
	}
	b := l.B
	return func(a bool, _ *event.Event) bool { return (a == b) == eq }, nil
}

// ---- single fields (sequence join keys, output templates) ----

// Field is a compiled field reference, possibly wrapped in functions.
type Field struct {
	name string
	v    valuer
}

// CompileField compiles a field reference such as "ps.exe",
// "evt.arg[signal]" or "base(file.path)".
func CompileField(name string) (*Field, error) {
	toks, err := lex(name)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	op, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, errAt(t.pos, "unexpected %s after field", t.describe())
	}
	v, err := compileOperand(op)
	if err != nil {
		return nil, err
	}
	return &Field{name: op.String(), v: v}, nil
}

// Value resolves the field on e (nil when absent).
func (f *Field) Value(e *event.Event) event.Value {
	if e == nil {
		return nil
	}
	return f.v.get(e)
}

// Kind is the static type of the field.
func (f *Field) Kind() event.FieldKind { return f.v.kind }

// String returns the canonical field text.
func (f *Field) String() string { return f.name }
