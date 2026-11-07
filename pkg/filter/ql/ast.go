package ql

import (
	"strconv"
	"strings"
)

// Node is an AST node of a condition.
type Node interface {
	Pos() Pos
	String() string
}

// BoolExpr is `L and R` or `L or R`.
type BoolExpr struct {
	Op   string // "and" | "or"
	L, R Node
	P    Pos
}

// NotExpr is `not X`.
type NotExpr struct {
	X Node
	P Pos
}

// ConstExpr is a bare `true` or `false`.
type ConstExpr struct {
	V bool
	P Pos
}

// MacroExpr is an inlined expression macro. X is the parsed macro body.
type MacroExpr struct {
	Name string
	X    Node
	P    Pos
}

// Operand is a field reference, optionally wrapped in functions.
type Operand struct {
	Field string   // static field name, or indexed root (evt.arg)
	Key   string   // index key for indexed fields; "" otherwise
	Index bool     // true when Field[Key]
	Func  string   // function name when this is a call; Arg is then set
	Arg   *Operand // function argument
	P     Pos
}

func (o *Operand) String() string {
	if o.Func != "" {
		return o.Func + "(" + o.Arg.String() + ")"
	}
	if o.Index {
		return o.Field + "[" + o.Key + "]"
	}
	return o.Field
}

// LitKind is the type of a literal.
type LitKind int

const (
	LitString LitKind = iota
	LitInt
	LitBool
)

// Lit is a literal value.
type Lit struct {
	Kind LitKind
	S    string
	I    int64
	B    bool
	P    Pos
}

func (l Lit) String() string {
	switch l.Kind {
	case LitInt:
		return strconv.FormatInt(l.I, 10)
	case LitBool:
		return strconv.FormatBool(l.B)
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(l.S) + "'"
}

// RHS is the right-hand side of a comparison: literal(s), a list macro, or a field.
type RHS struct {
	Lits  []Lit
	List  bool     // written as a list literal or list macro
	Macro string   // list macro name, when used
	Field *Operand // field on the right-hand side
	P     Pos
}

func (r *RHS) String() string {
	if r.Field != nil {
		return r.Field.String()
	}
	if r.Macro != "" {
		return r.Macro
	}
	if !r.List && len(r.Lits) == 1 {
		return r.Lits[0].String()
	}
	parts := make([]string, len(r.Lits))
	for i, l := range r.Lits {
		parts[i] = l.String()
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// CmpExpr is `LHS op RHS`; RHS == nil means a bare boolean field predicate.
type CmpExpr struct {
	LHS *Operand
	Op  string // = != < <= > >= in iin contains ...
	Neg bool   // infix negation: `not in`, `not imatches`
	RHS *RHS
	P   Pos
}

func (n *BoolExpr) Pos() Pos  { return n.P }
func (n *NotExpr) Pos() Pos   { return n.P }
func (n *ConstExpr) Pos() Pos { return n.P }
func (n *MacroExpr) Pos() Pos { return n.P }
func (n *CmpExpr) Pos() Pos   { return n.P }

func (n *BoolExpr) String() string {
	return "(" + n.L.String() + " " + n.Op + " " + n.R.String() + ")"
}
func (n *NotExpr) String() string   { return "not " + n.X.String() }
func (n *ConstExpr) String() string { return strconv.FormatBool(n.V) }
func (n *MacroExpr) String() string { return n.X.String() }
func (n *CmpExpr) String() string {
	if n.RHS == nil {
		return n.LHS.String()
	}
	op := n.Op
	if n.Neg {
		op = "not " + op
	}
	return n.LHS.String() + " " + op + " " + n.RHS.String()
}
