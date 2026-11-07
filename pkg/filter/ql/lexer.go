// Package ql implements ZAAFVesper's rule condition language: a lexer, a parser
// that produces an AST (with macros inlined), a type checker and an evaluator.
//
// The language is in the style of Fibratus (field op value, macros, lists),
// written from the specification in docs/plans/2026-11-07-zaafvesper-mvp.md.
package ql

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxExprLen bounds the length of a single condition. Rule files are trusted
// (root-owned) but the bound keeps pathological input from exhausting memory.
const MaxExprLen = 1 << 20

// Pos is a 1-based line and column (in bytes) inside the expression.
type Pos struct {
	Line int
	Col  int
}

func (p Pos) String() string { return fmt.Sprintf("line %d col %d", p.Line, p.Col) }

// Error is a lexing, parsing or type error at a position.
type Error struct {
	Pos Pos
	Msg string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Pos, e.Msg) }

func errAt(p Pos, format string, args ...any) *Error {
	return &Error{Pos: p, Msg: fmt.Sprintf(format, args...)}
}

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tInt
	tLParen
	tRParen
	tComma
	tOp // = != < <= > >=
)

func (k tokKind) String() string {
	switch k {
	case tEOF:
		return "end of expression"
	case tIdent:
		return "identifier"
	case tString:
		return "string"
	case tInt:
		return "integer"
	case tLParen:
		return "'('"
	case tRParen:
		return "')'"
	case tComma:
		return "','"
	case tOp:
		return "operator"
	}
	return "token"
}

type token struct {
	kind tokKind
	text string // raw text (identifier, operator) or decoded string value
	num  int64
	pos  Pos
}

func (t token) describe() string {
	switch t.kind {
	case tEOF:
		return "end of expression"
	case tString:
		return strconv.Quote(t.text)
	case tInt:
		return strconv.FormatInt(t.num, 10)
	}
	return fmt.Sprintf("%q", t.text)
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// lex splits src into tokens.
func lex(src string) ([]token, error) {
	if len(src) > MaxExprLen {
		return nil, errAt(Pos{1, 1}, "expression longer than %d bytes", MaxExprLen)
	}
	var toks []token
	line, lineStart := 1, 0
	pos := func(i int) Pos { return Pos{Line: line, Col: i - lineStart + 1} }
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			i++
			line, lineStart = line+1, i
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tLParen, text: "(", pos: pos(i)})
			i++
		case c == ')':
			toks = append(toks, token{kind: tRParen, text: ")", pos: pos(i)})
			i++
		case c == ',':
			toks = append(toks, token{kind: tComma, text: ",", pos: pos(i)})
			i++
		case c == '=':
			p := pos(i)
			if i+1 < len(src) && src[i+1] == '=' {
				return nil, errAt(p, "unexpected '==' (use '=')")
			}
			toks = append(toks, token{kind: tOp, text: "=", pos: p})
			i++
		case c == '!':
			p := pos(i)
			if i+1 < len(src) && src[i+1] == '=' {
				toks = append(toks, token{kind: tOp, text: "!=", pos: p})
				i += 2
				continue
			}
			return nil, errAt(p, "unexpected '!' (use 'not' or '!=')")
		case c == '<' || c == '>':
			p := pos(i)
			op := string(c)
			if i+1 < len(src) && src[i+1] == '=' {
				op += "="
				i++
			}
			i++
			toks = append(toks, token{kind: tOp, text: op, pos: p})
		case c == '\'':
			p := pos(i)
			var b strings.Builder
			i++
			closed := false
			for i < len(src) {
				ch := src[i]
				if ch == '\\' && i+1 < len(src) && (src[i+1] == '\'' || src[i+1] == '\\') {
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if ch == '\'' {
					closed = true
					i++
					break
				}
				if ch == '\n' {
					line, lineStart = line+1, i+1
				}
				b.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, errAt(p, "unterminated string")
			}
			toks = append(toks, token{kind: tString, text: b.String(), pos: p})
		case c == '"':
			return nil, errAt(pos(i), "strings use single quotes")
		case isDigit(c) || (c == '-' && i+1 < len(src) && isDigit(src[i+1])):
			p := pos(i)
			j := i + 1
			for j < len(src) && isDigit(src[j]) {
				j++
			}
			if j < len(src) && isIdentStart(src[j]) {
				return nil, errAt(p, "invalid number %q", src[i:j+1])
			}
			n, err := strconv.ParseInt(src[i:j], 10, 64)
			if err != nil {
				return nil, errAt(p, "invalid integer %q", src[i:j])
			}
			toks = append(toks, token{kind: tInt, text: src[i:j], num: n, pos: p})
			i = j
		case isIdentStart(c):
			p := pos(i)
			j := i + 1
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			// Indexed field: name[key] with no space before '['.
			if j < len(src) && src[j] == '[' {
				k := j + 1
				for k < len(src) && src[k] != ']' && src[k] != '\n' {
					k++
				}
				if k >= len(src) || src[k] != ']' {
					return nil, errAt(p, "unterminated '[' in field %q", src[i:j])
				}
				j = k + 1
			}
			toks = append(toks, token{kind: tIdent, text: src[i:j], pos: p})
			i = j
		default:
			return nil, errAt(pos(i), "unexpected character %q", rune(c))
		}
	}
	toks = append(toks, token{kind: tEOF, pos: pos(i)})
	return toks, nil
}
