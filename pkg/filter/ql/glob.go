package ql

import (
	"strings"
	"unicode/utf8"
)

// glob is a compiled wildcard pattern: '*' matches any run of characters
// (including '/'), '?' matches exactly one character. There are no escapes
// and no character classes. Common shapes are reduced to plain string tests.
type glob struct {
	kind int
	lit  string // literal part for the fast shapes
	pat  string // full pattern for the general shape
}

const (
	globExact    = iota // no wildcard
	globPrefix          // abc*
	globSuffix          // *abc
	globContains        // *abc*
	globAny             // *
	globGeneral
)

func compileGlob(p string) *glob {
	if !strings.ContainsAny(p, "*?") {
		return &glob{kind: globExact, lit: p}
	}
	if strings.ContainsRune(p, '?') {
		return &glob{kind: globGeneral, pat: p}
	}
	inner := strings.Trim(p, "*")
	if inner == "" {
		return &glob{kind: globAny}
	}
	if strings.ContainsRune(inner, '*') {
		return &glob{kind: globGeneral, pat: p}
	}
	lead := strings.HasPrefix(p, "*")
	trail := strings.HasSuffix(p, "*")
	// Only a single leading/trailing star collapses; "**x" is equivalent anyway.
	switch {
	case lead && trail:
		return &glob{kind: globContains, lit: inner}
	case lead:
		return &glob{kind: globSuffix, lit: inner}
	default:
		_ = trail
		return &glob{kind: globPrefix, lit: inner}
	}
}

func (g *glob) match(s string) bool {
	switch g.kind {
	case globExact:
		return s == g.lit
	case globPrefix:
		return strings.HasPrefix(s, g.lit)
	case globSuffix:
		return strings.HasSuffix(s, g.lit)
	case globContains:
		return strings.Contains(s, g.lit)
	case globAny:
		return true
	}
	return wildMatch(g.pat, s)
}

// wildMatch matches s against p with single-star backtracking. It runs in
// O(len(p)*len(s)) worst case and never recurses.
func wildMatch(p, s string) bool {
	px, sx := 0, 0
	starPx, starSx := -1, -1
	for px < len(p) || sx < len(s) {
		if px < len(p) {
			switch c := p[px]; c {
			case '*':
				starPx, starSx = px, sx
				px++
				continue
			case '?':
				if sx < len(s) {
					_, w := utf8.DecodeRuneInString(s[sx:])
					px++
					sx += w
					continue
				}
			default:
				if sx < len(s) && s[sx] == c {
					px++
					sx++
					continue
				}
			}
		}
		// Mismatch: let the last star absorb one more character and retry.
		if starPx >= 0 && starSx < len(s) {
			_, w := utf8.DecodeRuneInString(s[starSx:])
			starSx += w
			px, sx = starPx+1, starSx
			continue
		}
		return false
	}
	return true
}
