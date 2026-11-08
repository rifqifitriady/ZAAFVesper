package yara

import (
	"errors"
	"fmt"
)

// AllowedModules are the only YARA modules a rule file may import. "magic"
// is not among them: libmagic loads its database at scan time from a
// (Homebrew, user-owned) path, which a root sensor must not read. "cuckoo"
// reads a JSON report and is not needed either. The check does not rely on
// libyara being built without a module.
var AllowedModules = []string{"pe", "elf", "macho", "math", "hash", "dotnet", "time", "string", "console"}

var (
	errModuleNotAllowed = errors.New("import of a module outside the allow-list")
	errInclude          = errors.New("include directives are not allowed")
	errRuleSyntax       = errors.New("unterminated comment, string or regular expression")
)

// checkRuleSource scans YARA source the way libyara's lexer splits it and
// refuses every `include`, and every `import` whose literal is not exactly
// (byte for byte, no escape processing) one of AllowedModules.
//
// Lexing follows libyara's lexer.l: `//` and `/* */` are comments (also
// inside hex strings), `"` starts a text string with backslash escapes, and
// any other `/` starts a regular expression (YARA's division operator is
// `\`, so `/` is never an operator). `import` and `include` are reserved
// words, so outside comments, strings and regexps they can only be the
// directives. Identifiers with a `$ # @ !` sigil are skipped whole. The
// lexer never desynchronises from libyara's on valid input; on input it
// cannot finish (an unterminated comment, string or regexp) it refuses.
func checkRuleSource(src []byte) error {
	n := len(src)
	i := 0
	// next skips whitespace and comments; it returns false on an
	// unterminated block comment.
	next := func() bool {
		for i < n {
			switch c := src[i]; {
			case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f':
				i++
			case c == '/' && i+1 < n && src[i+1] == '/':
				for i < n && src[i] != '\n' {
					i++
				}
			case c == '/' && i+1 < n && src[i+1] == '*':
				end := indexFrom(src, i+2, "*/")
				if end < 0 {
					return false
				}
				i = end + 2
			default:
				return true
			}
		}
		return true
	}
	// quoted returns the raw bytes between the quotes of the string literal
	// that starts at src[i] (== '"') and moves past it.
	quoted := func() (string, bool) {
		start := i + 1
		for j := start; j < n; j++ {
			switch src[j] {
			case '\\':
				j++
			case '\n':
				return "", false // libyara refuses a newline inside a text string
			case '"':
				i = j + 1
				return string(src[start:j]), true
			}
		}
		return "", false
	}
	for {
		if !next() {
			return errRuleSyntax
		}
		if i >= n {
			return nil
		}
		c := src[i]
		switch {
		case c == '"':
			if _, ok := quoted(); !ok {
				return errRuleSyntax
			}
		case c == '/': // a regular expression: up to the next unescaped '/'
			j := i + 1
			for ; j < n && src[j] != '/'; j++ {
				if src[j] == '\\' {
					j++
				} else if src[j] == '\n' {
					return errRuleSyntax
				}
			}
			if j >= n {
				return errRuleSyntax
			}
			i = j + 1
		case c == '$' || c == '#' || c == '@' || c == '!' || isIdentByte(c):
			start := i
			i++
			for i < n && isIdentByte(src[i]) {
				i++
			}
			word := string(src[start:i])
			switch word {
			case "include":
				return errInclude
			case "import":
				if !next() {
					return errRuleSyntax
				}
				if i >= n || src[i] != '"' {
					return fmt.Errorf("%w: import without a module name", errModuleNotAllowed)
				}
				mod, ok := quoted()
				if !ok {
					return errRuleSyntax
				}
				if !moduleAllowed(mod) {
					return fmt.Errorf("%w: %q (allowed: %v)", errModuleNotAllowed, mod, AllowedModules)
				}
			}
		default:
			i++
		}
	}
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func moduleAllowed(raw string) bool {
	for _, m := range AllowedModules {
		if raw == m {
			return true
		}
	}
	return false
}

func indexFrom(b []byte, from int, sub string) int {
	for j := from; j+len(sub) <= len(b); j++ {
		if string(b[j:j+len(sub)]) == sub {
			return j
		}
	}
	return -1
}
