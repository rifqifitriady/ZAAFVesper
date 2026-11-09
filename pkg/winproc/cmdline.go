package winproc

import "strings"

// SplitCommandLine splits a Windows command line into arguments with the
// Microsoft C runtime rules (learn.microsoft.com/cpp/c-language/parsing-c-command-line-arguments):
// argv[0] ends at the first whitespace or, when it starts with a double
// quote, at the next double quote; afterwards 2n backslashes before a quote
// give n backslashes and toggle quoting, 2n+1 give n backslashes and a
// literal quote, other backslashes are literal, and "" inside a quoted
// region gives one literal quote. The program decides how to parse its own
// command line, so the result is a best effort for ps.args; ps.cmdline
// keeps the exact string. At most max arguments are returned (0: no limit).
func SplitCommandLine(s string, max int) []string {
	var args []string
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return nil
	}
	// argv[0]
	var b strings.Builder
	if s[i] == '"' {
		i++
		for i < len(s) && s[i] != '"' {
			b.WriteByte(s[i])
			i++
		}
		i++
	} else {
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			b.WriteByte(s[i])
			i++
		}
	}
	args = append(args, b.String())
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) || (max > 0 && len(args) >= max) {
			return args
		}
		b.Reset()
		quoted := false
		for i < len(s) {
			c := s[i]
			if !quoted && (c == ' ' || c == '\t') {
				break
			}
			if c == '\\' {
				n := 0
				for i < len(s) && s[i] == '\\' {
					n++
					i++
				}
				if i < len(s) && s[i] == '"' {
					b.WriteString(strings.Repeat(`\`, n/2))
					if n%2 == 1 {
						b.WriteByte('"')
						i++
					}
					continue
				}
				b.WriteString(strings.Repeat(`\`, n))
				continue
			}
			if c == '"' {
				if quoted && i+1 < len(s) && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				quoted = !quoted
				i++
				continue
			}
			b.WriteByte(c)
			i++
		}
		args = append(args, b.String())
	}
}
