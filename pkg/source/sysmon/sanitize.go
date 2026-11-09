package sysmon

import (
	"bytes"
	"strconv"
	"unicode/utf8"
)

// replacement is U+FFFD in UTF-8.
var replacement = []byte("�")

// legalXMLChar reports whether r may appear in an XML 1.0 document.
func legalXMLChar(r rune) bool {
	return r == 0x9 || r == 0xA || r == 0xD ||
		r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF
}

// Sanitize returns raw with every character XML 1.0 forbids replaced by
// U+FFFD: invalid UTF-8 bytes, raw control characters other than tab, CR and
// LF, U+FFFE and U+FFFF, and numeric character references (&#1; &#x1B;) to
// any of those. Process command lines and file names may contain such
// characters; without this, one of them would make the whole event fail to
// parse and vanish. The input is returned unchanged (no copy) when it is
// already clean.
func Sanitize(raw []byte) []byte {
	if clean(raw) {
		return raw
	}
	out := make([]byte, 0, len(raw)+16)
	for i := 0; i < len(raw); {
		c := raw[i]
		if c == '&' && i+2 < len(raw) && raw[i+1] == '#' {
			if n, ok := charRef(raw[i:]); ok {
				ref := raw[i : i+n]
				if r, valid := refRune(ref); valid && !legalXMLChar(r) {
					out = append(out, replacement...)
				} else {
					out = append(out, ref...)
				}
				i += n
				continue
			}
		}
		if c < utf8.RuneSelf {
			if legalXMLChar(rune(c)) {
				out = append(out, c)
			} else {
				out = append(out, replacement...)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size <= 1 || !legalXMLChar(r) {
			out = append(out, replacement...)
			i += max(size, 1)
			continue
		}
		out = append(out, raw[i:i+size]...)
		i += size
	}
	return out
}

// clean is the fast path: valid UTF-8, only legal characters, and no
// numeric character reference at all.
func clean(raw []byte) bool {
	if bytes.Contains(raw, []byte("&#")) || !utf8.Valid(raw) {
		return false
	}
	for _, r := range string(raw) {
		if !legalXMLChar(r) {
			return false
		}
	}
	return true
}

// charRef returns the length of the "&#...;" reference at the start of b
// (at most 12 bytes), or false.
func charRef(b []byte) (int, bool) {
	for n := 3; n < len(b) && n <= 12; n++ {
		if b[n] == ';' {
			return n + 1, true
		}
	}
	return 0, false
}

// refRune decodes "&#123;" or "&#x1F;"; valid is false when it is not a
// well-formed number (left for the XML decoder to reject).
func refRune(ref []byte) (rune, bool) {
	body := string(ref[2 : len(ref)-1])
	base := 10
	if len(body) > 0 && (body[0] == 'x' || body[0] == 'X') {
		base, body = 16, body[1:]
	}
	n, err := strconv.ParseUint(body, base, 32)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}
