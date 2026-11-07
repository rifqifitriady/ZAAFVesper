package eslogger

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The eslogger schema is explicitly unstable ("NOT API in any sense", man
// eslogger). These scalar types accept whatever shape a field turns up in
// (number, numeric string, bool, null, object) and fall back to the zero value
// instead of failing, so one odd field never costs the whole event.

// jnum is an integer that tolerates numbers, numeric strings, bools and null.
type jnum int64

func (n *jnum) UnmarshalJSON(b []byte) error {
	*n = 0
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case 't':
		*n = 1
		return nil
	case '"':
		var s string
		if json.Unmarshal(b, &s) != nil {
			return nil
		}
		b = []byte(strings.TrimSpace(s))
	case '{':
		// A C union rendered as an object, e.g. "from_uid": {"uid": 0}.
		var m map[string]jnum
		if json.Unmarshal(b, &m) == nil {
			for _, v := range m {
				*n = v
				return nil
			}
		}
		return nil
	}
	s := string(b)
	if v, err := strconv.ParseInt(s, 0, 64); err == nil {
		*n = jnum(v)
		return nil
	}
	if v, err := strconv.ParseUint(s, 0, 64); err == nil {
		*n = jnum(int64(v)) // wraps for values above MaxInt64; callers that care cast back
		return nil
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		*n = jnum(int64(v))
	}
	return nil
}

// jbool is a bool that tolerates numbers and strings.
type jbool bool

func (v *jbool) UnmarshalJSON(b []byte) error {
	*v = false
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case 't':
		*v = true
	case '"':
		var s string
		if json.Unmarshal(b, &s) == nil {
			p, _ := strconv.ParseBool(strings.TrimSpace(s))
			*v = jbool(p)
		}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		f, err := strconv.ParseFloat(string(b), 64)
		*v = jbool(err == nil && f != 0)
	}
	return nil
}

// jstr is a string that tolerates null, numbers and es_string_token_t-style
// objects ({"data": "...", "length": n}).
type jstr string

func (s *jstr) UnmarshalJSON(b []byte) error {
	*s = ""
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case '"':
		var v string
		if json.Unmarshal(b, &v) == nil {
			*s = jstr(v)
		}
	case '{':
		var tok struct {
			Data jstr `json:"data"`
		}
		if json.Unmarshal(b, &tok) == nil {
			*s = tok.Data
		}
	case 'n', '[':
		// null or array: leave empty
	default:
		*s = jstr(b) // number or bool literal
	}
	return nil
}

// jstrs is a string list that tolerates null and non-string elements.
type jstrs []string

func (l *jstrs) UnmarshalJSON(b []byte) error {
	*l = nil
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '[' {
		return nil
	}
	var raw []jstr
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = string(v)
	}
	*l = out
	return nil
}

// jtime accepts RFC 3339 strings (eslogger's format), a struct timeval /
// timespec object, or a number of seconds since the epoch.
type jtime time.Time

func (t *jtime) UnmarshalJSON(b []byte) error {
	*t = jtime(time.Time{})
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case '"':
		var s string
		if json.Unmarshal(b, &s) != nil {
			return nil
		}
		if v, err := time.Parse(time.RFC3339Nano, s); err == nil {
			*t = jtime(v.UTC())
		}
	case '{':
		var tv struct {
			Sec  jnum `json:"tv_sec"`
			Usec jnum `json:"tv_usec"`
			Nsec jnum `json:"tv_nsec"`
		}
		if json.Unmarshal(b, &tv) == nil && (tv.Sec != 0 || tv.Usec != 0 || tv.Nsec != 0) {
			*t = jtime(time.Unix(int64(tv.Sec), int64(tv.Usec)*1000+int64(tv.Nsec)).UTC())
		}
	default:
		var n jnum
		_ = n.UnmarshalJSON(b)
		if n != 0 {
			*t = jtime(time.Unix(int64(n), 0).UTC())
		}
	}
	return nil
}

// jhex is a byte string rendered as lowercase hex. eslogger renders cdhash as
// a hex string; an array of byte values is accepted too.
type jhex string

func (h *jhex) UnmarshalJSON(b []byte) error {
	*h = ""
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case '"':
		var s string
		if json.Unmarshal(b, &s) == nil {
			*h = jhex(strings.ToLower(strings.TrimSpace(s)))
		}
	case '[':
		var arr []jnum
		if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
			buf := make([]byte, len(arr))
			for i, v := range arr {
				buf[i] = byte(v)
			}
			*h = jhex(hex.EncodeToString(buf))
		}
	}
	if strings.Trim(string(*h), "0") == "" {
		*h = "" // an all-zero cdhash means "no cdhash"
	}
	return nil
}

// isObject reports whether b holds a JSON object (not null, not a scalar).
func isObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{'
}
