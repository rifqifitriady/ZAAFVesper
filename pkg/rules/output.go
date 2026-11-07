package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

// template renders a rule's output string. "%ps.exe" refers to the last
// event; "%2.file.path" to the event that matched step 2 of a sequence;
// "%%" is a literal percent sign.
type template struct {
	parts []tmplPart
}

type tmplPart struct {
	lit   string
	step  int // 0 = last event, else 1-based sequence step
	field *ql.Field
}

func isFieldChar(c byte) bool {
	return c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// parseTemplate compiles an output string. steps is the number of sequence
// steps (0 for single-event rules).
func parseTemplate(s string, steps int) (*template, error) {
	t := &template{}
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			t.parts = append(t.parts, tmplPart{lit: lit.String()})
			lit.Reset()
		}
	}
	i := 0
	for i < len(s) {
		c := s[i]
		if c != '%' {
			lit.WriteByte(c)
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '%' {
			lit.WriteByte('%')
			i += 2
			continue
		}
		j := i + 1
		step := 0
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			k := j
			for k < len(s) && s[k] >= '0' && s[k] <= '9' {
				k++
			}
			if k < len(s) && s[k] == '.' {
				n, err := strconv.Atoi(s[j:k])
				if err != nil || n < 1 {
					return nil, fmt.Errorf("output: %%%s.: step numbers start at 1", s[j:k])
				}
				step = n
				j = k + 1
			}
		}
		k := j
		for k < len(s) && isFieldChar(s[k]) {
			k++
		}
		if k < len(s) && s[k] == '[' {
			if end := strings.IndexByte(s[k:], ']'); end > 0 {
				k += end + 1
			}
		}
		name := s[j:k]
		// Trailing dots are punctuation ("wrote %file.path.").
		for strings.HasSuffix(name, ".") && !strings.Contains(name, "[") {
			name = name[:len(name)-1]
			k--
		}
		if name == "" {
			lit.WriteByte('%')
			i++
			continue
		}
		f, err := ql.CompileField(name)
		if err != nil {
			return nil, fmt.Errorf("output: %%%s: %v", s[i+1:k], err)
		}
		if step != 0 {
			if steps == 0 {
				return nil, fmt.Errorf("output: %%%d.%s refers to a sequence step but the rule is not a sequence", step, name)
			}
			if step < 1 || step > steps {
				return nil, fmt.Errorf("output: %%%d.%s refers to step %d of %d", step, name, step, steps)
			}
		}
		flush()
		t.parts = append(t.parts, tmplPart{step: step, field: f})
		i = k
	}
	flush()
	return t, nil
}

// FormatValue renders a field value for output.
func FormatValue(v event.Value) string {
	switch x := v.(type) {
	case nil:
		return "<none>"
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	case []string:
		return "[" + strings.Join(x, " ") + "]"
	}
	return fmt.Sprint(v)
}

// render expands the template. events are the matched events in step order;
// the last one is the default for unnumbered references.
func (t *template) render(events []*event.Event) string {
	if t == nil || len(events) == 0 {
		return ""
	}
	var b strings.Builder
	for _, p := range t.parts {
		if p.field == nil {
			b.WriteString(p.lit)
			continue
		}
		e := events[len(events)-1]
		if p.step > 0 && p.step <= len(events) {
			e = events[p.step-1]
		}
		b.WriteString(FormatValue(p.field.Value(e)))
	}
	return b.String()
}
