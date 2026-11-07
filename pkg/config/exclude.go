package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

type exclusion struct {
	name   string
	filter *ql.Filter // nil = every event of the listed names
	hits   uint64
}

// Exclusions is the compiled set of global exclusions. Match is called from
// the single pipeline goroutine.
type Exclusions struct {
	byName map[string][]*exclusion
	any    []*exclusion
	all    []*exclusion
}

// CompileExclusions compiles exclusion entries with the rules' macros (m may
// be nil). An entry needs events, a condition, or both.
func CompileExclusions(list []Exclusion, m *ql.Macros) (*Exclusions, error) {
	known := map[string]bool{}
	for _, n := range ql.KnownEvents() {
		known[n] = true
	}
	x := &Exclusions{byName: map[string][]*exclusion{}}
	var errs []error
	for i, ex := range list {
		label := ex.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if len(ex.Events) == 0 && strings.TrimSpace(ex.Condition) == "" {
			errs = append(errs, fmt.Errorf("exclusion %q: needs events, a condition, or both", label))
			continue
		}
		c := &exclusion{name: label}
		if strings.TrimSpace(ex.Condition) != "" {
			f, err := ql.Compile(ex.Condition, m)
			if err != nil {
				errs = append(errs, fmt.Errorf("exclusion %q: %w", label, err))
				continue
			}
			c.filter = f
		}
		names := ex.Events
		bad := false
		for _, n := range names {
			if !known[n] {
				errs = append(errs, fmt.Errorf("exclusion %q: unknown event %q", label, n))
				bad = true
			}
		}
		if bad {
			continue
		}
		if len(names) == 0 {
			names = c.filter.EventNames()
		}
		x.all = append(x.all, c)
		if names == nil {
			x.any = append(x.any, c)
			continue
		}
		for _, n := range names {
			x.byName[n] = append(x.byName[n], c)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return x, nil
}

// Match reports whether e is excluded and by which entry.
func (x *Exclusions) Match(e *event.Event) (string, bool) {
	if x == nil || e == nil {
		return "", false
	}
	for _, list := range [2][]*exclusion{x.byName[e.Name], x.any} {
		for _, c := range list {
			if c.filter == nil || c.filter.Match(e) {
				c.hits++
				return c.name, true
			}
		}
	}
	return "", false
}

// Len returns the number of exclusions.
func (x *Exclusions) Len() int {
	if x == nil {
		return 0
	}
	return len(x.all)
}

// Stats returns hit counts by exclusion name (only entries that matched).
func (x *Exclusions) Stats() map[string]uint64 {
	out := map[string]uint64{}
	if x == nil {
		return out
	}
	for _, c := range x.all {
		if c.hits > 0 {
			out[c.name] += c.hits
		}
	}
	return out
}
