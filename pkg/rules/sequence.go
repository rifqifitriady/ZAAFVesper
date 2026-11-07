package rules

import (
	"container/list"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

const (
	minSteps   = 2
	maxSteps   = 5
	maxMaxSpan = 24 * time.Hour
	// DefaultMaxPartials bounds the partial sequences kept per rule.
	DefaultMaxPartials = 10000
	// DefaultMaxPartialBytes bounds the estimated memory of all partial
	// sequences of an engine, across rules.
	DefaultMaxPartialBytes = 64 << 20
)

// Sequence is a compiled sequence condition:
//
//	sequence maxspan 2m [by <field>]
//	  |<expr>| [by <field>]
//	  |<expr>| [by <field>]
type Sequence struct {
	MaxSpan  time.Duration
	Steps    []*Step
	GlobalBy string // field named after the header's "by", if any
}

// Step is one step of a sequence.
type Step struct {
	Expr   string
	Filter *ql.Filter
	By     *ql.Field // join field; nil when the sequence has no join
}

// EventNames is the union of the steps' event names (nil = any).
func (s *Sequence) EventNames() []string {
	set := map[string]bool{}
	for _, st := range s.Steps {
		names := st.Filter.EventNames()
		if names == nil {
			return nil
		}
		for _, n := range names {
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// isSequence reports whether a condition is a sequence.
func isSequence(cond string) bool {
	s := strings.TrimSpace(cond)
	if !strings.HasPrefix(s, "sequence") {
		return false
	}
	rest := s[len("sequence"):]
	return rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n' || rest[0] == '\r' || rest[0] == '|'
}

// scanStep returns the index of the '|' closing a step body that starts at
// s[0], skipping '|' inside single-quoted strings.
func scanStep(s string) int {
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr && c == '\\' && i+1 < len(s):
			i++
		case c == '\'':
			inStr = !inStr
		case !inStr && c == '|':
			return i
		}
	}
	return -1
}

func compileBy(name string) (*ql.Field, error) {
	f, err := ql.CompileField(name)
	if err != nil {
		return nil, fmt.Errorf("by %s: %v", name, err)
	}
	if k := f.Kind(); k != event.KindString && k != event.KindInt {
		return nil, fmt.Errorf("by %s: join field must be a string or integer field", name)
	}
	return f, nil
}

// parseSequence compiles a sequence condition.
func parseSequence(cond string, m *ql.Macros) (*Sequence, error) {
	s := strings.TrimSpace(cond)
	s = strings.TrimSpace(s[len("sequence"):])
	bar := strings.IndexByte(s, '|')
	if bar < 0 {
		return nil, fmt.Errorf("sequence has no |step|")
	}
	seq := &Sequence{}
	header := strings.Fields(s[:bar])
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case "maxspan":
			if i+1 >= len(header) {
				return nil, fmt.Errorf("maxspan needs a duration")
			}
			d, err := time.ParseDuration(header[i+1])
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("maxspan %q is not a positive duration (units ms, s, m, h)", header[i+1])
			}
			if d > maxMaxSpan {
				return nil, fmt.Errorf("maxspan %s exceeds %s", d, maxMaxSpan)
			}
			seq.MaxSpan = d
			i++
		case "by":
			if i+1 >= len(header) {
				return nil, fmt.Errorf("by needs a field")
			}
			seq.GlobalBy = header[i+1]
			i++
		default:
			return nil, fmt.Errorf("unexpected %q in sequence header (expected maxspan or by)", header[i])
		}
	}
	if seq.MaxSpan == 0 {
		return nil, fmt.Errorf("sequence needs maxspan")
	}
	var global *ql.Field
	if seq.GlobalBy != "" {
		f, err := compileBy(seq.GlobalBy)
		if err != nil {
			return nil, err
		}
		global = f
	}

	rest := s[bar:]
	perStepBy := 0
	for n := 1; rest != ""; n++ {
		if rest[0] != '|' {
			return nil, fmt.Errorf("expected '|' to open step %d, found %q", n, firstWord(rest))
		}
		end := scanStep(rest[1:])
		if end < 0 {
			return nil, fmt.Errorf("step %d: missing closing '|'", n)
		}
		expr := strings.TrimSpace(rest[1 : 1+end])
		rest = strings.TrimSpace(rest[2+end:])
		if expr == "" {
			return nil, fmt.Errorf("step %d is empty", n)
		}
		f, err := ql.Compile(expr, m)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", n, err)
		}
		st := &Step{Expr: expr, Filter: f, By: global}
		if strings.HasPrefix(rest, "by") && (len(rest) == 2 || rest[2] == ' ' || rest[2] == '\t' || rest[2] == '\n' || rest[2] == '\r') {
			next := strings.IndexByte(rest, '|')
			if next < 0 {
				next = len(rest)
			}
			name := strings.TrimSpace(rest[2:next])
			rest = rest[next:]
			if global != nil {
				return nil, fmt.Errorf("step %d: per-step by cannot be combined with a global by", n)
			}
			if name == "" {
				return nil, fmt.Errorf("step %d: by needs a field", n)
			}
			bf, err := compileBy(name)
			if err != nil {
				return nil, fmt.Errorf("step %d: %v", n, err)
			}
			st.By = bf
			perStepBy++
		}
		seq.Steps = append(seq.Steps, st)
		if len(seq.Steps) > maxSteps {
			return nil, fmt.Errorf("sequence has more than %d steps", maxSteps)
		}
	}
	if len(seq.Steps) < minSteps {
		return nil, fmt.Errorf("sequence needs at least %d steps", minSteps)
	}
	if perStepBy != 0 && perStepBy != len(seq.Steps) {
		return nil, fmt.Errorf("per-step by must be given on every step (%d of %d have one)", perStepBy, len(seq.Steps))
	}
	return seq, nil
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}

// ---- runtime state ----

// partialBudget is the memory budget shared by every sequence rule of an
// engine. Partials are charged an estimate of the bytes they hold; when the
// total exceeds max the oldest partial of any rule is evicted first.
type partialBudget struct {
	max     int64
	used    int64
	order   *list.List // all partials of all rules, oldest first
	evicted uint64
}

func newPartialBudget(max int64) *partialBudget {
	if max <= 0 {
		max = DefaultMaxPartialBytes
	}
	return &partialBudget{max: max, order: list.New()}
}

type partial struct {
	st     *seqState
	key    string
	stage  int // index of the step this partial waits for
	start  time.Time
	events []*event.Event
	size   int64
	elem   *list.Element // in st.order
	gelem  *list.Element // in budget.order
}

type seqState struct {
	seq     *Sequence
	waiting []map[string]*partial // index = stage (1..n-1)
	order   *list.List            // this rule's partials by creation time, oldest first
	max     int
	budget  *partialBudget
	evicted uint64
	expired uint64
}

func newSeqState(seq *Sequence, max int, budget *partialBudget) *seqState {
	if max <= 0 {
		max = DefaultMaxPartials
	}
	if budget == nil {
		budget = newPartialBudget(0)
	}
	st := &seqState{seq: seq, order: list.New(), max: max, budget: budget}
	st.waiting = make([]map[string]*partial, len(seq.Steps))
	for i := range st.waiting {
		st.waiting[i] = map[string]*partial{}
	}
	return st
}

func joinKey(st *Step, e *event.Event) (string, bool) {
	if st.By == nil {
		return "", true
	}
	switch v := st.By.Value(e).(type) {
	case string:
		return v, v != ""
	case int64:
		return strconv.FormatInt(v, 10), true
	}
	return "", false
}

// MaxSlimField caps strings kept in partial sequences (cmdline, each arg
// list, each evt.arg value).
const MaxSlimField = 4 << 10

func capStr(s string) string {
	if len(s) <= MaxSlimField {
		return s
	}
	return s[:MaxSlimField]
}

func slimProc(p *event.Proc, withParent bool) (*event.Proc, int64) {
	if p == nil {
		return nil, 0
	}
	cp := *p
	cp.Env = nil // never held in sequence state
	cp.Cmdline = capStr(cp.Cmdline)
	size := int64(len(cp.Exe) + len(cp.Name) + len(cp.Cmdline) + len(cp.Cwd) + len(cp.Username) +
		len(cp.SigningID) + len(cp.TeamID) + len(cp.CDHash) + len(cp.TTY) + 160)
	if len(cp.Args) > 0 {
		var args []string
		total := 0
		for _, a := range cp.Args {
			if total+len(a) > MaxSlimField {
				break
			}
			total += len(a)
			args = append(args, a)
		}
		cp.Args = args
		size += int64(total + 16*len(args))
	}
	for _, a := range cp.Ancestors {
		size += int64(len(a) + 16)
	}
	if withParent && cp.Parent != nil {
		pp, n := slimProc(cp.Parent, false)
		pp.Parent = nil
		cp.Parent = pp
		size += n
	} else {
		cp.Parent = nil
	}
	return &cp, size
}

// slimEvent returns the copy of e kept in a partial sequence: no
// environment, strings capped at MaxSlimField, and its estimated size.
func slimEvent(e *event.Event) (*event.Event, int64) {
	cp := *e
	size := int64(len(cp.Name) + len(cp.Source) + 96)
	var n int64
	cp.Proc, n = slimProc(e.Proc, true)
	size += n
	cp.Target, n = slimProc(e.Target, true)
	size += n
	if e.File != nil {
		f := *e.File
		cp.File = &f
		size += int64(len(f.Path) + len(f.Dest) + 48)
	}
	if e.Args != nil {
		cp.Args = make(map[string]string, len(e.Args))
		for k, v := range e.Args {
			v = capStr(v)
			cp.Args[k] = v
			size += int64(len(k) + len(v) + 32)
		}
	}
	if e.Yara != nil {
		y := *e.Yara
		cp.Yara = &y
		size += int64(len(y.Rule) + len(y.Namespace) + len(y.Target) + 64)
		for _, t := range y.Tags {
			size += int64(len(t) + 16)
		}
		for k, v := range y.Meta {
			size += int64(len(k) + len(v) + 32)
		}
	}
	return &cp, size
}

func (st *seqState) remove(p *partial) {
	if cur := st.waiting[p.stage][p.key]; cur == p {
		delete(st.waiting[p.stage], p.key)
	}
	if p.elem != nil {
		st.order.Remove(p.elem)
		p.elem = nil
	}
	if p.gelem != nil {
		st.budget.order.Remove(p.gelem)
		p.gelem = nil
		st.budget.used -= p.size
	}
}

// charge adds an event to p and enforces the shared byte budget.
func (st *seqState) charge(p *partial, n int64) {
	p.size += n
	st.budget.used += n
	for st.budget.used > st.budget.max && st.budget.order.Len() > 0 {
		old := st.budget.order.Front().Value.(*partial)
		old.st.remove(old)
		old.st.evicted++
		st.budget.evicted++
	}
}

func (st *seqState) expire(now time.Time) {
	for el := st.order.Front(); el != nil; el = st.order.Front() {
		p := el.Value.(*partial)
		if now.Sub(p.start) <= st.seq.MaxSpan {
			return
		}
		st.remove(p)
		st.expired++
	}
}

// len returns the number of live partials.
func (st *seqState) len() int { return st.order.Len() }

// process feeds one event and returns the event lists of completed sequences.
// Steps are tried from last to first so that one event never advances the
// same partial twice. Earlier steps are slim copies (see slimEvent); the
// completing event is the original.
func (st *seqState) process(e *event.Event, now time.Time) [][]*event.Event {
	st.expire(now)
	var done [][]*event.Event
	last := len(st.seq.Steps) - 1
	for i := last; i >= 0; i-- {
		step := st.seq.Steps[i]
		if !step.Filter.Match(e) {
			continue
		}
		key, ok := joinKey(step, e)
		if !ok {
			continue
		}
		if i == 0 {
			if old := st.waiting[1][key]; old != nil {
				st.remove(old) // the newest start wins
			}
			for st.order.Len() >= st.max {
				st.remove(st.order.Front().Value.(*partial))
				st.evicted++
			}
			se, n := slimEvent(e)
			p := &partial{st: st, key: key, stage: 1, start: now, events: []*event.Event{se}}
			p.elem = st.order.PushBack(p)
			p.gelem = st.budget.order.PushBack(p)
			st.waiting[1][key] = p
			st.charge(p, n)
			continue
		}
		p := st.waiting[i][key]
		if p == nil {
			continue
		}
		if now.Sub(p.start) > st.seq.MaxSpan {
			st.remove(p)
			st.expired++
			continue
		}
		if i == last {
			events := append(p.events, e)
			st.remove(p)
			done = append(done, events)
			continue
		}
		delete(st.waiting[i], key)
		p.stage = i + 1
		if old := st.waiting[i+1][key]; old != nil {
			st.remove(old)
		}
		st.waiting[i+1][key] = p
		se, n := slimEvent(e)
		p.events = append(p.events, se)
		st.charge(p, n)
	}
	return done
}
