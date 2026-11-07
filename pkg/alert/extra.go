package alert

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// ---- environment redaction ----

// Redacted replaces environment values in stored events.
const Redacted = "<redacted>"

// KeepEnvPrefixes are environment variables whose values are kept even when
// redacting: they are the detection evidence (DYLD_INSERT_LIBRARIES, ...).
var KeepEnvPrefixes = []string{"DYLD_"}

func keepEnvValue(k string) bool {
	for _, p := range KeepEnvPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

func redactProc(p *event.Proc) *event.Proc {
	if p == nil {
		return nil
	}
	cp := *p
	if p.Env != nil {
		cp.Env = make(map[string]string, len(p.Env))
		for k, v := range p.Env {
			if keepEnvValue(k) {
				cp.Env[k] = v
			} else {
				cp.Env[k] = Redacted
			}
		}
	}
	cp.Parent = redactProc(p.Parent)
	return &cp
}

// RedactEvent returns a copy of e whose process environments keep variable
// names but replace values with "<redacted>", except DYLD_* variables. e is
// not modified. Used for captures and JSONL alerts unless --keep-env.
func RedactEvent(e *event.Event) *event.Event {
	if e == nil {
		return nil
	}
	if !hasEnv(e.Proc) && !hasEnv(e.Target) {
		return e
	}
	cp := *e
	cp.Proc = redactProc(e.Proc)
	cp.Target = redactProc(e.Target)
	return &cp
}

func hasEnv(p *event.Proc) bool {
	for ; p != nil; p = p.Parent {
		if len(p.Env) > 0 {
			return true
		}
	}
	return false
}

// RedactAlert returns a copy of a with every event redacted.
func RedactAlert(a *rules.Alert) *rules.Alert {
	cp := *a
	cp.Events = make([]*event.Event, len(a.Events))
	for i, e := range a.Events {
		cp.Events[i] = RedactEvent(e)
	}
	return &cp
}

// ---- deduplication ----

// DefaultDedupWindow is how long repeats of (rule, pid) are suppressed.
const DefaultDedupWindow = 10 * time.Second

const maxDedupKeys = 65536

// Deduper suppresses repeated alerts of the same rule for the same process
// within a window (measured on alert time, i.e. event time). Not safe for
// concurrent use; the pipeline calls it from one goroutine.
type Deduper struct {
	window     time.Duration
	last       map[string]time.Time
	suppressed map[string]uint64 // rule name -> suppressed count
}

// NewDeduper returns a deduper; window <= 0 uses DefaultDedupWindow.
func NewDeduper(window time.Duration) *Deduper {
	if window <= 0 {
		window = DefaultDedupWindow
	}
	return &Deduper{window: window, last: map[string]time.Time{}, suppressed: map[string]uint64{}}
}

// Allow reports whether a should be delivered.
func (d *Deduper) Allow(a *rules.Alert) bool {
	var pid int32
	if e := a.Last(); e != nil && e.Proc != nil {
		pid = e.Proc.PID
	}
	key := a.RuleID + "|" + strconv.FormatInt(int64(pid), 10)
	if t, ok := d.last[key]; ok && a.Time.Sub(t) < d.window && a.Time.Sub(t) >= 0 {
		d.suppressed[a.RuleName]++
		return false
	}
	if len(d.last) >= maxDedupKeys {
		for k, t := range d.last {
			if a.Time.Sub(t) >= d.window {
				delete(d.last, k)
			}
		}
		if len(d.last) >= maxDedupKeys {
			d.last = map[string]time.Time{} // bounded memory beats perfect dedup
		}
	}
	d.last[key] = a.Time
	return true
}

// Suppressed returns suppressed counts by rule name.
func (d *Deduper) Suppressed() map[string]uint64 {
	out := make(map[string]uint64, len(d.suppressed))
	for k, v := range d.suppressed {
		out[k] = v
	}
	return out
}

// ---- asynchronous delivery ----

// DefaultQueue is the default Async queue length.
const DefaultQueue = 1024

// Async delivers alerts to a sink from its own goroutine through a bounded
// queue, so a blocked terminal never stalls the event pipeline. When the
// queue is full the alert is dropped and counted.
type Async struct {
	sink    Sink
	q       chan *rules.Alert
	done    chan struct{}
	dropped atomic.Uint64
	errs    atomic.Uint64
	once    sync.Once
}

// NewAsync starts the delivery goroutine. queue <= 0 uses DefaultQueue.
func NewAsync(s Sink, queue int) *Async {
	if queue <= 0 {
		queue = DefaultQueue
	}
	a := &Async{sink: s, q: make(chan *rules.Alert, queue), done: make(chan struct{})}
	go func() {
		defer close(a.done)
		for al := range a.q {
			if err := s.Send(al); err != nil {
				a.errs.Add(1)
			}
		}
	}()
	return a
}

// Send queues the alert without blocking.
func (a *Async) Send(al *rules.Alert) (err error) {
	defer func() {
		if recover() != nil { // send after Close
			a.dropped.Add(1)
			err = errors.New("alert: async sink closed")
		}
	}()
	select {
	case a.q <- al:
		return nil
	default:
		a.dropped.Add(1)
		return nil
	}
}

// Dropped returns the number of alerts dropped because the queue was full.
func (a *Async) Dropped() uint64 { return a.dropped.Load() }

// Errors returns the number of delivery errors of the wrapped sink.
func (a *Async) Errors() uint64 { return a.errs.Load() }

// Close stops accepting alerts and waits up to timeout for the queue to
// drain. It reports an error if the sink is still blocked.
func (a *Async) Close(timeout time.Duration) error {
	a.once.Do(func() { close(a.q) })
	select {
	case <-a.done:
		return nil
	case <-time.After(timeout):
		return errors.New("alert: sink still blocked at shutdown; pending alerts abandoned")
	}
}
