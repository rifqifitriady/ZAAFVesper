package ebpf

import (
	"fmt"
	"sync"
	"time"
)

// SensorDegraded conditions reported by this source (OnDegraded).
const (
	// CondEventsDropped: the kernel side could not report events: the ring
	// buffer was full (ZAAFVesper read too slowly), a program found the
	// scratch buffers of its CPU in use, the kernel skipped a program
	// because another one was running there (recursion misses), or a
	// port-53 datagram could not be read. Counted per CPU and per kind in
	// the kernel, read every second.
	CondEventsDropped = "ebpf_events_dropped"
	// CondEventsUnreadable: a record could not be decoded and was not
	// evaluated.
	CondEventsUnreadable = "ebpf_events_unreadable"
)

// degradedEvery rate-limits reports per condition (as the Sysmon source).
const degradedEvery = time.Minute

// reporter delivers condition reports at most once a minute per
// condition; the next report counts the ones suppressed meanwhile.
type reporter struct {
	mu       sync.Mutex
	fn       func(condition, detail string)
	now      func() time.Time
	last     map[string]time.Time
	suppress map[string]uint64
}

func newReporter() *reporter {
	return &reporter{now: time.Now, last: map[string]time.Time{}, suppress: map[string]uint64{}}
}

func (r *reporter) set(fn func(condition, detail string)) {
	r.mu.Lock()
	r.fn = fn
	r.mu.Unlock()
}

func (r *reporter) report(condition, detail string) {
	r.mu.Lock()
	fn := r.fn
	if fn == nil {
		r.mu.Unlock()
		return
	}
	now := r.now()
	if t, ok := r.last[condition]; ok && now.Sub(t) < degradedEvery && now.Sub(t) >= 0 {
		r.suppress[condition]++
		r.mu.Unlock()
		return
	}
	r.last[condition] = now
	if n := r.suppress[condition]; n > 0 {
		detail = fmt.Sprintf("%s (%d similar reports suppressed in the last minute)", detail, n)
		r.suppress[condition] = 0
	}
	r.mu.Unlock()
	fn(condition, detail)
}

// dropTracker turns the kernel's cumulative per-kind drop counters into
// reports of what was lost since the last poll.
type dropTracker struct {
	last  [nSlots]uint64
	total uint64
}

// update takes the current per-kind totals (summed over CPUs) and returns
// the number lost since the previous call and a description, or 0.
func (d *dropTracker) update(now [nSlots]uint64) (uint64, string) {
	var delta uint64
	detail := ""
	for k := 1; k < nSlots; k++ {
		if now[k] < d.last[k] { // counters never go back; treat as a reset
			d.last[k] = 0
		}
		if n := now[k] - d.last[k]; n > 0 {
			delta += n
			if detail != "" {
				detail += ", "
			}
			detail += fmt.Sprintf("%d %s", n, kindNames[k])
		}
		d.last[k] = now[k]
	}
	if delta == 0 {
		return 0, ""
	}
	d.total += delta
	return delta, fmt.Sprintf("the kernel side lost %d events (ring buffer full, or programs skipped while another one used the CPU: %s); %d lost in total", delta, detail, d.total)
}
