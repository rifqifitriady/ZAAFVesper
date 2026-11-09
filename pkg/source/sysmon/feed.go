package sysmon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// CondEventsDropped is the OnDegraded condition reported when Sysmon's
// EventRecordID skips numbers: events were lost between Sysmon and
// ZAAFVesper (event log overwrite, journald rate limiting, a restart).
const CondEventsDropped = "sysmon_events_dropped"

// degradedEvery rate-limits reports per condition.
const degradedEvery = time.Minute

// Feeder is the part of a Sysmon source shared by the Windows and Linux
// readers: decode, bind the kernel identity, detect lost events, filter by
// the subscription and send. It runs on one reading goroutine.
type Feeder struct {
	Binder *Binder // nil: no identity binding (kills then always refuse)
	wanted map[string]bool

	mu       sync.Mutex
	fn       func(condition, detail string)
	lastRep  time.Time
	suppress uint64
	now      func() time.Time

	lastRecord                                                   uint64
	received, decoded, unsupported, decodeErrors, filtered, sent atomic.Uint64
	gaps, missed                                                 atomic.Uint64
}

// NewFeeder returns a feeder for the subscribed canonical events (empty:
// all).
func NewFeeder(events []string, b *Binder) *Feeder {
	f := &Feeder{Binder: b, now: time.Now}
	if len(events) > 0 {
		f.wanted = map[string]bool{}
		for _, n := range events {
			f.wanted[n] = true
		}
	}
	return f
}

// OnDegraded registers fn for CondEventsDropped reports (at most one a
// minute; the next report counts the suppressed ones). fn is called on the
// reading goroutine and must not block.
func (f *Feeder) OnDegraded(fn func(condition, detail string)) {
	f.mu.Lock()
	f.fn = fn
	f.mu.Unlock()
}

// Handle processes one rendered event. It returns ctx.Err() when the
// context ended while sending; decode problems are counted, not returned.
func (f *Feeder) Handle(ctx context.Context, raw []byte, out chan<- *event.Event) error {
	f.received.Add(1)
	r, err := Parse(raw)
	if err != nil {
		f.decodeErrors.Add(1)
		return nil
	}
	f.checkRecord(r.RecordID)
	e, err := Map(r)
	if errors.Is(err, ErrUnsupported) {
		f.unsupported.Add(1)
		return nil
	}
	if err != nil {
		f.decodeErrors.Add(1)
		return nil
	}
	f.decoded.Add(1)
	if f.Binder != nil {
		f.Binder.Bind(e) // every event, so creates and exits keep the map right
	}
	if f.wanted != nil && !f.wanted[e.Name] {
		f.filtered.Add(1)
		return nil
	}
	select {
	case out <- e:
		f.sent.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// checkRecord tracks EventRecordID. A number that does not increase starts
// a new sequence (log cleared, Sysmon or the reader restarted).
func (f *Feeder) checkRecord(rec uint64) {
	if rec == 0 {
		return
	}
	last := f.lastRecord
	f.lastRecord = rec
	if last == 0 || rec <= last+1 {
		return
	}
	n := rec - last - 1
	f.gaps.Add(1)
	f.missed.Add(n)
	f.report(CondEventsDropped, fmt.Sprintf("missed %d Sysmon events (EventRecordID %d to %d); %d missed in total", n, last+1, rec-1, f.missed.Load()))
}

// Restarted tells the feeder that the reader restarted, so a jump in
// EventRecordID across the restart is still counted but the next record
// is not compared with one from before when resume is impossible.
func (f *Feeder) Restarted(resumed bool) {
	if !resumed {
		f.lastRecord = 0
	}
}

func (f *Feeder) report(cond, detail string) {
	f.mu.Lock()
	fn := f.fn
	now := f.now()
	if fn == nil {
		f.mu.Unlock()
		return
	}
	if !f.lastRep.IsZero() && now.Sub(f.lastRep) < degradedEvery {
		f.suppress++
		f.mu.Unlock()
		return
	}
	if f.suppress > 0 {
		detail = fmt.Sprintf("%s (%d earlier reports suppressed)", detail, f.suppress)
	}
	f.lastRep, f.suppress = now, 0
	f.mu.Unlock()
	fn(cond, detail)
}

// Stats reports the feeder's (and binder's) counters.
func (f *Feeder) Stats() map[string]uint64 {
	st := map[string]uint64{
		"received": f.received.Load(), "decoded": f.decoded.Load(), "unsupported": f.unsupported.Load(),
		"decode_errors": f.decodeErrors.Load(), "filtered": f.filtered.Load(), "sent": f.sent.Load(),
		"seq_gaps": f.gaps.Load(), "events_missed": f.missed.Load(),
	}
	if f.Binder != nil {
		for k, v := range f.Binder.Stats() {
			st[k] = v
		}
	}
	return st
}
