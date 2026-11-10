package output

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// Forwarder defaults.
const (
	DefaultQueue      = 4096
	DefaultBatch      = 100
	DefaultBatchBytes = 1 << 20
	DefaultFlushEvery = time.Second
	// DefaultQueueBytes bounds the bytes held in a forwarder's queue.
	DefaultQueueBytes = 32 << 20
	minBackoff        = time.Second
	maxBackoff        = time.Minute
	// finalFlushTimeout bounds the last delivery attempt at Close.
	finalFlushTimeout = 3 * time.Second
	// closeMargin is kept free of the final flush within Close's timeout.
	closeMargin = 500 * time.Millisecond
)

// Conditions of the SensorDegraded events a forwarder reports.
const (
	CondDown      = "output_down"
	CondSpoolFull = "output_spool_full"
	CondQueueFull = "output_queue_full"
)

// ForwarderConfig configures a Forwarder.
type ForwarderConfig struct {
	Transport Transport
	Spool     *Spool // nil: no spool (failed batches are dropped, counted)
	Encoder   Encoder
	// Events also forwards events (SendEvent); alerts are always forwarded.
	Events bool
	// Bounds (zero: defaults).
	Queue, Batch, BatchBytes, QueueBytes int
	FlushEvery                           time.Duration
	// OnDegraded receives CondDown, CondSpoolFull and CondQueueFull reports
	// (the pipeline rate-limits them). It may be called from any goroutine.
	OnDegraded func(condition, detail string)
	// Log receives one line per state change (endpoint down / back up). It
	// never contains a token.
	Log func(format string, args ...any)
}

// Forwarder ships records through a Transport from its own goroutine.
// Send and SendEvent never block the caller: records go to a bounded queue;
// when the queue is full an alert is written to the spool directly and an
// event is dropped. A batch the transport rejects goes to the spool, and the
// spool is retried (oldest first, before new records) with exponential
// backoff up to a minute. It implements alert.Sink.
type Forwarder struct {
	cfg   ForwarderConfig
	queue chan Record
	done  chan struct{}
	stop  context.CancelFunc
	wg    sync.WaitGroup

	closeOnce sync.Once
	closed    atomic.Bool

	sent, failedBatches, queueDropped, encodeErrs, spooled, lost, spoolSent atomic.Uint64
	down                                                                    atomic.Bool
	queuedBytes                                                             atomic.Int64
	// flushBudget bounds the final delivery at Close (nanoseconds): the
	// smaller of finalFlushTimeout and Close's timeout minus a margin, so
	// the transport is never closed under a running Send.
	flushBudget atomic.Int64
}

// NewForwarder starts the forwarder's goroutine.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	if cfg.Queue <= 0 {
		cfg.Queue = DefaultQueue
	}
	if cfg.Batch <= 0 {
		cfg.Batch = DefaultBatch
	}
	if cfg.BatchBytes <= 0 {
		cfg.BatchBytes = DefaultBatchBytes
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = DefaultQueueBytes
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = DefaultFlushEvery
	}
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{cfg: cfg, queue: make(chan Record, cfg.Queue), done: make(chan struct{}), stop: cancel}
	f.wg.Add(1)
	go f.loop(ctx)
	return f
}

func (f *Forwarder) degraded(cond, detail string) {
	if f.cfg.OnDegraded != nil {
		f.cfg.OnDegraded(cond, f.cfg.Transport.Name()+": "+detail)
	}
}

// Send queues an alert (alert.Sink).
func (f *Forwarder) Send(a *rules.Alert) error {
	r, err := f.cfg.Encoder.Alert(a)
	if err != nil {
		f.encodeErrs.Add(1)
		return err
	}
	f.enqueue(r)
	return nil
}

// SendEvent queues an event when events are forwarded.
func (f *Forwarder) SendEvent(e *event.Event) {
	if !f.cfg.Events || e == nil {
		return
	}
	r, err := f.cfg.Encoder.Event(e)
	if err != nil {
		f.encodeErrs.Add(1)
		return
	}
	f.enqueue(r)
}

func (f *Forwarder) enqueue(r Record) {
	if f.closed.Load() {
		f.toSpool([]Record{r})
		return
	}
	// Bounded by count and by bytes: a flood of large records cannot pin
	// more than QueueBytes in memory.
	if f.queuedBytes.Load()+int64(len(r.Body)) <= int64(f.cfg.QueueBytes) {
		select {
		case f.queue <- r:
			f.queuedBytes.Add(int64(len(r.Body)))
			return
		default:
		}
	}
	if r.Kind == KindAlert {
		f.toSpool([]Record{r})
		return
	}
	f.queueDropped.Add(1)
	f.degraded(CondQueueFull, fmt.Sprintf("the output queue (%d records or %d bytes) is full; events are dropped until it drains", f.cfg.Queue, f.cfg.QueueBytes))
}

// toSpool keeps records for later; without a spool (or when it refuses them)
// they are lost (counted and reported).
func (f *Forwarder) toSpool(recs []Record) {
	if len(recs) == 0 {
		return
	}
	if f.cfg.Spool == nil {
		f.lost.Add(uint64(len(recs)))
		f.degraded(CondSpoolFull, fmt.Sprintf("no spool configured; %d records lost", len(recs)))
		return
	}
	refused, err := f.cfg.Spool.Append(recs)
	f.spooled.Add(uint64(len(recs) - refused))
	if refused > 0 {
		f.lost.Add(uint64(refused))
		detail := fmt.Sprintf("the spool is full; %d records refused (events are refused at half the cap, alerts at the cap)", refused)
		if err != nil {
			detail += ": " + err.Error()
		}
		f.degraded(CondSpoolFull, detail)
	}
}

func (f *Forwarder) loop(ctx context.Context) {
	defer f.wg.Done()
	defer close(f.done)
	tick := time.NewTicker(f.cfg.FlushEvery)
	defer tick.Stop()
	var batch []Record
	size := 0
	backoff := time.Duration(0)
	var retryAt time.Time
	flush := func() {
		if len(batch) == 0 && (f.cfg.Spool == nil || f.cfg.Spool.Empty()) {
			return
		}
		now := time.Now()
		if now.Before(retryAt) {
			f.toSpool(batch)
			batch, size = nil, 0
			return
		}
		ok := f.drainSpool(ctx)
		if ok && len(batch) > 0 {
			ok = f.deliver(ctx, batch) // spools what it could not send
		} else if len(batch) > 0 {
			f.toSpool(batch)
		}
		batch, size = nil, 0
		if ok {
			backoff, retryAt = 0, time.Time{}
			if f.down.Swap(false) {
				f.cfg.Log("%s: endpoint reachable again", f.cfg.Transport.Name())
			}
			return
		}
		if backoff == 0 {
			backoff = minBackoff
		} else if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
		retryAt = time.Now().Add(backoff)
	}
	for {
		select {
		case <-ctx.Done():
			// Close: whatever is queued or batched is delivered in one last
			// bounded attempt when the endpoint is up, and spooled otherwise
			// (or when that attempt fails), so it is sent at the next start.
			for {
				select {
				case r := <-f.queue:
					f.queuedBytes.Add(-int64(len(r.Body)))
					batch = append(batch, r)
					continue
				default:
				}
				break
			}
			if budget := time.Duration(f.flushBudget.Load()); len(batch) > 0 && budget > 0 && !f.down.Load() && !time.Now().Before(retryAt) {
				fctx, cancel := context.WithTimeout(context.Background(), budget)
				f.deliver(fctx, batch) // spools what it could not send
				cancel()
			} else {
				f.toSpool(batch)
			}
			return
		case r := <-f.queue:
			f.queuedBytes.Add(-int64(len(r.Body)))
			batch = append(batch, r)
			size += len(r.Body)
			if len(batch) >= f.cfg.Batch || size >= f.cfg.BatchBytes {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// deliver sends one batch (split at the batch bounds); on failure the
// records not yet delivered go to the spool.
func (f *Forwarder) deliver(ctx context.Context, recs []Record) bool {
	for start := 0; start < len(recs); {
		end, size := start, 0
		for end < len(recs) && end-start < f.cfg.Batch && (end == start || size+len(recs[end].Body) <= f.cfg.BatchBytes) {
			size += len(recs[end].Body)
			end++
		}
		sctx, cancel := context.WithTimeout(ctx, sendTimeout+5*time.Second)
		err := f.cfg.Transport.Send(sctx, recs[start:end])
		cancel()
		if err != nil {
			f.failedBatches.Add(1)
			if !f.down.Swap(true) {
				f.cfg.Log("%s: delivery failed (%v); spooling and retrying with backoff", f.cfg.Transport.Name(), err)
			}
			f.degraded(CondDown, err.Error())
			f.toSpool(recs[start:])
			return false
		}
		f.sent.Add(uint64(end - start))
		start = end
	}
	return true
}

// drainSpool delivers spooled files, oldest first. It reports false when a
// delivery failed (the endpoint is still down).
func (f *Forwarder) drainSpool(ctx context.Context) bool {
	if f.cfg.Spool == nil {
		return true
	}
	for i := 0; i < maxSpoolFiles && !f.cfg.Spool.Empty(); i++ {
		seq, recs, err := f.cfg.Spool.Oldest()
		if err == io.EOF {
			return true
		}
		if err != nil {
			f.cfg.Log("%s: %v", f.cfg.Transport.Name(), err)
			continue
		}
		if len(recs) > 0 && !f.deliverSpooled(ctx, recs) {
			return false
		}
		f.spoolSent.Add(uint64(len(recs)))
		if err := f.cfg.Spool.Remove(seq); err != nil {
			f.cfg.Log("%s: %v", f.cfg.Transport.Name(), err)
			return true
		}
	}
	return true
}

// deliverSpooled sends records read back from the spool; on failure the
// file stays (nothing is re-spooled, so nothing is duplicated on disk).
func (f *Forwarder) deliverSpooled(ctx context.Context, recs []Record) bool {
	for start := 0; start < len(recs); start += f.cfg.Batch {
		end := start + f.cfg.Batch
		if end > len(recs) {
			end = len(recs)
		}
		sctx, cancel := context.WithTimeout(ctx, sendTimeout+5*time.Second)
		err := f.cfg.Transport.Send(sctx, recs[start:end])
		cancel()
		if err != nil {
			f.failedBatches.Add(1)
			if !f.down.Swap(true) {
				f.cfg.Log("%s: delivery failed (%v); spooling and retrying with backoff", f.cfg.Transport.Name(), err)
			}
			f.degraded(CondDown, err.Error())
			return false
		}
		f.sent.Add(uint64(end - start))
	}
	return true
}

// Close stops the forwarder within timeout: queued records are spooled.
func (f *Forwarder) Close(timeout time.Duration) error {
	var err error
	f.closeOnce.Do(func() {
		budget := finalFlushTimeout
		if b := timeout - closeMargin; b < budget {
			budget = b // may be <= 0: no final attempt, the records are spooled
		}
		f.flushBudget.Store(int64(budget))
		f.closed.Store(true)
		f.stop()
		select {
		case <-f.done:
		case <-time.After(timeout):
			err = fmt.Errorf("%s: forwarder did not stop within %v", f.cfg.Transport.Name(), timeout)
		}
		err = joinErr(err, f.cfg.Transport.Close())
		if f.cfg.Spool != nil {
			f.wg.Wait()
			err = joinErr(err, f.cfg.Spool.Close())
		}
	})
	return err
}

func joinErr(a, b error) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return fmt.Errorf("%w; %v", a, b)
}

// Stats returns the forwarder's counters (with the spool's).
func (f *Forwarder) Stats() map[string]uint64 {
	m := map[string]uint64{"sent": f.sent.Load(), "failed_batches": f.failedBatches.Load(),
		"queue_dropped_events": f.queueDropped.Load(), "encode_errors": f.encodeErrs.Load(),
		"spooled": f.spooled.Load(), "sent_from_spool": f.spoolSent.Load(), "lost": f.lost.Load()}
	if f.cfg.Spool != nil {
		for k, v := range f.cfg.Spool.Stats() {
			m[k] = v
		}
	}
	return m
}
