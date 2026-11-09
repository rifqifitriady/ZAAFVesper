package response

import (
	"sync"
	"sync/atomic"
)

// worker runs the slow actions (file copies, codesign, launchctl, pfctl)
// off the sensor's event loop, one at a time, from a bounded queue. Kill and
// suspend never go through it.
type worker struct {
	ch       chan func()
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
	dropping atomic.Bool // shutdown: queued actions not yet started are dropped
	dropped  atomic.Uint64
}

// StartWorker starts the background worker with room for queue waiting
// actions. Without it, Go runs actions inline (tests, replay).
func (r *Responder) StartWorker(queue int) {
	if queue < 1 {
		queue = 1
	}
	w := &worker{ch: make(chan func(), queue)}
	go func() {
		for f := range w.ch {
			if w.dropping.Load() {
				w.dropped.Add(1)
			} else {
				f()
			}
			w.wg.Done()
		}
	}()
	r.work.Store(w)
}

// Go runs f on the worker, or inline when no worker was started. It returns
// false, without running f, when the queue is full or the worker stopped;
// the caller reports that as a degraded response.
func (r *Responder) Go(f func()) bool {
	w := r.work.Load()
	if w == nil {
		f()
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	w.wg.Add(1)
	select {
	case w.ch <- f:
		return true
	default:
		w.wg.Done()
		return false
	}
}

// Wait blocks until every queued action has run.
func (r *Responder) Wait() {
	w := r.work.Load()
	if w != nil {
		w.wg.Wait()
	}
}

// stopWorker stops the worker. The action running now finishes; with drop,
// queued actions that have not started are dropped (counted in Stats as
// "worker dropped at shutdown"), otherwise they run first.
func (r *Responder) stopWorker(drop bool) {
	w := r.work.Load()
	if w == nil {
		return
	}
	if drop {
		w.dropping.Store(true)
	}
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	w.wg.Wait()
	if n := w.dropped.Swap(0); n > 0 {
		r.mu.Lock()
		r.stats["worker dropped at shutdown"] += n
		r.mu.Unlock()
	}
}

// StopWorker stops the worker at shutdown: the running action finishes,
// queued ones are dropped (Close does this too, after resuming the
// suspended processes).
func (r *Responder) StopWorker() { r.stopWorker(true) }

// ResumeAll resumes every process this responder suspended (Close does
// this too).
func (r *Responder) ResumeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	for pid := range r.suspended {
		r.resumeLocked(pid, now, "sensor shutting down")
	}
}
