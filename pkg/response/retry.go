package response

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Retry of slow actions refused only because their budget was spent (owner
// decision 9 Nov 2026, security re-check N2): without it, malware that
// writes ten decoy launch plists in a minute keeps its real eleventh one.
// A retry runs the whole action again on the worker, every guard rail
// included (the file must still be the event's dev/ino), so a file that
// changed or went away is refused and dropped from the list.
const (
	retryEvery  = 10 * time.Second // between two attempts
	retryWindow = 10 * time.Minute // an entry older than this is abandoned
	maxRetries  = 64               // entries waiting at once
)

type retryEntry struct {
	run      func() error
	rule     string
	first    time.Time // first refusal
	next     time.Time // next attempt
	desc     string
	inFlight bool // handed to the worker, not finished yet
}

// retryOnLimit records run for a later attempt when err is a budget
// refusal, and forgets key when the action ran to any other end (success
// or a refusal that a retry cannot change). Dry-run never retries. When
// the list is full, the oldest entry of the same rule makes room (decoys
// come first, the real action last); with none, the new one is dropped. A
// drop or an eviction raises response_rate_limited.
func (r *Responder) retryOnLimit(key, rule, desc string, err error, run func() error) error {
	notice := ""
	defer func() { // after the unlock below
		if notice != "" && r.cfg.OnDegraded != nil {
			r.cfg.OnDegraded(CondRateLimited, notice)
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.DryRun {
		return err
	}
	if errors.Is(err, ErrRateLimited) {
		now := r.cfg.Now()
		if en, ok := r.retries[key]; ok {
			en.next, en.inFlight = now.Add(retryEvery), false
			return err
		}
		if len(r.retries) >= maxRetries {
			oldest := ""
			for k, en := range r.retries {
				if en.rule == rule && !en.inFlight && (oldest == "" || en.first.Before(r.retries[oldest].first)) {
					oldest = k
				}
			}
			if oldest == "" {
				r.stats["retry list full"]++
				notice = fmt.Sprintf("response retry list full (%d); %s not retried", maxRetries, desc)
				return err
			}
			r.stats["retry evicted"]++
			notice = fmt.Sprintf("response retry list full (%d); dropped the oldest retry of %s", maxRetries, r.retries[oldest].desc)
			delete(r.retries, oldest)
		}
		r.retries[key] = &retryEntry{run: run, rule: rule, first: now, next: now.Add(retryEvery), desc: desc}
		r.stats["retry scheduled"]++
		return err
	}
	if _, ok := r.retries[key]; ok {
		delete(r.retries, key)
		if err == nil {
			r.stats["retry succeeded"]++
		} else {
			r.stats["retry ended refused"]++
		}
	}
	return err
}

// deferSeq numbers the entries of Defer.
var deferSeq atomic.Uint64

// Defer lists an action that could not even be queued (the worker queue
// was full) for a later attempt, like a budget refusal: run is the public
// action, which then lists itself again under its own key if its budget
// refuses it.
func (r *Responder) Defer(rule, desc string, run func()) {
	key := fmt.Sprintf("deferred|%d", deferSeq.Add(1))
	_ = r.retryOnLimit(key, rule, desc, ErrRateLimited, func() error {
		r.mu.Lock()
		delete(r.retries, key)
		r.mu.Unlock()
		run()
		return nil
	})
}

// tickRetries hands the due retries to the worker and abandons those older
// than retryWindow. An entry already handed to the worker is not handed
// again, and retries only use the worker while its queue is less than half
// full, so fresh actions keep room. It never runs an action itself (Tick is
// on the event loop). Caller holds no lock.
func (r *Responder) tickRetries(now time.Time) {
	type job struct {
		en  *retryEntry
		run func() error
	}
	var due []job
	r.mu.Lock()
	for key, en := range r.retries {
		switch {
		case en.inFlight:
		case now.Sub(en.first) > retryWindow:
			delete(r.retries, key)
			r.logLocked(Decision{Time: now, Action: "retry", Target: TargetFile, Reason: en.desc, Outcome: "retry-abandoned",
				Detail: fmt.Sprintf("still refused by the response budget after %s", retryWindow)})
		case !now.Before(en.next):
			en.next, en.inFlight = now.Add(retryEvery), true
			due = append(due, job{en, en.run})
		}
	}
	r.mu.Unlock()
	for _, j := range due {
		j := j
		if !r.queueHasRoom() || !r.Go(func() { _ = j.run() }) {
			r.mu.Lock()
			j.en.inFlight = false
			r.mu.Unlock()
		}
	}
}

// queueHasRoom reports whether the worker queue is less than half full
// (always true without a worker).
func (r *Responder) queueHasRoom() bool {
	w := r.work.Load()
	return w == nil || len(w.ch) < cap(w.ch)/2
}

// Retries returns how many actions wait for a retry (tests, stats).
func (r *Responder) Retries() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.retries)
}

func fileRetryKey(action, rule string, e *event.Event, target string) string {
	if e == nil {
		return action + "|" + rule
	}
	path, b, _ := fileTarget(e, target)
	return fmt.Sprintf("%s|%s|%s|%s", action, rule, path, b)
}
