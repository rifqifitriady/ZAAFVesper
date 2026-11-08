package eslogger

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// CondEventsDropped is the OnDegraded condition reported when
// global_seq_num skips numbers: Endpoint Security (or eslogger) dropped
// events before they reached ZAAFVesper.
const CondEventsDropped = "es_events_dropped"

// The rate limiter below is the same as pkg/yara's degradedHook (a copy, so
// neither package imports the other).
const (
	// degradedEvery rate-limits reports per (condition, key).
	degradedEvery = time.Minute
	// maxDegradedKeys bounds the rate limiter's memory (LRU).
	maxDegradedKeys = 256
)

// degradedHook delivers condition reports to the registered function. It
// rate-limits per (condition, key), the key being a pid or a path, so one
// decoy report cannot hide the next one about another process for a
// minute. Keys live in a bounded LRU. Reports suppressed by the limit are
// counted per condition and announced in that condition's next report. The
// function is called synchronously, outside the hook's lock, from the
// goroutine reading eslogger's output.
type degradedHook struct {
	mu         sync.Mutex
	fn         func(condition, detail string)
	now        func() time.Time
	keys       map[string]*list.Element // condition + "\x00" + key -> lru element
	lru        *list.List               // of *hookKey, most recent first
	suppressed map[string]uint64        // per condition, since its last report
}

type hookKey struct {
	id   string
	last time.Time
}

func (h *degradedHook) set(fn func(condition, detail string)) {
	h.mu.Lock()
	h.fn = fn
	h.mu.Unlock()
}

func (h *degradedHook) report(condition, key, detail string) {
	h.mu.Lock()
	fn := h.fn
	if fn == nil {
		h.mu.Unlock()
		return
	}
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	if h.keys == nil {
		h.keys, h.lru, h.suppressed = map[string]*list.Element{}, list.New(), map[string]uint64{}
	}
	id := condition + "\x00" + key
	if el, ok := h.keys[id]; ok {
		k := el.Value.(*hookKey)
		h.lru.MoveToFront(el)
		if d := now.Sub(k.last); d < degradedEvery && d >= 0 {
			h.suppressed[condition]++
			h.mu.Unlock()
			return
		}
		k.last = now
	} else {
		h.keys[id] = h.lru.PushFront(&hookKey{id: id, last: now})
		for h.lru.Len() > maxDegradedKeys {
			old := h.lru.Back()
			h.lru.Remove(old)
			delete(h.keys, old.Value.(*hookKey).id)
		}
	}
	if n := h.suppressed[condition]; n > 0 {
		detail += fmt.Sprintf(" (%d more suppressed since last report)", n)
		delete(h.suppressed, condition)
	}
	h.mu.Unlock()
	fn(condition, detail)
}
