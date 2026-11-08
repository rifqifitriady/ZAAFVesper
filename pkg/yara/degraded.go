package yara

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// Conditions the scanner reports through OnDegraded. The pipeline turns each
// report into a SensorDegraded event (evt.arg[condition], evt.arg[detail]).
const (
	// CondQueueFull: a scan submission was dropped because the queue was
	// full (or a queued file scan was displaced by an exec scan).
	CondQueueFull = "yara_queue_full"
	// CondExecReplaced: the path of an exec'd file no longer leads to the
	// file that ran (gone, or device, inode or ctime differ from Endpoint
	// Security's stat at exec), so it was not scanned. Swapping or deleting
	// a binary right after exec is itself suspicious.
	CondExecReplaced = "yara_exec_replaced"
	// CondSkippedNonLocal: the target lies on a file system without
	// MNT_LOCAL (SMB, NFS, AFP, WebDAV, …) and was not scanned, so a slow
	// or hostile server cannot stall the workers.
	CondSkippedNonLocal = "yara_skipped_nonlocal"
)

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
// function is called synchronously, outside the hook's lock, from whichever
// goroutine hit the condition (Submit's caller or a scan worker).
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
