//go:build yara

package yara

import "sync"

// jobQueue is a bounded two-class FIFO: exec jobs are always popped before
// file jobs, and an exec job pushed into a full queue displaces the oldest
// file job. push never blocks.
type jobQueue struct {
	mu         sync.Mutex
	cond       *sync.Cond
	exec, file []job
	cap        int
	running    bool // between open and close
	closed     bool
}

type pushResult int

const (
	pushOK            pushResult = iota
	pushDisplacedFile            // queued; the oldest file job was dropped to make room
	pushRejected                 // not queued: full
	pushNotRunning               // not queued: before Start or after Close
)

func newJobQueue(capacity int) *jobQueue {
	q := &jobQueue{cap: capacity}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *jobQueue) open() {
	q.mu.Lock()
	if !q.closed {
		q.running = true
	}
	q.mu.Unlock()
}

func (q *jobQueue) close() {
	q.mu.Lock()
	q.closed, q.running = true, false
	q.exec, q.file = nil, nil
	q.mu.Unlock()
	q.cond.Broadcast()
}

func (q *jobQueue) push(j job) pushResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.running {
		return pushNotRunning
	}
	res := pushOK
	if len(q.exec)+len(q.file) >= q.cap {
		if !j.exec || len(q.file) == 0 {
			return pushRejected
		}
		q.file[0] = job{}
		q.file = q.file[1:]
		res = pushDisplacedFile
	}
	if j.exec {
		q.exec = append(q.exec, j)
	} else {
		q.file = append(q.file, j)
	}
	q.cond.Signal()
	return res
}

// pop blocks until a job is available or the queue is closed (ok=false).
func (q *jobQueue) pop() (job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.exec) == 0 && len(q.file) == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed {
		return job{}, false
	}
	var j job
	if len(q.exec) > 0 {
		j, q.exec[0] = q.exec[0], job{}
		q.exec = q.exec[1:]
	} else {
		j, q.file[0] = q.file[0], job{}
		q.file = q.file[1:]
	}
	return j, true
}

// lens reports the queued exec and file jobs (tests).
func (q *jobQueue) lens() (int, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.exec), len(q.file)
}
