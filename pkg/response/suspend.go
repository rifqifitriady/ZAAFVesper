package response

import (
	"fmt"
	"syscall"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// maxSuspended bounds the stopped processes waiting for their resume. The
// response budgets (30 actions a minute) keep the real number far lower.
const maxSuspended = 1024

// suspension is a process stopped by suspend and not yet resumed.
type suspension struct {
	proc   event.Proc // identity at the decision (Parent dropped)
	rule   string
	reason string
	target string
	until  time.Time
}

// SuspendEvent sends SIGSTOP to the process of e (action suspend, target
// process). Every guard rail of KillEvent applies (kernel unique id, start
// time, protected pids, paths and names, platform binaries, seeded or
// unverified identity, signing category, budgets, dry-run). The process is
// resumed after Config.SuspendFor unless a kill of the same process follows
// (Tick does the resume). A suspend cannot run before the event that
// triggered it: it only stops the process from doing more while the next
// action is decided.
func (r *Responder) SuspendEvent(e *event.Event, rule, reason string) error {
	return r.signalEvent(e, rule, reason, syscall.SIGSTOP)
}

// SuspendParent is SuspendEvent for the parent of e's process (action
// suspend, target parent), with KillParent's identity rules.
func (r *Responder) SuspendParent(e *event.Event, rule, reason string) error {
	return r.signalParent(e, rule, reason, syscall.SIGSTOP)
}

// holdSuspended records a stopped process for its resume. Caller holds mu.
func (r *Responder) holdSuspended(p *event.Proc, rule, reason string, now time.Time) {
	if old, ok := r.suspended[p.PID]; ok && old.proc.UniqueID == p.UniqueID {
		old.until = now.Add(r.cfg.SuspendFor) // stopped again: restart its clock
		return
	}
	if len(r.suspended) >= maxSuspended {
		// Resume the oldest at once rather than forget a stopped process.
		var oldest int32
		var at time.Time
		for pid, s := range r.suspended {
			if at.IsZero() || s.until.Before(at) {
				oldest, at = pid, s.until
			}
		}
		r.resumeLocked(oldest, now, "too many suspended processes")
	}
	cp := *p
	cp.Parent = nil
	r.suspended[p.PID] = &suspension{proc: cp, rule: rule, reason: reason, until: now.Add(r.cfg.SuspendFor)}
}

// forgetSuspended drops the pending resume of a process that was killed.
// Caller holds mu.
func (r *Responder) forgetSuspended(p *event.Proc) {
	if s, ok := r.suspended[p.PID]; ok && s.proc.UniqueID == p.UniqueID {
		delete(r.suspended, p.PID)
	}
}

// resumeLocked sends SIGCONT to a suspended process after checking it is
// still the same incarnation (kernel unique id and start time), then
// forgets it. Caller holds mu.
func (r *Responder) resumeLocked(pid int32, now time.Time, why string) {
	s, ok := r.suspended[pid]
	if !ok {
		return
	}
	delete(r.suspended, pid)
	d := Decision{Time: now, Action: ActionSuspend, PID: pid, Target: TargetProcess, Name: s.proc.Name, Exe: s.proc.Exe, Reason: s.reason}
	id, err := r.cfg.Identify(pid)
	switch {
	case err != nil:
		d.Outcome, d.Detail = OutcomeResumeSkipped, "process gone: "+err.Error()
	case !id.UniqueKnown || id.UniqueID != s.proc.UniqueID:
		d.Outcome, d.Detail = OutcomeResumeSkipped, "pid now belongs to another process"
	case id.StartTime.Sub(s.proc.StartTime) > StartTolerance || s.proc.StartTime.Sub(id.StartTime) > StartTolerance:
		d.Outcome, d.Detail = OutcomeResumeSkipped, "start time differs (pid reused)"
	default:
		if err := r.cfg.KillFunc(int(pid), syscall.SIGCONT); err != nil {
			d.Outcome, d.Detail = OutcomeError, "SIGCONT: "+err.Error()
		} else {
			d.Outcome, d.Detail = OutcomeResumed, why
		}
	}
	r.logLocked(d)
}

// tickSuspended resumes every suspension whose time is over. Caller holds mu.
func (r *Responder) tickSuspended(now time.Time) {
	for pid, s := range r.suspended {
		if !now.Before(s.until) {
			r.resumeLocked(pid, now, fmt.Sprintf("no kill followed within %s", r.cfg.SuspendFor))
		}
	}
}

// Suspended returns the pids waiting for their resume (for tests and stats).
func (r *Responder) Suspended() []int32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int32, 0, len(r.suspended))
	for pid := range r.suspended {
		out = append(out, pid)
	}
	return out
}
