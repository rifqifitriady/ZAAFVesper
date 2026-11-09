package response

import "fmt"

// RefuseUnsupported logs an action that the host platform does not support
// (for example isolate_process, which uses pf, on Linux or Windows) as
// refused-unsupported, counted and rate-limited like every other refusal.
// Nothing is changed on the system.
func (r *Responder) RefuseUnsupported(action, target string, pid int32, rule, reason, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	r.stats[action+" "+OutcomeUnsupported]++
	if r.repeatRefusal(action+"|"+rule, target, pid, OutcomeUnsupported, now) {
		r.stats["log_suppressed"]++
		return
	}
	r.cfg.Log(Decision{Time: now, Action: action, PID: pid, Target: target, Reason: reason, Outcome: OutcomeUnsupported,
		Detail: fmt.Sprintf("%s (nothing was changed)", why)})
}
