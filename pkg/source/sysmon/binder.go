package sysmon

import (
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Stamp is the kernel's identity of a running process: an incarnation
// number that never repeats for a pid within a boot (Windows: creation time
// as a raw FILETIME; Linux: start time in clock ticks since boot), its
// wall-clock form as the responder's identify reads it (Start), and the most
// precise wall-clock start available (Precise), used only for the check
// against the event's time.
type Stamp struct {
	ID      uint64
	Start   time.Time
	Precise time.Time
}

// StampReader reads the kernel stamp of pid now.
type StampReader func(pid int32) (Stamp, error)

// MaxBound bounds the pid -> identity map of a Binder (as the process table
// bounds its entries).
const MaxBound = 65536

// Binder ties Sysmon's ProcessGuid to the kernel's identity of the process,
// so that the kill guard rails (pkg/response) can check that a pid still is
// the process an event described. It runs on the source's reading goroutine.
//
// On a CreateProcess event the Binder reads the kernel stamp of the new pid
// at once. The process that Sysmon reported held that pid at the event's
// time, so a process that holds it now and was created no later than the
// event (plus Tolerance for clock resolution) is that process: a recycled
// pid would belong to a process created after the event. Then the event's
// Proc gets UniqueID = stamp ID and StartTime = stamp Start, and the pair
// (pid, ProcessGuid) is remembered. Later events of the same pid with the
// same ProcessGuid get the same identity; events whose GUID was never bound
// (processes started before the sensor, or bound too late) get none, and
// response refuses to kill them ("kernel unique id not recorded").
type Binder struct {
	read      StampReader
	tolerance time.Duration
	mu        sync.Mutex
	byPID     map[int32]*list.Element // of *bound, oldest create first in order
	order     *list.List

	bound, late, readErrors, resets, matched, unmatched atomic.Uint64
}

type bound struct {
	pid   int32
	guid  string
	stamp Stamp // ID 0: no kernel identity
	ppid  int32
}

// NewBinder returns a Binder. tolerance covers the resolution difference
// between the event's time and the kernel's start time (milliseconds on
// Windows, a tick plus clock rounding on Linux).
func NewBinder(read StampReader, tolerance time.Duration) *Binder {
	return &Binder{read: read, tolerance: tolerance, byPID: map[int32]*list.Element{}, order: list.New()}
}

// Bind sets Proc.UniqueID and Proc.StartTime (and those of e.Target) from
// the kernel when the identity is proven as described on Binder; otherwise
// it clears UniqueID so nothing downstream mistakes the pid for a known
// incarnation. It also fills a missing PPID from the process's create event
// (same pid and ProcessGuid).
func (b *Binder) Bind(e *event.Event) {
	if e == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if p := e.Proc; p != nil && p.PID > 0 {
		if e.Name == event.CreateProcess {
			b.create(p, e.Time)
		} else {
			b.lookup(p)
		}
		if e.Name == event.TerminateProcess {
			b.forget(p.PID)
		}
	}
	if t := e.Target; t != nil && t.PID > 0 {
		b.lookup(t)
	}
}

func (b *Binder) forget(pid int32) {
	if el, ok := b.byPID[pid]; ok {
		b.order.Remove(el)
		delete(b.byPID, pid)
	}
}

func (b *Binder) create(p *event.Proc, at time.Time) {
	b.forget(p.PID)
	p.UniqueID = 0
	if p.GUID == "" {
		return
	}
	// Full (exits not reported, e.g. a Sysmon config without event 5):
	// forget the processes seen least recently, not everything; a process
	// that keeps producing events stays.
	for len(b.byPID) >= MaxBound {
		b.forget(b.order.Front().Value.(*bound).pid)
		b.resets.Add(1)
	}
	// The parent pid is remembered even without a kernel identity: later
	// Sysmon events of the process carry no ParentProcessId.
	bd := &bound{pid: p.PID, guid: p.GUID, ppid: p.PPID}
	b.byPID[p.PID] = b.order.PushBack(bd)
	st, err := b.read(p.PID)
	switch {
	case err != nil || st.ID == 0:
		b.readErrors.Add(1)
		return
	case st.Precise.After(at.Add(b.tolerance)):
		b.late.Add(1) // the pid already belongs to a newer process
		return
	}
	bd.stamp = st
	p.UniqueID, p.StartTime = st.ID, st.Start
	b.bound.Add(1)
}

func (b *Binder) lookup(p *event.Proc) {
	el, ok := b.byPID[p.PID]
	var bd *bound
	if ok {
		bd = el.Value.(*bound)
	}
	if !ok || p.GUID == "" || !sameGUID(bd.guid, p.GUID) {
		p.UniqueID = 0
		b.unmatched.Add(1)
		return
	}
	if p.PPID == 0 {
		p.PPID = bd.ppid
	}
	if bd.stamp.ID == 0 {
		p.UniqueID = 0
		b.unmatched.Add(1)
		return
	}
	p.UniqueID, p.StartTime = bd.stamp.ID, bd.stamp.Start
	b.matched.Add(1)
	b.order.MoveToBack(el) // least recently seen is evicted first
}

// sameGUID compares two ProcessGuids ignoring case and braces.
func sameGUID(a, b string) bool {
	return strings.EqualFold(strings.Trim(a, "{} "), strings.Trim(b, "{} "))
}

// Stats reports the Binder's counters.
func (b *Binder) Stats() map[string]uint64 {
	b.mu.Lock()
	n := uint64(len(b.byPID))
	b.mu.Unlock()
	return map[string]uint64{
		"identity_bound": b.bound.Load(), "identity_late": b.late.Load(), "identity_read_errors": b.readErrors.Load(),
		"identity_evicted": b.resets.Load(), "identity_matched": b.matched.Load(), "identity_unmatched": b.unmatched.Load(),
		"identity_live": n,
	}
}
