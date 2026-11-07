// Package ps maintains a process table from fork/exec/exit events and enriches
// events with parent, ancestor, uuid and username information.
//
// The table is keyed by pid and checked against pidversion (the per-pid
// incarnation counter in the audit token), so a recycled pid is never
// mistaken for the process that used it before. It is bounded twice: at most
// MaxEntries processes and about MaxBytes of retained strings. Exited
// processes are kept for ExitTTL so that late events and children can still
// resolve them, and are the first to go when a bound is hit.
//
// Processes seeded at start (bootstrap) take their exe, argv and environment
// from kern.procargs2, which the process itself can rewrite. Until an exec
// event from Endpoint Security replaces such an image, every event of that
// process carries evt.arg[identity]=unverified (and parent_identity /
// target_identity for its role as parent or target).
package ps

import (
	"container/list"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

const (
	// MaxEntries bounds the process table.
	MaxEntries = 65536
	// MaxBytes bounds the approximate memory retained by table entries.
	MaxBytes = 128 << 20
	// ExitTTL is how long an exited process stays resolvable.
	ExitTTL = 30 * time.Second
	// MaxAncestors bounds Proc.Ancestors.
	MaxAncestors = 16
	// maxUserCache bounds the uid -> username cache.
	maxUserCache = 4096
	// sweepEvery: exited entries are swept at most this often (event time).
	sweepEvery = 5 * time.Second
	// entryOverhead approximates the fixed cost of one entry.
	entryOverhead = 512
)

// Values of the identity markers in evt.arg.
const (
	ArgIdentity       = "identity"
	ArgParentIdentity = "parent_identity"
	ArgTargetIdentity = "target_identity"
	Unverified        = "unverified"
)

// RequiredEvents are the canonical events the snapshotter needs to keep the
// table correct. Whoever builds the source subscription should always add
// them, even when no rule uses them.
func RequiredEvents() []string {
	return []string{event.CreateProcess, event.Fork, event.TerminateProcess}
}

type entry struct {
	proc       event.Proc // Parent and Ancestors always nil
	parent     parentRef  // from parent_audit_token when the source provided it
	exited     time.Time  // zero while alive
	unverified bool       // image details came from kern.procargs2, not from ES
	size       int64
	elem       *list.Element // in Snapshotter.live or Snapshotter.dead; Value is the pid
}

// parentRef identifies a parent incarnation; pv 0 means "unknown, accept any".
type parentRef struct {
	pid int32
	pv  uint32
}

// Snapshotter implements source.Enricher.
type Snapshotter struct {
	mu        sync.Mutex
	procs     map[int32]*entry
	live      *list.List // alive entries, least recently (re)imaged first
	dead      *list.List // exited entries, earliest exit first
	bytes     int64
	max       int
	maxBytes  int64
	ttl       time.Duration
	now       func() time.Time
	lastSweep time.Time
	evictions uint64

	users      map[int64]string
	lookupUser func(uid int64) string

	bootstrapped int
	bootErr      error
}

// NewSnapshotter returns a snapshotter. If bootstrap is true it seeds the table
// from the running processes (sysctl kern.proc.all + kern.procargs2); those
// entries are marked unverified.
func NewSnapshotter(bootstrap bool) *Snapshotter {
	s := newSnapshotter(MaxEntries, MaxBytes)
	if bootstrap {
		procs, err := listProcesses()
		s.bootErr = err
		for i := range procs {
			if len(s.procs) >= s.max {
				break
			}
			s.seed(procs[i])
		}
		s.bootstrapped = len(s.procs)
	}
	return s
}

func newSnapshotter(max int, maxBytes int64) *Snapshotter {
	return &Snapshotter{
		procs:      make(map[int32]*entry),
		live:       list.New(),
		dead:       list.New(),
		max:        max,
		maxBytes:   maxBytes,
		ttl:        ExitTTL,
		now:        time.Now,
		users:      make(map[int64]string),
		lookupUser: osLookupUser,
	}
}

// seed inserts a bootstrap process (unverified identity).
func (s *Snapshotter) seed(p event.Proc) {
	s.put(&p)
	if en, ok := s.procs[p.PID]; ok {
		en.unverified = true
	}
}

// BootstrapStats reports how many processes were seeded at start and the
// error from reading the process list, if any. Without root only the
// caller's own processes carry an executable path.
func (s *Snapshotter) BootstrapStats() (seeded int, err error) {
	return s.bootstrapped, s.bootErr
}

// Len returns the number of tracked processes (including recently exited).
func (s *Snapshotter) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.procs)
}

// Stats reports table counters: entries, bytes (approximate), evictions.
func (s *Snapshotter) Stats() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]uint64{
		"entries":   uint64(len(s.procs)),
		"bytes":     uint64(s.bytes),
		"evictions": s.evictions,
	}
}

// Lookup returns a copy of the tracked process for pid.
func (s *Snapshotter) Lookup(pid int32) (event.Proc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if en, ok := s.procs[pid]; ok {
		return en.proc, true
	}
	return event.Proc{}, false
}

// Enrich updates the table from e and fills e.Proc (and e.Target) with
// Parent, Ancestors, UUID, Username and, for events that do not carry them,
// Args/Cmdline/Cwd/Env from the table.
func (s *Snapshotter) Enrich(e *event.Event) {
	if e == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := e.Time
	if ts.IsZero() {
		ts = s.now()
	}
	s.maybeSweep(ts)

	if p := e.Proc; p != nil && p.PID > 0 {
		switch e.Name {
		case event.Fork:
			s.fork(p)
		case event.CreateProcess:
			s.put(p) // a fresh image from ES: verified
		case event.TerminateProcess:
			s.observe(p)
			s.markExited(p.PID, ts)
		default:
			s.observe(p)
		}
		if en, ok := s.procs[p.PID]; ok && en.unverified && samePID(&en.proc, p) {
			setArg(e, ArgIdentity, Unverified)
		}
		if par := s.decorate(p, true); par != nil && par.unverified {
			setArg(e, ArgParentIdentity, Unverified)
		}
	}
	if t := e.Target; t != nil && t.PID > 0 {
		s.observe(t)
		if en, ok := s.procs[t.PID]; ok && en.unverified && samePID(&en.proc, t) {
			setArg(e, ArgTargetIdentity, Unverified)
		}
		s.decorate(t, false)
	}
}

func setArg(e *event.Event, k, v string) {
	if e.Args == nil {
		e.Args = map[string]string{}
	}
	e.Args[k] = v
}

// fork records a child: it starts as a copy of its parent's image, and
// inherits the parent's unverified mark when it inherits its details.
func (s *Snapshotter) fork(child *event.Proc) {
	inherited, unverified := false, false
	if par := s.resolve(s.parentOf(child)); par != nil {
		pp := &par.proc
		if len(child.Args) == 0 && len(pp.Args) > 0 {
			child.Args, child.Cmdline, inherited = pp.Args, pp.Cmdline, true
		}
		if child.Cwd == "" && pp.Cwd != "" {
			child.Cwd, inherited = pp.Cwd, true
		}
		if child.Env == nil && pp.Env != nil {
			child.Env, inherited = pp.Env, true
		}
		if child.Exe == "" {
			child.Exe, child.Name = pp.Exe, pp.Name
		}
		unverified = par.unverified && inherited
	}
	s.put(child)
	if en, ok := s.procs[child.PID]; ok {
		en.unverified = unverified
	}
}

// put inserts or replaces the entry for p (exec, fork, bootstrap, or a stale
// entry). The new image counts as verified.
func (s *Snapshotter) put(p *event.Proc) {
	cp := *p
	cp.Parent, cp.Ancestors = nil, nil
	ref := stubRef(p)
	if en, ok := s.procs[p.PID]; ok {
		en.proc, en.parent, en.unverified = cp, ref, false
		if !en.exited.IsZero() {
			s.dead.Remove(en.elem)
			en.exited = time.Time{}
			en.elem = s.live.PushBack(p.PID)
		} else {
			s.live.MoveToBack(en.elem)
		}
		s.resize(en)
		s.enforce(p.PID)
		return
	}
	en := &entry{proc: cp, parent: ref}
	en.size = procSize(&en.proc)
	s.makeRoom(en.size)
	en.elem = s.live.PushBack(p.PID)
	s.procs[p.PID] = en
	s.bytes += en.size
}

// observe merges what a non-lifecycle event says about p into the table and
// fills p's missing image details from the table.
func (s *Snapshotter) observe(p *event.Proc) {
	en, ok := s.procs[p.PID]
	if !ok || !samePID(&en.proc, p) {
		s.put(p) // first sight, or the pid was recycled behind our back
		return
	}
	if ref := stubRef(p); ref.pid > 0 {
		en.parent = ref
	}
	t := &en.proc
	// Identity: the event is authoritative (bootstrap entries lack signing data).
	if p.Exe != "" {
		if t.Exe != p.Exe {
			// A different image than the one we recorded: old details are wrong.
			t.Args, t.Cmdline, t.Env, t.Cwd = nil, "", nil, ""
			en.unverified = false
		}
		t.Exe, t.Name = p.Exe, p.Name
		t.SigningID, t.TeamID, t.CDHash = p.SigningID, p.TeamID, p.CDHash
		t.IsPlatform, t.IsSigned = p.IsPlatform, p.IsSigned
		t.UID, t.EUID = p.UID, p.EUID
	}
	if p.PIDVersion != 0 {
		t.PIDVersion = p.PIDVersion
	}
	if p.PPID != 0 {
		t.PPID = p.PPID
	}
	if p.TTY != "" {
		t.TTY = p.TTY
	}
	if t.StartTime.IsZero() {
		t.StartTime = p.StartTime
	}
	// Details: the table is authoritative (only exec events carry them).
	if len(p.Args) == 0 {
		p.Args, p.Cmdline = t.Args, t.Cmdline
	} else if len(t.Args) == 0 {
		t.Args, t.Cmdline = p.Args, p.Cmdline
	}
	if p.Cwd == "" {
		p.Cwd = t.Cwd
	}
	if p.Env == nil {
		p.Env = t.Env
	}
	if p.Exe == "" {
		p.Exe, p.Name = t.Exe, t.Name
	}
	s.resize(en)
	s.enforce(p.PID)
}

func (s *Snapshotter) markExited(pid int32, ts time.Time) {
	en, ok := s.procs[pid]
	if !ok || !en.exited.IsZero() {
		return
	}
	s.live.Remove(en.elem)
	en.exited = ts
	en.elem = s.dead.PushBack(pid)
}

// samePID reports whether a and b are the same process incarnation. A zero
// pidversion (bootstrap entries) matches anything.
func samePID(a, b *event.Proc) bool {
	return a.PID == b.PID && (a.PIDVersion == 0 || b.PIDVersion == 0 || a.PIDVersion == b.PIDVersion)
}

// decorate sets UUID, Username and, when withParent, Parent and Ancestors.
// It returns the parent's entry, if resolved.
func (s *Snapshotter) decorate(p *event.Proc, withParent bool) *entry {
	if p.UUID == 0 {
		p.UUID = UUID(p.PID, p.PIDVersion)
	}
	if p.Username == "" {
		p.Username = s.username(p.UID)
	}
	if !withParent {
		p.Parent = nil // drop the source's parent stub; targets carry no parent
		return nil
	}
	ref := s.parentOf(p)
	p.Parent, p.Ancestors = nil, nil
	var parent *entry
	seen := map[int32]bool{p.PID: true}
	for len(p.Ancestors) < MaxAncestors && ref.pid > 0 && !seen[ref.pid] {
		en := s.resolve(ref)
		if en == nil {
			break // unknown, or the pid now belongs to a different process
		}
		seen[ref.pid] = true
		if p.Parent == nil {
			parent = en
			par := en.proc
			par.Parent, par.Ancestors = nil, nil
			if par.UUID == 0 {
				par.UUID = UUID(par.PID, par.PIDVersion)
			}
			if par.Username == "" {
				par.Username = s.username(par.UID)
			}
			p.Parent = &par
		}
		p.Ancestors = append(p.Ancestors, en.proc.Exe)
		if ref.pid == 1 {
			break // launchd
		}
		ref = en.parentRefOrPPID()
	}
	return parent
}

// stubRef reads the parent stub the source put in p.Parent (pid and
// pidversion from parent_audit_token). A full Parent (already enriched) is
// read the same way.
func stubRef(p *event.Proc) parentRef {
	if p.Parent != nil && p.Parent.PID > 0 {
		return parentRef{pid: p.Parent.PID, pv: p.Parent.PIDVersion}
	}
	return parentRef{}
}

// parentOf returns the parent reference for an event's process: its own
// stub, else what the table remembers for this incarnation, else its ppid.
func (s *Snapshotter) parentOf(p *event.Proc) parentRef {
	if ref := stubRef(p); ref.pid > 0 {
		return ref
	}
	if en, ok := s.procs[p.PID]; ok && samePID(&en.proc, p) && en.parent.pid > 0 {
		return en.parent
	}
	return parentRef{pid: p.PPID}
}

func (en *entry) parentRefOrPPID() parentRef {
	if en.parent.pid > 0 {
		return en.parent
	}
	return parentRef{pid: en.proc.PPID}
}

// resolve returns the table entry for ref if it is the same incarnation.
func (s *Snapshotter) resolve(ref parentRef) *entry {
	if ref.pid <= 0 {
		return nil
	}
	en, ok := s.procs[ref.pid]
	if !ok {
		return nil
	}
	if ref.pv != 0 && en.proc.PIDVersion != 0 && en.proc.PIDVersion != ref.pv {
		return nil
	}
	return en
}

// UUID is the process identity used in ps.uuid: pid in the high 32 bits,
// pidversion in the low 32 bits.
func UUID(pid int32, pidversion uint32) uint64 {
	return uint64(uint32(pid))<<32 | uint64(pidversion)
}

func (s *Snapshotter) username(uid int64) string {
	if uid < 0 {
		return ""
	}
	if n, ok := s.users[uid]; ok {
		return n
	}
	n := s.lookupUser(uid)
	if len(s.users) >= maxUserCache {
		clear(s.users)
	}
	s.users[uid] = n // negative results are cached too
	return n
}

func osLookupUser(uid int64) string {
	u, err := user.LookupId(strconv.FormatInt(uid, 10))
	if err != nil {
		return ""
	}
	return u.Username
}

// ---- bounds ----

// procSize approximates the bytes an entry keeps alive, including Go
// allocator rounding. Strings shared with a parent (fork) are counted again,
// so the estimate errs high.
func procSize(p *event.Proc) int64 {
	n := int64(entryOverhead)
	for _, str := range []string{p.Exe, p.Name, p.Cmdline, p.Cwd, p.Username, p.SigningID, p.TeamID, p.CDHash, p.TTY} {
		n += allocSize(len(str))
	}
	for _, a := range p.Args {
		n += allocSize(len(a)) + 16
	}
	for k, v := range p.Env {
		n += allocSize(len(k)) + allocSize(len(v)) + 48
	}
	return n
}

// allocSize rounds n up the way the Go allocator does, roughly: large
// objects take whole 8 KiB pages, small ones a size class at most ~1/8 above.
func allocSize(n int) int64 {
	switch {
	case n == 0:
		return 0
	case n > 32<<10:
		return int64((n + 8191) &^ 8191)
	default:
		return int64(n + n/8 + 16)
	}
}

func (s *Snapshotter) resize(en *entry) {
	n := procSize(&en.proc)
	s.bytes += n - en.size
	en.size = n
}

// makeRoom evicts until one more entry of size n fits.
func (s *Snapshotter) makeRoom(n int64) {
	for len(s.procs) > 0 && (len(s.procs) >= s.max || s.bytes+n > s.maxBytes) {
		if !s.evictOne(-1) {
			return
		}
	}
}

// enforce evicts other entries while the table is over a bound.
func (s *Snapshotter) enforce(keep int32) {
	for len(s.procs) > s.max || s.bytes > s.maxBytes {
		if !s.evictOne(keep) {
			return
		}
	}
}

// evictOne removes the earliest-exited entry, else the least recently
// (re)imaged live one other than launchd, the kernel and keep. O(1) amortized.
func (s *Snapshotter) evictOne(keep int32) bool {
	for _, l := range []*list.List{s.dead, s.live} {
		for el := l.Front(); el != nil; el = el.Next() {
			pid := el.Value.(int32)
			if pid <= 1 || pid == keep {
				continue
			}
			s.remove(pid)
			s.evictions++
			return true
		}
	}
	return false
}

func (s *Snapshotter) remove(pid int32) {
	en, ok := s.procs[pid]
	if !ok {
		return
	}
	if en.exited.IsZero() {
		s.live.Remove(en.elem)
	} else {
		s.dead.Remove(en.elem)
	}
	s.bytes -= en.size
	delete(s.procs, pid)
}

// maybeSweep drops exited entries older than the TTL, at most every sweepEvery.
func (s *Snapshotter) maybeSweep(now time.Time) {
	if now.Sub(s.lastSweep) < sweepEvery && !now.Before(s.lastSweep) {
		return
	}
	s.lastSweep = now
	s.sweep(now)
}

// sweep walks the exited list from the earliest exit and stops at the first
// entry still within the TTL.
func (s *Snapshotter) sweep(now time.Time) {
	for el := s.dead.Front(); el != nil; {
		next := el.Next()
		en := s.procs[el.Value.(int32)]
		if now.Sub(en.exited) < s.ttl {
			break
		}
		s.remove(el.Value.(int32))
		el = next
	}
}
