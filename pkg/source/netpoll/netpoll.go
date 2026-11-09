// Package netpoll is ZAAFVesper's network telemetry on macOS without a
// NetworkExtension or any entitlement. It polls the kernel's socket tables
// per process with proc_info (PROC_PIDLISTFDS, then PROC_PIDFDSOCKETINFO for
// each socket descriptor), pure Go, no cgo, every Config.Interval and on
// each exec (Nudge), and emits one event per socket:
//
//   - NetworkConnect (net.direction outbound) for an established TCP
//     connection or a connected UDP socket that this host initiated;
//   - NetworkAccept (net.direction inbound) for an established TCP
//     connection accepted on a local listening port;
//   - NetworkAccept (net.direction listen) for a listening TCP socket or a
//     bound, unconnected UDP socket.
//
// Limits, stated honestly: a connection that opens and closes between two
// polls is never seen; DNS queries are not visible on macOS at all; the
// direction of an established TCP connection is inferred (inbound when its
// local port is a listening port on this host); without root only the
// caller's own processes can be read.
//
// Security note N7: netpoll never writes to the process table. It only
// reads it through Config.Lookup, and the events it emits must not be
// passed through the table's Enricher (the response layer trusts the
// table's platform flags because eslogger is the table's only writer). A
// process the table does not know (or knows as another incarnation) gets an
// identity read from the kernel that is marked unverified (Proc.Seeded and
// evt.arg[identity] = unverified), so response never acts on it.
package netpoll

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Name is the source name (evt.source).
const Name = "netpoll"

// Defaults and bounds. Every loop is bounded: per poll, per process and in
// the number of sockets remembered.
const (
	DefaultInterval = time.Second
	// MinInterval is the smallest accepted --net-interval.
	MinInterval = 100 * time.Millisecond
	// DefaultMaxProcs bounds the processes walked in one poll.
	DefaultMaxProcs = 8192
	// DefaultMaxFDsPerProc bounds the descriptors listed per process. It is
	// above macOS's default kern.maxfilesperproc (61,440), so padding the
	// descriptor table cannot push a socket out of the list.
	DefaultMaxFDsPerProc = 65536
	// DefaultMaxSocketsPerProc bounds the sockets inspected per process in
	// one poll. A process with more socket descriptors is inspected through
	// a window that moves on every poll, so every socket is reached within
	// a few polls, and the cut is reported (CondFDCapped).
	DefaultMaxSocketsPerProc = 1024
	// DefaultMaxSocketCalls bounds the socket inspections (one syscall
	// each) in one poll, over all processes. A poll that reaches it starts
	// the next poll where it stopped, so no process is skipped forever.
	DefaultMaxSocketCalls = 20000
	// DefaultMaxTracked bounds the sockets remembered (to emit each once).
	DefaultMaxTracked = 65536
	// DefaultMaxTrackedPerProc bounds the sockets remembered for one process,
	// so one process cannot fill the host-wide table.
	DefaultMaxTrackedPerProc = 4096
	// maxListeners bounds the listening sockets remembered.
	maxListeners = 65536
	// nudgeMinGap: a process is not nudge-polled again sooner than this.
	nudgeMinGap = 200 * time.Millisecond
	// nudgePerSecond bounds the nudge polls per second (each can cost up to
	// MaxSocketsPerProc socket inspections outside the full-poll budget).
	nudgePerSecond = 100
	// nudgeQueue bounds pending exec nudges; more are dropped (counted).
	nudgeQueue = 256
	// nudgeRepeat: a nudged process is polled at once and again after this
	// delay, since a freshly executed process usually connects after exec.
	nudgeRepeat = 250 * time.Millisecond
	// maxPending bounds the delayed nudge polls held at once.
	maxPending = 512
	// maxAncestors mirrors pkg/ps.MaxAncestors for the read-only walk.
	maxAncestors = 16
)

// Conditions of the SensorDegraded events netpoll reports.
const (
	CondBudget   = "netpoll_budget_exhausted"
	CondTracking = "netpoll_tracking_full"
	CondFailed   = "netpoll_failed"
	// CondFDCapped: a process holds more socket descriptors than one poll
	// inspects (or more descriptors than are listed); its sockets are
	// reached over several polls. Often deliberate padding.
	CondFDCapped = "netpoll_fd_capped"
)

// Socket is one inspected socket of a process (from the kernel).
type Socket struct {
	FD     int32
	Proto  string // "tcp" or "udp"
	Local  netip.AddrPort
	Remote netip.AddrPort // zero when not connected
	// TCPState is the TCP state (TCPListen, TCPEstablished, ...); -1 for UDP.
	TCPState int
	// Gen is the kernel's generation count of the protocol control block
	// (insi_gencnt): together with the pid incarnation, fd and addresses
	// it identifies a socket across polls.
	Gen uint64
}

// TCP states (tcpsi_state, <netinet/tcp_fsm.h> TSI_S_*).
const (
	TCPClosed      = 0
	TCPListen      = 1
	TCPSynSent     = 2
	TCPSynReceived = 3
	TCPEstablished = 4
	TCPCloseWait   = 5
	TCPFinWait1    = 6
	TCPClosing     = 7
	TCPLastAck     = 8
	TCPFinWait2    = 9
	TCPTimeWait    = 10
)

// Ident is a process identity read from the kernel.
type Ident struct {
	PID, PPID  int32
	PIDVersion uint32
	UniqueID   uint64
	UID, EUID  int64
	Name       string // short command name (p_comm)
	Exe        string // proc_pidpath; "" when unreadable
	IsPlatform bool   // csops CS_PLATFORM_BINARY (kernel truth)
	StartTime  time.Time
}

// Kernel reads processes and sockets. The darwin implementation uses
// proc_info; tests inject a fake.
type Kernel interface {
	// PIDs lists the running processes.
	PIDs() ([]int32, error)
	// Ident reads pid's identity (unique id and pidversion at least).
	Ident(pid int32) (Ident, error)
	// Sockets returns pid's IPv4/IPv6 TCP and UDP sockets within w.
	Sockets(pid int32, w Window) (SocketList, error)
}

// Window selects the socket descriptors of a process to inspect: at most
// MaxFDs descriptors are listed and at most Max socket descriptors are
// inspected, starting at index Start (mod the number of socket
// descriptors, wrapping around).
type Window struct {
	MaxFDs, Start, Max int
}

// SocketList is the result of Sockets.
type SocketList struct {
	Socks []Socket
	// Calls is the number of socket inspections made (one syscall each).
	Calls int
	// SocketFDs is the number of socket descriptors listed.
	SocketFDs int
	// Capped: not every socket descriptor was inspected (the window was
	// smaller than SocketFDs, or the descriptor list was cut at MaxFDs).
	Capped bool
	// Inspected lists the descriptors inspected (when Capped), so closed
	// sockets among them can be forgotten.
	Inspected []int32
	// FDListCut: the process holds more than MaxFDs descriptors, so some
	// were not even listed.
	FDListCut bool
}

// ErrUnsupported is returned by Run on platforms without a kernel reader.
var ErrUnsupported = errors.New("netpoll: socket polling is only implemented on macOS")

// Config configures the poller.
type Config struct {
	// Interval between full polls (default DefaultInterval).
	Interval time.Duration
	// Lookup reads the process table (pkg/ps Snapshotter.Lookup). It must
	// be read-only. nil: every identity comes from the kernel (unverified).
	Lookup func(pid int32) (event.Proc, bool)
	// IncludeLoopback also reports loopback connections and listeners
	// (default: skipped, they are local IPC and noise).
	IncludeLoopback bool
	// Bounds (zero: the defaults).
	MaxProcs, MaxFDsPerProc, MaxSocketsPerProc, MaxSocketCalls, MaxTracked, MaxTrackedPerProc int
	// SelfPID is skipped (ZAAFVesper's own sockets, e.g. SIEM outputs).
	SelfPID int32
	// Kernel overrides the platform reader (tests).
	Kernel Kernel
	// Now is the clock (tests; default time.Now).
	Now func() time.Time
}

// sockKey identifies one socket of one process incarnation.
type sockKey struct {
	pid      int32
	pv       uint32
	uniq     uint64
	fd       int32
	gen      uint64
	proto    string
	class    uint8
	local    netip.AddrPort
	remote   netip.AddrPort
	tcpState int8
}

const (
	classListen uint8 = iota + 1
	classConn
)

// Source is the socket poller. It implements source.Source.
type Source struct {
	cfg    Config
	kernel Kernel
	nudges chan int32

	mu         sync.Mutex
	onDegraded func(condition, detail string)

	// Poll state: the Run goroutine only.
	seen      map[sockKey]uint64 // socket -> poll number it was last seen in
	perProc   map[int32]int      // sockets in seen, by pid
	listening map[listenKey]uint64
	winStart  map[int32]int // next window start of a capped process
	poll      uint64
	offset    int // where the next poll starts in the pid list (fairness)
	pending   []pendingNudge
	// Nudge rate limits.
	lastNudge   map[int32]time.Time
	nudgeSecond time.Time
	nudgeCount  int

	polls, overruns, procsRead, procErrors, socketsSeen       atomic.Uint64
	connects, accepts, listens, fdCaps, budgetHits, untracked atomic.Uint64
	nudged, nudgesDropped, nudgesSkipped, unverified, emitted atomic.Uint64
}

// listenKey is one listening TCP socket: its local address (unmapped; the
// unspecified address for a wildcard listener), port and owning process.
type listenKey struct {
	addr netip.Addr
	port uint16
	pid  int32
}

type pendingNudge struct {
	pid int32
	at  time.Time
}

// New returns a poller.
func New(cfg Config) *Source {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Interval < MinInterval {
		cfg.Interval = MinInterval
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&cfg.MaxProcs, DefaultMaxProcs)
	def(&cfg.MaxFDsPerProc, DefaultMaxFDsPerProc)
	def(&cfg.MaxSocketsPerProc, DefaultMaxSocketsPerProc)
	def(&cfg.MaxSocketCalls, DefaultMaxSocketCalls)
	def(&cfg.MaxTracked, DefaultMaxTracked)
	def(&cfg.MaxTrackedPerProc, DefaultMaxTrackedPerProc)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	k := cfg.Kernel
	if k == nil {
		k = platformKernel()
	}
	return &Source{cfg: cfg, kernel: k, nudges: make(chan int32, nudgeQueue),
		seen: map[sockKey]uint64{}, perProc: map[int32]int{}, listening: map[listenKey]uint64{},
		winStart: map[int32]int{}, lastNudge: map[int32]time.Time{}}
}

// Name implements source.Source.
func (s *Source) Name() string { return Name }

// OnDegraded registers fn for SensorDegraded reports (CondBudget,
// CondTracking, CondFailed). fn may be called from the poller's goroutine;
// the pipeline's degraded hook is safe for that and rate-limits.
func (s *Source) OnDegraded(fn func(condition, detail string)) {
	s.mu.Lock()
	s.onDegraded = fn
	s.mu.Unlock()
}

func (s *Source) degraded(cond, detail string) {
	s.mu.Lock()
	fn := s.onDegraded
	s.mu.Unlock()
	if fn != nil {
		fn(cond, detail)
	}
}

// Nudge asks for pid to be polled now (and once more shortly after),
// typically right after it executed. It never blocks: a full queue drops
// the nudge (counted); the next full poll still covers the process.
func (s *Source) Nudge(pid int32) {
	if pid <= 0 {
		return
	}
	select {
	case s.nudges <- pid:
		s.nudged.Add(1)
	default:
		s.nudgesDropped.Add(1)
	}
}

// Stats implements source.Source.
func (s *Source) Stats() map[string]uint64 {
	return map[string]uint64{
		"polls": s.polls.Load(), "poll_overruns": s.overruns.Load(), "procs_read": s.procsRead.Load(),
		"proc_errors": s.procErrors.Load(), "sockets_seen": s.socketsSeen.Load(),
		"connect_events": s.connects.Load(), "accept_events": s.accepts.Load(), "listen_events": s.listens.Load(),
		"fd_caps": s.fdCaps.Load(), "budget_exhausted": s.budgetHits.Load(), "untracked_sockets": s.untracked.Load(),
		"nudges": s.nudged.Load(), "nudges_dropped": s.nudgesDropped.Load(), "nudges_skipped": s.nudgesSkipped.Load(), "unverified_identities": s.unverified.Load(),
		"emitted": s.emitted.Load(),
	}
}

// Run polls until ctx is cancelled. The events list is ignored: netpoll
// produces only NetworkConnect and NetworkAccept, and the caller starts it
// only when they are wanted.
func (s *Source) Run(ctx context.Context, _ []string, out chan<- *event.Event) error {
	if s.kernel == nil {
		return ErrUnsupported
	}
	tick := time.NewTicker(s.cfg.Interval)
	defer tick.Stop()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	if err := s.fullPoll(ctx, out); err != nil {
		return err
	}
	for {
		var timerC <-chan time.Time
		if len(s.pending) > 0 {
			d := time.Until(s.pending[0].at)
			if d < 0 {
				d = 0
			}
			timer.Reset(d)
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			start := time.Now()
			if err := s.fullPoll(ctx, out); err != nil {
				return err
			}
			if time.Since(start) > s.cfg.Interval {
				s.overruns.Add(1)
			}
		case pid := <-s.nudges:
			if !s.nudgeAllowed(pid) {
				continue
			}
			if _, err := s.pollPID(ctx, out, pid, nil); err != nil {
				return err
			}
			if len(s.pending) < maxPending {
				s.pending = append(s.pending, pendingNudge{pid: pid, at: time.Now().Add(nudgeRepeat)})
			}
		case <-timerC:
			now := time.Now()
			for len(s.pending) > 0 && !s.pending[0].at.After(now) {
				pid := s.pending[0].pid
				s.pending = s.pending[1:]
				if !s.nudgeAllowed(pid) {
					continue
				}
				if _, err := s.pollPID(ctx, out, pid, nil); err != nil {
					return err
				}
			}
		}
		if timerC != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

// nudgeAllowed applies the nudge limits: not the same pid again within
// nudgeMinGap, and at most nudgePerSecond nudge polls a second. A skipped
// nudge costs nothing: the next full poll covers the process.
func (s *Source) nudgeAllowed(pid int32) bool {
	now := time.Now()
	if last, ok := s.lastNudge[pid]; ok && now.Sub(last) < nudgeMinGap {
		s.nudgesSkipped.Add(1)
		return false
	}
	if now.Sub(s.nudgeSecond) >= time.Second {
		s.nudgeSecond, s.nudgeCount = now, 0
	}
	if s.nudgeCount >= nudgePerSecond {
		s.nudgesSkipped.Add(1)
		return false
	}
	s.nudgeCount++
	if len(s.lastNudge) >= 4*nudgeQueue {
		for k, t := range s.lastNudge {
			if now.Sub(t) >= nudgeMinGap {
				delete(s.lastNudge, k)
			}
		}
	}
	s.lastNudge[pid] = now
	return true
}

// pollBudget tracks the socket inspections left in one full poll.
type pollBudget struct{ left int }

// fullPoll walks every process once (within the bounds), emits new sockets
// and forgets sockets that were not seen (closed).
func (s *Source) fullPoll(ctx context.Context, out chan<- *event.Event) error {
	pids, err := s.kernel.PIDs()
	if err != nil {
		s.degraded(CondFailed, "listing processes failed: "+err.Error())
		return nil // keep running: the next poll may succeed
	}
	s.poll++
	s.polls.Add(1)
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	n := len(pids)
	if n == 0 {
		return nil
	}
	limit := n
	if limit > s.cfg.MaxProcs {
		limit = s.cfg.MaxProcs
	}
	if s.offset >= n {
		s.offset = 0
	}
	budget := &pollBudget{left: s.cfg.MaxSocketCalls}
	alive := make(map[int32]bool, n)
	for _, pid := range pids {
		alive[pid] = true
	}
	// walked: processes whose sockets were all inspected in this poll;
	// partial: the descriptors inspected of a capped process.
	walked := map[int32]bool{}
	partial := map[int32]map[int32]bool{}
	next := (s.offset + limit) % n
	for i := 0; i < limit; i++ {
		pid := pids[(s.offset+i)%n]
		if budget.left <= 0 {
			next = (s.offset + i) % n
			s.budgetHits.Add(1)
			s.degraded(CondBudget, fmt.Sprintf("a poll reached its budget of %d socket inspections after %d of %d processes; the next poll continues from there", s.cfg.MaxSocketCalls, i, n))
			break
		}
		res, err := s.pollPID(ctx, out, pid, budget)
		if err != nil {
			return err
		}
		switch {
		case res.full:
			walked[pid] = true
		case res.inspected != nil:
			partial[pid] = res.inspected
		}
	}
	s.offset = next
	// Forget closed sockets: those of a process inspected in this poll that
	// were not seen (for a capped process: among the descriptors inspected),
	// and those of processes that are gone. A process the budget skipped
	// keeps its sockets, so they are not reported again.
	for k, last := range s.seen {
		if !alive[k.pid] || (last < s.poll && (walked[k.pid] || partial[k.pid][k.fd])) {
			s.forget(k)
		}
	}
	for k, last := range s.listening {
		if !alive[k.pid] || (walked[k.pid] && last < s.poll) {
			delete(s.listening, k)
		}
	}
	for pid := range s.winStart {
		if !alive[pid] {
			delete(s.winStart, pid)
		}
	}
	return nil
}

func (s *Source) forget(k sockKey) {
	delete(s.seen, k)
	if n := s.perProc[k.pid] - 1; n > 0 {
		s.perProc[k.pid] = n
	} else {
		delete(s.perProc, k.pid)
	}
}

// pollResult tells fullPoll what was inspected of one process.
type pollResult struct {
	full      bool           // every socket descriptor was inspected
	inspected map[int32]bool // capped: the descriptors inspected
}

// pollPID inspects one process (budget nil: a nudge, not counted against a
// full poll's budget) and emits its new sockets.
func (s *Source) pollPID(ctx context.Context, out chan<- *event.Event, pid int32, budget *pollBudget) (pollResult, error) {
	if pid <= 0 || pid == s.cfg.SelfPID {
		return pollResult{}, nil
	}
	maxSock := s.cfg.MaxSocketsPerProc
	if budget != nil && budget.left < maxSock {
		maxSock = budget.left
	}
	start := s.winStart[pid]
	list, err := s.kernel.Sockets(pid, Window{MaxFDs: s.cfg.MaxFDsPerProc, Start: start, Max: maxSock})
	if budget != nil {
		budget.left -= list.Calls
	}
	if err != nil {
		s.procErrors.Add(1) // EPERM (not root), ESRCH (exited): normal
		return pollResult{}, nil
	}
	s.procsRead.Add(1)
	res := pollResult{full: !list.Capped}
	if list.Capped {
		s.fdCaps.Add(1)
		res.inspected = make(map[int32]bool, len(list.Inspected))
		for _, fd := range list.Inspected {
			res.inspected[fd] = true
		}
		if list.SocketFDs > 0 {
			s.winStart[pid] = (start + list.Calls) % list.SocketFDs
		}
	} else {
		delete(s.winStart, pid)
	}
	if len(list.Socks) == 0 && !list.Capped {
		return res, nil
	}
	id, err := s.kernel.Ident(pid)
	if err != nil {
		s.procErrors.Add(1)
		return pollResult{}, nil
	}
	if list.FDListCut || list.SocketFDs > s.cfg.MaxSocketsPerProc {
		// Cut by the per-process bounds (not by the poll budget): often
		// deliberate padding to hide a socket.
		s.degraded(CondFDCapped, fmt.Sprintf("pid %d (%s) holds %d socket descriptors (descriptor list cut: %v), more than the %d inspected per poll; its sockets are reached over several polls",
			pid, id.Exe, list.SocketFDs, list.FDListCut, s.cfg.MaxSocketsPerProc))
	}
	// Listening sockets first: they decide the direction of established
	// connections of the same process and its children.
	for _, so := range list.Socks {
		if so.Proto == "tcp" && so.TCPState == TCPListen {
			k := listenKey{addr: so.Local.Addr().Unmap(), port: so.Local.Port(), pid: pid}
			if _, ok := s.listening[k]; ok || len(s.listening) < maxListeners {
				s.listening[k] = s.poll
			}
		}
	}
	var proc *event.Proc
	verified := false
	for _, so := range list.Socks {
		s.socketsSeen.Add(1)
		name, dir, class, ok := s.classify(so, pid, id.PPID)
		if !ok {
			continue
		}
		k := sockKey{pid: pid, pv: id.PIDVersion, uniq: id.UniqueID, fd: so.FD, gen: so.Gen, proto: so.Proto,
			class: class, local: so.Local, remote: so.Remote}
		if _, dup := s.seen[k]; dup {
			s.seen[k] = s.poll
			continue
		}
		if len(s.seen) >= s.cfg.MaxTracked || s.perProc[pid] >= s.cfg.MaxTrackedPerProc {
			// Not remembered, so not emitted either: emitting it would
			// repeat it every poll.
			s.untracked.Add(1)
			s.degraded(CondTracking, fmt.Sprintf("pid %d (%s) has %d tracked sockets (cap %d per process, %d in all, %d tracked now); its new sockets are not reported until some close",
				pid, id.Exe, s.perProc[pid], s.cfg.MaxTrackedPerProc, s.cfg.MaxTracked, len(s.seen)))
			continue
		}
		s.seen[k] = s.poll
		s.perProc[pid]++
		if proc == nil {
			proc, verified = s.identity(id)
		}
		e := s.buildEvent(name, dir, so, proc, verified)
		select {
		case out <- e:
			s.emitted.Add(1)
		case <-ctx.Done():
			return pollResult{}, nil
		}
		switch {
		case name == event.NetworkConnect:
			s.connects.Add(1)
		case dir == "listen":
			s.listens.Add(1)
		default:
			s.accepts.Add(1)
		}
	}
	return res, nil
}

// inboundListener reports whether an established TCP connection with local
// address local was accepted on a listener of the same process or of its
// parent (a server that forks per connection), bound to that exact address
// or to the wildcard. A listener elsewhere (another process, a loopback
// listener on the same port number) never turns a connection inbound.
func (s *Source) inboundListener(local netip.AddrPort, pid, ppid int32) bool {
	addr := local.Addr().Unmap()
	cands := []netip.Addr{addr, netip.IPv6Unspecified()}
	if addr.Is4() {
		cands = append(cands, netip.IPv4Unspecified())
	}
	for _, owner := range []int32{pid, ppid} {
		if owner <= 0 {
			continue
		}
		for _, a := range cands {
			if _, ok := s.listening[listenKey{addr: a, port: local.Port(), pid: owner}]; ok {
				return true
			}
		}
	}
	return false
}

// classify maps a socket of process pid (parent ppid) to an event (ok
// false: not reported).
func (s *Source) classify(so Socket, pid, ppid int32) (name, dir string, class uint8, ok bool) {
	loopLocal := isLoopback(so.Local.Addr())
	switch so.Proto {
	case "tcp":
		switch so.TCPState {
		case TCPListen:
			if loopLocal && !s.cfg.IncludeLoopback {
				return "", "", 0, false
			}
			return event.NetworkAccept, "listen", classListen, true
		case TCPEstablished, TCPCloseWait, TCPFinWait1, TCPClosing, TCPLastAck, TCPFinWait2:
			if !so.Remote.IsValid() || so.Remote.Port() == 0 {
				return "", "", 0, false
			}
			if isLoopback(so.Remote.Addr()) && !s.cfg.IncludeLoopback {
				return "", "", 0, false
			}
			if s.inboundListener(so.Local, pid, ppid) {
				return event.NetworkAccept, "inbound", classConn, true
			}
			return event.NetworkConnect, "outbound", classConn, true
		}
		return "", "", 0, false // SYN_SENT and closed states: not (yet) a connection
	case "udp":
		if so.Remote.IsValid() && so.Remote.Port() != 0 && !so.Remote.Addr().IsUnspecified() {
			if isLoopback(so.Remote.Addr()) && !s.cfg.IncludeLoopback {
				return "", "", 0, false
			}
			return event.NetworkConnect, "outbound", classConn, true
		}
		if so.Local.Port() == 0 || (loopLocal && !s.cfg.IncludeLoopback) {
			return "", "", 0, false
		}
		return event.NetworkAccept, "listen", classListen, true
	}
	return "", "", 0, false
}

func isLoopback(a netip.Addr) bool {
	return a.IsValid() && a.Unmap().IsLoopback()
}

// buildEvent fills the event. Src is the initiator, Dst the responder (the
// Sysmon convention): outbound src=local dst=remote; inbound src=remote
// dst=local; listen dst=local.
func (s *Source) buildEvent(name, dir string, so Socket, proc *event.Proc, verified bool) *event.Event {
	n := &event.Net{Proto: so.Proto, Direction: dir}
	switch dir {
	case "outbound":
		n.SrcIP, n.SrcPort = addrString(so.Local.Addr()), so.Local.Port()
		n.DstIP, n.DstPort = addrString(so.Remote.Addr()), so.Remote.Port()
	case "inbound":
		n.SrcIP, n.SrcPort = addrString(so.Remote.Addr()), so.Remote.Port()
		n.DstIP, n.DstPort = addrString(so.Local.Addr()), so.Local.Port()
	default:
		n.DstIP, n.DstPort = addrString(so.Local.Addr()), so.Local.Port()
	}
	p := *proc // each event gets its own copy (enrichment-free, see N7)
	if p.Parent != nil {
		par := *p.Parent
		p.Parent = &par
	}
	args := map[string]string{"fd": strconv.Itoa(int(so.FD))}
	if !verified {
		args["identity"] = "unverified"
	}
	return &event.Event{Time: s.cfg.Now().UTC(), Name: name, Source: Name, Platform: event.PlatformMacOS,
		Proc: &p, Net: n, Args: args}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.Unmap().String()
}

// identity returns the process for an event: the table's entry when it is
// the same incarnation (unique id and pidversion agree) and verified, with
// a read-only parent and ancestry walk; else a kernel identity marked
// unverified.
func (s *Source) identity(id Ident) (*event.Proc, bool) {
	if s.cfg.Lookup != nil {
		if tp, ok := s.cfg.Lookup(id.PID); ok && sameIncarnation(&tp, id) {
			p := tp
			s.decorate(&p)
			if p.Seeded {
				s.unverified.Add(1)
				return &p, false
			}
			return &p, true
		}
	}
	s.unverified.Add(1)
	p := &event.Proc{PID: id.PID, PPID: id.PPID, PIDVersion: id.PIDVersion, UniqueID: id.UniqueID,
		UID: id.UID, EUID: id.EUID, Name: id.Name, Exe: id.Exe, IsPlatform: id.IsPlatform,
		StartTime: id.StartTime, Seeded: true}
	if id.Exe != "" {
		p.Name = baseName(id.Exe)
	}
	s.decorate(p)
	return p, false
}

func sameIncarnation(tp *event.Proc, id Ident) bool {
	if tp.PID != id.PID {
		return false
	}
	// Positive evidence is required: the kernel unique id (when the table
	// knows it) must be read and equal; otherwise both pidversions must be
	// known and equal. Without either, the entry may belong to an earlier
	// process with the same pid, and the kernel identity is used instead.
	if tp.UniqueID != 0 {
		return tp.UniqueID == id.UniqueID &&
			(tp.PIDVersion == 0 || id.PIDVersion == 0 || tp.PIDVersion == id.PIDVersion)
	}
	return tp.PIDVersion != 0 && tp.PIDVersion == id.PIDVersion
}

// decorate sets Parent, Ancestors and AncestorsUntrusted from the table,
// read-only (the same rules as pkg/ps: a chain that does not reach launchd,
// or holds a process that is neither a platform binary nor a verified
// vendor, is untrusted). A parent whose start time is after the child's is
// a recycled pid and ends the walk.
func (s *Source) decorate(p *event.Proc) {
	p.Parent, p.Ancestors, p.AncestorsUntrusted = nil, nil, true
	if s.cfg.Lookup == nil {
		return
	}
	complete := p.PID == 1
	var chain []event.Proc
	seen := map[int32]bool{p.PID: true}
	child := *p
	ppid := p.PPID
	for len(chain) < maxAncestors && ppid > 0 && !seen[ppid] {
		par, ok := s.cfg.Lookup(ppid)
		if !ok || (!par.StartTime.IsZero() && !child.StartTime.IsZero() && par.StartTime.After(child.StartTime)) {
			break
		}
		seen[ppid] = true
		chain = append(chain, par)
		if ppid == 1 {
			complete = true
			break
		}
		child, ppid = par, par.PPID
	}
	untrusted := !complete
	for i := len(chain) - 1; i >= 0; i-- {
		q := &chain[i]
		untrusted = untrusted || !(q.PID == 1 || q.IsPlatform ||
			q.TeamID != "" && (q.CSCategory == event.CSDeveloperID || q.CSCategory == event.CSAppStore))
		if i == 0 {
			par := *q
			par.Parent, par.Ancestors = nil, nil
			p.Parent = &par
		}
	}
	p.AncestorsUntrusted = untrusted
	if len(chain) > 0 {
		p.Ancestors = make([]string, len(chain))
		for i := range chain {
			p.Ancestors[i] = chain[i].Exe
		}
		// The parent's own flag covers the chain above it.
		up := !complete
		for i := len(chain) - 1; i >= 1; i-- {
			q := &chain[i]
			up = up || !(q.PID == 1 || q.IsPlatform ||
				q.TeamID != "" && (q.CSCategory == event.CSDeveloperID || q.CSCategory == event.CSAppStore))
		}
		p.Parent.AncestorsUntrusted = up
	}
}

func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
