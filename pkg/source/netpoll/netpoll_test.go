package netpoll

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

type fakeKernel struct {
	mu     sync.Mutex
	socks  map[int32][]Socket
	idents map[int32]Ident
	calls  int // Sockets calls
}

func (f *fakeKernel) PIDs() ([]int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int32
	for p := range f.socks {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeKernel) Ident(pid int32) (Ident, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.idents[pid]
	if !ok {
		return Ident{}, errors.New("no such process")
	}
	return id, nil
}

func (f *fakeKernel) Sockets(pid int32, w Window) (SocketList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	all, ok := f.socks[pid]
	if !ok {
		return SocketList{}, errors.New("EPERM")
	}
	res := SocketList{SocketFDs: len(all)}
	count, start := len(all), 0
	if count > w.Max {
		count, res.Capped = w.Max, true
		start = w.Start % len(all)
	}
	for j := 0; j < count; j++ {
		so := all[(start+j)%len(all)]
		res.Calls++
		if res.Capped {
			res.Inspected = append(res.Inspected, so.FD)
		}
		res.Socks = append(res.Socks, so)
	}
	return res, nil
}

func (f *fakeKernel) set(pid int32, socks ...Socket) {
	f.mu.Lock()
	f.socks[pid] = socks
	f.mu.Unlock()
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func tcp(fd int32, local, remote string, state int) Socket {
	so := Socket{FD: fd, Proto: "tcp", Local: ap(local), TCPState: state, Gen: uint64(fd) * 7}
	if remote != "" {
		so.Remote = ap(remote)
	}
	return so
}

func newFake() *fakeKernel {
	return &fakeKernel{socks: map[int32][]Socket{}, idents: map[int32]Ident{
		100: {PID: 100, PPID: 1, PIDVersion: 3, UniqueID: 1000, Name: "bash", Exe: "/bin/bash", IsPlatform: true},
		200: {PID: 200, PPID: 1, PIDVersion: 5, UniqueID: 2000, Name: "nginx", Exe: "/opt/homebrew/bin/nginx"},
		300: {PID: 300, PPID: 100, PIDVersion: 1, UniqueID: 3000, Name: "x", Exe: "/private/tmp/x"},
	}}
}

// poll runs one full poll and returns the events.
func poll(t *testing.T, s *Source) []*event.Event {
	t.Helper()
	out := make(chan *event.Event, 1024)
	if err := s.fullPoll(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var evs []*event.Event
	for e := range out {
		evs = append(evs, e)
	}
	return evs
}

func TestClassifyAndOncePerSocket(t *testing.T) {
	k := newFake()
	k.set(100, tcp(3, "10.0.0.5:50001", "203.0.113.9:4444", TCPEstablished))
	k.set(200,
		tcp(4, "0.0.0.0:8080", "", TCPListen),
		tcp(5, "10.0.0.5:8080", "198.51.100.3:61000", TCPEstablished),
		tcp(6, "10.0.0.5:50002", "203.0.113.1:443", TCPSynSent), // not established: not reported
		tcp(7, "127.0.0.1:9000", "", TCPListen),                 // loopback: skipped
		tcp(8, "127.0.0.1:50003", "127.0.0.1:9000", TCPEstablished),
		Socket{FD: 9, Proto: "udp", Local: ap("0.0.0.0:5353"), TCPState: -1, Gen: 1},
		Socket{FD: 10, Proto: "udp", Local: ap("10.0.0.5:50004"), Remote: ap("192.0.2.53:53"), TCPState: -1, Gen: 2},
	)
	s := New(Config{Kernel: k})
	evs := poll(t, s)
	type want struct{ name, dir, proto, sip, dip string }
	got := map[want]int{}
	for _, e := range evs {
		got[want{e.Name, e.Net.Direction, e.Net.Proto, e.Net.SrcIP, e.Net.DstIP}]++
		if e.Platform != event.PlatformMacOS || e.Source != Name || e.Args["fd"] == "" {
			t.Fatalf("event %+v", e)
		}
	}
	for _, w := range []want{
		{event.NetworkConnect, "outbound", "tcp", "10.0.0.5", "203.0.113.9"},
		{event.NetworkAccept, "listen", "tcp", "", "0.0.0.0"},
		{event.NetworkAccept, "inbound", "tcp", "198.51.100.3", "10.0.0.5"},
		{event.NetworkAccept, "listen", "udp", "", "0.0.0.0"},
		{event.NetworkConnect, "outbound", "udp", "10.0.0.5", "192.0.2.53"},
	} {
		if got[w] != 1 {
			t.Fatalf("%+v reported %d times; all: %v", w, got[w], got)
		}
	}
	if len(evs) != 5 {
		t.Fatalf("%d events, want 5: %v", len(evs), got)
	}
	// Second poll: nothing new.
	if evs := poll(t, s); len(evs) != 0 {
		t.Fatalf("second poll emitted %d events", len(evs))
	}
	// A socket that closes and a new one with the same fd is new.
	k.set(100, tcp(3, "10.0.0.5:50009", "203.0.113.9:4444", TCPEstablished))
	evs = poll(t, s)
	if len(evs) != 1 || evs[0].Net.SrcPort != 50009 {
		t.Fatalf("reused fd: %d events", len(evs))
	}
	// Forgotten after closing: the tracked set shrinks.
	k.set(200)
	poll(t, s)
	if len(s.seen) != 1 {
		t.Fatalf("tracked %d sockets after close, want 1", len(s.seen))
	}
}

func TestIdentityFromTableAndUnverifiedFallback(t *testing.T) {
	k := newFake()
	k.set(100, tcp(3, "10.0.0.5:50001", "203.0.113.9:4444", TCPEstablished))
	k.set(300, tcp(3, "10.0.0.5:50002", "203.0.113.9:4445", TCPEstablished))
	table := map[int32]event.Proc{
		1:   {PID: 1, Exe: "/sbin/launchd", IsPlatform: true},
		100: {PID: 100, PPID: 1, PIDVersion: 3, UniqueID: 1000, Exe: "/bin/bash", Name: "bash", IsPlatform: true, IsSigned: true, Cmdline: "bash -i"},
		// pid 300 in the table is an older incarnation (another unique id).
		300: {PID: 300, PPID: 100, PIDVersion: 1, UniqueID: 2999, Exe: "/usr/bin/true", Name: "true", IsPlatform: true},
	}
	lookups := 0
	s := New(Config{Kernel: k, Lookup: func(pid int32) (event.Proc, bool) {
		lookups++
		p, ok := table[pid]
		return p, ok
	}})
	evs := poll(t, s)
	if len(evs) != 2 {
		t.Fatalf("%d events", len(evs))
	}
	for _, e := range evs {
		switch e.Proc.PID {
		case 100:
			if e.Proc.Seeded || e.Args["identity"] != "" || e.Proc.Cmdline != "bash -i" || e.Proc.Parent == nil ||
				e.Proc.Parent.Exe != "/sbin/launchd" || e.Proc.AncestorsUntrusted {
				t.Fatalf("table identity: %+v", e.Proc)
			}
		case 300:
			if !e.Proc.Seeded || e.Args["identity"] != "unverified" || e.Proc.Exe != "/private/tmp/x" || e.Proc.Name != "x" ||
				e.Proc.IsSigned || e.Proc.Parent == nil || e.Proc.Parent.Exe != "/bin/bash" {
				t.Fatalf("fallback identity: %+v", e.Proc)
			}
		}
	}
	// The events' processes are copies: changing one does not change the
	// table or another event.
	evs[0].Proc.Exe = "changed"
	if table[100].Exe != "/bin/bash" {
		t.Fatal("event shares the table's process")
	}
}

func TestSameIncarnationNeedsEvidence(t *testing.T) {
	id := Ident{PID: 7, PIDVersion: 4, UniqueID: 70}
	for _, c := range []struct {
		tp   event.Proc
		want bool
	}{
		{event.Proc{PID: 7, UniqueID: 70, PIDVersion: 4}, true},
		{event.Proc{PID: 7, UniqueID: 70}, true},
		{event.Proc{PID: 7, UniqueID: 69, PIDVersion: 4}, false},
		{event.Proc{PID: 7, PIDVersion: 4}, true},  // no unique id: pidversion agrees
		{event.Proc{PID: 7, PIDVersion: 3}, false}, // another incarnation
		{event.Proc{PID: 7}, false},                // a seeded entry: no evidence
		{event.Proc{PID: 8, UniqueID: 70}, false},
	} {
		if got := sameIncarnation(&c.tp, id); got != c.want {
			t.Errorf("%+v: got %v", c.tp, got)
		}
	}
	if sameIncarnation(&event.Proc{PID: 7, UniqueID: 70}, Ident{PID: 7}) {
		t.Error("an unreadable kernel unique id confirmed the incarnation")
	}
}

func TestBudgetAndFairness(t *testing.T) {
	k := newFake()
	for pid := int32(1); pid <= 10; pid++ {
		k.idents[pid] = Ident{PID: pid, UniqueID: uint64(pid)}
		k.set(pid, tcp(3, "10.0.0.5:5000"+string(rune('0'+pid%10)), "203.0.113.9:443", TCPEstablished))
	}
	var conds []string
	s := New(Config{Kernel: k, MaxSocketCalls: 4})
	s.OnDegraded(func(c, d string) { conds = append(conds, c) })
	seen := map[int32]bool{}
	for i := 0; i < 3; i++ {
		for _, e := range poll(t, s) {
			seen[e.Proc.PID] = true
		}
	}
	if len(seen) != 10 {
		t.Fatalf("after 3 budget-limited polls %d of 10 processes were reported", len(seen))
	}
	if len(conds) == 0 || conds[0] != CondBudget || s.Stats()["budget_exhausted"] == 0 {
		t.Fatalf("budget not reported: %v", conds)
	}
	// Sockets of processes skipped in one poll are not re-emitted.
	if evs := poll(t, s); len(evs) != 0 {
		t.Fatalf("re-emitted %d", len(evs))
	}
}

func TestTrackingCap(t *testing.T) {
	k := newFake()
	var socks []Socket
	for fd := int32(3); fd < 13; fd++ {
		socks = append(socks, tcp(fd, "10.0.0.5:4000"+string(rune('0'+fd%10)), "203.0.113.9:443", TCPEstablished))
	}
	k.set(100, socks...)
	var conds []string
	s := New(Config{Kernel: k, MaxTracked: 4})
	s.OnDegraded(func(c, d string) { conds = append(conds, c) })
	if evs := poll(t, s); len(evs) != 4 {
		t.Fatalf("%d events with a tracking cap of 4", len(evs))
	}
	if evs := poll(t, s); len(evs) != 0 {
		t.Fatalf("untracked sockets re-emitted: %d", len(evs))
	}
	if len(conds) == 0 || conds[0] != CondTracking {
		t.Fatalf("tracking cap not reported: %v", conds)
	}
}

func TestPerProcessCapAndSelf(t *testing.T) {
	k := newFake()
	var socks []Socket
	for fd := int32(3); fd < 20; fd++ {
		socks = append(socks, tcp(fd, "10.0.0.5:1", "203.0.113.9:443", TCPEstablished))
	}
	for i := range socks {
		socks[i].Local = netip.AddrPortFrom(netip.MustParseAddr("10.0.0.5"), uint16(30000+i))
	}
	k.set(100, socks...)
	k.set(200, tcp(3, "10.0.0.5:1", "203.0.113.9:443", TCPEstablished))
	var conds []string
	s := New(Config{Kernel: k, MaxSocketsPerProc: 5, SelfPID: 200})
	s.OnDegraded(func(c, d string) { conds = append(conds, c) })
	evs := poll(t, s)
	if len(evs) != 5 || s.Stats()["fd_caps"] != 1 || len(conds) == 0 || conds[0] != CondFDCapped {
		t.Fatalf("%d events, fd_caps=%d, conds %v", len(evs), s.Stats()["fd_caps"], conds)
	}
	// The window moves: every one of the 17 sockets is reported within
	// four polls, each once.
	total := len(evs)
	for i := 0; i < 3; i++ {
		total += len(poll(t, s))
	}
	if total != 17 {
		t.Fatalf("%d sockets reported over 4 polls, want 17", total)
	}
	for _, e := range evs {
		if e.Proc.PID == 200 {
			t.Fatal("own process reported")
		}
	}
}

func TestNudgeNeverBlocksAndRunPolls(t *testing.T) {
	k := newFake()
	s := New(Config{Kernel: k, Interval: time.Hour})
	for i := 0; i < nudgeQueue+10; i++ {
		s.Nudge(100)
	}
	if s.Stats()["nudges_dropped"] != 10 {
		t.Fatalf("dropped %d", s.Stats()["nudges_dropped"])
	}
	// Drain the queue, then a nudge for a process that just connected is
	// reported without waiting for the hour-long interval.
	s = New(Config{Kernel: k, Interval: time.Hour})
	out := make(chan *event.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, nil, out) }()
	time.Sleep(50 * time.Millisecond)
	k.set(300, tcp(3, "10.0.0.5:50002", "203.0.113.9:4445", TCPEstablished))
	s.Nudge(300)
	select {
	case e := <-out:
		if e.Proc.PID != 300 {
			t.Fatalf("pid %d", e.Proc.PID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nudge not polled")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIntervalFloor(t *testing.T) {
	if s := New(Config{Kernel: newFake(), Interval: time.Millisecond}); s.cfg.Interval != MinInterval {
		t.Fatalf("interval %v", s.cfg.Interval)
	}
}

// A loopback listener (or another process's listener) on the local port of
// an outbound connection must not turn it into an inbound one (security
// review finding 1).
func TestListenerSpoofDoesNotFlipDirection(t *testing.T) {
	k := newFake()
	k.set(300,
		tcp(3, "10.0.0.5:50123", "203.0.113.9:4444", TCPEstablished),
		tcp(4, "127.0.0.1:50123", "", TCPListen))
	k.set(200, tcp(5, "0.0.0.0:50124", "", TCPListen)) // another process
	k.set(100, tcp(6, "10.0.0.5:50124", "203.0.113.9:4445", TCPEstablished))
	s := New(Config{Kernel: k})
	poll(t, s)
	evs := poll(t, s) // listeners are known now; nothing new is emitted
	if len(evs) != 0 {
		t.Fatalf("%d events", len(evs))
	}
	s = New(Config{Kernel: k})
	for pass := 0; pass < 2; pass++ {
		for _, e := range poll(t, s) {
			if e.Net.Direction != "listen" && e.Name != event.NetworkConnect {
				t.Fatalf("pid %d %s/%s: an outbound connection was relabelled", e.Proc.PID, e.Name, e.Net.Direction)
			}
		}
	}
	// A real server: a child (ppid 200) holds a connection accepted on its
	// parent's wildcard listener.
	k.idents[400] = Ident{PID: 400, PPID: 200, UniqueID: 4000}
	k.set(400, tcp(7, "10.0.0.5:50124", "198.51.100.1:61000", TCPEstablished))
	s = New(Config{Kernel: k})
	poll(t, s)
	k.set(400, tcp(8, "10.0.0.5:50124", "198.51.100.1:61001", TCPEstablished))
	evs = poll(t, s)
	if len(evs) != 1 || evs[0].Net.Direction != "inbound" {
		t.Fatalf("accepted connection: %+v", evs)
	}
}

// One capped process re-connecting its sockets every poll cannot fill the
// host-wide table (security review finding 2).
func TestCappedProcessCannotFillTracking(t *testing.T) {
	k := newFake()
	mk := func(round int) []Socket {
		var out []Socket
		for fd := int32(3); fd < 3+40; fd++ {
			out = append(out, Socket{FD: fd, Proto: "udp", Local: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.5"), uint16(30000+fd)),
				Remote: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(1000+round)), TCPState: -1, Gen: uint64(fd)})
		}
		return out
	}
	s := New(Config{Kernel: k, MaxSocketsPerProc: 10, MaxTrackedPerProc: 25, MaxTracked: 1000})
	for round := 0; round < 30; round++ {
		k.set(300, mk(round)...)
		poll(t, s)
		if s.perProc[300] > 25 || len(s.seen) > 25 {
			t.Fatalf("round %d: %d tracked for the process, %d in all", round, s.perProc[300], len(s.seen))
		}
	}
	// Another process is still reported.
	k.set(100, tcp(3, "10.0.0.5:50001", "203.0.113.9:4444", TCPEstablished))
	found := false
	for _, e := range poll(t, s) {
		found = found || e.Proc.PID == 100
	}
	if !found {
		t.Fatal("another process's socket was not reported")
	}
}

func TestNudgeLimits(t *testing.T) {
	s := New(Config{Kernel: newFake()})
	if !s.nudgeAllowed(5) || s.nudgeAllowed(5) {
		t.Fatal("same pid nudged twice within the gap")
	}
	n := 1
	for pid := int32(10); pid < 1000; pid++ {
		if s.nudgeAllowed(pid) {
			n++
		}
	}
	if n != nudgePerSecond || s.Stats()["nudges_skipped"] == 0 {
		t.Fatalf("%d nudges allowed in a second", n)
	}
}
