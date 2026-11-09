//go:build darwin

package netpoll

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
)

// TestKernelReadsOwnSockets checks the proc_info layouts against the
// running kernel, with sockets this test opens itself (loopback only, plus a
// connected UDP socket to a documentation address: connect(2) on UDP sends
// no packet).
func TestKernelReadsOwnSockets(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acc <- c
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc := <-acc
	defer sc.Close()
	ln6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer ln6.Close()
	u, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 4444})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	k := &darwinKernel{}
	pid := int32(os.Getpid())
	list, err := k.Sockets(pid, Window{MaxFDs: DefaultMaxFDsPerProc, Max: DefaultMaxSocketsPerProc})
	if err != nil {
		t.Fatal(err)
	}
	socks := list.Socks
	if list.Capped || list.Calls == 0 {
		t.Fatalf("list %+v", list)
	}
	lport := uint16(ln.Addr().(*net.TCPAddr).Port)
	cport := uint16(c.LocalAddr().(*net.TCPAddr).Port)
	l6port := uint16(ln6.Addr().(*net.TCPAddr).Port)
	uport := uint16(u.LocalAddr().(*net.UDPAddr).Port)
	var gotListen, gotConn, gotListen6, gotUDP bool
	for _, so := range socks {
		switch {
		case so.Proto == "tcp" && so.TCPState == TCPListen && so.Local.Port() == lport:
			gotListen = so.Local.Addr() == netip.MustParseAddr("127.0.0.1")
		case so.Proto == "tcp" && so.TCPState == TCPEstablished && so.Local.Port() == cport:
			gotConn = so.Remote == netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), lport) && so.Gen != 0
		case so.Proto == "tcp" && so.TCPState == TCPListen && so.Local.Port() == l6port:
			gotListen6 = so.Local.Addr() == netip.IPv6Loopback()
		case so.Proto == "udp" && so.Local.Port() == uport:
			gotUDP = so.Remote == netip.MustParseAddrPort("192.0.2.7:4444")
		}
	}
	if !gotListen || !gotConn || !gotListen6 || !gotUDP {
		t.Fatalf("listen=%v conn=%v listen6=%v udp=%v; sockets: %+v", gotListen, gotConn, gotListen6, gotUDP, socks)
	}

	id, err := k.Ident(pid)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ps.ReadUniqueID(pid)
	if err != nil {
		t.Fatal(err)
	}
	if id.UniqueID != want || id.UniqueID == 0 || id.PIDVersion == 0 {
		t.Fatalf("ident %+v, want unique id %d", id, want)
	}
	if id.PPID != int32(os.Getppid()) || id.EUID != int64(os.Geteuid()) || id.UID != int64(os.Getuid()) {
		t.Fatalf("ident %+v: ppid/uid mismatch", id)
	}
	if id.Exe == "" || id.Name == "" || id.StartTime.IsZero() || time.Since(id.StartTime) > 24*time.Hour {
		t.Fatalf("ident %+v: exe/name/start", id)
	}

	// A window smaller than the socket count rotates and reports what it
	// inspected.
	w1, err := k.Sockets(pid, Window{MaxFDs: DefaultMaxFDsPerProc, Start: 0, Max: 2})
	if err != nil || !w1.Capped || len(w1.Inspected) != 2 || w1.SocketFDs < 5 {
		t.Fatalf("window: %+v %v", w1, err)
	}
	w2, _ := k.Sockets(pid, Window{MaxFDs: DefaultMaxFDsPerProc, Start: 2, Max: 2})
	if w2.Inspected[0] == w1.Inspected[0] {
		t.Fatalf("window did not move: %v %v", w1.Inspected, w2.Inspected)
	}

	pids, err := k.PIDs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pids {
		found = found || p == pid
	}
	if !found || len(pids) < 10 {
		t.Fatalf("own pid not listed among %d pids", len(pids))
	}
}

// TestRunEmitsOwnUDP runs the real poller against this process: the
// connected UDP socket to a non-loopback address is reported once as an
// outbound NetworkConnect with an unverified kernel identity, and the
// process table it reads is left untouched (N7).
func TestRunEmitsOwnUDP(t *testing.T) {
	u, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 5555})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	snap := ps.NewSnapshotter(false)
	before := snap.Len()
	pid := int32(os.Getpid())
	s := New(Config{Interval: 100 * time.Millisecond, Lookup: snap.Lookup, Kernel: onlyPID{&darwinKernel{}, pid}})
	out := make(chan *event.Event, 64)
	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx, nil, out); err != nil {
		t.Fatal(err)
	}
	close(out)
	n := 0
	for e := range out {
		if e.Net.DstIP == "192.0.2.9" && e.Net.DstPort == 5555 {
			n++
			if e.Name != event.NetworkConnect || e.Net.Direction != "outbound" || e.Net.Proto != "udp" ||
				e.Proc.PID != pid || !e.Proc.Seeded || e.Args["identity"] != "unverified" || e.Platform != event.PlatformMacOS {
				t.Fatalf("bad event %+v / %+v / %+v", e, e.Net, e.Proc)
			}
		}
	}
	if n != 1 {
		t.Fatalf("UDP socket reported %d times, want once", n)
	}
	if snap.Len() != before {
		t.Fatalf("netpoll changed the process table: %d -> %d entries", before, snap.Len())
	}
}

// onlyPID restricts a kernel to one pid (the test process).
type onlyPID struct {
	Kernel
	pid int32
}

func (o onlyPID) PIDs() ([]int32, error) { return []int32{o.pid}, nil }
