//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
)

// These tests load the real kernel programs, so they need root and a
// kernel with BTF; elsewhere they skip. CI's normal job runs as a user, so
// they run in the live-linux-ebpf workflow (sudo) and locally in a
// privileged container (see README.md, "Tests"). Set ZAAF_EBPF_REQUIRE=1
// to turn the skip into a failure, so a run that is meant to exercise them
// cannot pass by skipping.
func needLive(t *testing.T) {
	t.Helper()
	why := ""
	switch {
	case os.Geteuid() != 0:
		why = "needs root"
	case !hasCap(39) && !hasCap(21): // CAP_BPF or CAP_SYS_ADMIN
		why = "no CAP_BPF (an unprivileged container)"
	default:
		if _, err := os.Stat(kernelBTF); err != nil {
			why = "kernel has no BTF"
		}
	}
	if why == "" {
		return
	}
	if os.Getenv("ZAAF_EBPF_REQUIRE") == "1" {
		t.Fatalf("live eBPF test required but cannot run: %s", why)
	}
	t.Skip(why)
}

// hasCap reports whether capability number c is in this process's
// effective set (/proc/self/status CapEff).
func hasCap(c uint) bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && n&(1<<c) != 0
		}
	}
	return false
}

// collector runs the source and keeps every event.
type collector struct {
	src  *Source
	mu   sync.Mutex
	evs  []*event.Event
	stop context.CancelFunc
	done chan error
	degr []string
}

func startSource(t *testing.T, cfg Config, events []string, buffer int) *collector {
	t.Helper()
	ready := make(chan struct{})
	cfg.OnReady = func() { close(ready) }
	cfg.Logf = t.Logf
	c := &collector{src: New(cfg), done: make(chan error, 1)}
	c.src.OnDegraded(func(cond, detail string) {
		c.mu.Lock()
		c.degr = append(c.degr, cond+": "+detail)
		c.mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	c.stop = cancel
	out := make(chan *event.Event, buffer)
	go func() { c.done <- c.src.Run(ctx, events, out) }()
	if buffer > 0 {
		go func() {
			for e := range out {
				c.mu.Lock()
				c.evs = append(c.evs, e)
				c.mu.Unlock()
			}
		}()
	}
	select {
	case <-ready:
	case err := <-c.done:
		t.Fatalf("source stopped before it was ready: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("source not ready after 30s")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-c.done:
			if err != nil && err != context.Canceled {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	return c
}

func (c *collector) waitFor(t *testing.T, what string, pred func(*event.Event) bool) *event.Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, e := range c.evs {
			if pred(e) {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s event within 10s", what)
	return nil
}

func statTicks(t *testing.T, pid int) uint64 {
	t.Helper()
	st, err := procfs.Default.Stat(int32(pid))
	if err != nil {
		t.Fatal(err)
	}
	return st.StartTicks
}

func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLiveProcessLifecycle(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, nil, 1<<16)
	sleep := lookPath(t, "sleep")
	cmd := exec.Command(sleep, "1.5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	ticks := statTicks(t, pid)
	_ = cmd.Wait()

	ex := c.waitFor(t, "CreateProcess", func(e *event.Event) bool {
		return e.Name == event.CreateProcess && e.Proc.PID == int32(pid)
	})
	p := ex.Proc
	if p.Exe != sleep || p.Name != filepath.Base(sleep) {
		t.Errorf("exe %q name %q, want %q", p.Exe, p.Name, sleep)
	}
	if strings.Join(p.Args, " ") != sleep+" 1.5" || p.Cmdline != sleep+" 1.5" {
		t.Errorf("args %q cmdline %q", p.Args, p.Cmdline)
	}
	if p.Parent == nil || p.Parent.PID != int32(os.Getpid()) || p.PPID != int32(os.Getpid()) {
		t.Errorf("parent %+v ppid %d, want %d", p.Parent, p.PPID, os.Getpid())
	}
	if p.UniqueID != ticks {
		t.Errorf("UniqueID %d, /proc start ticks %d", p.UniqueID, ticks)
	}
	bt, _ := procfs.Default.BootTime()
	if !p.StartTime.Equal(procfs.StartTime(bt, ticks)) {
		t.Errorf("StartTime %v, want %v", p.StartTime, procfs.StartTime(bt, ticks))
	}
	var fst unix.Stat_t
	if err := unix.Stat(sleep, &fst); err != nil {
		t.Fatal(err)
	}
	if p.ExeIno != fst.Ino || p.ExeDev != fst.Dev {
		t.Errorf("exe dev/ino %d/%d, stat %d/%d", p.ExeDev, p.ExeIno, fst.Dev, fst.Ino)
	}
	if p.ExeCtimeNs != fst.Ctim.Nano() {
		t.Errorf("exe ctime %d, stat %d", p.ExeCtimeNs, fst.Ctim.Nano())
	}
	if cwd, _ := os.Getwd(); p.Cwd != cwd {
		t.Errorf("cwd %q, want %q", p.Cwd, cwd)
	}
	if ex.Source != SourceName || ex.Platform != event.PlatformLinux {
		t.Errorf("source %q platform %q", ex.Source, ex.Platform)
	}
	if d := time.Since(ex.Time); d < 0 || d > time.Minute {
		t.Errorf("event time %v is %v from now", ex.Time, d)
	}
	f := c.waitFor(t, "Fork", func(e *event.Event) bool { return e.Name == event.Fork && e.Proc.PID == int32(pid) })
	if f.Proc.UniqueID != ticks || f.Proc.Parent == nil || f.Proc.Parent.PID != int32(os.Getpid()) {
		t.Errorf("fork %+v", f.Proc)
	}
	x := c.waitFor(t, "TerminateProcess", func(e *event.Event) bool {
		return e.Name == event.TerminateProcess && e.Proc.PID == int32(pid)
	})
	if x.Proc.Exe != sleep || x.Args[argExitStatus] != "0" {
		t.Errorf("exit exe %q status %q", x.Proc.Exe, x.Args[argExitStatus])
	}
}

// A process started by a thread other than the main one still gets its
// process (thread-group) id as parent: the v0.3 Sysmon finding.
func TestLiveParentIsThreadGroup(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, []string{event.CreateProcess}, 1<<16)
	sleep := lookPath(t, "sleep")
	pidc := make(chan int, 1)
	go func() {
		runtime.LockOSThread() // a thread that is not the group leader
		cmd := exec.Command(sleep, "0.2")
		if cmd.Start() == nil {
			pidc <- cmd.Process.Pid
			_ = cmd.Wait()
		} else {
			pidc <- 0
		}
	}()
	pid := <-pidc
	e := c.waitFor(t, "CreateProcess", func(e *event.Event) bool {
		return e.Name == event.CreateProcess && e.Proc.PID == int32(pid)
	})
	if e.Proc.PPID != int32(os.Getpid()) {
		t.Errorf("ppid %d, want the test's process %d", e.Proc.PPID, os.Getpid())
	}
}

func TestLiveFiles(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, nil, 1<<16)
	sh := lookPath(t, "sh")
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	script := "echo x > " + a + " && echo y > " + a + " && mv " + a + " " + b + " && cat " + b + " >/dev/null && rm " + b
	if out, err := exec.Command(sh, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	cr := c.waitFor(t, "CreateFile", func(e *event.Event) bool {
		return e.Name == event.CreateFile && e.File.Path == a && e.Args[argTruncated] == ""
	})
	if cr.Proc.Exe != sh {
		t.Errorf("CreateFile by %q, want %q", cr.Proc.Exe, sh)
	}
	c.waitFor(t, "CreateFile (truncate)", func(e *event.Event) bool {
		return e.Name == event.CreateFile && e.File.Path == a && e.Args[argTruncated] == "true"
	})
	mv := c.waitFor(t, "RenameFile", func(e *event.Event) bool { return e.Name == event.RenameFile && e.File.Path == a })
	if mv.File.Dest != b || mv.Proc.Name == "" {
		t.Errorf("rename %+v by %q", mv.File, mv.Proc.Exe)
	}
	c.waitFor(t, "OpenFile", func(e *event.Event) bool {
		return e.Name == event.OpenFile && e.File.Path == b && strings.HasSuffix(e.Proc.Exe, "/cat")
	})
	rm := c.waitFor(t, "DeleteFile", func(e *event.Event) bool { return e.Name == event.DeleteFile && e.File.Path == b })
	if !strings.HasSuffix(rm.Proc.Exe, "rm") {
		t.Errorf("DeleteFile by %q", rm.Proc.Exe)
	}

	// The sensor's own file activity is not reported.
	own := filepath.Join(dir, "own.txt")
	if err := os.WriteFile(own, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(sh, "-c", "true").Run(); err != nil { // a marker after it
		t.Fatal(err)
	}
	c.waitFor(t, "marker", func(e *event.Event) bool { return e.Name == event.TerminateProcess && e.Proc.Exe == sh })
	c.mu.Lock()
	for _, e := range c.evs {
		if e.File != nil && e.File.Path == own {
			t.Errorf("own file activity reported: %s %+v", e.Name, e.File)
		}
	}
	c.mu.Unlock()
}

// Without a rule for OpenFile, plain opens are filtered in the kernel and
// never reach the ring buffer, while creations still do.
func TestLiveOpenOnlyWhenSubscribed(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, []string{event.CreateFile, event.CreateProcess}, 1<<16)
	sh := lookPath(t, "sh")
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := exec.Command(sh, "-c", "echo x > "+f+" && cat "+f+" >/dev/null").Run(); err != nil {
		t.Fatal(err)
	}
	c.waitFor(t, "CreateFile", func(e *event.Event) bool { return e.Name == event.CreateFile && e.File.Path == f })
	// Counted before the Go-side subscription filter: zero means the
	// kernel never sent a plain open.
	if n := c.src.openSeen.Load(); n != 0 {
		t.Fatalf("%d OpenFile records reached user space without a subscription", n)
	}
}

func TestLiveSetUID(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, []string{event.SetUID}, 1<<16)
	setpriv := lookPath(t, "setpriv")
	tr := lookPath(t, "true")
	cmd := exec.Command(setpriv, "--reuid=65534", "--regid=65534", "--clear-groups", tr)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	e := c.waitFor(t, "SetUID", func(e *event.Event) bool {
		return e.Name == event.SetUID && e.Proc.PID == int32(cmd.Process.Pid)
	})
	if e.Args[argOldUID] != "0" || e.Args[argNewUID] != "65534" || e.Args[argNewEUID] != "65534" {
		t.Errorf("args %v", e.Args)
	}
	if e.Proc.Exe != setpriv {
		t.Errorf("exe %q", e.Proc.Exe)
	}
}

func TestLiveProcessAccess(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, []string{event.Ptrace, event.OpenProcess}, 1<<16)
	sleep := lookPath(t, "sleep")
	cmd := exec.Command(sleep, "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	ticks := statTicks(t, pid)

	// process_vm_readv of an address that is not mapped: the permission
	// check (and the event) happens before the copy fails.
	buf := make([]byte, 8)
	_, _ = unix.ProcessVMReadv(pid, []unix.Iovec{{Base: &buf[0], Len: 8}}, []unix.RemoteIovec{{Base: 0x1000, Len: 8}}, 0)
	vm := c.waitFor(t, "OpenProcess", func(e *event.Event) bool {
		return e.Name == event.OpenProcess && e.Target != nil && e.Target.PID == int32(pid)
	})
	if vm.Args[argSyscall] != "process_vm_readv" || vm.Target.Exe != sleep || vm.Target.UniqueID != ticks {
		t.Errorf("OpenProcess %v target %+v", vm.Args, vm.Target)
	}
	if vm.Proc.PID != int32(os.Getpid()) {
		t.Errorf("actor %d", vm.Proc.PID)
	}

	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := unix.PtraceAttach(pid); err != nil {
			done <- err
			return
		}
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, unix.WALL, nil)
		done <- unix.PtraceDetach(pid)
	}()
	if err := <-done; err != nil {
		t.Fatalf("ptrace: %v", err)
	}
	pt := c.waitFor(t, "Ptrace", func(e *event.Event) bool {
		return e.Name == event.Ptrace && e.Target != nil && e.Target.PID == int32(pid)
	})
	if pt.Args[argSyscall] != "ptrace_attach" || pt.Target.Exe != sleep {
		t.Errorf("Ptrace %v target %+v", pt.Args, pt.Target)
	}
}

func TestLiveTCP(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, []string{event.NetworkConnect, event.NetworkAccept}, 1<<16)
	for _, nw := range []struct{ network, addr string }{{"tcp4", "127.0.0.1:0"}, {"tcp6", "[::1]:0"}} {
		ln, err := net.Listen(nw.network, nw.addr)
		if err != nil {
			t.Logf("%s: %v (skipped)", nw.network, err)
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		go func() {
			if conn, err := ln.Accept(); err == nil {
				conn.Close()
			}
		}()
		conn, err := net.Dial(nw.network, ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cport := conn.LocalAddr().(*net.TCPAddr).Port
		ip := ln.Addr().(*net.TCPAddr).IP.String()
		out := c.waitFor(t, "NetworkConnect "+nw.network, func(e *event.Event) bool {
			return e.Name == event.NetworkConnect && e.Net.DstPort == uint16(port)
		})
		if out.Net.Proto != "tcp" || out.Net.Direction != "outbound" || out.Net.DstIP != ip || out.Net.SrcPort != uint16(cport) {
			t.Errorf("connect %+v (want dst %s:%d src port %d)", out.Net, ip, port, cport)
		}
		in := c.waitFor(t, "NetworkAccept "+nw.network, func(e *event.Event) bool {
			return e.Name == event.NetworkAccept && e.Net.DstPort == uint16(port)
		})
		if in.Net.Direction != "inbound" || in.Net.SrcPort != uint16(cport) || in.Net.SrcIP != ip {
			t.Errorf("accept %+v", in.Net)
		}
		conn.Close()
		ln.Close()
	}
}

func dnsQuery(name string, qtype uint16) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1)
}

func TestLiveDNS(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{}, []string{event.DNSQuery}, 1<<16)
	// Connected (destination taken from the socket) and unconnected
	// (destination in the message) sends, IPv4 and IPv6. Nothing needs to
	// listen: the query is seen as it is sent.
	conn, err := net.Dial("udp4", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(dnsQuery("Connected.ZAAF-test.example", 1))
	conn.Close()
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err == nil {
		_, _ = pc.WriteTo(dnsQuery("unconnected6.zaaf-test.example", 28), &net.UDPAddr{IP: net.IPv6loopback, Port: 53})
		pc.Close()
	}
	e := c.waitFor(t, "DNSQuery", func(e *event.Event) bool {
		return e.Name == event.DNSQuery && e.DNS.Query == "connected.zaaf-test.example"
	})
	if e.DNS.Type != "A" || e.Net.DstIP != "127.0.0.1" || e.Net.DstPort != 53 || e.Proc.PID != int32(os.Getpid()) {
		t.Errorf("dns %+v net %+v", e.DNS, e.Net)
	}
	if err == nil {
		e6 := c.waitFor(t, "DNSQuery v6", func(e *event.Event) bool {
			return e.Name == event.DNSQuery && e.DNS.Query == "unconnected6.zaaf-test.example"
		})
		if e6.DNS.Type != "AAAA" || e6.Net.DstIP != "::1" {
			t.Errorf("dns6 %+v net %+v", e6.DNS, e6.Net)
		}
	}
}

// TestLiveKernelModule loads and unloads one module named by
// ZAAF_EBPF_TEST_MODULE (set only on throw-away runners; it changes the
// running kernel).
func TestLiveKernelModule(t *testing.T) {
	needLive(t)
	mod := os.Getenv("ZAAF_EBPF_TEST_MODULE")
	if mod == "" {
		t.Skip("set ZAAF_EBPF_TEST_MODULE to a module that is safe to load (throw-away machines only)")
	}
	c := startSource(t, Config{}, []string{event.DriverLoad}, 1<<16)
	// Not lookPath: modprobe is a link to kmod, which dispatches on the
	// name it is run as.
	modprobe, err := exec.LookPath("modprobe")
	if err != nil {
		t.Skip("modprobe not installed")
	}
	if out, err := exec.Command(modprobe, mod).CombinedOutput(); err != nil {
		t.Fatalf("modprobe %s: %v: %s", mod, err, out)
	}
	defer exec.Command(modprobe, "-r", mod).Run()
	e := c.waitFor(t, "DriverLoad", func(e *event.Event) bool { return e.Name == event.DriverLoad && e.Args[argModuleName] == mod })
	if e.Args[argModuleSource] != "file" || !strings.Contains(e.Module.Path, "/"+mod+".ko") {
		t.Errorf("module %+v args %v", e.Module, e.Args)
	}
}

// A ring buffer that is too small for a burst while the reader is stalled
// loses records in the kernel; the loss is counted and reported.
func TestLiveDropsAreCounted(t *testing.T) {
	needLive(t)
	c := startSource(t, Config{RingBytes: 4096}, nil, 0) // unbuffered, never read: the reader stalls
	tr := lookPath(t, "true")
	for i := 0; i < 200; i++ {
		_ = exec.Command(tr).Run()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.src.Stats()["events_missed"] == 0 {
		time.Sleep(100 * time.Millisecond)
	}
	if st := c.src.Stats(); st["events_missed"] == 0 || st["seq_gaps"] == 0 {
		t.Fatalf("no drops counted: %v", st)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.degr) == 0 || !strings.HasPrefix(c.degr[0], CondEventsDropped+": the kernel ring buffer was full") {
		t.Fatalf("SensorDegraded reports %q", c.degr)
	}
}

// procImage refuses a pid whose start time is not the one asked for.
func TestProcImageChecksStartTime(t *testing.T) {
	pid := int32(os.Getpid())
	st, err := procfs.Default.Stat(pid)
	if err != nil {
		t.Skip(err)
	}
	img, ok := procImage(pid, st.StartTicks)
	if !ok {
		t.Fatal("own process not found")
	}
	if exe, _ := os.Executable(); img.exe != exe {
		t.Errorf("exe %q, want %q", img.exe, exe)
	}
	if _, ok := procImage(pid, st.StartTicks+1); ok {
		t.Error("image returned for a different start time")
	}
}
