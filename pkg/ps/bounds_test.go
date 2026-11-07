package ps

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/eslogger"
)

func TestByteBudgetEvictsExitedFirst(t *testing.T) {
	s := testSnap(MaxEntries)
	s.maxBytes = 64 << 10
	seed(s)
	big := func(pid int32) *event.Proc {
		p := proc(pid, 200, uint32(pid), "/bin/big")
		p.Args = []string{strings.Repeat("x", 10<<10)}
		return p
	}
	s.Enrich(ev(event.CreateProcess, 1, big(500)))
	s.Enrich(ev(event.CreateProcess, 1, big(501)))
	s.Enrich(ev(event.TerminateProcess, 2, big(501)))
	s.Enrich(ev(event.CreateProcess, 2, big(502)))
	// Push over the budget: 501 (exited) must go before any live one.
	for i := int32(600); s.Stats()["evictions"] == 0; i++ {
		s.Enrich(ev(event.CreateProcess, 3, big(i)))
	}
	if _, ok := s.Lookup(501); ok {
		t.Error("exited entry survived the first eviction")
	}
	for _, pid := range []int32{1, 100, 200, 500, 502} {
		if _, ok := s.Lookup(pid); !ok {
			t.Errorf("live pid %d evicted before the exited one", pid)
		}
	}
	// Keep going: oldest live entries go next, launchd never.
	for i := int32(700); i < 760; i++ {
		s.Enrich(ev(event.CreateProcess, 4, big(i)))
	}
	if st := s.Stats(); int64(st["bytes"]) > s.maxBytes {
		t.Errorf("bytes %d over budget %d", st["bytes"], s.maxBytes)
	}
	if _, ok := s.Lookup(500); ok {
		t.Error("oldest live entry not evicted")
	}
	if _, ok := s.Lookup(1); !ok {
		t.Error("launchd evicted")
	}
}

// TestBytesAccountingConsistent recomputes the byte total from scratch after
// a mixed workload.
func TestBytesAccountingConsistent(t *testing.T) {
	s := testSnap(64)
	s.maxBytes = 32 << 10
	seed(s)
	for i := int32(0); i < 500; i++ {
		pid := 1000 + i%90
		p := proc(pid, 200, uint32(i), "/bin/w")
		p.Args = []string{strings.Repeat("a", int(i%7)*300)}
		switch i % 4 {
		case 0:
			s.Enrich(ev(event.CreateProcess, int(i), p))
		case 1:
			s.Enrich(ev(event.OpenFile, int(i), p))
		case 2:
			s.Enrich(ev(event.TerminateProcess, int(i), p))
		case 3:
			s.Enrich(ev(event.Fork, int(i), p))
		}
	}
	var sum int64
	n := 0
	for _, en := range s.procs {
		if en.size != procSize(&en.proc) {
			t.Fatalf("stale size for pid %d", en.proc.PID)
		}
		sum += en.size
		n++
	}
	if sum != s.bytes || n != s.live.Len()+s.dead.Len() {
		t.Fatalf("bytes %d vs %d, lists %d+%d vs %d", s.bytes, sum, s.live.Len(), s.dead.Len(), n)
	}
	if len(s.procs) > 64 || s.bytes > s.maxBytes {
		t.Fatalf("bounds: %d entries, %d bytes", len(s.procs), s.bytes)
	}
}

// TestEvictionIsCheap: at the entry cap every insert evicts; with the
// linked lists that stays far from O(n) per insert.
func TestEvictionIsCheap(t *testing.T) {
	s := testSnap(MaxEntries)
	for i := int32(2); i < MaxEntries+2; i++ {
		s.Enrich(ev(event.CreateProcess, 0, &event.Proc{PID: i, PPID: 1, PIDVersion: 1, Exe: "/bin/c"}))
	}
	start := time.Now()
	const extra = 200_000
	for i := int32(0); i < extra; i++ {
		s.Enrich(ev(event.CreateProcess, 0, &event.Proc{PID: 100_000 + i, PPID: 1, PIDVersion: 1, Exe: "/bin/c"}))
	}
	d := time.Since(start)
	if s.Len() != MaxEntries {
		t.Fatalf("len %d", s.Len())
	}
	t.Logf("%d inserts at the cap took %s (%s each)", extra, d, d/extra)
	if d > 10*time.Second { // O(n) eviction would be ~65536x slower per insert
		t.Fatalf("eviction too slow: %s", d)
	}
}

func TestBootstrapUnverified(t *testing.T) {
	s := testSnap(MaxEntries)
	s.seed(event.Proc{PID: 1, Exe: "/sbin/launchd"})
	s.seed(event.Proc{PID: 50, PPID: 1, Exe: "/usr/libexec/sshd-session", Args: []string{"sshd: alice"}, Cmdline: "sshd: alice"})
	// An event of the seeded process is flagged.
	e := ev(event.OpenFile, 1, &event.Proc{PID: 50, PPID: 1, PIDVersion: 5, Exe: "/usr/libexec/sshd-session"})
	s.Enrich(e)
	if e.Args[ArgIdentity] != Unverified || e.Args[ArgParentIdentity] != Unverified {
		t.Fatalf("args %v", e.Args)
	}
	// Its fork inherits the procargs2 details, so the child is unverified too.
	c := &event.Proc{PID: 51, PPID: 50, PIDVersion: 51, Exe: "/usr/libexec/sshd-session", Parent: &event.Proc{PID: 50, PIDVersion: 5}}
	f := ev(event.Fork, 2, c)
	s.Enrich(f)
	if f.Args[ArgIdentity] != Unverified || c.Cmdline != "sshd: alice" {
		t.Fatalf("fork: args %v cmdline %q", f.Args, c.Cmdline)
	}
	// A target that is a seeded process is flagged as such.
	g := ev(event.OpenProcess, 3, &event.Proc{PID: 900, PPID: 1, PIDVersion: 900, Exe: "/tmp/x"})
	g.Target = &event.Proc{PID: 50, PIDVersion: 5, Exe: "/usr/libexec/sshd-session"}
	s.Enrich(g)
	if g.Args[ArgTargetIdentity] != Unverified || g.Args[ArgIdentity] != "" {
		t.Fatalf("target: %v", g.Args)
	}
	// exec from ES replaces the image: verified from then on.
	x := ev(event.CreateProcess, 4, &event.Proc{PID: 51, PPID: 50, PIDVersion: 52, Exe: "/bin/zsh", Args: []string{"-zsh"}})
	s.Enrich(x)
	if x.Args[ArgIdentity] != "" {
		t.Fatalf("exec still unverified: %v", x.Args)
	}
	y := ev(event.OpenFile, 5, &event.Proc{PID: 51, PPID: 50, PIDVersion: 52, Exe: "/bin/zsh"})
	s.Enrich(y)
	if y.Args[ArgIdentity] != "" || y.Args[ArgParentIdentity] != Unverified {
		t.Fatalf("after exec: %v", y.Args)
	}
	// An ES event showing a different image than procargs2 claimed resets it.
	z := ev(event.OpenFile, 6, &event.Proc{PID: 50, PIDVersion: 5, Exe: "/usr/bin/other"})
	s.Enrich(z)
	if z.Args[ArgIdentity] != "" || z.Proc.Cmdline != "" {
		t.Fatalf("image change kept unverified details: %v %q", z.Args, z.Proc.Cmdline)
	}
}

func TestProcArgsBudgets(t *testing.T) {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = append(b, "/bin/x\x00"...)
	b = append(b, strings.Repeat("A", 1<<20)+"\x00"...) // 1 MiB argv[0]
	b = append(b, "two\x00three\x00"...)
	for i := 0; i < 100; i++ {
		b = append(b, fmt.Sprintf("K%d=%s\x00", i, strings.Repeat("v", 1000))...)
	}
	exe, args, env := parseProcArgs(b)
	total := 0
	for _, a := range args {
		total += len(a)
	}
	if exe != "/bin/x" || len(args) != 1 || total != bootArgsBudget {
		t.Errorf("args: n=%d total=%d", len(args), total)
	}
	envBytes := 0
	for k, v := range env {
		envBytes += len(k) + len(v)
	}
	if envBytes > bootEnvBudget || len(env) == 0 {
		t.Errorf("env bytes %d (n=%d)", envBytes, len(env))
	}
}

// TestHeapBoundedUnderHugeExecArgs: 2 000 execs with a 1 MiB argument each,
// decoded by the eslogger decoder and kept by the snapshotter, must not
// retain more than the table's byte budget.
func TestHeapBoundedUnderHugeExecArgs(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~2 GB in total")
	}
	arg := strings.Repeat("A", 1<<20)
	mkLine := func(pid int) []byte {
		return []byte(fmt.Sprintf(`{"time":"2026-11-07T08:00:00Z","event_type":9,"process":{"audit_token":{"pid":1,"pidversion":1},"executable":{"path":"/sbin/launchd"}},`+
			`"event":{"exec":{"target":{"audit_token":{"pid":%d,"pidversion":%d},"ppid":1,"executable":{"path":"/tmp/x"}},"args":["x","%s"],"env":["BIG=%s"]}}}`, pid, pid, arg, arg))
	}
	s := newSnapshotter(MaxEntries, MaxBytes)
	s.lookupUser = func(int64) string { return "" }
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	truncated := 0
	for i := 0; i < 2000; i++ {
		e, ok, err := eslogger.Decode(mkLine(1000 + i))
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		if e.Args["args_truncated"] == "true" && e.Args["env_truncated"] == "true" {
			truncated++
		}
		s.Enrich(e)
	}
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	st := s.Stats()
	t.Logf("2000 execs x 1 MiB args: heap retained %.1f MiB, table %d entries, %.1f MiB accounted, %d evictions, budget %d MiB",
		float64(retained)/(1<<20), st["entries"], float64(st["bytes"])/(1<<20), st["evictions"], MaxBytes>>20)
	if truncated != 2000 {
		t.Errorf("truncation marker on %d of 2000", truncated)
	}
	if int64(st["bytes"]) > MaxBytes {
		t.Errorf("accounted bytes over budget")
	}
	if retained > MaxBytes {
		t.Errorf("retained %d bytes, budget %d", retained, MaxBytes)
	}
	runtime.KeepAlive(s)
}
