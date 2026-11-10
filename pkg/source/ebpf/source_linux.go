//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
)

// kernelBTF is where the running kernel describes its own types. The
// source refuses to start without it rather than let the loader fall back
// to a vmlinux file on disk that may not match the running kernel.
const kernelBTF = "/sys/kernel/btf/vmlinux"

// DefaultRingBytes is the ring buffer size (power of two, page multiple).
const DefaultRingBytes = 8 << 20

// Config configures the source.
type Config struct {
	// Logf receives operational messages (skipped hooks). Nil discards them.
	Logf func(format string, args ...any)
	// RingBytes overrides DefaultRingBytes.
	RingBytes uint32
	// OnReady, if set, is called once the programs are attached.
	OnReady func()
}

// Source is the eBPF event source. Create it with New; Run once.
type Source struct {
	cfg Config
	rep *reporter

	received, decoded, decodeErrors, filtered, sent atomic.Uint64
	// eventsMissed counts records the kernel could not add to the full ring
	// buffer; seqGaps counts the polls (one a second) in which that rose.
	// The names match the other sources' lost-event counters.
	eventsMissed, seqGaps atomic.Uint64
	recursionMisses       atomic.Uint64 // programs the kernel skipped (their sum, last poll)
	openSeen              atomic.Uint64 // OpenFile records, before the subscription filter
	m                     atomic.Pointer[mapper]
}

// New returns a source.
func New(cfg Config) *Source {
	if cfg.RingBytes == 0 {
		cfg.RingBytes = DefaultRingBytes
	}
	return &Source{cfg: cfg, rep: newReporter()}
}

// Name implements source.Source.
func (s *Source) Name() string { return SourceName }

// OnDegraded registers fn for CondEventsDropped and CondEventsUnreadable.
func (s *Source) OnDegraded(fn func(condition, detail string)) { s.rep.set(fn) }

// Stats implements source.Source.
func (s *Source) Stats() map[string]uint64 {
	st := map[string]uint64{
		"received": s.received.Load(), "decoded": s.decoded.Load(), "decode_errors": s.decodeErrors.Load(),
		"filtered": s.filtered.Load(), "sent": s.sent.Load(),
		"events_missed": s.eventsMissed.Load(), "seq_gaps": s.seqGaps.Load(),
		"recursion_misses": s.recursionMisses.Load(),
	}
	if m := s.m.Load(); m != nil {
		st["image_cache_evicted"] = m.evicted.Load()
		st["proc_lookups"] = m.lookups.Load()
		st["proc_lookup_misses"] = m.lookupMisses.Load()
		st["dns_unparsed"] = m.dnsUnparsed.Load()
		st["args_incomplete"] = m.argsIncomplete.Load()
	}
	return st
}

func (s *Source) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// ErrUnavailable wraps every reason the kernel programs cannot run here;
// the message ends with the alternative (--source sysmon).
var ErrUnavailable = errors.New("the eBPF source cannot run on this system")

func unavailable(why string, args ...any) error {
	return fmt.Errorf("%w: %s; use --source sysmon (Sysmon for Linux) instead", ErrUnavailable, fmt.Sprintf(why, args...))
}

// loaded is what Run attached; close releases it. Nothing is pinned to
// bpffs, so closing (or the process exiting) detaches every program.
type loaded struct {
	coll  *ebpf.Collection
	links []link.Link
}

func (l *loaded) close() {
	for _, k := range l.links {
		k.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
}

// load loads and attaches the groups the subscription needs. An optional
// group whose program the kernel refuses, or whose hook does not exist, is
// left out with a warning.
func (s *Source) load(events []string) (*loaded, []string, error) {
	if _, err := os.Stat(kernelBTF); err != nil {
		return nil, nil, unavailable("the kernel has no BTF type information (%s is missing; it needs CONFIG_DEBUG_INFO_BTF, standard on Ubuntu 20.10+, Debian 11+, RHEL 8.2+)", kernelBTF)
	}
	if nested, err := inChildPIDNamespace(); err == nil && nested {
		return nil, nil, unavailable("ZAAFVesper runs in a child PID namespace (a container); the kernel reports host process ids, so it must run in the host's PID namespace")
	}
	use, wantOpen := plan(events)
	cache := btf.NewCache()
	var skipped []string
	for attempt := 0; attempt <= len(use); attempt++ {
		spec, err := loadZaaf()
		if err != nil {
			return nil, nil, fmt.Errorf("embedded eBPF objects: %w", err)
		}
		if err := spec.Variables["self_tgid"].Set(uint32(os.Getpid())); err != nil {
			return nil, nil, err
		}
		open := uint32(0)
		if wantOpen {
			open = 1
		}
		if err := spec.Variables["want_open"].Set(open); err != nil {
			return nil, nil, err
		}
		spec.Maps["events"].MaxEntries = s.cfg.RingBytes
		keep := map[string]bool{}
		for _, g := range use {
			for _, p := range g.programs {
				keep[p] = true
			}
		}
		for name := range spec.Programs {
			if !keep[name] {
				delete(spec.Programs, name)
			}
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Cache: cache})
		if errors.Is(err, unix.EPERM) {
			return nil, nil, unavailable("the kernel refused to load eBPF programs: permission denied; %s", requirements)
		}
		if err != nil {
			g, ok := failedGroup(use, err)
			if !ok || g.required {
				return nil, nil, unavailable("%s", refusedMessage(shortErr(err)))
			}
			s.logf("eBPF: %s events unavailable on this kernel (%v)", g.name, shortErr(err))
			skipped = append(skipped, g.name)
			use = without(use, g.name)
			continue
		}
		l := &loaded{coll: coll}
		for _, g := range use {
			links, err := attachGroup(coll, spec, g)
			if err != nil {
				for _, k := range links {
					k.Close()
				}
				if g.required {
					l.close()
					return nil, nil, unavailable("cannot attach the %s programs: %v; %s", g.name, shortErr(err), requirements)
				}
				s.logf("eBPF: %s events unavailable on this kernel (%v)", g.name, shortErr(err))
				skipped = append(skipped, g.name)
				continue
			}
			l.links = append(l.links, links...)
		}
		return l, skipped, nil
	}
	return nil, nil, unavailable("no set of programs loaded")
}

func without(gs []group, name string) []group {
	var out []group
	for _, g := range gs {
		if g.name != name {
			out = append(out, g)
		}
	}
	return out
}

// failedGroup finds the group whose program the loader error names
// (cilium/ebpf wraps load errors as "program <name>: ...").
func failedGroup(use []group, err error) (group, bool) {
	msg := err.Error()
	for _, g := range use {
		for _, p := range g.programs {
			if strings.Contains(msg, "program "+p+":") || strings.Contains(msg, "program "+p+" ") {
				return g, true
			}
		}
	}
	return group{}, false
}

// shortErr keeps an error to one line (verifier logs are long).
func shortErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func attachGroup(coll *ebpf.Collection, spec *ebpf.CollectionSpec, g group) ([]link.Link, error) {
	var links []link.Link
	for _, name := range g.programs {
		prog := coll.Programs[name]
		ps := spec.Programs[name]
		if prog == nil || ps == nil {
			return links, fmt.Errorf("program %s missing", name)
		}
		var (
			k   link.Link
			err error
		)
		switch ps.Type {
		case ebpf.Tracing:
			k, err = link.AttachTracing(link.TracingOptions{Program: prog})
		case ebpf.TracePoint:
			// Section "tracepoint/<group>/<name>".
			parts := strings.Split(ps.SectionName, "/")
			if len(parts) != 3 {
				return links, fmt.Errorf("program %s: unexpected section %q", name, ps.SectionName)
			}
			k, err = link.Tracepoint(parts[1], parts[2], prog, nil)
		default:
			return links, fmt.Errorf("program %s: unexpected type %v", name, ps.Type)
		}
		if err != nil {
			return links, fmt.Errorf("program %s: %w", name, err)
		}
		links = append(links, k)
	}
	return links, nil
}

// inChildPIDNamespace reports whether this process sees itself under more
// than one pid (the NSpid line of /proc/self/status lists one per nested
// PID namespace).
func inChildPIDNamespace() (bool, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "NSpid:"); ok {
			return len(strings.Fields(rest)) > 1, nil
		}
	}
	return false, nil
}

// systemClock reads the clocks the mapper needs.
func systemClock() (clock, error) {
	var rt, bt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &rt); err != nil {
		return clock{}, err
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt); err != nil {
		return clock{}, err
	}
	btime, err := procfs.Default.BootTime()
	if err != nil {
		return clock{}, err
	}
	return clock{bootWallNs: rt.Nano() - bt.Nano(), btime: btime}, nil
}

// ownMntNS returns the inode number of the sensor's own mount namespace
// ("mnt:[4026531841]" in /proc/self/ns/mnt), 0 when it cannot be read.
func ownMntNS() uint32 {
	l, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "mnt:["), "]"), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// procImage reads a running process's executable from /proc, only if the
// process at pid has the given start ticks before and after the read (so a
// recycled pid is never described with another process's image).
func procImage(pid int32, ticks uint64) (image, bool) {
	st, err := procfs.Default.Stat(pid)
	if err != nil || st.StartTicks != ticks {
		return image{}, false
	}
	exe, _, err := procfs.Default.Exe(pid)
	if err != nil || exe == "" {
		return image{}, false
	}
	img := image{exe: exe}
	var fst unix.Stat_t
	if unix.Stat("/proc/"+strconv.Itoa(int(pid))+"/exe", &fst) == nil {
		img.dev, img.ino = fst.Dev, fst.Ino
		img.ctimeNs = fst.Ctim.Nano()
	}
	if st2, err := procfs.Default.Stat(pid); err != nil || st2.StartTicks != ticks {
		return image{}, false
	}
	return img, true
}

// Run implements source.Source.
func (s *Source) Run(ctx context.Context, events []string, out chan<- *event.Event) error {
	clk, err := systemClock()
	if err != nil {
		return fmt.Errorf("eBPF source clocks: %w", err)
	}
	l, skipped, err := s.load(events)
	if err != nil {
		return err
	}
	defer l.close()
	if len(skipped) > 0 {
		s.logf("eBPF: running without: %s", strings.Join(skipped, ", "))
	}
	rd, err := ringbuf.NewReader(l.coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("eBPF ring buffer: %w", err)
	}
	m := newMapper(clk, procImage)
	m.hostMntNS = ownMntNS()
	s.m.Store(m)
	if s.cfg.OnReady != nil {
		s.cfg.OnReady()
	}

	var wanted map[string]bool
	if events != nil {
		wanted = map[string]bool{}
		for _, n := range events {
			wanted[n] = true
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // Close interrupts the blocking read below.
		defer wg.Done()
		<-runCtx.Done()
		rd.Close()
	}()
	go func() {
		defer wg.Done()
		s.pollDrops(runCtx, l.coll.Maps["drops"], l.coll.Programs)
	}()
	defer wg.Wait()
	defer cancel()

	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("eBPF ring buffer read: %w", err)
		}
		if err := s.handle(ctx, m, rec.RawSample, wanted, out); err != nil {
			return err
		}
	}
}

// handle decodes and sends one record. Sending blocks when the pipeline is
// slow: the kernel side then finds the ring buffer full and counts the
// records it could not add (CondEventsDropped), so nothing is lost
// without a count.
func (s *Source) handle(ctx context.Context, m *mapper, raw []byte, wanted map[string]bool, out chan<- *event.Event) error {
	s.received.Add(1)
	r, err := parseRecord(raw)
	var e *event.Event
	if err == nil {
		e, err = m.mapRecord(r)
	}
	if err != nil {
		n := s.decodeErrors.Add(1)
		s.rep.report(CondEventsUnreadable, fmt.Sprintf("an eBPF record could not be decoded and was not evaluated (%v); %d in total", err, n))
		return nil
	}
	if e == nil {
		s.filtered.Add(1)
		return nil
	}
	s.decoded.Add(1)
	if e.Name == event.OpenFile {
		s.openSeen.Add(1)
	}
	if wanted != nil && !wanted[e.Name] {
		s.filtered.Add(1)
		return nil
	}
	select {
	case out <- e:
		s.sent.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// pollDrops reads the kernel's per-CPU drop counters once a second.
func (s *Source) pollDrops(ctx context.Context, drops *ebpf.Map, progs map[string]*ebpf.Program) {
	var tr dropTracker
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		var now [nSlots]uint64
		for k := uint32(1); k < kindMax; k++ {
			var perCPU []uint64
			if err := drops.Lookup(k, &perCPU); err != nil {
				continue
			}
			for _, v := range perCPU {
				now[k] += v
			}
		}
		// Programs the kernel did not run because another BPF program was
		// already running on the CPU leave no record and no drop count of
		// their own; the kernel keeps a counter per program.
		for _, p := range progs {
			if st, err := p.Stats(); err == nil {
				now[slotMisses] += st.RecursionMisses
			}
		}
		s.recursionMisses.Store(now[slotMisses])
		if n, detail := tr.update(now); n > 0 {
			s.eventsMissed.Add(n)
			s.seqGaps.Add(1)
			s.rep.report(CondEventsDropped, detail)
		}
	}
}
