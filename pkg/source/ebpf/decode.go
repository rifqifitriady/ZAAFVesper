package ebpf

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
)

// SourceName is evt.source for events from this source.
const SourceName = "ebpf"

// evt.arg keys set by this source. exit_status and args_truncated have the
// meaning they have for eslogger; the SetUID keys are part of the contract
// (pkg/event); the others are specific to this source.
const (
	argExitStatus     = "exit_status"
	argArgsTruncated  = "args_truncated"
	argPathIncomplete = "path_incomplete"
	argTruncated      = "truncated"
	argSyscall        = "syscall"
	argModuleName     = "module_name"
	argModuleSource   = "module_source"
	argOldUID         = "old_uid"
	argOldEUID        = "old_euid"
	argNewUID         = "new_uid"
	argNewEUID        = "new_euid"
)

// image is what a process runs: its executable and the file's identity.
type image struct {
	exe      string
	dev, ino uint64
	ctimeNs  int64
}

// procKey names one process: a pid and its start time in clock ticks,
// which together never repeat within a boot.
type procKey struct {
	pid   int32
	ticks uint64
}

// clock converts the kernel's boot-relative times.
type clock struct {
	// bootWallNs is the wall-clock time of boot in Unix nanoseconds
	// (CLOCK_REALTIME minus CLOCK_BOOTTIME), for event times.
	bootWallNs int64
	// btime is /proc/stat's btime (seconds). Process start times are
	// computed from it exactly as the responder computes them
	// (procfs.StartTime), so the two always agree.
	btime int64
}

// defaultMaxImages bounds the image cache. A busy server has a few
// thousand processes; when the cache is full one entry is dropped and
// counted, and that process's later events fall back to /proc.
const defaultMaxImages = 1 << 16

// mapper turns records into canonical events. Only records carry the
// executable of a process at exec, so the mapper remembers each live
// process's image (filled by exec, copied to children at fork, dropped at
// exit) and puts it on every later event of that process: rules match
// ps.exe on file and network events too. A process that started before
// the sensor is looked up once in /proc (lookup), checked against its
// start time. It runs on the one reading goroutine; it is not locked.
type mapper struct {
	clk       clock
	images    map[procKey]image
	maxImages int
	// lookup reads a process's image from /proc when the cache has none;
	// it must return false unless the process at pid has exactly the
	// start ticks given. Nil: no fallback (tests).
	lookup func(pid int32, ticks uint64) (image, bool)

	evicted, lookups, lookupMisses atomic.Uint64 // read by Stats
}

func newMapper(clk clock, lookup func(int32, uint64) (image, bool)) *mapper {
	return &mapper{clk: clk, images: map[procKey]image{}, maxImages: defaultMaxImages, lookup: lookup}
}

// ticksOf converts nanoseconds since boot to the clock ticks of
// /proc/<pid>/stat field 22 (the kernel's nsec_to_clock_t).
func ticksOf(ns uint64) uint64 { return ns / uint64(time.Second/procfs.UserHZ) }

// pidVersion distinguishes incarnations of a pid in the process table
// (pkg/ps): derived from the start ticks, never 0 (0 means "unknown").
func pidVersion(ticks uint64) uint32 {
	v := uint32(ticks) + 1
	if v == 0 {
		v = 1
	}
	return v
}

// userDev converts a kernel dev_t (MAJOR<<20 | MINOR) to the encoding
// stat(2) returns (new_encode_dev), which is what ExeDev is compared with.
func userDev(k uint32) uint64 {
	major, minor := uint64(k>>20), uint64(k&0xfffff)
	return (minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12)
}

func (m *mapper) remember(k procKey, img image) {
	if _, ok := m.images[k]; !ok && len(m.images) >= m.maxImages {
		for old := range m.images {
			delete(m.images, old)
			m.evicted.Add(1)
			break
		}
	}
	m.images[k] = img
}

func (m *mapper) image(k procKey) (image, bool) {
	if img, ok := m.images[k]; ok {
		return img, true
	}
	if m.lookup == nil || k.pid <= 0 {
		return image{}, false
	}
	m.lookups.Add(1)
	img, ok := m.lookup(k.pid, k.ticks)
	if !ok {
		m.lookupMisses.Add(1)
		return image{}, false
	}
	m.remember(k, img)
	return img, true
}

func (m *mapper) startTime(ticks uint64) time.Time {
	if m.clk.btime == 0 {
		return time.Time{}
	}
	return procfs.StartTime(m.clk.btime, ticks)
}

func applyImage(p *event.Proc, img image) {
	if img.exe == "" {
		return
	}
	p.Exe, p.Name = img.exe, filepath.Base(img.exe)
	p.ExeDev, p.ExeIno, p.ExeCtimeNs = img.dev, img.ino, img.ctimeNs
}

// proc describes the record's process (the acting process; for fork, the
// child), with a parent stub the process table resolves.
func (m *mapper) proc(h *header) (*event.Proc, procKey) {
	ticks := ticksOf(h.StartNs)
	p := &event.Proc{
		PID: int32(h.PID), PPID: int32(h.PPID), UID: int64(h.UID), EUID: int64(h.EUID),
		UniqueID: ticks, PIDVersion: pidVersion(ticks), StartTime: m.startTime(ticks), Name: h.Comm,
	}
	if h.PPID != 0 {
		p.Parent = &event.Proc{PID: int32(h.PPID), PIDVersion: pidVersion(ticksOf(h.PStartNs)), UID: -1, EUID: -1}
	}
	return p, procKey{p.PID, ticks}
}

func setArg(e *event.Event, k, v string) {
	if e.Args == nil {
		e.Args = map[string]string{}
	}
	e.Args[k] = v
}

// splitArgs splits the kernel's argv area (NUL-separated, NUL-terminated).
func splitArgs(s string) []string {
	s = strings.TrimSuffix(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// mapRecord decodes one record. It returns (nil, nil) for a record that
// yields no event (a DNS datagram that is not a query).
func (m *mapper) mapRecord(r *record) (*event.Event, error) {
	e := &event.Event{
		Time:     time.Unix(0, m.clk.bootWallNs+int64(r.KTime)).UTC(),
		Source:   SourceName,
		Platform: event.PlatformLinux,
	}
	p, key := m.proc(&r.header)
	e.Proc = p
	b := r.body

	switch r.Kind {
	case kindExec:
		eflags := le32(b, 4)
		s, err := r.strings(execSize, le32(b, 24), le32(b, 28), le32(b, 32))
		if err != nil {
			return nil, err
		}
		img := image{exe: s[0], dev: userDev(le32(b, 0)), ino: le64(b, 8), ctimeNs: int64(le64(b, 16))}
		m.remember(key, img)
		applyImage(p, img)
		e.Name = event.CreateProcess
		p.Args = splitArgs(s[1])
		p.Cmdline = strings.Join(p.Args, " ")
		p.Cwd = s[2]
		if eflags&(flArgsTrunc|flArgsErr) != 0 {
			setArg(e, argArgsTruncated, "true")
		}
		if eflags&(flPathTrunc|flPath2Trunc) != 0 {
			setArg(e, argPathIncomplete, "true")
		}

	case kindExit:
		if img, ok := m.image(key); ok {
			applyImage(p, img)
		}
		delete(m.images, key)
		e.Name = event.TerminateProcess
		setArg(e, argExitStatus, strconv.FormatUint(uint64(le32(b, 0)), 10))
		if _, err := r.strings(exitSize); err != nil {
			return nil, err
		}

	case kindFork:
		if _, err := r.strings(0); err != nil {
			return nil, err
		}
		// The child runs its parent's image until it execs.
		if img, ok := m.image(procKey{int32(r.PPID), ticksOf(r.PStartNs)}); ok {
			m.remember(key, img)
			applyImage(p, img)
		}
		e.Name = event.Fork

	case kindFile:
		op, fflags := le32(b, 0), le32(b, 20)
		s, err := r.strings(fileSize, le32(b, 12), le32(b, 16))
		if err != nil {
			return nil, err
		}
		m.fill(p, key)
		e.File = &event.File{Path: s[0]}
		switch op {
		case fileOpen:
			e.Name = event.OpenFile
		case fileCreate:
			e.Name = event.CreateFile
			if fflags&flTruncated != 0 {
				setArg(e, argTruncated, "true")
			}
		case fileUnlink:
			e.Name = event.DeleteFile
		case fileRename:
			e.Name = event.RenameFile
			e.File.Dest = s[1]
		default:
			return nil, fmt.Errorf("%w: file operation %d", errRecord, op)
		}
		if fflags&(flPathTrunc|flPath2Trunc) != 0 {
			setArg(e, argPathIncomplete, "true")
		}

	case kindSetUID:
		if _, err := r.strings(setuidSize); err != nil {
			return nil, err
		}
		m.fill(p, key)
		e.Name = event.SetUID
		setArg(e, argOldUID, strconv.FormatUint(uint64(le32(b, 0)), 10))
		setArg(e, argOldEUID, strconv.FormatUint(uint64(le32(b, 4)), 10))
		setArg(e, argNewUID, strconv.FormatUint(uint64(le32(b, 8)), 10))
		setArg(e, argNewEUID, strconv.FormatUint(uint64(le32(b, 12)), 10))

	case kindProcAcc:
		sc, req, tflags := le32(b, 0), le32(b, 4), le32(b, 12)
		s, err := r.strings(procAccSize, le32(b, 24))
		if err != nil {
			return nil, err
		}
		m.fill(p, key)
		tticks := ticksOf(le64(b, 16))
		t := &event.Proc{PID: int32(le32(b, 8)), UniqueID: tticks, PIDVersion: pidVersion(tticks),
			StartTime: m.startTime(tticks), UID: -1, EUID: -1}
		if s[0] != "" {
			applyImage(t, image{exe: s[0]})
		} else if img, ok := m.image(procKey{t.PID, tticks}); ok {
			applyImage(t, img)
		}
		e.Target = t
		switch {
		case sc == sysPtrace && req == ptraceAttach:
			e.Name = event.Ptrace
			setArg(e, argSyscall, "ptrace_attach")
		case sc == sysPtrace && req == ptraceSeize:
			e.Name = event.Ptrace
			setArg(e, argSyscall, "ptrace_seize")
		case sc == sysVMReadv:
			e.Name = event.OpenProcess
			setArg(e, argSyscall, "process_vm_readv")
		case sc == sysVMWritev:
			e.Name = event.OpenProcess
			setArg(e, argSyscall, "process_vm_writev")
		default:
			return nil, fmt.Errorf("%w: process access syscall %d request %d", errRecord, sc, req)
		}
		if tflags&flPathTrunc != 0 {
			setArg(e, argPathIncomplete, "true")
		}

	case kindModule:
		src := le32(b, 0)
		s, err := r.strings(moduleSize, le32(b, 4))
		if err != nil {
			return nil, err
		}
		m.fill(p, key)
		e.Name = event.DriverLoad
		e.Module = &event.Module{Path: s[0]}
		setArg(e, argModuleName, cstr(b[8:64]))
		switch src {
		case 1:
			setArg(e, argModuleSource, "file")
		case 2:
			setArg(e, argModuleSource, "memory")
		default:
			setArg(e, argModuleSource, "unknown")
		}

	case kindNet, kindDNS:
		n, payload, err := parseNet(r)
		if err != nil {
			return nil, err
		}
		m.fill(p, key)
		if r.Kind == kindNet {
			e.Net = n
			if n.Direction == "outbound" {
				e.Name = event.NetworkConnect
			} else {
				e.Name = event.NetworkAccept
			}
			break
		}
		name, qtype, err := parseDNSQuery(payload)
		if err != nil {
			return nil, nil // not a query: nothing to report
		}
		e.Name = event.DNSQuery
		e.Net = n
		e.DNS = &event.DNS{Query: name, Type: qtype}

	default:
		return nil, fmt.Errorf("%w: kind %d", errRecord, r.Kind)
	}
	return e, nil
}

// fill puts the process's remembered image on p.
func (m *mapper) fill(p *event.Proc, key procKey) {
	if img, ok := m.image(key); ok {
		applyImage(p, img)
	}
}

// parseNet reads struct net_body. Kernel order is local address/port in
// saddr/sport and remote in daddr/dport; for an accepted connection the
// event follows Sysmon (source = the remote peer, destination = the local
// listener), so rules read both sources the same way.
func parseNet(r *record) (*event.Net, []byte, error) {
	b := r.body
	family, proto, dir := le16(b, 0), le16(b, 2), b[4]
	lport, rport := le16(b, 8), le16(b, 10)
	plen := le32(b, 12)
	var local, remote netip.Addr
	switch family {
	case 2: // AF_INET
		local = netip.AddrFrom4([4]byte(b[16:20]))
		remote = netip.AddrFrom4([4]byte(b[32:36]))
	case 10: // AF_INET6
		local = netip.AddrFrom16([16]byte(b[16:32])).Unmap()
		remote = netip.AddrFrom16([16]byte(b[32:48])).Unmap()
	default:
		return nil, nil, fmt.Errorf("%w: address family %d", errRecord, family)
	}
	var payload []byte
	if r.Kind == kindDNS {
		s, err := r.strings(netSize, plen)
		if err != nil {
			return nil, nil, err
		}
		payload = []byte(s[0])
	} else if _, err := r.strings(netSize); err != nil {
		return nil, nil, err
	}
	n := &event.Net{}
	switch proto {
	case 6:
		n.Proto = "tcp"
	case 17:
		n.Proto = "udp"
	default:
		return nil, nil, fmt.Errorf("%w: protocol %d", errRecord, proto)
	}
	switch dir {
	case 1:
		n.Direction = "outbound"
		if r.Kind == kindNet || local.IsValid() && !local.IsUnspecified() {
			n.SrcIP, n.SrcPort = local.String(), lport
		}
		n.DstIP, n.DstPort = remote.String(), rport
	case 2:
		n.Direction = "inbound"
		n.SrcIP, n.SrcPort = remote.String(), rport
		n.DstIP, n.DstPort = local.String(), lport
	default:
		return nil, nil, fmt.Errorf("%w: direction %d", errRecord, dir)
	}
	return n, payload, nil
}
