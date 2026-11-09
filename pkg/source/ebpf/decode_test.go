package ebpf

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
)

// The tests build records byte by byte with the layout of zaaf.bpf.c, so
// the decoder is checked on any OS; source_linux_test.go checks the same
// fields against records from the real kernel programs.

const (
	tBootWall = int64(1_700_000_000_000_000_000) // ns
	tBtime    = int64(1_700_000_000)
)

type hdrIn struct {
	pid, tid, ppid, uid, euid uint32
	mntns                     uint32
	startNs, pstartNs, ktime  uint64
	comm                      string
}

func defHdr() hdrIn {
	return hdrIn{pid: 4242, tid: 4242, ppid: 100, uid: 1000, euid: 1000,
		startNs: 12_340_000_000, pstartNs: 5_000_000_000, ktime: 20_000_000_000, comm: "cmd"}
}

func le32b(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.LittleEndian.AppendUint32(b, x)
	}
	return b
}

func le64b(v ...uint64) []byte {
	var b []byte
	for _, x := range v {
		b = binary.LittleEndian.AppendUint64(b, x)
	}
	return b
}

func build(kind uint32, h hdrIn, body []byte, strs ...string) []byte {
	var b []byte
	b = append(b, le32b(kind, 0)...)
	b = append(b, le64b(h.ktime)...)
	b = append(b, le32b(h.pid, h.tid, h.ppid, h.uid, h.euid, h.mntns)...)
	b = append(b, le64b(h.startNs, h.pstartNs)...)
	comm := make([]byte, 16)
	copy(comm, h.comm)
	b = append(b, comm...)
	b = append(b, body...)
	for _, s := range strs {
		b = append(b, s...)
	}
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	return b
}

func execRec(h hdrIn, exe, args, cwd string, eflags uint32) []byte {
	return execRecN(h, exe, args, cwd, eflags, 0)
}

// execRecN is an exec record that says conts K_ARGS records precede it.
func execRecN(h hdrIn, exe, args, cwd string, eflags, conts uint32) []byte {
	body := le32b(0x00800001, eflags) // s_dev: major 8, minor 1
	body = append(body, le64b(77, uint64(1_600_000_000_123_456_789))...)
	body = append(body, le32b(uint32(len(exe)), uint32(len(args)), uint32(len(cwd)), conts)...)
	return build(kindExec, h, body, exe, args, cwd)
}

func argsRec(h hdrIn, seq uint32, chunk string) []byte {
	return build(kindArgs, h, le32b(seq, uint32(len(chunk))), chunk)
}

// forkRec is a fork record: h describes the child, forker the task that
// called clone (not necessarily the child's real parent).
func forkRec(h hdrIn, forkerPid uint32, forkerStartNs uint64) []byte {
	body := le32b(forkerPid, 0)
	body = append(body, le64b(forkerStartNs)...)
	return build(kindFork, h, body)
}

func fileRec(h hdrIn, op, fflags uint32, path, dest string) []byte {
	body := le32b(op, 0, 0, uint32(len(path)), uint32(len(dest)), fflags)
	return build(kindFile, h, body, path, dest)
}

func netRec(kind uint32, h hdrIn, family, proto uint16, dir uint8, lport, rport uint16, local, remote []byte, payload []byte) []byte {
	body := binary.LittleEndian.AppendUint16(nil, family)
	body = binary.LittleEndian.AppendUint16(body, proto)
	body = append(body, dir, 0, 0, 0)
	body = binary.LittleEndian.AppendUint16(body, lport)
	body = binary.LittleEndian.AppendUint16(body, rport)
	body = append(body, le32b(uint32(len(payload)))...)
	l, r := make([]byte, 16), make([]byte, 16)
	copy(l, local)
	copy(r, remote)
	body = append(body, l...)
	body = append(body, r...)
	return build(kind, h, body, string(payload))
}

func newTestMapper() *mapper { return newMapper(clock{bootWallNs: tBootWall, btime: tBtime}, nil) }

func decodeOK(t *testing.T, m *mapper, raw []byte) *event.Event {
	t.Helper()
	r, err := parseRecord(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e, err := m.mapRecord(r)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	return e
}

func TestDecodeExec(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	e := decodeOK(t, m, execRec(h, "/usr/bin/curl", "curl\x00-s\x00http://x\x00", "/home/u", 0))
	p := e.Proc
	if e.Name != event.CreateProcess || e.Source != "ebpf" || e.Platform != event.PlatformLinux {
		t.Fatalf("name %q source %q platform %q", e.Name, e.Source, e.Platform)
	}
	if want := time.Unix(0, tBootWall+20_000_000_000).UTC(); !e.Time.Equal(want) {
		t.Errorf("time %v want %v", e.Time, want)
	}
	if p.PID != 4242 || p.PPID != 100 || p.UID != 1000 || p.EUID != 1000 {
		t.Errorf("ids %+v", p)
	}
	// 12.34 s after boot = 1234 ticks, exactly /proc/<pid>/stat field 22.
	if p.UniqueID != 1234 || p.PIDVersion != 1235 {
		t.Errorf("UniqueID %d PIDVersion %d", p.UniqueID, p.PIDVersion)
	}
	if !p.StartTime.Equal(procfs.StartTime(tBtime, 1234)) {
		t.Errorf("StartTime %v", p.StartTime)
	}
	if p.Parent == nil || p.Parent.PID != 100 || p.Parent.PIDVersion != 501 {
		t.Errorf("parent stub %+v", p.Parent)
	}
	if p.Exe != "/usr/bin/curl" || p.Name != "curl" || p.Cwd != "/home/u" {
		t.Errorf("exe %q name %q cwd %q", p.Exe, p.Name, p.Cwd)
	}
	if strings.Join(p.Args, "|") != "curl|-s|http://x" || p.Cmdline != "curl -s http://x" {
		t.Errorf("args %q cmdline %q", p.Args, p.Cmdline)
	}
	// stat(2) encoding of major 8 minor 1 is 0x801.
	if p.ExeDev != 0x801 || p.ExeIno != 77 || p.ExeCtimeNs != 1_600_000_000_123_456_789 {
		t.Errorf("dev %#x ino %d ctime %d", p.ExeDev, p.ExeIno, p.ExeCtimeNs)
	}
	if len(e.Args) != 0 {
		t.Errorf("args %v", e.Args)
	}

	e = decodeOK(t, m, execRec(h, "/x", "a\x00b", "/", flArgsTrunc|flPath2Trunc))
	if e.Args[argArgsTruncated] != "true" || e.Args[argPathIncomplete] != "true" || strings.Join(e.Proc.Args, "|") != "a|b" {
		t.Errorf("flags: args %v proc args %q", e.Args, e.Proc.Args)
	}
}

func TestUserDev(t *testing.T) {
	for _, c := range []struct {
		k    uint32
		want uint64
	}{
		{8<<20 | 1, 0x801},
		{259<<20 | 2, 0x10302},                        // nvme: major 259
		{0<<20 | 300, (300 & 0xff) | (300&^0xff)<<12}, // minor > 255
	} {
		if got := userDev(c.k); got != c.want {
			t.Errorf("userDev(%#x) = %#x, want %#x", c.k, got, c.want)
		}
	}
}

// Later events of a process carry the image its exec recorded; a forked
// child carries its parent's until it execs; exit forgets it.
func TestImageCache(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	decodeOK(t, m, execRec(h, "/usr/bin/bash", "bash\x00", "/", 0))
	f := decodeOK(t, m, fileRec(h, fileCreate, 0, "/etc/cron.d/x", ""))
	if f.Proc.Exe != "/usr/bin/bash" || f.Proc.ExeIno != 77 {
		t.Errorf("file event exe %q ino %d", f.Proc.Exe, f.Proc.ExeIno)
	}
	child := h
	child.pid, child.tid, child.ppid, child.startNs, child.pstartNs = 4300, 4300, 4242, 13_000_000_000, h.startNs
	fk := decodeOK(t, m, forkRec(child, h.pid, h.startNs))
	if fk.Name != event.Fork || fk.Proc.Exe != "/usr/bin/bash" || fk.Proc.Parent.PID != 4242 || fk.Proc.Parent.PIDVersion != 1235 {
		t.Errorf("fork %+v parent %+v", fk.Proc, fk.Proc.Parent)
	}
	x := decodeOK(t, m, build(kindExit, h, le32b(256, 0)))
	if x.Name != event.TerminateProcess || x.Proc.Exe != "/usr/bin/bash" || x.Args[argExitStatus] != "256" {
		t.Errorf("exit %+v %v", x.Proc, x.Args)
	}
	if after := decodeOK(t, m, fileRec(h, fileUnlink, 0, "/a", "")); after.Proc.Exe != "" {
		t.Errorf("image kept after exit: %q", after.Proc.Exe)
	}
	// Same pid, another incarnation (other start time): never the old image.
	m2 := newTestMapper()
	decodeOK(t, m2, execRec(h, "/usr/bin/bash", "", "/", 0))
	other := h
	other.startNs += 1e9
	if e := decodeOK(t, m2, fileRec(other, fileUnlink, 0, "/a", "")); e.Proc.Exe != "" {
		t.Errorf("recycled pid got %q", e.Proc.Exe)
	}
}

func TestImageLookupAndBound(t *testing.T) {
	asked := 0
	m := newMapper(clock{btime: tBtime}, func(pid int32, ticks uint64) (image, bool) {
		asked++
		if pid == 4242 && ticks == 1234 {
			return image{exe: "/opt/old"}, true
		}
		return image{}, false
	})
	m.maxImages = 2
	h := defHdr()
	if e := decodeOK(t, m, fileRec(h, fileUnlink, 0, "/a", "")); e.Proc.Exe != "/opt/old" {
		t.Fatalf("lookup not used: %q", e.Proc.Exe)
	}
	decodeOK(t, m, fileRec(h, fileUnlink, 0, "/a", ""))
	if asked != 1 {
		t.Errorf("lookup asked %d times, want 1 (cached)", asked)
	}
	for i := uint32(0); i < 5; i++ {
		x := h
		x.pid = 5000 + i
		decodeOK(t, m, execRec(x, "/bin/x", "", "/", 0))
	}
	if len(m.images) > 2 || m.evicted.Load() == 0 {
		t.Errorf("cache %d entries, %d evicted", len(m.images), m.evicted.Load())
	}
	if m.lookupMisses.Load() != 0 {
		t.Errorf("misses %d", m.lookupMisses.Load())
	}
}

func TestDecodeFiles(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	decodeOK(t, m, execRec(h, "/usr/bin/touch", "touch\x00", "/", 0)) // the image is known
	cases := []struct {
		raw  []byte
		name string
		path string
		dest string
		args map[string]string
	}{
		{fileRec(h, fileOpen, 0, "/etc/shadow", ""), event.OpenFile, "/etc/shadow", "", nil},
		{fileRec(h, fileCreate, 0, "/etc/sudoers.d/x", ""), event.CreateFile, "/etc/sudoers.d/x", "", nil},
		{fileRec(h, fileCreate, flTruncated, "/etc/crontab", ""), event.CreateFile, "/etc/crontab", "", map[string]string{argTruncated: "true"}},
		{fileRec(h, fileUnlink, 0, "/root/.bash_history", ""), event.DeleteFile, "/root/.bash_history", "", nil},
		{fileRec(h, fileRename, flPath2Trunc, "/tmp/a", "/etc/b"), event.RenameFile, "/tmp/a", truncMarker + "/etc/b", map[string]string{argPathIncomplete: "true"}},
	}
	for _, c := range cases {
		e := decodeOK(t, m, c.raw)
		if e.Name != c.name || e.File.Path != c.path || e.File.Dest != c.dest {
			t.Errorf("%s: got %s %+v", c.name, e.Name, e.File)
		}
		if len(e.Args) != len(c.args) {
			t.Errorf("%s: args %v want %v", c.name, e.Args, c.args)
		}
		for k, v := range c.args {
			if e.Args[k] != v {
				t.Errorf("%s: arg %s = %q want %q", c.name, k, e.Args[k], v)
			}
		}
	}
	if _, err := m.mapRecord(mustParse(t, fileRec(h, 9, 0, "/a", ""))); !errors.Is(err, errRecord) {
		t.Errorf("unknown op: %v", err)
	}
}

func mustParse(t *testing.T, raw []byte) *record {
	t.Helper()
	r, err := parseRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDecodeSetUID(t *testing.T) {
	m := newTestMapper()
	decodeOK(t, m, execRec(defHdr(), "/usr/bin/su", "su\x00", "/", 0))
	e := decodeOK(t, m, build(kindSetUID, defHdr(), le32b(1000, 1000, 0, 0)))
	want := map[string]string{argOldUID: "1000", argOldEUID: "1000", argNewUID: "0", argNewEUID: "0"}
	if e.Name != event.SetUID || len(e.Args) != 4 {
		t.Fatalf("%s %v", e.Name, e.Args)
	}
	for k, v := range want {
		if e.Args[k] != v {
			t.Errorf("%s = %q want %q", k, e.Args[k], v)
		}
	}
	if event.Category(e.Name) != "process" {
		t.Errorf("category %q", event.Category(e.Name))
	}
}

func procAccRec(h hdrIn, sc, req, target uint32, tstart uint64, texe string) []byte {
	body := le32b(sc, req, target, 0)
	body = append(body, le64b(tstart)...)
	body = append(body, le32b(uint32(len(texe)), 0)...)
	return build(kindProcAcc, h, body, texe)
}

func TestDecodeProcessAccess(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	for _, c := range []struct {
		sc, req   uint32
		name, arg string
	}{
		{sysPtrace, ptraceAttach, event.Ptrace, "ptrace_attach"},
		{sysPtrace, ptraceSeize, event.Ptrace, "ptrace_seize"},
		{sysVMReadv, 0, event.OpenProcess, "process_vm_readv"},
		{sysVMWritev, 0, event.OpenProcess, "process_vm_writev"},
	} {
		e := decodeOK(t, m, procAccRec(h, c.sc, c.req, 777, 3_000_000_000, "/usr/sbin/sshd"))
		if e.Name != c.name || e.Args[argSyscall] != c.arg {
			t.Errorf("%s: %s %v", c.arg, e.Name, e.Args)
		}
		tg := e.Target
		if tg == nil || tg.PID != 777 || tg.UniqueID != 300 || tg.PIDVersion != 301 || tg.Exe != "/usr/sbin/sshd" || tg.Name != "sshd" {
			t.Errorf("%s: target %+v", c.arg, tg)
		}
	}
	if _, err := m.mapRecord(mustParse(t, procAccRec(h, sysPtrace, 4, 1, 1, ""))); !errors.Is(err, errRecord) {
		t.Errorf("PTRACE_POKEDATA record accepted: %v", err)
	}
}

func TestDecodeModule(t *testing.T) {
	m := newTestMapper()
	name := make([]byte, 56)
	copy(name, "rootkit")
	path := "/tmp/rootkit.ko"
	body := append(le32b(1, uint32(len(path))), name...)
	e := decodeOK(t, m, build(kindModule, defHdr(), body, path))
	if e.Name != event.DriverLoad || e.Module.Path != path || e.Args[argModuleName] != "rootkit" || e.Args[argModuleSource] != "file" {
		t.Fatalf("%s %+v %v", e.Name, e.Module, e.Args)
	}
	body = append(le32b(2, 0), name...)
	e = decodeOK(t, m, build(kindModule, defHdr(), body))
	if e.Module.Path != "" || e.Args[argModuleSource] != "memory" {
		t.Errorf("memory module %+v %v", e.Module, e.Args)
	}
}

func TestDecodeNetwork(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	lo4 := []byte{127, 0, 0, 1}
	ext4 := []byte{198, 51, 100, 9}
	out := decodeOK(t, m, netRec(kindNet, h, 2, 6, 1, 40000, 443, lo4, ext4, nil))
	if out.Name != event.NetworkConnect || *out.Net != (event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "127.0.0.1", SrcPort: 40000, DstIP: "198.51.100.9", DstPort: 443}) {
		t.Errorf("connect %+v", out.Net)
	}
	// Accepted: the remote peer is the source, the local listener the
	// destination (as Sysmon reports it).
	in := decodeOK(t, m, netRec(kindNet, h, 2, 6, 2, 4444, 61000, lo4, ext4, nil))
	if in.Name != event.NetworkAccept || *in.Net != (event.Net{Proto: "tcp", Direction: "inbound", SrcIP: "198.51.100.9", SrcPort: 61000, DstIP: "127.0.0.1", DstPort: 4444}) {
		t.Errorf("accept %+v", in.Net)
	}
	mapped := append(make([]byte, 10), 0xff, 0xff, 10, 0, 0, 5)
	v6 := decodeOK(t, m, netRec(kindNet, h, 10, 6, 1, 1, 2, net6("::1"), mapped, nil))
	if v6.Net.SrcIP != "::1" || v6.Net.DstIP != "10.0.0.5" {
		t.Errorf("v6 %+v", v6.Net)
	}
	for _, bad := range [][]byte{
		netRec(kindNet, h, 7, 6, 1, 1, 2, lo4, lo4, nil),
		netRec(kindNet, h, 2, 99, 1, 1, 2, lo4, lo4, nil),
		netRec(kindNet, h, 2, 6, 3, 1, 2, lo4, lo4, nil),
		netRec(kindNet, h, 2, 6, 1, 1, 2, lo4, lo4, []byte("x")), // payload on a TCP record
	} {
		if _, err := m.mapRecord(mustParse(t, bad)); !errors.Is(err, errRecord) {
			t.Errorf("bad net record accepted: %v", err)
		}
	}
}

func net6(s string) []byte {
	b := make([]byte, 16)
	if s == "::1" {
		b[15] = 1
	}
	return b
}

func TestDecodeDNS(t *testing.T) {
	m := newTestMapper()
	q := dnsQueryBytes("Evil.Example.COM", 16)
	e := decodeOK(t, m, netRec(kindDNS, defHdr(), 2, 17, 1, 0, 53, nil, []byte{127, 0, 0, 53}, q))
	if e.Name != event.DNSQuery || e.DNS.Query != "evil.example.com" || e.DNS.Type != "TXT" {
		t.Fatalf("%s %+v", e.Name, e.DNS)
	}
	if e.Net.DstIP != "127.0.0.53" || e.Net.DstPort != 53 || e.Net.Proto != "udp" || e.Net.SrcIP != "" {
		t.Errorf("net %+v", e.Net)
	}
	resp := append([]byte(nil), q...)
	resp[2] |= 0x80
	if e := decodeOK(t, m, netRec(kindDNS, defHdr(), 2, 17, 1, 0, 53, nil, []byte{1, 1, 1, 1}, resp)); e != nil {
		t.Errorf("a response produced %+v", e)
	}
}

func dnsQueryBytes(name string, qtype uint16) []byte {
	b := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1)
}

func TestParseDNSQuery(t *testing.T) {
	ok := []struct {
		pkt        []byte
		name, kind string
	}{
		{dnsQueryBytes("a.b", 1), "a.b", "A"},
		{dnsQueryBytes("x", 28), "x", "AAAA"},
		{dnsQueryBytes("x", 4000), "x", "TYPE4000"},
		{append([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, 0, 2, 0, 1), ".", "NS"},
	}
	for _, c := range ok {
		n, k, err := parseDNSQuery(c.pkt)
		if err != nil || n != c.name || k != c.kind {
			t.Errorf("%q: %q %q %v", c.name, n, k, err)
		}
	}
	long := strings.Repeat("a", 64)
	bad := map[string][]byte{
		"short":       {0, 1, 2},
		"response":    func() []byte { b := dnsQueryBytes("a", 1); b[2] |= 0x80; return b }(),
		"opcode":      func() []byte { b := dnsQueryBytes("a", 1); b[2] |= 0x28; return b }(),
		"no question": func() []byte { b := dnsQueryBytes("a", 1); b[5] = 0; return b }(),
		"label > 63":  dnsQueryBytes(long, 1),
		"compression": append([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 0x0c, 0, 1, 0, 1),
		"control":     dnsQueryBytes("a\nb", 1),
		"truncated":   dnsQueryBytes("abc", 1)[:15],
		"no type":     dnsQueryBytes("abc", 1)[:18],
		"name > 253":  dnsQueryBytes(strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 60)+".", 5), "."), 1),
	}
	for what, pkt := range bad {
		if n, _, err := parseDNSQuery(pkt); err == nil {
			t.Errorf("%s accepted as %q", what, n)
		}
	}
}

func TestParseRecordRejects(t *testing.T) {
	good := forkRec(defHdr(), 1, 1)
	cases := map[string][]byte{
		"short":        good[:hdrSize-1],
		"size field":   func() []byte { b := append([]byte(nil), good...); b[4]++; return b }(),
		"kind 0":       build(0, defHdr(), nil),
		"kind too big": build(kindMax, defHdr(), nil),
		"pid 0":        forkRec(hdrIn{startNs: 1}, 1, 1),
		"short body":   build(kindExit, defHdr(), le32b(1)),
		"too big":      append(make([]byte, maxRecord), 0),
	}
	for what, raw := range cases {
		if _, err := parseRecord(raw); !errors.Is(err, errRecord) {
			t.Errorf("%s: %v", what, err)
		}
	}
	// A string length that runs past the record, and trailing bytes.
	m := newTestMapper()
	over := fileRec(defHdr(), fileOpen, 0, "/a", "")
	binary.LittleEndian.PutUint32(over[hdrSize+12:], 1000)
	if _, err := m.mapRecord(mustParse(t, over)); !errors.Is(err, errRecord) {
		t.Errorf("overrun: %v", err)
	}
	trailing := build(kindExit, defHdr(), le32b(0, 0), "junk")
	if _, err := m.mapRecord(mustParse(t, trailing)); !errors.Is(err, errRecord) {
		t.Errorf("trailing: %v", err)
	}
}

// FuzzRecord: no input from the ring buffer can make the decoder panic or
// read past the record.
func FuzzRecord(f *testing.F) {
	h := defHdr()
	f.Add(execRec(h, "/bin/sh", "sh\x00-c\x00x\x00", "/", 0))
	f.Add(fileRec(h, fileRename, 0, "/a", "/b"))
	f.Add(netRec(kindDNS, h, 2, 17, 1, 0, 53, nil, []byte{1, 1, 1, 1}, dnsQueryBytes("a.b", 1)))
	f.Add(procAccRec(h, sysPtrace, ptraceAttach, 1, 1, "/x"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := parseRecord(raw)
		if err != nil {
			return
		}
		_, _ = newTestMapper().mapRecord(r)
	})
}

func TestPlan(t *testing.T) {
	all, open := plan(nil)
	if len(all) != len(groups) || !open {
		t.Errorf("nil subscription: %d groups, open %v", len(all), open)
	}
	use, open := plan([]string{event.CreateProcess, event.CreateFile, event.DNSQuery})
	var names []string
	for _, g := range use {
		names = append(names, g.name)
	}
	if strings.Join(names, ",") != "process,file-open-create,dns" || open {
		t.Errorf("groups %v open %v", names, open)
	}
	if _, open := plan([]string{event.OpenFile}); !open {
		t.Error("OpenFile subscribed but not wanted")
	}
	// Every event a group lists is a canonical event, and every program is
	// in the embedded objects (zaaf_*_bpfel.go lists them).
	known := map[string]bool{}
	for _, n := range event.Names() {
		known[n] = true
	}
	for _, n := range Supported() {
		if !known[n] {
			t.Errorf("group event %q is not canonical", n)
		}
	}
}

func TestReporterRateLimit(t *testing.T) {
	r := newReporter()
	now := time.Unix(0, 0)
	r.now = func() time.Time { return now }
	var got []string
	r.set(func(c, d string) { got = append(got, c+": "+d) })
	r.report(CondEventsDropped, "a")
	r.report(CondEventsDropped, "b")
	r.report(CondEventsUnreadable, "c")
	now = now.Add(61 * time.Second)
	r.report(CondEventsDropped, "d")
	want := []string{"ebpf_events_dropped: a", "ebpf_events_unreadable: c",
		"ebpf_events_dropped: d (1 similar reports suppressed in the last minute)"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s", strings.Join(got, "\n"))
	}
}

func TestDropTracker(t *testing.T) {
	var d dropTracker
	var now [nSlots]uint64
	if n, _ := d.update(now); n != 0 {
		t.Fatal("drops from zero counters")
	}
	now[kindExec], now[kindFile] = 3, 7
	n, detail := d.update(now)
	if n != 10 || detail != "the kernel side lost 10 events (ring buffer full, or programs skipped while another one used the CPU: 3 exec, 7 file); 10 lost in total" {
		t.Errorf("%d %q", n, detail)
	}
	now[kindFile] = 9
	if n, detail := d.update(now); n != 2 || !strings.HasSuffix(detail, "12 lost in total") {
		t.Errorf("%d %q", n, detail)
	}
	if n, _ := d.update(now); n != 0 {
		t.Errorf("no change reported %d", n)
	}
}

// F1: under clone(CLONE_PARENT) the child's real parent is the forker's
// parent, but it runs the image of the task that forked it.
func TestForkImageFromForkerNotParent(t *testing.T) {
	m := newTestMapper()
	grand := hdrIn{pid: 100, tid: 100, ppid: 1, uid: 0, euid: 0, startNs: 5_000_000_000, pstartNs: 1_000_000_000, ktime: 1, comm: "init"}
	forker := hdrIn{pid: 200, tid: 200, ppid: 100, uid: 1000, euid: 1000, startNs: 6_000_000_000, pstartNs: grand.startNs, ktime: 2, comm: "mal"}
	decodeOK(t, m, execRec(grand, "/usr/sbin/sshd", "sshd\x00", "/", 0))
	decodeOK(t, m, execRec(forker, "/tmp/mal", "mal\x00", "/tmp", 0))
	// The child: real_parent is the grandparent (100), forker is 200.
	child := hdrIn{pid: 300, tid: 300, ppid: 100, uid: 1000, euid: 1000, startNs: 7_000_000_000, pstartNs: grand.startNs, ktime: 3, comm: "mal"}
	e := decodeOK(t, m, forkRec(child, forker.pid, forker.startNs))
	if e.Name != event.Fork || e.Proc.Exe != "/tmp/mal" || e.Proc.Name != "mal" {
		t.Fatalf("child image %q (%q), want the forker's /tmp/mal", e.Proc.Exe, e.Proc.Name)
	}
	if e.Proc.PPID != 100 || e.Proc.Parent == nil || e.Proc.Parent.PID != 100 {
		t.Errorf("real parent lost: %+v", e.Proc)
	}
	// Later events of the child carry the forker's image too.
	if f := decodeOK(t, m, fileRec(child, fileCreate, 0, "/tmp/x", "")); f.Proc.Exe != "/tmp/mal" {
		t.Errorf("file event by child: exe %q", f.Proc.Exe)
	}
}

// F2/F6: pseudo files keep their name, deleted files and truncated paths
// are marked.
func TestDecodePathMarkers(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	e := decodeOK(t, m, execRec(h, "/memfd:payload", "x\x00", "/", flDeleted))
	if e.Proc.Exe != "/memfd:payload" || e.Proc.Name != "memfd:payload" || e.Args[argPathDeleted] != "true" {
		t.Errorf("exe %q name %q args %v", e.Proc.Exe, e.Proc.Name, e.Args)
	}
	e = decodeOK(t, m, execRec(h, "/deep/er/bin/x", "x\x00", "/a/b", flPathTrunc|flPath2Trunc))
	if e.Proc.Exe != truncMarker+"/deep/er/bin/x" || e.Proc.Cwd != truncMarker+"/a/b" || e.Args[argPathIncomplete] != "true" {
		t.Errorf("exe %q cwd %q args %v", e.Proc.Exe, e.Proc.Cwd, e.Args)
	}
	if strings.HasPrefix(e.Proc.Exe, "/") {
		t.Errorf("a truncated path looks absolute: %q", e.Proc.Exe)
	}
	f := decodeOK(t, m, fileRec(h, fileRename, flPathTrunc|flPath2Trunc|flDeleted, "/p/q", "/r/s"))
	if f.File.Path != truncMarker+"/p/q" || f.File.Dest != truncMarker+"/r/s" || f.Args[argPathDeleted] != "true" {
		t.Errorf("file %+v args %v", f.File, f.Args)
	}
	f = decodeOK(t, m, fileRec(h, fileOpen, 0, "/whole", ""))
	if f.File.Path != "/whole" {
		t.Errorf("complete path changed: %q", f.File.Path)
	}
}

// F3: argv longer than one record arrives in K_ARGS records before the
// exec; the tail survives, a lost chunk is flagged.
func TestDecodeArgsContinuation(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	first := "sh\x00-c\x00" + strings.Repeat("A", 4090)
	second := strings.Repeat("B", 4096)
	third := strings.Repeat("C", 100) + "TAILMARKER\x00"
	if e := decodeOK(t, m, argsRec(h, 1, second)); e != nil {
		t.Fatalf("a continuation produced %+v", e)
	}
	decodeOK(t, m, argsRec(h, 2, third))
	e := decodeOK(t, m, execRecN(h, "/bin/sh", first, "/", 0, 2))
	args := e.Proc.Args
	if len(args) != 3 || !strings.HasSuffix(args[2], "TAILMARKER") || len(args[2]) != 4090+4096+100+10 {
		t.Fatalf("args: %d, last %d bytes", len(args), len(args[len(args)-1]))
	}
	if e.Args[argArgsTruncated] != "" || len(m.pending) != 0 {
		t.Errorf("flagged or leaked: %v, %d pending", e.Args, len(m.pending))
	}
	// A lost chunk: the exec says 2 but only chunk 1 came.
	decodeOK(t, m, argsRec(h, 1, second))
	e = decodeOK(t, m, execRecN(h, "/bin/sh", first, "/", 0, 2))
	if e.Args[argArgsTruncated] != "true" || m.argsIncomplete.Load() != 1 || len(m.pending) != 0 {
		t.Errorf("lost chunk: %v incomplete %d pending %d", e.Args, m.argsIncomplete.Load(), len(m.pending))
	}
	// Chunks of other processes stay apart and are bounded.
	for i := uint32(0); i < 3*maxPendingArgs; i++ {
		x := h
		x.pid = 10_000 + i
		decodeOK(t, m, argsRec(x, 1, "x"))
	}
	if len(m.pending) > maxPendingArgs {
		t.Errorf("%d pending", len(m.pending))
	}
	// A continuation with a length that overruns is rejected.
	bad := argsRec(h, 1, "abc")
	binary.LittleEndian.PutUint32(bad[hdrSize+4:], 99)
	if _, err := m.mapRecord(mustParse(t, bad)); !errors.Is(err, errRecord) {
		t.Errorf("overrun: %v", err)
	}
}

// F5: an event from another mount namespace says so.
func TestDecodeMountNamespace(t *testing.T) {
	m := newTestMapper()
	m.hostMntNS = 4026531841
	h := defHdr()
	h.mntns = 4026531841
	if e := decodeOK(t, m, fileRec(h, fileOpen, 0, "/a", "")); e.Args[argMntNS] != "" {
		t.Errorf("host namespace flagged: %v", e.Args)
	}
	h.mntns = 4026532600
	if e := decodeOK(t, m, fileRec(h, fileOpen, 0, "/usr/bin/true", "")); e.Args[argMntNS] != "4026532600" {
		t.Errorf("foreign namespace: %v", e.Args)
	}
	m.hostMntNS = 0 // unknown: nothing claimed
	if e := decodeOK(t, m, fileRec(h, fileOpen, 0, "/a", "")); e.Args[argMntNS] != "" {
		t.Errorf("unknown host: %v", e.Args)
	}
}

// F7: port-53 datagrams the parser cannot read are counted, responses are not.
func TestDNSUnparsedCounted(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	srv := []byte{127, 0, 0, 53}
	hdrOnly := dnsQueryBytes("a.b", 1)[:12]
	if e := decodeOK(t, m, netRec(kindDNS, h, 2, 17, 1, 0, 53, nil, srv, hdrOnly)); e != nil {
		t.Fatalf("header-only produced %+v", e)
	}
	bad := dnsQueryBytes("a.b", 1)
	bad[12+1] = 0x07 // a byte outside 0x21-0x7e in the first label
	decodeOK(t, m, netRec(kindDNS, h, 2, 17, 1, 0, 53, nil, srv, bad))
	resp := dnsQueryBytes("a.b", 1)
	resp[2] |= 0x80
	decodeOK(t, m, netRec(kindDNS, h, 2, 17, 1, 0, 53, nil, srv, resp))
	if n := m.dnsUnparsed.Load(); n != 2 {
		t.Errorf("unparsed %d, want 2 (the response is not counted)", n)
	}
}

func TestDropTrackerCountsSkippedPrograms(t *testing.T) {
	var d dropTracker
	var now [nSlots]uint64
	now[slotMisses] = 4
	n, detail := d.update(now)
	if n != 4 || !strings.Contains(detail, "4 skipped (program recursion)") {
		t.Errorf("%d %q", n, detail)
	}
}

// D2: comm is chosen by the process, so it is never ps.name. With no image
// the name stays empty and comm is reported as an argument; with an image the
// name is the executable's basename even when comm differs.
func TestNameNeverFromComm(t *testing.T) {
	m := newTestMapper()
	h := defHdr()
	h.comm = "kworker/0:1" // what a malicious /tmp/mal sets with prctl(PR_SET_NAME)
	e := decodeOK(t, m, fileRec(h, fileCreate, 0, "/tmp/x", ""))
	if e.Proc.Name != "" || e.Proc.Exe != "" {
		t.Fatalf("no image known: name %q exe %q", e.Proc.Name, e.Proc.Exe)
	}
	if e.Args[argNameFromComm] != "kworker/0:1" {
		t.Errorf("name_from_comm %q", e.Args[argNameFromComm])
	}

	e = decodeOK(t, m, execRec(h, "/tmp/mal", "mal\x00", "/tmp", 0))
	if e.Proc.Name != "mal" || e.Proc.Exe != "/tmp/mal" {
		t.Errorf("exec: name %q exe %q", e.Proc.Name, e.Proc.Exe)
	}
	if _, ok := e.Args[argNameFromComm]; ok {
		t.Errorf("name_from_comm set although the image is known: %v", e.Args)
	}
	e = decodeOK(t, m, fileRec(h, fileCreate, 0, "/tmp/y", ""))
	if e.Proc.Name != "mal" {
		t.Errorf("later event: name %q, want the exe basename", e.Proc.Name)
	}
}

// CK-23: a set-uid exec changes only the effective ids (uid stays 1000,
// euid becomes 0); it is a SetUID event with the old and new ids. The
// kernel hook (commit_creds) fires for any change of uid or euid; the live
// counterpart is TestLiveSetUIDExec.
func TestDecodeSetUIDExec(t *testing.T) {
	e := decodeOK(t, newTestMapper(), build(kindSetUID, defHdr(), le32b(1000, 1000, 1000, 0)))
	if e.Name != event.SetUID {
		t.Fatalf("name %q", e.Name)
	}
	want := map[string]string{argOldUID: "1000", argOldEUID: "1000", argNewUID: "1000", argNewEUID: "0"}
	for k, v := range want {
		if e.Args[k] != v {
			t.Errorf("%s = %q want %q", k, e.Args[k], v)
		}
	}
}

// CK-44: a refusal that is not a missing BTF file names the minimum kernel and
// what the process needs.
func TestRefusedMessageNamesRequirements(t *testing.T) {
	msg := refusedMessage("program on_x: invalid argument")
	for _, w := range []string{"5.17", "BTF", "CAP_BPF", "CAP_PERFMON", "invalid argument"} {
		if !strings.Contains(msg, w) {
			t.Errorf("message %q lacks %q", msg, w)
		}
	}
}
