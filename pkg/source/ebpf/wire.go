package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Record layout shared with bpf/zaaf.bpf.c (struct hdr and the *_body
// structs; the C file asserts the same sizes). All fields are
// little-endian: the source runs on amd64 and arm64 only.
const (
	kindExec    = 1
	kindExit    = 2
	kindFork    = 3
	kindFile    = 4
	kindSetUID  = 5
	kindProcAcc = 6
	kindModule  = 7
	kindNet     = 8
	kindDNS     = 9
	kindMax     = 10

	hdrSize     = 72
	execSize    = 40
	exitSize    = 8
	fileSize    = 24
	setuidSize  = 16
	procAccSize = 32
	moduleSize  = 64
	netSize     = 48

	// maxRecord bounds a record (the kernel side cannot exceed 16 KiB).
	maxRecord = 16384
)

// File operations and flags (zaaf.bpf.c F_* and FL_*).
const (
	fileOpen   = 1
	fileCreate = 2
	fileUnlink = 3
	fileRename = 4

	flArgsTrunc  = 1
	flArgsErr    = 2
	flPathTrunc  = 4
	flPath2Trunc = 8
	flTruncated  = 16
)

// Process-access syscalls (S_*).
const (
	sysPtrace   = 1
	sysVMReadv  = 2
	sysVMWritev = 3

	ptraceAttach = 16
	ptraceSeize  = 0x4206
)

var kindNames = [kindMax]string{"", "exec", "exit", "fork", "file", "setuid", "procacc", "module", "net", "dns"}

// errRecord is wrapped by every decode error: a malformed record from the
// ring buffer (which the kernel side should never produce) is counted and
// reported, never trusted.
var errRecord = errors.New("malformed eBPF record")

// header is struct hdr.
type header struct {
	Kind     uint32
	Size     uint32
	KTime    uint64 // nanoseconds since boot (CLOCK_BOOTTIME)
	PID      uint32 // thread-group id
	TID      uint32
	PPID     uint32 // real_parent's thread-group id
	UID      uint32
	EUID     uint32
	StartNs  uint64 // group leader's start_boottime
	PStartNs uint64 // real_parent group leader's start_boottime
	Comm     string
}

// record is one decoded ring-buffer record: the header and the body bytes
// that follow it (fixed part, then the variable strings).
type record struct {
	header
	body []byte
}

func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }
func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }

// cstr returns b up to its first NUL.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// parseRecord checks the header against the sample length and the kind's
// fixed body size. Every length used later is checked against the sample
// again (strings), so a record cannot make the decoder read past it.
func parseRecord(raw []byte) (*record, error) {
	if len(raw) < hdrSize {
		return nil, fmt.Errorf("%w: %d bytes, shorter than the header", errRecord, len(raw))
	}
	if len(raw) > maxRecord {
		return nil, fmt.Errorf("%w: %d bytes, larger than %d", errRecord, len(raw), maxRecord)
	}
	r := &record{header: header{
		Kind: le32(raw, 0), Size: le32(raw, 4), KTime: le64(raw, 8),
		PID: le32(raw, 16), TID: le32(raw, 20), PPID: le32(raw, 24),
		UID: le32(raw, 28), EUID: le32(raw, 32),
		StartNs: le64(raw, 40), PStartNs: le64(raw, 48), Comm: cstr(raw[56:72]),
	}}
	if int(r.Size) != len(raw) {
		return nil, fmt.Errorf("%w: size field %d, sample %d bytes", errRecord, r.Size, len(raw))
	}
	if r.Kind == 0 || r.Kind >= kindMax {
		return nil, fmt.Errorf("%w: unknown kind %d", errRecord, r.Kind)
	}
	if r.PID == 0 {
		return nil, fmt.Errorf("%w: pid 0", errRecord)
	}
	r.body = raw[hdrSize:]
	if min := bodySize(r.Kind); len(r.body) < min {
		return nil, fmt.Errorf("%w: %s record body %d bytes, want at least %d", errRecord, kindNames[r.Kind], len(r.body), min)
	}
	return r, nil
}

func bodySize(kind uint32) int {
	switch kind {
	case kindExec:
		return execSize
	case kindExit:
		return exitSize
	case kindFile:
		return fileSize
	case kindSetUID:
		return setuidSize
	case kindProcAcc:
		return procAccSize
	case kindModule:
		return moduleSize
	case kindNet, kindDNS:
		return netSize
	}
	return 0
}

// strings splits the variable part of r (after fixed bytes of fixed
// length) into consecutive pieces of the given lengths. The pieces must
// fill the record exactly.
func (r *record) strings(fixed int, lens ...uint32) ([]string, error) {
	pos := fixed
	out := make([]string, len(lens))
	for i, n := range lens {
		if n > uint32(len(r.body)-pos) {
			return nil, fmt.Errorf("%w: %s string %d of %d bytes overruns the record", errRecord, kindNames[r.Kind], i, n)
		}
		out[i] = string(r.body[pos : pos+int(n)])
		pos += int(n)
	}
	if pos != len(r.body) {
		return nil, fmt.Errorf("%w: %s record has %d trailing bytes", errRecord, kindNames[r.Kind], len(r.body)-pos)
	}
	return out, nil
}
