//go:build darwin

package netpoll

import (
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_info(2) and csops(2), called directly (pure Go, no cgo). Layouts are
// from xnu <sys/proc_info.h>; TestKernelReadsOwnSockets checks them against
// the running kernel with sockets the test opens itself.
const (
	sysProcInfo = 336 // SYS_proc_info
	sysCsops    = 169 // SYS_csops

	callListPIDs  = 1 // PROC_INFO_CALL_LISTPIDS
	callPIDInfo   = 2 // PROC_INFO_CALL_PIDINFO
	callPIDFDInfo = 3 // PROC_INFO_CALL_PIDFDINFO

	allPIDs = 1 // PROC_ALL_PIDS

	flavorListFDs     = 1  // PROC_PIDLISTFDS
	flavorTBSDInfo    = 3  // PROC_PIDTBSDINFO
	flavorPathInfo    = 11 // PROC_PIDPATHINFO
	flavorUniqIDInfo  = 17 // PROC_PIDUNIQIDENTIFIERINFO
	flavorFDSocketInf = 3  // PROC_PIDFDSOCKETINFO

	fdTypeSocket = 2 // PROX_FDTYPE_SOCKET

	sizeFDInfo       = 8   // struct proc_fdinfo
	sizeSocketFDInfo = 792 // struct socket_fdinfo (PROC_PIDFDSOCKETINFO_SIZE)
	sizeBSDInfo      = 136 // struct proc_bsdinfo
	sizeUniqIDInfo   = 56  // struct proc_uniqidentifierinfo
	maxPathSize      = 4096

	// Offsets inside struct socket_fdinfo: proc_fileinfo is 24 bytes, then
	// socket_info (vinfo_stat 136 bytes, soi_so, soi_pcb, ...).
	offSI        = 24
	offSoiProto  = offSI + 156
	offSoiFamily = offSI + 160
	offSoiKind   = offSI + 232
	offSoiUnion  = offSI + 240
	// in_sockinfo inside the union.
	offFPort  = 0
	offLPort  = 4
	offGenCnt = 8
	offVFlag  = 24
	offFAddr  = 32
	offLAddr  = 48
	offTCPSt  = 80 // tcp_sockinfo.tcpsi_state (after the 80-byte in_sockinfo)

	sockinfoIn  = 1 // SOCKINFO_IN
	sockinfoTCP = 2 // SOCKINFO_TCP

	afInet  = 2  // AF_INET
	afInet6 = 30 // AF_INET6

	iniIPv4 = 0x1
	iniIPv6 = 0x2

	ipprotoTCP = 6
	ipprotoUDP = 17

	csPlatformBinary = 0x4000000 // CS_PLATFORM_BINARY
)

// darwinKernel reuses its buffers; it is used from the poller's goroutine
// only.
type darwinKernel struct {
	fds  []byte
	sock []int32
}

func platformKernel() Kernel { return &darwinKernel{} }

func procInfo(call, pid, flavor int, arg uint64, buf []byte) (int, error) {
	var p unsafe.Pointer
	if len(buf) > 0 {
		p = unsafe.Pointer(&buf[0])
	}
	n, _, e := unix.Syscall6(sysProcInfo, uintptr(call), uintptr(pid), uintptr(flavor), uintptr(arg),
		uintptr(p), uintptr(len(buf)))
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

func (*darwinKernel) PIDs() ([]int32, error) {
	need, err := procInfo(callListPIDs, allPIDs, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	// Room for processes started since the size query (bounded).
	size := need + 256*4
	if size > 1<<20 {
		size = 1 << 20
	}
	buf := make([]byte, size)
	n, err := procInfo(callListPIDs, allPIDs, 0, 0, buf)
	if err != nil {
		return nil, err
	}
	if n > len(buf) {
		n = len(buf)
	}
	out := make([]int32, 0, n/4)
	for i := 0; i+4 <= n; i += 4 {
		if pid := int32(binary.LittleEndian.Uint32(buf[i:])); pid > 0 {
			out = append(out, pid)
		}
	}
	return out, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (*darwinKernel) Ident(pid int32) (Ident, error) {
	id := Ident{PID: pid}
	var bsd [sizeBSDInfo]byte
	n, err := procInfo(callPIDInfo, int(pid), flavorTBSDInfo, 0, bsd[:])
	if err != nil {
		return id, err
	}
	if n != sizeBSDInfo {
		return id, unix.EIO
	}
	le := binary.LittleEndian
	id.PPID = int32(le.Uint32(bsd[16:]))
	id.EUID = int64(le.Uint32(bsd[20:])) // pbi_uid: the effective uid
	id.UID = int64(le.Uint32(bsd[28:]))  // pbi_ruid
	id.Name = cstr(bsd[48:64])
	if sec := le.Uint64(bsd[120:]); sec != 0 {
		id.StartTime = time.Unix(int64(sec), int64(le.Uint64(bsd[128:]))*1000).UTC()
	}
	var uq [sizeUniqIDInfo]byte
	if n, err := procInfo(callPIDInfo, int(pid), flavorUniqIDInfo, 0, uq[:]); err == nil && n == sizeUniqIDInfo {
		id.UniqueID = le.Uint64(uq[16:])
		id.PIDVersion = uint32(int32(le.Uint32(uq[32:])))
	}
	path := make([]byte, maxPathSize)
	if _, err := procInfo(callPIDInfo, int(pid), flavorPathInfo, 0, path); err == nil {
		id.Exe = cstr(path)
	}
	var flags uint32
	if _, _, e := unix.Syscall6(sysCsops, uintptr(pid), 0, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0, 0); e == 0 {
		id.IsPlatform = flags&csPlatformBinary != 0
	}
	return id, nil
}

func (k *darwinKernel) Sockets(pid int32, w Window) (SocketList, error) {
	var res SocketList
	need, err := procInfo(callPIDInfo, int(pid), flavorListFDs, 0, nil)
	if err != nil {
		return res, err
	}
	if need <= 0 {
		return res, nil
	}
	if need > w.MaxFDs*sizeFDInfo {
		need, res.FDListCut = w.MaxFDs*sizeFDInfo, true
	}
	if cap(k.fds) < need {
		k.fds = make([]byte, need)
	}
	buf := k.fds[:need]
	n, err := procInfo(callPIDInfo, int(pid), flavorListFDs, 0, buf)
	if err != nil {
		return res, err
	}
	if n > len(buf) {
		n = len(buf)
	}
	le := binary.LittleEndian
	socks := k.sock[:0]
	for i := 0; i+sizeFDInfo <= n; i += sizeFDInfo {
		if le.Uint32(buf[i+4:]) == fdTypeSocket {
			socks = append(socks, int32(le.Uint32(buf[i:])))
		}
	}
	k.sock = socks
	res.SocketFDs = len(socks)
	count := len(socks)
	start := 0
	if count > w.Max {
		count = w.Max
		res.Capped = true
		if len(socks) > 0 {
			start = w.Start % len(socks)
			if start < 0 {
				start = 0
			}
		}
	}
	if res.FDListCut {
		res.Capped = true
	}
	var si [sizeSocketFDInfo]byte
	for j := 0; j < count; j++ {
		fd := socks[(start+j)%len(socks)]
		res.Calls++
		if res.Capped {
			res.Inspected = append(res.Inspected, fd)
		}
		m, err := procInfo(callPIDFDInfo, int(pid), flavorFDSocketInf, uint64(uint32(fd)), si[:])
		if err != nil || m != sizeSocketFDInfo {
			continue // closed meanwhile
		}
		if so, ok := parseSocket(si[:]); ok {
			so.FD = fd
			res.Socks = append(res.Socks, so)
		}
	}
	return res, nil
}

// parseSocket decodes an IPv4/IPv6 TCP or UDP socket_fdinfo.
func parseSocket(b []byte) (Socket, bool) {
	le := binary.LittleEndian
	family := int32(le.Uint32(b[offSoiFamily:]))
	if family != afInet && family != afInet6 {
		return Socket{}, false
	}
	kind := int32(le.Uint32(b[offSoiKind:]))
	proto := int32(le.Uint32(b[offSoiProto:]))
	so := Socket{TCPState: -1}
	switch {
	case kind == sockinfoTCP && proto == ipprotoTCP:
		so.Proto = "tcp"
		so.TCPState = int(int32(le.Uint32(b[offSoiUnion+offTCPSt:])))
	case kind == sockinfoIn && proto == ipprotoUDP:
		so.Proto = "udp"
	default:
		return Socket{}, false
	}
	in := b[offSoiUnion:]
	// Ports are stored in network byte order in an int.
	fport := uint16(in[offFPort])<<8 | uint16(in[offFPort+1])
	lport := uint16(in[offLPort])<<8 | uint16(in[offLPort+1])
	so.Gen = le.Uint64(in[offGenCnt:])
	vflag := in[offVFlag]
	var faddr, laddr netip.Addr
	switch {
	case vflag&iniIPv4 != 0:
		// struct in4in6_addr: 12 bytes of padding, then the IPv4 address.
		faddr = netip.AddrFrom4([4]byte(in[offFAddr+12 : offFAddr+16]))
		laddr = netip.AddrFrom4([4]byte(in[offLAddr+12 : offLAddr+16]))
	case vflag&iniIPv6 != 0:
		faddr = netip.AddrFrom16([16]byte(in[offFAddr : offFAddr+16]))
		laddr = netip.AddrFrom16([16]byte(in[offLAddr : offLAddr+16]))
	default:
		return Socket{}, false
	}
	so.Local = netip.AddrPortFrom(laddr, lport)
	if fport != 0 && !faddr.IsUnspecified() {
		so.Remote = netip.AddrPortFrom(faddr, fport)
	}
	return so, true
}
