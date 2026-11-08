//go:build darwin

package ps

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_info(2) and csops(2), called directly (pure Go, no cgo).
const (
	sysProcInfo = 336 // SYS_proc_info, <sys/syscall.h>
	sysCsops    = 169 // SYS_csops, <sys/syscall.h>

	procInfoCallPIDInfo       = 2  // PROC_INFO_CALL_PIDINFO
	procPIDUniqIdentifierInfo = 17 // PROC_PIDUNIQIDENTIFIERINFO (xnu sys/proc_info_private.h)

	csOpsStatus      = 0         // CS_OPS_STATUS
	csPlatformBinary = 0x4000000 // CS_PLATFORM_BINARY, <kern/cs_blobs.h>
)

// procUniqIdentifierInfo mirrors xnu's struct proc_uniqidentifierinfo (56
// bytes; the public SDK carries the same layout as
// crashinfo_proc_uniqidentifierinfo in <kern/kcdata.h>). Checked on macOS
// 26: p_puniqueid of a process equals p_uniqueid of its parent, and
// p_idversion equals the audit-token pidversion.
type procUniqIdentifierInfo struct {
	UUID            [16]byte
	UniqueID        uint64
	PUniqueID       uint64
	IDVersion       int32
	OrigPPIDVersion int32
	Reserve3        uint64
	Reserve4        uint64
}

// ReadUniqueID returns the kernel's per-boot unique id of pid (p_uniqueid).
// Unlike a pid it is never reused until reboot.
func ReadUniqueID(pid int32) (uint64, error) {
	id, _, err := readUniqueIdentifiers(pid)
	return id, err
}

// readUniqueIdentifiers returns p_uniqueid and p_idversion (the pidversion
// of the current incarnation) of pid.
func readUniqueIdentifiers(pid int32) (uint64, uint32, error) {
	var in procUniqIdentifierInfo
	n, _, e := unix.Syscall6(sysProcInfo, procInfoCallPIDInfo, uintptr(pid), procPIDUniqIdentifierInfo, 0,
		uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	if e != 0 {
		return 0, 0, e
	}
	if n != unsafe.Sizeof(in) {
		return 0, 0, unix.EIO
	}
	return in.UniqueID, uint32(in.IDVersion), nil
}

// readPlatform reports whether the running image of pid is an Apple
// platform binary (csops CS_OPS_STATUS, CS_PLATFORM_BINARY): kernel truth,
// unlike the kern.procargs2 path of a bootstrap entry.
func readPlatform(pid int32) (bool, error) {
	var flags uint32
	_, _, e := unix.Syscall6(sysCsops, uintptr(pid), csOpsStatus, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0, 0)
	if e != 0 {
		return false, e
	}
	return flags&csPlatformBinary != 0, nil
}
