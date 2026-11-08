//go:build darwin

package response

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_info(2) selectors, from <sys/proc_info.h> and libproc.c.
const (
	sysProcInfo         = 336      // SYS_proc_info
	procInfoCallPIDInfo = 2        // PROC_INFO_CALL_PIDINFO
	procPIDPathInfo     = 11       // PROC_PIDPATHINFO
	procPIDPathInfoSize = 4 * 1024 // PROC_PIDPATHINFO_MAXSIZE = 4*MAXPATHLEN
	// PROC_PIDUNIQIDENTIFIERINFO and struct proc_uniqidentifierinfo are in
	// XNU's private proc_info header, not in the public SDK. The layout is
	// the same as the SDK's struct crashinfo_proc_uniqidentifierinfo
	// (<kern/kcdata.h>): uint8_t p_uuid[16]; uint64_t p_uniqueid;
	// uint64_t p_puniqueid; then 24 bytes; 56 in all. Checked by running it:
	// launchd's p_uniqueid is 1, a child's p_puniqueid is its parent's
	// p_uniqueid, and a smaller buffer gets ENOMEM.
	procPIDUniqIdentifierInfo     = 17
	procUniqIdentifierInfoSize    = 56
	procUniqIdentifierUniqueIDOff = 16
)

// csops(2), from <sys/syscall.h> (SYS_csops = 169) and XNU's
// <sys/codesign.h> (CS_OPS_STATUS = 0, not shipped in the macOS SDK; checked
// empirically: launchd, zsh and Finder report CS_PLATFORM_BINARY, a
// third-party process does not).
const (
	sysCsops    = 169
	csOpsStatus = 0
)

// identify reads, without cgo:
//   - the process start time (kern.proc.pid, p_starttime);
//   - the kernel's path of the running image (proc_pidpath, i.e. proc_info
//     PROC_PIDPATHINFO), resolved by the kernel from the text vnode as
//     Endpoint Security resolves its executable path; ENOENT (the file was
//     unlinked after exec) is reported as ErrExeUnlinked, other failures in
//     ExeErr;
//   - the device and inode of the file now at that path (Lstat);
//   - the code-signing status flags of the running image (csops
//     CS_OPS_STATUS), which carry CS_PLATFORM_BINARY.
//
// Only a failure to read the start time is an error. Root can read every
// process; others only their own.
func identify(pid int32) (Identity, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return Identity{}, err
	}
	if kp.Proc.P_pid != pid {
		return Identity{}, fmt.Errorf("pid %d not found", pid)
	}
	id := Identity{StartTime: time.Unix(int64(kp.Proc.P_starttime.Sec), int64(kp.Proc.P_starttime.Usec)*1000).UTC()}
	if flags, err := csStatus(pid); err == nil {
		id.CSFlags, id.CSKnown = flags, true
	}
	if uid, err := uniqueID(pid); err == nil {
		id.UniqueID, id.UniqueKnown = uid, true
	}
	exe, err := procPIDPath(pid)
	switch {
	case errors.Is(err, syscall.ENOENT):
		id.ExeErr = ErrExeUnlinked
	case err != nil:
		id.ExeErr = err
	default:
		id.Exe = exe
		var st unix.Stat_t
		if err := unix.Lstat(exe, &st); err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG {
			id.Dev, id.Ino, id.HasFileID = uint64(uint32(st.Dev)), st.Ino, true
		}
	}
	return id, nil
}

// uniqueID returns the kernel's per-boot unique id of pid (p_uniqueid):
// proc_info(PROC_INFO_CALL_PIDINFO, pid, PROC_PIDUNIQIDENTIFIERINFO, 0,
// buf, 56). Unlike a pid it is never reused until reboot.
func uniqueID(pid int32) (uint64, error) {
	var buf [procUniqIdentifierInfoSize]byte
	r, _, errno := syscall.Syscall6(sysProcInfo, procInfoCallPIDInfo, uintptr(pid), procPIDUniqIdentifierInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return 0, fmt.Errorf("proc_pidinfo(%d, PROC_PIDUNIQIDENTIFIERINFO): %w", pid, errno)
	}
	if r != procUniqIdentifierInfoSize {
		return 0, fmt.Errorf("proc_pidinfo(%d, PROC_PIDUNIQIDENTIFIERINFO): %d bytes", pid, r)
	}
	id := binary.LittleEndian.Uint64(buf[procUniqIdentifierUniqueIDOff:])
	if id == 0 {
		return 0, fmt.Errorf("proc_pidinfo(%d): unique id 0", pid)
	}
	return id, nil
}

// csStatus returns the code-signing status flags of pid's running image.
func csStatus(pid int32) (uint32, error) {
	var flags uint32
	_, _, errno := syscall.Syscall6(sysCsops, uintptr(pid), csOpsStatus, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("csops(%d): %w", pid, errno)
	}
	return flags, nil
}

// procPIDPath is libproc's proc_pidpath: proc_info(PROC_INFO_CALL_PIDINFO,
// pid, PROC_PIDPATHINFO, 0, buf, 4*MAXPATHLEN). The kernel returns 0 and a
// NUL-terminated path.
func procPIDPath(pid int32) (string, error) {
	buf := make([]byte, procPIDPathInfoSize)
	_, _, errno := syscall.Syscall6(sysProcInfo, procInfoCallPIDInfo, uintptr(pid), procPIDPathInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return "", fmt.Errorf("proc_pidpath(%d): %w", pid, errno)
	}
	n := bytes.IndexByte(buf, 0)
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath(%d): empty path", pid)
	}
	return string(buf[:n]), nil
}
