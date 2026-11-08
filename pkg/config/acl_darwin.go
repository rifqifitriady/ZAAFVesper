//go:build darwin

package config

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	attrCmnReturnedAttrs = 0x80000000 // ATTR_CMN_RETURNED_ATTRS
	fsoptPackInvalAttrs  = 0x8        // FSOPT_PACK_INVAL_ATTRS
	aclBufSize           = 8 << 10    // header + 128 ACEs fits easily
)

// readFilesec returns the kauth_filesec of path (nofollow) or of fd (when
// path is ""), or nil when the object has no extended security. Pure Go:
// getattrlist / fgetattrlist with ATTR_CMN_EXTENDED_SECURITY.
func readFilesec(path string, fd int) ([]byte, error) {
	al := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: attrCmnReturnedAttrs | unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, aclBufSize)
	var errno syscall.Errno
	if path != "" {
		p, err := syscall.BytePtrFromString(path)
		if err != nil {
			return nil, err
		}
		_, _, errno = syscall.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&al)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_NOFOLLOW|fsoptPackInvalAttrs, 0)
	} else {
		_, _, errno = syscall.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&al)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), fsoptPackInvalAttrs, 0)
	}
	if errno != 0 {
		return nil, errno
	}
	// u_int32_t length; attribute_set_t returned (5 x u_int32_t);
	// attrreference_t {int32 offset (from the reference), u_int32_t length}.
	le := binary.LittleEndian
	total := int(le.Uint32(buf[0:4]))
	if total < 32 || total > len(buf) {
		return nil, fmt.Errorf("getattrlist: bad reply length %d", total)
	}
	if le.Uint32(buf[4:8])&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		return nil, nil // no extended security
	}
	off := int(int32(le.Uint32(buf[24:28])))
	n := int(le.Uint32(buf[28:32]))
	if n == 0 {
		return nil, nil
	}
	start := 24 + off
	if off < 0 || start+n > total {
		return nil, fmt.Errorf("getattrlist: ACL outside the reply")
	}
	return buf[start : start+n], nil
}

func checkACL(path string, fd int) error {
	fs, err := readFilesec(path, fd)
	if err != nil {
		return fmt.Errorf("cannot read ACL: %w", err)
	}
	why, err := writePermitACE(fs)
	if err != nil {
		return err
	}
	if why != "" {
		return fmt.Errorf("%s (remove it with chmod -N)", why)
	}
	return nil
}

// checkACLPath rejects path (not following a final symbolic link) when an
// ACL entry permits anyone a write-like right.
func checkACLPath(path string) error { return checkACL(path, -1) }

// checkACLFd is checkACLPath on an open descriptor.
func checkACLFd(fd int) error { return checkACL("", fd) }
