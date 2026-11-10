//go:build darwin

package response

import (
	"errors"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fileOpsSupported reports whether the file actions work on this platform.
const fileOpsSupported = true

func toInfo(st *unix.Stat_t) fileInfo {
	return fileInfo{Mode: uint32(st.Mode), Dev: uint64(uint32(st.Dev)), Ino: st.Ino, Nlink: uint64(st.Nlink),
		Size: st.Size, UID: st.Uid, GID: st.Gid, Birth: time.Unix(st.Btim.Unix())}
}

// devKey is the part of an event's device number fstat reports: dev_t is
// 32 bits on macOS.
func devKey(dev uint64) uint64 { return uint64(uint32(dev)) }

func fstatInfo(fd int) (fileInfo, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileInfo{}, err
	}
	return toInfo(&st), nil
}

func fstatatInfo(dirfd int, base string) (fileInfo, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileInfo{}, err
	}
	return toInfo(&st), nil
}

// fGetPath returns the kernel's current path of the open file (F_GETPATH):
// the name as stored on disk, in its real letter case.
func fGetPath(fd int) (string, error) {
	buf := make([]byte, unix.PathMax)
	_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buf[0])))
	if e != 0 {
		return "", e
	}
	if i := strings.IndexByte(string(buf), 0); i >= 0 {
		return string(buf[:i]), nil
	}
	return "", errors.New("F_GETPATH: unterminated path")
}

// keepXattr: every extended attribute is saved on macOS (the quarantine
// attribute and the resource fork included).
func keepXattr(string) bool { return true }

func hasXattr(fd int, name string) (bool, error) {
	_, err := unix.Fgetxattr(fd, name, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOATTR):
		return false, nil
	}
	return false, err
}

// consoleUID is the owner of /dev/console: the user logged in at the
// screen (0 at the login window).
func consoleUID() (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat("/dev/console", &st); err != nil {
		return 0, err
	}
	return st.Uid, nil
}

// isLocalFS reports whether the open file lives on a local file system
// (MNT_LOCAL): a network mount could stall a copy for minutes.
func isLocalFS(fd int) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.MNT_LOCAL != 0, nil
}
