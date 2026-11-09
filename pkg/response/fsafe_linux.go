//go:build linux

package response

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// fileOpsSupported reports whether the file actions work on this platform.
const fileOpsSupported = true

// statxMask is what the file actions read: the basic fields and the birth
// time (ext4, xfs, btrfs and tmpfs record it on current kernels).
const statxMask = unix.STATX_BASIC_STATS | unix.STATX_BTIME

func statxInfo(st *unix.Statx_t) fileInfo {
	fi := fileInfo{Mode: uint32(st.Mode), Dev: unix.Mkdev(st.Dev_major, st.Dev_minor), Ino: st.Ino, Nlink: uint64(st.Nlink),
		Size: int64(st.Size), UID: st.Uid, GID: st.Gid}
	if st.Mask&unix.STATX_BTIME != 0 {
		fi.Birth = time.Unix(st.Btime.Sec, int64(st.Btime.Nsec))
	}
	return fi
}

// devKey: Linux device numbers are compared whole.
func devKey(dev uint64) uint64 { return dev }

func fstatInfo(fd int) (fileInfo, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, statxMask, &st); err != nil {
		return fileInfo{}, err
	}
	return statxInfo(&st), nil
}

func fstatatInfo(dirfd int, base string) (fileInfo, error) {
	var st unix.Statx_t
	if err := unix.Statx(dirfd, base, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_SYNC_AS_STAT, statxMask, &st); err != nil {
		return fileInfo{}, err
	}
	return statxInfo(&st), nil
}

// fGetPath returns the kernel's current path of the open file (the
// /proc/self/fd link). A file that was unlinked since is refused.
func fGetPath(fd int) (string, error) {
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(p, " (deleted)") || !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("the file has no path any more (%q)", p)
	}
	return p, nil
}

// keepXattr: only the user namespace is saved and restored. security.*
// (file capabilities, SELinux labels) and trusted.* are never put back by a
// restore, like the setuid bit.
func keepXattr(name string) bool { return strings.HasPrefix(name, "user.") }

func hasXattr(fd int, name string) (bool, error) {
	_, err := unix.Fgetxattr(fd, name, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENODATA):
		return false, nil
	}
	return false, err
}

// consoleUID: Linux has no console user for launchd domains.
func consoleUID() (uint32, error) { return 0, errors.New("no console user on Linux") }

// Network and FUSE file systems, refused by isLocalFS: a copy from them
// could stall for minutes, and their answers come from another machine or
// a user-space daemon.
var remoteFS = map[int64]string{
	0x6969: "nfs", 0xff534d42: "cifs", 0xfe534d42: "smb2", 0x517b: "smb", 0x65735546: "fuse",
	0x564c: "ncp", 0x01021997: "9p", 0x00c36400: "ceph", 0x47504653: "gpfs", 0x0bd00bd0: "lustre", 0x5346414f: "afs", 0x6b414653: "afs",
}

// isLocalFS reports whether the open file lives on a local file system.
func isLocalFS(fd int) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return false, err
	}
	_, remote := remoteFS[int64(st.Type)]
	return !remote, nil
}
