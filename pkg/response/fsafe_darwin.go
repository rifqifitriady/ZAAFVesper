//go:build darwin

package response

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fileOpsSupported reports whether the file actions work on this platform.
const fileOpsSupported = true

// fileInfo is what fstat says about an open file.
type fileInfo struct {
	Mode  uint32 // st_mode (type and permission bits)
	Dev   uint64 // low 32 bits of st_dev
	Ino   uint64
	Nlink uint64
	Size  int64
	UID   uint32
	GID   uint32
}

func (fi fileInfo) isReg() bool { return fi.Mode&unix.S_IFMT == unix.S_IFREG }
func (fi fileInfo) isDir() bool { return fi.Mode&unix.S_IFMT == unix.S_IFDIR }

func toInfo(st *unix.Stat_t) fileInfo {
	return fileInfo{Mode: uint32(st.Mode), Dev: uint64(uint32(st.Dev)), Ino: st.Ino, Nlink: uint64(st.Nlink),
		Size: st.Size, UID: st.Uid, GID: st.Gid}
}

// openDirNoFollow opens the directory at the absolute, clean path dir by
// walking it from "/" one component at a time with O_NOFOLLOW: a symbolic
// link anywhere in the path refuses the open (ELOOP or ENOTDIR). Endpoint
// Security reports resolved paths (/private/tmp, not /tmp), so a real event
// path has no link in it.
func openDirNoFollow(dir string) (int, error) {
	if err := checkCleanAbs(dir); err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range strings.Split(strings.Trim(dir, "/"), "/") {
		if c == "" {
			continue
		}
		nfd, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("directory component %q: %w (missing, not a directory, or a symbolic link)", c, err)
		}
		fd = nfd
	}
	return fd, nil
}

// openParentNoFollow opens path's parent directory (see openDirNoFollow)
// and returns it with the base name.
func openParentNoFollow(path string) (int, string, error) {
	if err := checkCleanAbs(path); err != nil {
		return -1, "", err
	}
	i := strings.LastIndexByte(path, '/')
	dir, base := path[:i], path[i+1:]
	if dir == "" {
		dir = "/"
	}
	if base == "" || base == "." || base == ".." {
		return -1, "", fmt.Errorf("path %q has no file name", path)
	}
	fd, err := openDirNoFollow(dir)
	return fd, base, err
}

// openAt opens base in dirfd read-only without following a link and
// without blocking on a FIFO; the caller checks the file type with fstat.
func openAt(dirfd int, base string) (int, error) {
	return unix.Openat(dirfd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}

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

// Limits on the extended attributes saved in a quarantine sidecar.
const (
	maxXattrs      = 32
	maxXattrBytes  = 16 << 10
	maxXattrsTotal = 64 << 10
)

// readXattrs returns the extended attributes of the open file. Attributes
// over the limits are listed in skipped (by name) and not saved.
func readXattrs(fd int) (map[string][]byte, []string, error) {
	sz, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return nil, nil, err
	}
	if sz == 0 {
		return nil, nil, nil
	}
	if sz > 64<<10 {
		return nil, nil, fmt.Errorf("extended attribute list of %d bytes", sz)
	}
	names := make([]byte, sz)
	if sz, err = unix.Flistxattr(fd, names); err != nil {
		return nil, nil, err
	}
	out := map[string][]byte{}
	var skipped []string
	total := 0
	for _, n := range strings.Split(string(names[:sz]), "\x00") {
		if n == "" {
			continue
		}
		if len(out) >= maxXattrs {
			skipped = append(skipped, n)
			continue
		}
		vsz, err := unix.Fgetxattr(fd, n, nil)
		if err != nil || vsz > maxXattrBytes || total+vsz > maxXattrsTotal {
			skipped = append(skipped, n)
			continue
		}
		v := make([]byte, vsz)
		if vsz > 0 {
			if vsz, err = unix.Fgetxattr(fd, n, v); err != nil {
				skipped = append(skipped, n)
				continue
			}
		}
		total += vsz
		out[n] = v[:vsz]
	}
	return out, skipped, nil
}

func setXattr(fd int, name string, value []byte, createOnly bool) error {
	flags := 0
	if createOnly {
		flags = unix.XATTR_CREATE
	}
	return unix.Fsetxattr(fd, name, value, flags)
}

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

// createExcl creates base in dirfd (O_EXCL, no link followed) with mode.
func createExcl(dirfd int, base string, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(dirfd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), base), nil
}

// readAllAt reads base in dirfd (regular file, no link followed, at most
// max bytes).
func readAllAt(dirfd int, base string, max int64) ([]byte, error) {
	fd, err := openAt(dirfd, base)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), base)
	defer f.Close()
	fi, err := fstatInfo(fd)
	if err != nil {
		return nil, err
	}
	if !fi.isReg() {
		return nil, fmt.Errorf("%s is not a regular file", base)
	}
	if fi.Size > max {
		return nil, fmt.Errorf("%s is %d bytes, over %d", base, fi.Size, max)
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}

// writeAtomicAt writes data to base in dirfd through a temporary file and a
// rename, mode 0600.
func writeAtomicAt(dirfd int, base string, data []byte) error {
	tmp := ".tmp-" + base + "-" + randHex(8)
	f, err := createExcl(dirfd, tmp, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = unix.Renameat(dirfd, tmp, dirfd, base)
	}
	if werr != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
	}
	return werr
}

func unlinkAt(dirfd int, base string) error { return unix.Unlinkat(dirfd, base, 0) }

func renameAt(dirfd int, from, to string) error { return unix.Renameat(dirfd, from, dirfd, to) }

func mkdirAt(dirfd int, base string, mode uint32) error { return unix.Mkdirat(dirfd, base, mode) }

func closeFD(fd int) { _ = unix.Close(fd) }

func fchmod(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }

func fchown(fd int, uid, gid uint32) error { return unix.Fchown(fd, int(uid), int(gid)) }

// flockFD takes an exclusive advisory lock on fd (blocking).
func flockFD(fd int) error { return unix.Flock(fd, unix.LOCK_EX) }

// openLockAt opens (creating 0600) the lock file base in dirfd.
func openLockAt(dirfd int, base string) (int, error) {
	return unix.Openat(dirfd, base, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
}

func isNotExist(err error) bool { return errors.Is(err, syscall.ENOENT) }

func isExist(err error) bool { return errors.Is(err, syscall.EEXIST) }

// listDir returns the names in the open directory dirfd.
func listDir(name string, dirfd int) ([]string, error) {
	nfd, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), name)
	defer f.Close()
	return f.Readdirnames(-1)
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

// dirOwner returns the owner of the directory at the clean absolute path
// (no link followed in the path).
func dirOwner(path string) (uint32, error) {
	fd, err := openDirNoFollow(path)
	if err != nil {
		return 0, err
	}
	defer closeFD(fd)
	fi, err := fstatInfo(fd)
	if err != nil {
		return 0, err
	}
	return fi.UID, nil
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
