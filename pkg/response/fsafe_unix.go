//go:build darwin || linux

package response

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// fileInfo is what fstat says about an open file.
type fileInfo struct {
	Mode  uint32 // st_mode (type and permission bits)
	Dev   uint64 // low 32 bits of st_dev
	Ino   uint64
	Nlink uint64
	Size  int64
	UID   uint32
	GID   uint32
	// Birth is the file's creation time (zero when the file system does
	// not record it): what a Sysmon file event's CreationUtcTime is bound to.
	Birth time.Time
	// Attrs are Windows file attributes, Owner the Windows owner SID
	// (always empty here).
	Attrs uint32
	Owner string
}

func (fi fileInfo) isReg() bool { return fi.Mode&unix.S_IFMT == unix.S_IFREG }
func (fi fileInfo) isDir() bool { return fi.Mode&unix.S_IFMT == unix.S_IFDIR }

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
		if !keepXattr(n) {
			skipped = append(skipped, n)
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

// privateDir checks that the open directory (fstat info fi) is closed to
// group and others and owned by root (requireRoot) or the effective user:
// the vault and the state directory.
func privateDir(_ int, fi fileInfo, requireRoot bool) error {
	owner := uint32(os.Geteuid())
	if requireRoot {
		owner = 0
	}
	switch {
	case !fi.isDir():
		return errors.New("not a directory")
	case fi.Mode&0o077 != 0:
		return fmt.Errorf("mode %04o is open to group or others (must be 0700)", fi.Mode&0o7777)
	case fi.UID != owner:
		return fmt.Errorf("owned by uid %d, not %d", fi.UID, owner)
	}
	return nil
}

// sameFileID compares the file identity of the event (dev, ino) with fstat.
func sameFileID(fi fileInfo, dev, ino uint64) bool { return fi.Dev == devKey(dev) && fi.Ino == ino }

// unlinkBound removes base from dirfd if it is still the file fi (no link
// followed). A name swapped in after the open is left alone.
func unlinkBound(dirfd int, base string, fi fileInfo) error {
	now, err := fstatatInfo(dirfd, base)
	if err != nil {
		return err
	}
	if now.Dev != fi.Dev || now.Ino != fi.Ino {
		return fmt.Errorf("the name now points to another file (dev=%d ino=%d); left in place", now.Dev, now.Ino)
	}
	return unlinkAt(dirfd, base)
}
