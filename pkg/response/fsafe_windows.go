//go:build windows

package response

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The file actions on Windows work on handles (stored as int, like a file
// descriptor elsewhere). Every open uses FILE_FLAG_OPEN_REPARSE_POINT, so a
// symbolic link, junction or mount point is opened itself and then refused
// (fileInfo.isReg and isDir are false for a reparse point), and a directory
// is opened without FILE_SHARE_DELETE, so nobody can rename or delete it
// while it is held. A link or junction in an earlier component of the path
// is caught by comparing the handle's final path (GetFinalPathNameByHandle)
// with the path that was asked for: openDirNoFollow and openBound refuse
// when they differ (an 8.3 short name differs too).

const fileOpsSupported = true

// Synthesized st_mode type bits (Windows has none).
const (
	modeDir  = 0o040000
	modeReg  = 0o100000
	modeLink = 0o120000
	modeType = 0o170000
)

type fileInfo struct {
	Mode     uint32 // synthesized: type bits only
	Dev, Ino uint64 // volume serial number and file index
	Nlink    uint64
	Size     int64
	UID, GID uint32 // always 0
	Birth    time.Time
	Attrs    uint32 // FILE_ATTRIBUTE_*
	Owner    string // owner SID
}

func (fi fileInfo) isReg() bool { return fi.Mode&modeType == modeReg }
func (fi fileInfo) isDir() bool { return fi.Mode&modeType == modeDir }

func devKey(d uint64) uint64 { return d }

// keepXattr: Windows files carry no extended attributes the vault saves.
func keepXattr(string) bool { return false }

func handle(fd int) windows.Handle { return windows.Handle(uintptr(fd)) }

// longPath returns the \\?\ form of a checked absolute path.
func longPath(p string) (*uint16, error) { return windows.UTF16PtrFromString(`\\?\` + p) }

func createFile(p string, access, share, disposition, flags uint32) (int, error) {
	u, err := longPath(p)
	if err != nil {
		return -1, err
	}
	h, err := windows.CreateFile(u, access, share, nil, disposition, flags|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return -1, err
	}
	return int(h), nil
}

// finalPath returns the handle's final path without the \\?\ prefix. A
// network path (UNC) is an error.
func finalPath(fd int) (string, error) {
	buf := make([]uint16, 1024)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle(fd), &buf[0], uint32(len(buf)), 0 /* FILE_NAME_NORMALIZED|VOLUME_NAME_DOS */)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			p := windows.UTF16ToString(buf[:n])
			if strings.HasPrefix(p, `\\?\UNC\`) {
				return "", fmt.Errorf("network path %s", p)
			}
			p = strings.TrimPrefix(p, `\\?\`)
			return p, nil
		}
		if n > 32768 {
			return "", errors.New("final path too long")
		}
		buf = make([]uint16, n+1)
	}
}

// joinDir joins a directory's final path and a base name.
func joinDir(dir, base string) string {
	if strings.HasSuffix(dir, `\`) {
		return dir + base
	}
	return dir + `\` + base
}

func checkBase(base string) error {
	if base == "" || base == "." || base == ".." || strings.ContainsAny(base, `\/:*?"<>|`+"\x00") ||
		strings.HasSuffix(base, ".") || strings.HasSuffix(base, " ") {
		return fmt.Errorf("file name %q is not plain", base)
	}
	return nil
}

// openDirNoFollow opens the directory dir, refusing a reparse point at the
// end and (by its final path) anywhere on the way. The directory cannot be
// renamed or deleted while the handle is open.
func openDirNoFollow(dir string) (int, error) {
	if err := checkCleanAbs(dir); err != nil {
		return -1, err
	}
	fd, err := createFile(dir, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_EXISTING, 0)
	if err != nil {
		return -1, fmt.Errorf("directory %s: %w", dir, err)
	}
	fi, err := fstatInfo(fd)
	if err != nil {
		closeFD(fd)
		return -1, err
	}
	if !fi.isDir() {
		closeFD(fd)
		return -1, fmt.Errorf("directory %s: not a directory, or a link or junction", dir)
	}
	fp, err := finalPath(fd)
	if err != nil {
		closeFD(fd)
		return -1, fmt.Errorf("directory %s: %w", dir, err)
	}
	if !strings.EqualFold(strings.TrimSuffix(fp, `\`), strings.TrimSuffix(dir, `\`)) {
		closeFD(fd)
		return -1, fmt.Errorf("directory %s resolves to %s (a link or junction in the path)", dir, fp)
	}
	return fd, nil
}

func openParentNoFollow(path string) (int, string, error) {
	if err := checkCleanAbs(path); err != nil {
		return -1, "", err
	}
	i := strings.LastIndexByte(path, '\\')
	dir, base := path[:i], path[i+1:]
	if strings.HasSuffix(dir, ":") {
		dir += `\`
	}
	if err := checkBase(base); err != nil {
		return -1, "", err
	}
	fd, err := openDirNoFollow(dir)
	return fd, base, err
}

func dirPath(dirfd int, base string) (string, error) {
	if err := checkBase(base); err != nil {
		return "", err
	}
	dir, err := finalPath(dirfd)
	if err != nil {
		return "", err
	}
	return joinDir(dir, base), nil
}

// openAt opens base in dirfd for reading, without following a reparse
// point. Others may read it and delete or rename it (the delete is then
// noticed: unlinkBound compares the file id), but not write it.
func openAt(dirfd int, base string) (int, error) {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return -1, err
	}
	return createFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, windows.OPEN_EXISTING, 0)
}

func fstatInfo(fd int) (fileInfo, error) {
	var d windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle(fd), &d); err != nil {
		return fileInfo{}, err
	}
	fi := fileInfo{Dev: uint64(d.VolumeSerialNumber), Ino: uint64(d.FileIndexHigh)<<32 | uint64(d.FileIndexLow),
		Nlink: uint64(d.NumberOfLinks), Size: int64(d.FileSizeHigh)<<32 | int64(d.FileSizeLow), Attrs: d.FileAttributes,
		Birth: time.Unix(0, d.CreationTime.Nanoseconds())}
	switch {
	case d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		fi.Mode = modeLink
	case d.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		fi.Mode = modeDir | 0o700
	case d.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0:
	default:
		fi.Mode = modeReg | 0o600
	}
	if sd, err := windows.GetSecurityInfo(handle(fd), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
		if o, _, err := sd.Owner(); err == nil && o != nil {
			fi.Owner = o.String()
		}
	}
	return fi, nil
}

func fstatatInfo(dirfd int, base string) (fileInfo, error) {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return fileInfo{}, err
	}
	fd, err := createFile(p, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.OPEN_EXISTING, 0)
	if err != nil {
		return fileInfo{}, err
	}
	defer closeFD(fd)
	return fstatInfo(fd)
}

func fGetPath(fd int) (string, error) { return finalPath(fd) }

func readXattrs(int) (map[string][]byte, []string, error) { return nil, nil, nil }

var errNoXattr = errors.New("extended attributes are not used on Windows")

func setXattr(int, string, []byte, bool) error { return errNoXattr }
func hasXattr(int, string) (bool, error)       { return false, errNoXattr }

// createExcl creates base in dirfd (it must not exist); a new file inherits
// the directory's ACL.
func createExcl(dirfd int, base string, _ uint32) (*os.File, error) {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return nil, err
	}
	fd, err := createFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), p), nil
}

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
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = renameAt(dirfd, tmp, base)
	}
	if werr != nil {
		_ = unlinkAt(dirfd, tmp)
	}
	return werr
}

func unlinkAt(dirfd int, base string) error {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return err
	}
	u, err := longPath(p)
	if err != nil {
		return err
	}
	return windows.DeleteFile(u)
}

func renameAt(dirfd int, from, to string) error {
	pf, err := dirPath(dirfd, from)
	if err != nil {
		return err
	}
	pt, err := dirPath(dirfd, to)
	if err != nil {
		return err
	}
	uf, err := longPath(pf)
	if err != nil {
		return err
	}
	ut, err := longPath(pt)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(uf, ut, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func mkdirAt(dirfd int, base string, _ uint32) error {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return err
	}
	u, err := longPath(p)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(u, nil)
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = windows.CloseHandle(handle(fd))
	}
}

// fchmod and fchown: Windows files have no mode bits or uid; a restored
// file takes the directory's ACL (restoreOwner warns).
func fchmod(int, uint32) error         { return nil }
func fchown(int, uint32, uint32) error { return nil }

func flockFD(fd int) error {
	var ol windows.Overlapped
	return windows.LockFileEx(handle(fd), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

func openLockAt(dirfd int, base string) (int, error) {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return -1, err
	}
	return createFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL)
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
func isExist(err error) bool    { return errors.Is(err, os.ErrExist) }

func listDir(_ string, dirfd int) ([]string, error) {
	dir, err := finalPath(dirfd)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(`\\?\` + dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ents))
	for i, e := range ents {
		out[i] = e.Name()
	}
	return out, nil
}

func consoleUID() (uint32, error) { return 0, errors.New("no console uid on Windows") }

// isLocalFS refuses network drives (and unknown drive types).
func isLocalFS(fd int) (bool, error) {
	p, err := finalPath(fd)
	if err != nil {
		return false, err
	}
	if len(p) < 3 || p[1] != ':' {
		return false, nil
	}
	root, err := windows.UTF16PtrFromString(p[:3])
	if err != nil {
		return false, err
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
		return true, nil
	}
	return false, nil
}

// privateDir checks the directory's security descriptor: owned by SYSTEM
// or Administrators, protected DACL, access for SYSTEM and Administrators
// only. Without requireRoot (tests, an unelevated CLI) the current user is
// accepted too.
func privateDir(fd int, fi fileInfo, requireRoot bool) error {
	if !fi.isDir() {
		return errors.New("not a directory")
	}
	sd, err := windows.GetSecurityInfo(handle(fd), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("cannot read the owner: %v", err)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	hasDACL := err == nil && dacl != nil
	var aces []aclEntry
	if hasDACL {
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return err
			}
			a := aclEntry{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: uint32(ace.Mask)}
			if a.Type <= 1 {
				a.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			}
			aces = append(aces, a)
		}
	}
	allowed := map[string]bool{SIDSystem: true, SIDAdministrators: true}
	if !requireRoot {
		if u := currentUserSID(); u != "" {
			allowed[u] = true
		}
	}
	if why := privateACLProblem(owner.String(), hasDACL, ctl&windows.SE_DACL_PROTECTED != 0, aces, allowed); why != "" {
		return errors.New(why)
	}
	return nil
}

// currentUserSID is the SID of the process's user.
func currentUserSID() string {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return tu.User.Sid.String()
}

func sameFileID(fi fileInfo, dev, ino uint64) bool { return fi.Dev == dev && fi.Ino == ino }

// unlinkBound deletes base from dirfd if it is still the file fi: the name
// is opened with DELETE access (no reparse point followed), its file id
// compared, and that very handle is marked for deletion (POSIX semantics:
// the name goes at once even if others hold the file open). A name swapped
// in after the open is left alone.
func unlinkBound(dirfd int, base string, fi fileInfo) error {
	p, err := dirPath(dirfd, base)
	if err != nil {
		return err
	}
	fd, err := createFile(p, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.OPEN_EXISTING, 0)
	if err != nil {
		return err
	}
	defer closeFD(fd)
	now, err := fstatInfo(fd)
	if err != nil {
		return err
	}
	if now.Dev != fi.Dev || now.Ino != fi.Ino {
		return fmt.Errorf("the name now points to another file (volume %d id %d); left in place", now.Dev, now.Ino)
	}
	return deleteByHandle(fd)
}

// FILE_DISPOSITION_INFO_EX flags and class.
const (
	fileDispositionInfoEx       = 21 // FileDispositionInfoEx
	fileDispositionDelete       = 0x1
	fileDispositionPosix        = 0x2
	fileDispositionIgnoreReadOn = 0x10
)

// deleteByHandle marks the open file for deletion: POSIX semantics first
// (Windows 10 1709 and later), the classic disposition otherwise.
func deleteByHandle(fd int) error {
	flags := uint32(fileDispositionDelete | fileDispositionPosix | fileDispositionIgnoreReadOn)
	err := windows.SetFileInformationByHandle(handle(fd), fileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
	if err == nil {
		return nil
	}
	del := uint32(1) // FILE_DISPOSITION_INFO{DeleteFile: TRUE}
	return windows.SetFileInformationByHandle(handle(fd), windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&del)), uint32(unsafe.Sizeof(del)))
}
