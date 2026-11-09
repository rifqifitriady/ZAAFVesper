//go:build windows

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows "root" is an elevated token (Administrators, or the
// LocalSystem service account). What is enforced:
//   - every file read through SecureRead is opened without following a
//     reparse point and, when the process is elevated, its owner must be
//     SYSTEM, Administrators or TrustedInstaller and no allow ACE may give
//     any other SID a write-like right (checked on the open handle);
//   - CheckOwnership applies the same owner and ACL rule to each path,
//     everything beneath it, and (with the narrower ancestor rule in
//     winacl.go) every ancestor directory up to the volume root, and
//     refuses any symbolic link, junction or other reparse point inside
//     the checked trees or among the ancestors (literal path, not resolved).
//
// What is not enforced: privileges such as SeBackupPrivilege or
// SeRestorePrivilege, and SeTakeOwnershipPrivilege held by an administrator
// (administrators are trusted, as root is on Unix); mandatory integrity
// labels; and alternate data streams (only the unnamed stream is read).
func init() {
	if privileged() {
		requiredOwner.Store(0)
	} else {
		requiredOwner.Store(-1)
	}
}

// privileged reports whether this process runs elevated or as LocalSystem.
func privileged() bool {
	tok := windows.GetCurrentProcessToken()
	if tok.IsElevated() {
		return true
	}
	u, err := tok.GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// checkOpenFile checks the security descriptor of the handle SecureRead
// opened (owner and DACL), so the bytes read are those of the checked file.
func checkOpenFile(path string, f *os.File, _ fs.FileInfo, _ int64) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read the security descriptor: %w", path, err)
	}
	if why := describeSD(sd, false); why != "" {
		return fmt.Errorf("%s: %s", path, why)
	}
	return nil
}

// describeSD extracts the owner and the ACEs and applies winACLProblem.
func describeSD(sd *windows.SECURITY_DESCRIPTOR, ancestor bool) string {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "cannot read the owner"
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return winACLProblem(owner.String(), false, nil, ancestor) // no DACL at all: full access
		}
		return "cannot read the DACL: " + err.Error()
	}
	if dacl == nil {
		return winACLProblem(owner.String(), false, nil, ancestor)
	}
	aces := make([]winACE, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Sprintf("cannot read ACL entry %d: %v", i, err)
		}
		a := winACE{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: uint32(ace.Mask)}
		switch a.Type {
		case aceAccessAllowed, aceAccessAllowedCallback, 1, 0xA, 2, 3, 0xD, 0xE: // SID follows the mask
			a.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		aces = append(aces, a)
	}
	return winACLProblem(owner.String(), true, aces, ancestor)
}

func isReparse(fi fs.FileInfo) bool {
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return true
	}
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return false
}

func checkPathSD(p string, ancestor bool) error {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read the security descriptor: %w", p, err)
	}
	if why := describeSD(sd, ancestor); why != "" {
		what := ""
		if ancestor {
			what = "parent directory "
		}
		return fmt.Errorf("%s: %s%s", p, what, why)
	}
	return nil
}

// checkOwnership is the Windows walk (wantUID is unused: the trusted owners
// are fixed SIDs).
func checkOwnership(_ uint32, paths ...string) error {
	var errs []error
	seen := map[string]bool{}
	check := func(p string, fi fs.FileInfo, ancestor bool) {
		if seen[p] {
			return
		}
		seen[p] = true
		if !ancestor && isReparse(fi) {
			errs = append(errs, fmt.Errorf("%s: is a symbolic link, junction or reparse point (not allowed when running elevated)", p))
			return
		}
		if err := checkPathSD(p, ancestor); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Ancestors, on the literal path: a symbolic link or junction above
		// the checked tree is refused outright. Its target could pass the
		// checks while whoever owns the link can point it elsewhere later
		// (security review, finding 2).
		for d := filepath.Dir(abs); ; d = filepath.Dir(d) {
			fi, err := os.Lstat(d)
			if err != nil {
				errs = append(errs, err)
				break
			}
			if isReparse(fi) && !seen[d] {
				seen[d] = true
				errs = append(errs, fmt.Errorf("%s: parent directory is a symbolic link, junction or other reparse point (not allowed when running elevated)", d))
				break
			}
			check(d, fi, true)
			if d == filepath.Dir(d) {
				break
			}
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !fi.IsDir() || isReparse(fi) {
			check(abs, fi, false)
			continue
		}
		err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			info, err := os.Lstat(path)
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			check(path, info, false)
			if info.IsDir() && isReparse(info) {
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CreatePrivate creates a new file; it fails if the path already exists,
// symbolic link included (CREATE_NEW). The file inherits the directory's
// ACL: ZAAFVesper's output directory is created SYSTEM/Administrators-only
// by the install steps in packaging/windows.
func CreatePrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
