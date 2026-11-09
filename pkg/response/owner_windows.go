//go:build windows

package response

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// ownerOK reports whether the file belongs to the user of the event's
// process: the file's owner SID is the SID of the event's user name
// (Sysmon's User, DOMAIN\name). A file an elevated process created is
// owned by Administrators, not by the user, and is refused here.
func ownerOK(fi fileInfo, e *event.Event) bool {
	if e == nil || e.Proc == nil || e.Proc.Username == "" || fi.Owner == "" {
		return false
	}
	sid, _, _, err := windows.LookupSID("", e.Proc.Username)
	return err == nil && strings.EqualFold(sid.String(), fi.Owner)
}

func ownerString(fi fileInfo) string { return "owner " + fi.Owner }

// restoreOwner: a restored file takes the folder's permissions; the
// original owner is reported, not set (that needs SeRestorePrivilege).
func restoreOwner(_ int, rec QuarantineRecord) (string, error) {
	if rec.Owner != "" {
		return "owner " + rec.Owner + " not restored (the file takes the folder's permissions)", nil
	}
	return "", nil
}

// elevated reports whether the process runs with an administrator token.
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// mkdirPrivate creates base in pfd with a protected DACL: SYSTEM and
// Administrators only (privateSDDL), plus the current user when not
// elevated (tests, an unelevated CLI).
func mkdirPrivate(pfd int, base string) error {
	p, err := dirPath(pfd, base)
	if err != nil {
		return err
	}
	return mkdirSDDL(p)
}

func mkdirSDDL(p string) error {
	sddl := privateSDDL
	if !elevated() {
		sddl = fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", currentUserSID())
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	u, err := longPath(p)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(u, &sa)
}

// mkdirParent creates the missing state directory above the vault, one
// level only, private like the vault.
func mkdirParent(path string) error {
	parent := dirOf(path)
	gfd, pbase, err := openParentNoFollow(parent)
	if err != nil {
		return err
	}
	defer closeFD(gfd)
	if err := mkdirPrivate(gfd, pbase); err != nil && !isExist(err) {
		return err
	}
	return nil
}
