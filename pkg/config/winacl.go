package config

import "fmt"

// Windows security descriptor evaluation, kept free of Windows APIs so the
// decision logic is tested on every platform (files_windows.go extracts the
// owner and the ACEs and calls winACLProblem).

// Well-known SIDs that may own or write ZAAFVesper's files on Windows.
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	// sidOwnerRights stands for the object's owner, which is checked to be
	// one of the trusted SIDs before any ACE is looked at.
	sidOwnerRights = "S-1-3-4"
)

var trustedWinSIDs = map[string]bool{sidSystem: true, sidAdministrators: true, sidTrustedInstaller: true}

// ACE types (winnt.h) whose effect is to allow access.
const (
	aceAccessAllowed               = 0x0
	aceAccessAllowedCompound       = 0x4
	aceAccessAllowedObject         = 0x5
	aceAccessAllowedCallback       = 0x9
	aceAccessAllowedCallbackObject = 0xB
	aceFlagInheritOnly             = 0x08 // INHERIT_ONLY_ACE: does not apply to the object itself
)

// Access rights (winnt.h).
const (
	fileWriteData       = 0x0002 // FILE_WRITE_DATA / FILE_ADD_FILE
	fileAppendData      = 0x0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	fileWriteEA         = 0x0010
	fileDeleteChild     = 0x0040
	fileWriteAttributes = 0x0100
	rightDelete         = 0x00010000
	rightWriteDAC       = 0x00040000
	rightWriteOwner     = 0x00080000
	genericAll          = 0x10000000
	genericWrite        = 0x40000000
)

// winWriteRights let the holder change a file or a directory's entries,
// attributes, owner or ACL.
const winWriteRights = fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild | fileWriteAttributes |
	rightDelete | rightWriteDAC | rightWriteOwner | genericAll | genericWrite

// winAncestorRights let the holder replace, rename or re-permission an
// existing entry below an ancestor directory. Adding new entries (FILE_ADD_FILE,
// FILE_ADD_SUBDIRECTORY: Authenticated Users have the latter on C:\ by
// default) cannot replace C:\Program Files\ZAAFVesper, so it is allowed on
// ancestors only.
const winAncestorRights = fileDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner | genericAll

// winACE is one access control entry with its SID in string form.
type winACE struct {
	Type, Flags uint8
	Mask        uint32
	SID         string // "" when the ACE layout carries no plain SID (object ACEs)
}

// winACLProblem returns why a file or directory is not protected, or "":
// the owner must be SYSTEM, Administrators or TrustedInstaller; a NULL DACL
// (hasDACL false) grants everyone everything; and no allow entry that
// applies to the object itself may give any other SID a write-like right
// (ancestor directories: a right that can replace an existing entry).
// Deny, audit and label entries never grant anything and are ignored, as
// are inherit-only entries (they apply only to objects created later, and
// each file is checked again when it is read). An allow entry whose SID
// cannot be read (object ACE layouts) is refused when it carries a write
// right: fail closed.
func winACLProblem(owner string, hasDACL bool, aces []winACE, ancestor bool) string {
	if !trustedWinSIDs[owner] {
		return fmt.Sprintf("owned by %s, must be owned by SYSTEM, Administrators or TrustedInstaller", owner)
	}
	if !hasDACL {
		return "has a NULL DACL (everyone has full access)"
	}
	rights := uint32(winWriteRights)
	if ancestor {
		rights = winAncestorRights
	}
	for i, a := range aces {
		switch a.Type {
		case aceAccessAllowed, aceAccessAllowedCompound, aceAccessAllowedObject,
			aceAccessAllowedCallback, aceAccessAllowedCallbackObject:
		default:
			continue
		}
		if a.Flags&aceFlagInheritOnly != 0 || a.Mask&rights == 0 {
			continue
		}
		if a.SID != "" && (trustedWinSIDs[a.SID] || a.SID == sidOwnerRights) {
			continue
		}
		who := a.SID
		if who == "" {
			who = "an unparsed SID"
		}
		return fmt.Sprintf("ACL entry %d allows %s write-like rights %#x (remove it, e.g. icacls /inheritance:r and grant only SYSTEM and Administrators)", i, who, a.Mask&rights)
	}
	return ""
}
