package response

import "fmt"

// Windows ACL decision of the vault and state directories, kept free of
// Windows APIs so that it is tested on every platform (fsafe_windows.go
// reads the owner, the DACL control flags and the ACEs).

// Well-known SIDs.
const (
	SIDSystem         = "S-1-5-18"
	SIDAdministrators = "S-1-5-32-544"
)

// aclEntry is one ACE: its type (0 = access allowed), flags, mask and SID.
type aclEntry struct {
	Type, Flags uint8
	Mask        uint32
	SID         string
}

// privateACLProblem returns why a directory's security descriptor is not
// private, or "": the owner must be one of allowed, the DACL must be
// present and protected (no inheritance from the parent), and every entry
// must be an allow entry for one of allowed (deny entries only narrow
// access and are accepted).
func privateACLProblem(owner string, hasDACL, protected bool, aces []aclEntry, allowed map[string]bool) string {
	if !allowed[owner] {
		return fmt.Sprintf("owned by %s, not by SYSTEM or Administrators", owner)
	}
	if !hasDACL {
		return "has a NULL DACL (everyone has full access)"
	}
	if !protected {
		return "its DACL inherits entries from the parent directory (must be protected)"
	}
	for i, a := range aces {
		switch a.Type {
		case 0x0: // ACCESS_ALLOWED
			if !allowed[a.SID] {
				return fmt.Sprintf("ACL entry %d allows %s (only SYSTEM and Administrators may have access)", i, a.SID)
			}
		case 0x1: // ACCESS_DENIED
		default:
			return fmt.Sprintf("ACL entry %d has type %#x (only allow and deny entries are accepted)", i, a.Type)
		}
	}
	return ""
}

// privateSDDL is the security descriptor of a directory the vault or the
// state creates when ZAAFVesper runs elevated: owned by Administrators,
// protected DACL, full access for SYSTEM and Administrators only,
// inherited by every file and subdirectory.
const privateSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
