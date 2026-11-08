package config

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Extended ACLs (macOS kauth). A file whose mode bits look safe can still be
// writable through an ACL entry such as "everyone allow write", so the
// ownership checks also reject any ACL entry that permits a write-like right.
// The layout below is struct kauth_filesec from <sys/kauth.h>, as returned
// by getattrlist(ATTR_CMN_EXTENDED_SECURITY).
const (
	kauthFilesecMagic = 0x012cc16d
	kauthFilesecNoACL = 0xffffffff // acl_entrycount when there is no ACL
	kauthACEKindMask  = 0xf
	kauthACEPermit    = 1

	filesecHeader = 4 + 16 + 16 // magic, owner guid, group guid
	aclHeader     = 4 + 4       // entry count, flags
	aceSize       = 16 + 4 + 4  // applicable guid, flags, rights
	maxACLEntries = 128         // KAUTH_ACL_MAX_ENTRIES
)

// aclWriteRights are the kauth rights that let the holder change the file or
// directory (or its children, owner, ACL or attributes).
const aclWriteRights = 1<<2 | // WRITE_DATA / ADD_FILE
	1<<4 | // DELETE
	1<<5 | // APPEND_DATA / ADD_SUBDIRECTORY
	1<<6 | // DELETE_CHILD
	1<<8 | // WRITE_ATTRIBUTES
	1<<10 | // WRITE_EXTATTRIBUTES
	1<<12 | // WRITE_SECURITY
	1<<13 | // TAKE_OWNERSHIP (chown)
	1<<21 | // GENERIC_ALL
	1<<23 // GENERIC_WRITE

// errNoACL means the object has no extended ACL.
var errNoACL = errors.New("no ACL")

// writePermitACE parses a kauth_filesec and returns a description of the
// first ACE that permits a write-like right, or "" when there is none. Deny,
// audit and alarm entries never grant anything and are ignored. Inheritance
// flags are ignored on purpose: an inherit-only permit would grant write on
// whatever is created inside later, so it is rejected too.
func writePermitACE(fs []byte) (string, error) {
	if len(fs) == 0 {
		return "", nil
	}
	if len(fs) < filesecHeader+aclHeader {
		return "", fmt.Errorf("short ACL (%d bytes)", len(fs))
	}
	le := binary.LittleEndian
	if m := le.Uint32(fs[0:4]); m != kauthFilesecMagic {
		return "", fmt.Errorf("unexpected ACL magic %#x", m)
	}
	n := le.Uint32(fs[filesecHeader : filesecHeader+4])
	if n == kauthFilesecNoACL {
		return "", nil
	}
	if n > maxACLEntries || filesecHeader+aclHeader+int(n)*aceSize > len(fs) {
		return "", fmt.Errorf("malformed ACL (%d entries in %d bytes)", n, len(fs))
	}
	for i := 0; i < int(n); i++ {
		off := filesecHeader + aclHeader + i*aceSize
		flags := le.Uint32(fs[off+16 : off+20])
		rights := le.Uint32(fs[off+20 : off+24])
		if flags&kauthACEKindMask == kauthACEPermit && rights&aclWriteRights != 0 {
			return fmt.Sprintf("ACL entry %d permits write-like rights %#x", i, rights&aclWriteRights), nil
		}
	}
	return "", nil
}
