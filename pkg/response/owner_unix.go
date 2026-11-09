//go:build !windows

package response

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// procOwners returns the uid and euid of the event's process. A Sysmon for
// Linux event has no uid, only the user name: it is looked up in the
// passwd database.
func procOwners(e *event.Event) []int64 {
	if e == nil || e.Proc == nil {
		return nil
	}
	out := []int64{e.Proc.UID, e.Proc.EUID}
	if e.Proc.UID < 0 && e.Proc.EUID < 0 && e.Proc.Username != "" {
		if u, err := user.Lookup(e.Proc.Username); err == nil {
			if id, err := strconv.ParseInt(u.Uid, 10, 64); err == nil {
				out = append(out, id)
			}
		}
	}
	return out
}

// ownerOK reports whether the file belongs to the process of the event.
func ownerOK(fi fileInfo, e *event.Event) bool { return ownedBy(fi.UID, procOwners(e)) }

func ownerString(fi fileInfo) string { return fmt.Sprintf("uid %d", fi.UID) }

// restoreOwner gives a restored file its recorded owner. As root a failure
// is an error; otherwise a warning.
func restoreOwner(fd int, rec QuarantineRecord) (string, error) {
	if err := fchown(fd, rec.UID, rec.GID); err != nil {
		if os.Geteuid() == 0 {
			return "", fmt.Errorf("chown: %w", err)
		}
		return fmt.Sprintf("owner %d:%d not restored (%v)", rec.UID, rec.GID, err), nil
	}
	return "", nil
}

// restoreKind: only Windows stores records that are not files.
func restoreKind(rec QuarantineRecord, _ []byte, _, _ string) ([]string, error) {
	return nil, fmt.Errorf("record kind %q cannot be restored on this platform", rec.Kind)
}

// mkdirPrivate creates the vault or state directory base in pfd, 0700.
func mkdirPrivate(pfd int, base string) error { return mkdirAt(pfd, base, 0o700) }

// mkdirParent creates the missing parent of the vault (the state
// directory, 0700), one level only, without following links.
func mkdirParent(path string) error {
	gfd, pbase, err := openParentNoFollow(dirOf(path))
	if err != nil {
		return err
	}
	defer closeFD(gfd)
	if err := mkdirAt(gfd, pbase, 0o700); err != nil && !isExist(err) {
		return err
	}
	return nil
}
