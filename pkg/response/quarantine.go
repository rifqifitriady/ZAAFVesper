package response

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// QuarantineXattr is the extended attribute Gatekeeper reads.
const QuarantineXattr = "com.apple.quarantine"

// maxSidecarBytes bounds a sidecar file the vault reads back.
const maxSidecarBytes = 4 << 20

// maxRecordsPerID bounds the records kept for one content hash; the
// oldest are dropped first, also when the sidecar would grow past half of
// maxSidecarBytes.
const maxRecordsPerID = 16

// vaultLock is the lock file that serialises the sensor and the CLI.
const vaultLock = ".lock"

// QuarantineRecord describes one quarantined file (one entry of a sidecar).
type QuarantineRecord struct {
	ID            string            `json:"id"` // SHA-256 of the content: the vault file's name
	Time          time.Time         `json:"time"`
	Action        string            `json:"action"` // quarantine_file or remove_persistence
	OriginalPath  string            `json:"original_path"`
	Size          int64             `json:"size"`
	UID           uint32            `json:"uid"`
	GID           uint32            `json:"gid"`
	Mode          uint32            `json:"mode"` // permission bits as found (07777)
	Xattrs        map[string][]byte `json:"xattrs,omitempty"`
	XattrsSkipped []string          `json:"xattrs_skipped,omitempty"`
	Rule          string            `json:"rule,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	PID           int32             `json:"pid,omitempty"`
	Exe           string            `json:"exe,omitempty"`
	Label         string            `json:"label,omitempty"` // remove_persistence: the launchd label, systemd unit or Windows name
	// Kind is empty for a file. Windows remove_persistence also stores
	// "registry-value" (Run/RunOnce), "service" and "scheduled-task"
	// records, whose content is the saved definition (restoreKind).
	Kind  string `json:"kind,omitempty"`
	Owner string `json:"owner,omitempty"` // Windows: owner SID of the file
}

// sidecar is <id>.json in the vault.
type sidecar struct {
	ID      string             `json:"id"`
	Records []QuarantineRecord `json:"records"`
}

// Vault is the root-only quarantine directory: <sha256> holds the content
// (mode 0400, so no exec bit), <sha256>.json its records.
type Vault struct {
	Dir string
	// RequireRootOwned: the directory must be owned by root (production);
	// otherwise by the effective user (tests).
	RequireRootOwned bool
}

// open opens the vault directory without following links, creating it
// (0700) when create is set, and checks it is a directory closed to group
// and others and owned by root (or the effective user).
func (v Vault) open(create bool) (int, error) {
	fd, err := openDirNoFollow(v.Dir)
	if err != nil && create && isNotExist(errors.Unwrap(err)) {
		pfd, base, perr := openParentNoFollow(v.Dir)
		if perr != nil && isNotExist(errors.Unwrap(perr)) {
			perr = mkdirParent(v.Dir)
			if perr == nil {
				pfd, base, perr = openParentNoFollow(v.Dir)
			}
		}
		if perr != nil {
			return -1, fmt.Errorf("quarantine vault %s: %w", v.Dir, perr)
		}
		merr := mkdirPrivate(pfd, base)
		closeFD(pfd)
		if merr != nil && !isExist(merr) {
			return -1, fmt.Errorf("quarantine vault %s: %w", v.Dir, merr)
		}
		fd, err = openDirNoFollow(v.Dir)
	}
	if err != nil {
		return -1, fmt.Errorf("quarantine vault %s: %w", v.Dir, err)
	}
	fi, err := fstatInfo(fd)
	if err != nil {
		closeFD(fd)
		return -1, err
	}
	if err := privateDir(fd, fi, v.RequireRootOwned); err != nil {
		closeFD(fd)
		return -1, fmt.Errorf("quarantine vault %s: %w", v.Dir, err)
	}
	return fd, nil
}

// lockDir takes the lock of an open directory; the returned func releases it.
func lockDir(dirfd int) (func(), error) {
	lfd, err := openLockAt(dirfd, vaultLock)
	if err != nil {
		return nil, err
	}
	if err := flockFD(lfd); err != nil {
		closeFD(lfd)
		return nil, err
	}
	return func() { closeFD(lfd) }, nil
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func readSidecar(vfd int, id string) (*sidecar, error) {
	b, err := readAllAt(vfd, id+".json", maxSidecarBytes)
	if err != nil {
		return nil, err
	}
	var sc sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("sidecar %s.json: %w", id, err)
	}
	if sc.ID != id {
		return nil, fmt.Errorf("sidecar %s.json names id %q", id, sc.ID)
	}
	return &sc, nil
}

func writeSidecar(vfd int, sc *sidecar) error {
	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicAt(vfd, sc.ID+".json", append(b, '\n'))
}

// store copies the open regular file src (fstat info fi) into the vault,
// hashing it, and appends rec to its sidecar. The copy is created 0400 (no
// exec bit). It fails, leaving nothing behind, when the file changed size
// while it was copied or is over max bytes. An existing sidecar that cannot
// be read is never overwritten.
//
// expectID, when set, is the SHA-256 the content must have (the image hash
// of a Sysmon process event): any other content is not stored.
func (v Vault) store(src *os.File, fi fileInfo, max int64, rec QuarantineRecord, expectID string) (string, error) {
	vfd, err := v.open(true)
	if err != nil {
		return "", err
	}
	defer closeFD(vfd)
	unlock, err := lockDir(vfd)
	if err != nil {
		return "", err
	}
	defer unlock()
	tmp := ".tmp-" + randHex(8)
	dst, err := createExcl(vfd, tmp, 0o400)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, max+1))
	if cerr == nil {
		cerr = dst.Sync()
	}
	if err := dst.Close(); cerr == nil {
		cerr = err
	}
	if cerr == nil {
		switch now, err := fstatInfo(int(src.Fd())); {
		case err != nil:
			cerr = err
		case n > max:
			cerr = fmt.Errorf("file grew over the cap of %d bytes while it was copied", max)
		case n != fi.Size || now.Size != fi.Size:
			cerr = fmt.Errorf("file changed while it was copied (%d bytes copied, %d before, %d now)", n, fi.Size, now.Size)
		}
	}
	if cerr != nil {
		_ = unlinkAt(vfd, tmp)
		return "", cerr
	}
	id := hex.EncodeToString(h.Sum(nil))
	if expectID != "" && id != expectID {
		_ = unlinkAt(vfd, tmp)
		return "", fmt.Errorf("content SHA-256 %s is not the %s the event reported (file replaced since the event)", id, expectID)
	}
	return id, v.commit(vfd, tmp, id, rec)
}

// storeData stores data (a saved registry value, service or task
// definition) like store stores a file.
func (v Vault) storeData(data []byte, rec QuarantineRecord) (string, error) {
	vfd, err := v.open(true)
	if err != nil {
		return "", err
	}
	defer closeFD(vfd)
	unlock, err := lockDir(vfd)
	if err != nil {
		return "", err
	}
	defer unlock()
	tmp := ".tmp-" + randHex(8)
	dst, err := createExcl(vfd, tmp, 0o400)
	if err != nil {
		return "", err
	}
	_, werr := dst.Write(data)
	if werr == nil {
		werr = dst.Sync()
	}
	if err := dst.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		_ = unlinkAt(vfd, tmp)
		return "", werr
	}
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])
	return id, v.commit(vfd, tmp, id, rec)
}

// commit renames the copied content tmp to its id and appends rec to the
// id's sidecar. An existing sidecar that cannot be read is never
// overwritten. Caller holds the vault lock.
func (v Vault) commit(vfd int, tmp, id string, rec QuarantineRecord) error {
	sc, err := readSidecar(vfd, id)
	switch {
	case err == nil:
	case isNotExist(err):
		sc = &sidecar{ID: id}
	default:
		_ = unlinkAt(vfd, tmp)
		return fmt.Errorf("the existing record of %s cannot be read (%v); not overwritten", id, err)
	}
	if err := renameAt(vfd, tmp, id); err != nil {
		_ = unlinkAt(vfd, tmp)
		return err
	}
	rec.ID = id
	sc.Records = append(sc.Records, rec)
	if len(sc.Records) > maxRecordsPerID {
		sc.Records = sc.Records[len(sc.Records)-maxRecordsPerID:]
	}
	for len(sc.Records) > 1 {
		if b, err := json.Marshal(sc); err == nil && len(b) < maxSidecarBytes/2 {
			break
		}
		sc.Records = sc.Records[1:]
	}
	if err := writeSidecar(vfd, sc); err != nil {
		return fmt.Errorf("vault: content stored as %s but its record could not be written: %w", id, err)
	}
	return nil
}

// QuarantineEntry is one vault item for `zaafvesper quarantine list`.
type QuarantineEntry struct {
	ID      string
	Records []QuarantineRecord
}

// List returns the vault's items, newest record first.
func (v Vault) List() ([]QuarantineEntry, error) {
	vfd, err := v.open(false)
	if err != nil {
		return nil, err
	}
	defer closeFD(vfd)
	names, err := listDir(v.Dir, vfd)
	if err != nil {
		return nil, err
	}
	var out []QuarantineEntry
	for _, n := range names {
		id, ok := strings.CutSuffix(n, ".json")
		if !ok || !validID(id) {
			continue
		}
		sc, err := readSidecar(vfd, id)
		if err != nil || len(sc.Records) == 0 {
			continue
		}
		out = append(out, QuarantineEntry{ID: id, Records: sc.Records})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Records[len(out[i].Records)-1].Time.After(out[j].Records[len(out[j].Records)-1].Time)
	})
	return out, nil
}

// resolve finds the one item whose id starts with prefix (at least 8
// hexadecimal characters). The id used for any path is the vault's own
// (64 lowercase hex), never the user's string.
func (v Vault) resolve(prefix string) (string, error) {
	prefix = strings.ToLower(prefix)
	if len(prefix) < 8 || len(prefix) > 64 {
		return "", errors.New("give at least the first 8 characters of the id (see 'zaafvesper quarantine list')")
	}
	for _, c := range prefix {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", fmt.Errorf("id %q is not hexadecimal", prefix)
		}
	}
	items, err := v.List()
	if err != nil {
		return "", err
	}
	var found []string
	for _, it := range items {
		if strings.HasPrefix(it.ID, prefix) {
			found = append(found, it.ID)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no quarantined item with id %s", prefix)
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("id %s is ambiguous (%d items); give more characters", prefix, len(found))
}

// Restore puts the newest record of item id (or a unique id prefix) back at
// its original path: the file is created there (never over an existing
// file, no link followed in the path), with its owner, its extended
// attributes (the quarantine attribute included) and its permission bits
// without setuid, setgid and sticky. The record is then dropped; the
// content goes when no record is left. Returns the restored record and
// warnings (what could not be put back).
func (v Vault) Restore(idPrefix string) (QuarantineRecord, []string, error) {
	id, err := v.resolve(idPrefix)
	if err != nil {
		return QuarantineRecord{}, nil, err
	}
	vfd, err := v.open(false)
	if err != nil {
		return QuarantineRecord{}, nil, err
	}
	defer closeFD(vfd)
	unlock, err := lockDir(vfd)
	if err != nil {
		return QuarantineRecord{}, nil, err
	}
	defer unlock()
	sc, err := readSidecar(vfd, id)
	if err != nil {
		return QuarantineRecord{}, nil, err
	}
	if len(sc.Records) == 0 {
		return QuarantineRecord{}, nil, fmt.Errorf("item %s has no record", id)
	}
	rec := sc.Records[len(sc.Records)-1]
	if rec.Kind != "" {
		// Not a plain file: a registry value, a service or a scheduled task
		// (Windows). It is put back by restoreKind from the saved content.
		data, err := readAllAt(vfd, id, maxSidecarBytes)
		if err != nil {
			return rec, nil, fmt.Errorf("vault content %s: %w", id, err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != id {
			return rec, nil, errors.New("vault content does not match its SHA-256 id")
		}
		warn, err := restoreKind(rec, data, v.Dir, id)
		if err != nil {
			return rec, warn, err
		}
		v.dropRecord(vfd, sc, id, &warn)
		return rec, warn, nil
	}
	if why := protectedPath(rec.OriginalPath, []string{v.Dir}); why != "" {
		return rec, nil, fmt.Errorf("refusing to restore to %s: %s", rec.OriginalPath, why)
	}
	cfd, err := openAt(vfd, id)
	if err != nil {
		return rec, nil, fmt.Errorf("vault content %s: %w", id, err)
	}
	src := os.NewFile(uintptr(cfd), id)
	defer src.Close()
	if fi, err := fstatInfo(cfd); err != nil || !fi.isReg() {
		return rec, nil, fmt.Errorf("vault content %s is not a regular file", id)
	}
	dfd, base, err := openParentNoFollow(rec.OriginalPath)
	if err != nil {
		return rec, nil, fmt.Errorf("original directory: %w", err)
	}
	defer closeFD(dfd)
	dst, err := createExcl(dfd, base, 0o600)
	if err != nil {
		if isExist(err) {
			return rec, nil, fmt.Errorf("%s exists; move it away first", rec.OriginalPath)
		}
		return rec, nil, err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(dst, h), src)
	if cerr == nil && hex.EncodeToString(h.Sum(nil)) != id {
		cerr = errors.New("vault content does not match its SHA-256 id")
	}
	var warn []string
	if cerr == nil {
		var w string
		w, cerr = restoreOwner(int(dst.Fd()), rec)
		if w != "" {
			warn = append(warn, w)
		}
	}
	if cerr == nil {
		names := make([]string, 0, len(rec.Xattrs))
		for n := range rec.Xattrs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err := setXattr(int(dst.Fd()), n, rec.Xattrs[n], false); err != nil {
				warn = append(warn, fmt.Sprintf("extended attribute %s not restored (%v)", n, err))
			}
		}
		if len(rec.XattrsSkipped) > 0 {
			warn = append(warn, "extended attributes not saved at quarantine: "+strings.Join(rec.XattrsSkipped, ", "))
		}
		if rec.Mode&0o7000 != 0 {
			warn = append(warn, fmt.Sprintf("setuid/setgid/sticky bits %04o not restored", rec.Mode&0o7000))
		}
		cerr = fchmod(int(dst.Fd()), rec.Mode&0o777)
	}
	if cerr == nil {
		cerr = dst.Sync()
	}
	if err := dst.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = unlinkAt(dfd, base)
		return rec, warn, cerr
	}
	v.dropRecord(vfd, sc, id, &warn)
	return rec, warn, nil
}

// dropRecord removes the newest record of a restored item; the content goes
// when no record is left. Caller holds the vault lock.
func (v Vault) dropRecord(vfd int, sc *sidecar, id string, warn *[]string) {
	sc.Records = sc.Records[:len(sc.Records)-1]
	if len(sc.Records) == 0 {
		_ = unlinkAt(vfd, id)
		_ = unlinkAt(vfd, id+".json")
	} else if err := writeSidecar(vfd, sc); err != nil {
		*warn = append(*warn, "restored, but the vault record could not be updated: "+err.Error())
	}
}

// fileBind is what ties a file action to the file its event named. One of
// the bindings must be present, or the action is refused: acting on
// whatever is at the path now would let an attacker point root at another
// file.
type fileBind struct {
	// Dev and Ino: the inode the event named (eslogger; strongest).
	Dev, Ino uint64
	// Birth: the file's creation time (Sysmon CreationUtcTime). Weaker than
	// an inode: the file must also have exactly one name.
	Birth time.Time
	// SHA256: the content hash the event reported (Sysmon process create,
	// for target process). The copy in the vault must have it.
	SHA256 string
}

func (b fileBind) none() bool { return b.Dev == 0 && b.Ino == 0 && b.Birth.IsZero() && b.SHA256 == "" }

func (b fileBind) String() string {
	switch {
	case b.Dev != 0 || b.Ino != 0:
		return fmt.Sprintf("dev=%d ino=%d", b.Dev, b.Ino)
	case !b.Birth.IsZero():
		return "created " + b.Birth.UTC().Format("2006-01-02 15:04:05.000")
	case b.SHA256 != "":
		return "sha256 " + b.SHA256
	}
	return "unbound"
}

// sysmonTimeLayout is the layout of Sysmon's UtcTime and CreationUtcTime.
const sysmonTimeLayout = "2006-01-02 15:04:05.000"

// fileTarget returns the path and the binding of an action's file: the
// event's file (its destination for a rename) or, for target process, the
// executable of the event's process.
func fileTarget(e *event.Event, target string) (path string, b fileBind, why string) {
	if target == TargetProcess {
		if e.Proc == nil || e.Proc.Exe == "" {
			return "", b, "event has no executable"
		}
		if e.Proc.IsPlatform {
			return e.Proc.Exe, b, "Apple platform binary"
		}
		b.Dev, b.Ino = e.Proc.ExeDev, e.Proc.ExeIno
		if b.Dev == 0 && b.Ino == 0 {
			b.SHA256 = hashOf(e.Proc.Hashes, "SHA256")
		}
		return e.Proc.Exe, b, ""
	}
	if e.File == nil || e.File.Path == "" {
		return "", b, "event has no file"
	}
	path = e.File.Path
	if e.Name == event.RenameFile && e.File.Dest != "" {
		path = e.File.Dest // same inode, new name
	}
	b.Dev, b.Ino = e.File.Dev, e.File.Ino
	if b.Dev == 0 && b.Ino == 0 && e.Name == event.CreateFile {
		if t, err := time.Parse(sysmonTimeLayout, e.Args["creation_utc_time"]); err == nil && !t.IsZero() {
			b.Birth = t
		}
	}
	return path, b, ""
}

// hashOf returns the lower-case hash named alg ("SHA256") from a Sysmon
// Hashes value ("SHA1=..,MD5=..,SHA256=..,IMPHASH=.."), or "".
func hashOf(hashes, alg string) string {
	for _, kv := range strings.Split(hashes, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok && strings.EqualFold(k, alg) {
			v = strings.ToLower(strings.TrimSpace(v))
			if alg == "SHA256" && !validID(v) {
				return ""
			}
			return v
		}
	}
	return ""
}

// openBound opens the file at path for an action: the static path checks,
// no link (or Windows reparse point) followed anywhere, the file type, the
// event's binding (required: inode, creation time, or content hash), the
// size cap (regular files), a local file system, and the kernel's own path
// of the opened file through the path checks again. On success the caller
// owns dirfd and f.
//
// With an inode binding, a file with more than one hard link is accepted
// only when it belongs to the process the event is about (ownerOK): that
// process could have made the extra names itself, so refusing would let
// any payload escape with one link() call, while a link to somebody else's
// file is still refused. The weaker bindings (creation time, hash) accept
// only a file with exactly one name that belongs to the user of the
// event's process (ownerOK: uid or euid on Linux; the owner SID, or
// Administrators for an elevated process, on Windows): in a shared folder
// (/tmp, /dev/shm, C:\Users\Public, C:\Windows\Temp, ProgramData) another
// user can create the path first, and the creation-time tolerance (Linux
// 2 s, NTFS tunneling about 15 s) would otherwise let root or SYSTEM
// quarantine that user's file. On Linux the writer must also be in the
// host mount namespace (writerMountNS): a container's path names another
// file.
func (r *Responder) openBound(path string, b fileBind, allowDir bool, max int64, e *event.Event) (dirfd int, base string, f *os.File, fi fileInfo, res *result) {
	return r.openBoundIn(path, b, allowDir, max, e, "")
}

// openBoundIn is openBound with one protected directory opened up: a file
// directly or deeper under allow (Windows: System32\Tasks, whose task files
// remove_persistence reads; it never deletes them itself) passes the
// protected-path check. Every other check applies.
func (r *Responder) openBoundIn(path string, b fileBind, allowDir bool, max int64, e *event.Event, allow string) (dirfd int, base string, f *os.File, fi fileInfo, res *result) {
	fail := func(rr result) (int, string, *os.File, fileInfo, *result) { return -1, "", nil, fileInfo{}, &rr }
	if !fileOpsSupported {
		return fail(refused(OutcomeUnsupported, ErrFileCheck, "file actions are not implemented on this platform"))
	}
	protectedPath := func(p string, extra []string) string {
		why := protectedPath(p, extra)
		if why == "" || allow == "" || checkCleanAbs(p) != nil || !hasPrefixFold(p, allow) || len(p) == len(allow) {
			return why
		}
		for _, x := range extra { // the sensor's own files stay protected
			if x != "" && (strings.EqualFold(p, x) || hasPrefixFold(p, strings.TrimSuffix(x, sep)+sep)) {
				return "ZAAFVesper's own file or directory " + x
			}
		}
		return ""
	}
	if why := protectedPath(path, r.cfg.ProtectPaths); why != "" {
		return fail(refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why))
	}
	if b.none() {
		return fail(refused(OutcomeFileCheck, ErrFileCheck, "the event carries no file identity (dev/ino, creation time or hash); refusing to act on whatever is at the path now"))
	}
	// The opened-up directory (System32\Tasks) is writable by SYSTEM and
	// administrators only, so no other user can create a file there first,
	// and the Task Scheduler writes the file for whoever registered the
	// task: its owner says nothing about the writer. Everywhere else the
	// owner of a file bound by creation time or hash must be the writer.
	ownerChecked := !(allow != "" && hasPrefixASCIIFold(path, allow))
	if runtime.GOOS == "darwin" {
		bundlePath := path
		if allowDir {
			bundlePath = path + "/-" // a bundle directory is checked as a bundle itself
		}
		if why := r.checkBundles(bundlePath); why != "" {
			return fail(refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why))
		}
	}
	dirfd, base, err := openParentNoFollow(path)
	if err != nil {
		return fail(refused(OutcomeFileCheck, ErrFileCheck, "%v", err))
	}
	fd, err := openAt(dirfd, base)
	if err != nil {
		closeFD(dirfd)
		return fail(refused(OutcomeFileCheck, ErrFileCheck, "open %s: %v (gone, or a symbolic link)", base, err))
	}
	f = os.NewFile(uintptr(fd), path)
	bad := func(format string, args ...any) (int, string, *os.File, fileInfo, *result) {
		_ = f.Close()
		closeFD(dirfd)
		return fail(refused(OutcomeFileCheck, ErrFileCheck, format, args...))
	}
	fi, err = fstatInfo(fd)
	if err != nil {
		return bad("fstat: %v", err)
	}
	if !fi.isReg() && !(allowDir && fi.isDir()) {
		return bad("not a regular file (mode %o, attributes %#x)", fi.Mode, fi.Attrs)
	}
	switch {
	case b.Dev != 0 || b.Ino != 0:
		switch {
		case !sameFileID(fi, b.Dev, b.Ino):
			return bad("file at the path is dev=%d ino=%d, the event's was %s (replaced since the event)", fi.Dev, fi.Ino, b)
		case fi.isReg() && fi.Nlink != 1 && !ownerOK(fi, e):
			return bad("file has %d hard links and belongs to %s, not to the process of the event", fi.Nlink, ownerString(fi))
		}
	case !b.Birth.IsZero():
		d := fi.Birth.Sub(b.Birth)
		if d < 0 {
			d = -d
		}
		switch {
		case fi.Birth.IsZero():
			return bad("the file system does not record creation times; the file cannot be bound to the event")
		case d > birthTolerance:
			return bad("file at the path was created %s, the event's was %s (replaced since the event)",
				fi.Birth.UTC().Format(sysmonTimeLayout), b.Birth.UTC().Format(sysmonTimeLayout))
		case fi.Nlink != 1:
			return bad("file has %d names; a file bound by creation time must have one", fi.Nlink)
		case ownerChecked && !ownerOK(fi, e):
			return bad("file belongs to %s, not to the user of the process of the event; a file bound by creation time must be the writer's own (in a shared folder another user can put a file at the path first)", ownerString(fi))
		}
	default: // content hash: checked when the copy is made (Vault.store)
		switch {
		case fi.Nlink != 1:
			return bad("file has %d names; a file bound by its hash must have one", fi.Nlink)
		case ownerChecked && !ownerOK(fi, e):
			return bad("file belongs to %s, not to the user of the process of the event; a file bound by its hash must be that user's own", ownerString(fi))
		}
	}
	if b.Dev == 0 && b.Ino == 0 && r.writerNS != nil {
		// A path from the event names a file as its process sees it.
		if err := r.writerNS(procOf(e)); err != nil {
			return bad("%v", err)
		}
	}
	if fi.isReg() && fi.Size > max {
		return bad("file is %d bytes, over the cap of %d", fi.Size, max)
	}
	if local, err := isLocalFS(fd); err != nil || !local {
		return bad("not on a local file system (a network mount could stall the copy)")
	}
	kpath, err := fGetPath(fd)
	if err != nil {
		return bad("cannot read the kernel's path of the opened file: %v", err)
	}
	if why := protectedPath(kpath, r.cfg.ProtectPaths); why != "" {
		_ = f.Close()
		closeFD(dirfd)
		return fail(refused(OutcomeProtectedPath, ErrProtectedPath, "%s (kernel path %s)", why, kpath))
	}
	if !samePathFold(kpath, path) && runtime.GOOS != "darwin" {
		// macOS reports firmlinked paths (/System/Volumes/Data/...) here;
		// elsewhere any other name means a link or junction on the way.
		return bad("the kernel's path of the opened file is %s, not %s (a link or junction in the path)", kpath, path)
	}
	return dirfd, base, f, fi, nil
}

// samePathFold compares two paths with case folding.
func samePathFold(a, b string) bool { return strings.EqualFold(a, b) }

func ownedBy(uid uint32, owners []int64) bool {
	for _, o := range owners {
		if o >= 0 && uint32(o) == uid {
			return true
		}
	}
	return false
}

// linksNote says how many other names of the file remain after its event
// name was removed.
func linksNote(fi fileInfo) string {
	if fi.Nlink > 1 {
		return fmt.Sprintf("; %d other hard link(s) to the same file remain", fi.Nlink-1)
	}
	return ""
}

// untrustedRemover is requarantine's own check of the rule's judgement
// (macro untrusted_quarantine_remover): the remover has no verified
// identity, or it is an Apple tool (xattr) whose parent is unknown or has
// none.
func untrustedRemover(p *event.Proc) bool {
	if !p.IsPlatform {
		return !verifiedVendor(p)
	}
	// Unlike untrustedChain, ps.ancestors_untrusted is not used here: the
	// rule judges only the direct parent (macro untrusted_quarantine_remover).
	par := p.Parent
	return par == nil || par.Seeded || !(par.IsPlatform || verifiedVendor(par))
}

func procOf(e *event.Event) *event.Proc {
	if e == nil || e.Proc == nil {
		return &event.Proc{}
	}
	return e.Proc
}

// QuarantineFile moves the file of the event (target file: the event's
// file, its destination for a rename; target process: the executable of the
// event's process) into the vault and removes it from its place. Guard
// rails: see openBound, plus never an Apple platform binary, the executable
// of target process must belong to the process, and the process of the
// event must not be seeded or unverified. It acts after the event: a
// process already running from the file keeps running.
func (r *Responder) QuarantineFile(e *event.Event, target, rule, reason string) error {
	var run func() error
	run = func() error {
		return r.retryOnLimit(fileRetryKey(ActionQuarantineFile, rule, e, target), rule, reason, r.quarantineFile(e, target, rule, reason), run)
	}
	return run()
}

func (r *Responder) quarantineFile(e *event.Event, target, rule, reason string) error {
	if target == "" {
		target = TargetFile
	}
	p := procOf(e)
	d := Decision{Action: ActionQuarantineFile, PID: p.PID, Target: target, Name: p.Name, Exe: p.Exe, Reason: reason}
	if e != nil {
		d.Path, _, _ = fileTarget(e, target)
	}
	return r.act(d, rule, func(budget func() *result) result {
		if e == nil {
			return refused(OutcomeFileCheck, ErrFileCheck, "no event")
		}
		if target != TargetFile && target != TargetProcess {
			return refused(OutcomeUnknownTarget, ErrFileCheck, "target %q", target)
		}
		kind := preWriter
		if target == TargetProcess {
			kind = preExecutable
		}
		if _, res := r.preflight(e, target, kind); res != nil {
			return *res
		}
		path, b, why := fileTarget(e, target)
		if why != "" {
			return refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why)
		}
		if target == TargetProcess && b.Dev == 0 && b.Ino == 0 {
			// No inode from the event: bind to the image the matched
			// process runs now (Linux), after its identity is checked again.
			if dev, ino, ok := r.liveExeID(e.Proc); ok {
				b = fileBind{Dev: dev, Ino: ino}
			}
		}
		return r.quarantinePath(path, b, ActionQuarantineFile, rule, target, e, budget)
	})
}

// quarantinePath opens, checks and quarantines one file. With target
// process the file (the executable that ran) must belong to the process's
// uid or euid: root must not remove another user's file from a shared
// sticky directory just because the offender ran it. Caller holds actMu.
func (r *Responder) quarantinePath(path string, b fileBind, action, rule, target string, e *event.Event, budget func() *result) result {
	dirfd, base, f, fi, res := r.openBound(path, b, false, r.cfg.MaxQuarantineBytes, e)
	if res != nil {
		return *res
	}
	defer closeFD(dirfd)
	defer f.Close()
	if target == TargetProcess && !ownerOK(fi, e) {
		return refused(OutcomeFileCheck, ErrFileCheck, "the executable belongs to %s, not to the process that ran it", ownerString(fi))
	}
	if res := budget(); res != nil {
		return *res
	}
	if r.cfg.DryRun {
		return result{OutcomeDryRun, fmt.Sprintf("would move %s (%d bytes, bound by %s) into %s", path, fi.Size, b, r.cfg.VaultDir), nil}
	}
	xattrs, skipped, xerr := readXattrs(int(f.Fd()))
	if xerr != nil {
		skipped = append(skipped, "(list failed: "+xerr.Error()+")")
	}
	p := procOf(e)
	rec := QuarantineRecord{Time: r.cfg.Now().UTC(), Action: action, OriginalPath: path, Size: fi.Size,
		UID: fi.UID, GID: fi.GID, Mode: fi.Mode & 0o7777, Xattrs: xattrs, XattrsSkipped: skipped,
		Rule: rule, PID: p.PID, Exe: p.Exe, Owner: fi.Owner}
	v := Vault{Dir: r.cfg.VaultDir, RequireRootOwned: r.cfg.RequireRootOwned}
	id, err := v.store(f, fi, r.cfg.MaxQuarantineBytes, rec, b.SHA256)
	if err != nil {
		return result{OutcomeError, "vault: " + err.Error(), fmt.Errorf("response: quarantine %s: %w", path, err)}
	}
	if err := unlinkBound(dirfd, base, fi); err != nil {
		return result{OutcomeError, fmt.Sprintf("copied to the vault as %s, but the original could not be removed: %v", id, err),
			fmt.Errorf("response: quarantine %s: %w", path, err)}
	}
	return result{OutcomeQuarantined, "vault id " + id + " (restore: zaafvesper quarantine restore " + id[:12] + ")" + linksNote(fi), nil}
}

// RequarantineValue is the com.apple.quarantine value written by
// requarantine: flag 0x0001 (downloaded), the time, the agent name.
func RequarantineValue(now time.Time) []byte {
	return []byte(fmt.Sprintf("0001;%08x;ZAAFVesper;", now.Unix()))
}

// Requarantine re-adds com.apple.quarantine to the event's file (a
// DeleteXattr of that attribute), so Gatekeeper assesses it at its next
// launch. It never replaces an attribute that is present again. Guard
// rails: openBound (regular file or bundle directory, an Apple-signed
// bundle included), the event must be a DeleteXattr of the attribute, its
// process must not be seeded or unverified, and the remover must be
// untrusted (untrustedRemover; an Apple tool such as xattr counts when its
// parent is untrusted, so a platform remover alone is not refused). It does
// nothing for a copy of the file that already runs.
func (r *Responder) Requarantine(e *event.Event, rule, reason string) error {
	var run func() error
	run = func() error {
		return r.retryOnLimit(fileRetryKey(ActionRequarantine, rule, e, TargetFile), rule, reason, r.requarantine(e, rule, reason), run)
	}
	return run()
}

func (r *Responder) requarantine(e *event.Event, rule, reason string) error {
	p := procOf(e)
	d := Decision{Action: ActionRequarantine, PID: p.PID, Target: TargetFile, Name: p.Name, Exe: p.Exe, Reason: reason}
	if e != nil && e.File != nil {
		d.Path = e.File.Path
	}
	return r.act(d, rule, func(budget func() *result) result {
		if runtime.GOOS != "darwin" {
			return refused(OutcomeUnsupported, ErrFileCheck, "requarantine sets com.apple.quarantine: macOS only")
		}
		p, res := r.preflight(e, TargetFile, preWriter)
		if res != nil {
			return *res
		}
		if e.Name != event.DeleteXattr || e.Args["xattr"] != QuarantineXattr {
			return refused(OutcomeFileCheck, ErrFileCheck, "not a removal of %s (event %s)", QuarantineXattr, e.Name)
		}
		if !untrustedRemover(p) {
			return refused(OutcomeWriterNotUntrusted, ErrProtected, "the remover is not untrusted (a verified identity, or an Apple tool under a trusted parent)")
		}
		path, b, why := fileTarget(e, TargetFile)
		if why != "" {
			return refused(OutcomeFileCheck, ErrFileCheck, "%s", why)
		}
		dirfd, _, f, _, res := r.openBound(path, b, true, 1<<62, e)
		if res != nil {
			return *res
		}
		defer closeFD(dirfd)
		defer f.Close()
		has, err := hasXattr(int(f.Fd()), QuarantineXattr)
		if err != nil {
			return refused(OutcomeFileCheck, ErrFileCheck, "read %s: %v", QuarantineXattr, err)
		}
		if has {
			return result{OutcomeAlreadyQuarantined, "the attribute is present again", nil}
		}
		if res := budget(); res != nil {
			return *res
		}
		if r.cfg.DryRun {
			return result{OutcomeDryRun, "would set " + QuarantineXattr, nil}
		}
		if err := setXattr(int(f.Fd()), QuarantineXattr, RequarantineValue(r.cfg.Now()), true); err != nil {
			return result{OutcomeError, err.Error(), fmt.Errorf("response: requarantine %s: %w", path, err)}
		}
		return result{OutcomeRequarantined, QuarantineXattr + " set; Gatekeeper assesses the file at its next launch", nil}
	})
}
