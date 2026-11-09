package response

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// maxPlistBytes caps a launch item plist read by remove_persistence.
const maxPlistBytes = 1 << 20

// OwnLabel is ZAAFVesper's own LaunchDaemon label: never booted out.
const OwnLabel = "com.rifqifitriady.zaafvesper"

// labelRe is the launchd labels remove_persistence accepts: letters,
// digits, dot, dash and underscore, starting with a letter or digit. The
// label becomes part of a launchctl service target (domain/label), so "/"
// and anything else is refused.
var labelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// launchDomain returns the launchctl domain of a launch item plist at path,
// or why the path is not a launch item remove_persistence handles. Only a
// plist directly inside one of these directories qualifies:
// /Library/LaunchDaemons (system), /Library/LaunchAgents (gui/<console
// user>), /Users/<name>/Library/LaunchAgents (gui/<owner of the home>) and
// /private/var/root/Library/LaunchAgents (no GUI domain: the plist is
// quarantined, nothing is booted out).
func (r *Responder) launchDomain(path string) (domain string, why string) {
	if err := checkCleanAbs(path); err != nil {
		return "", err.Error()
	}
	root := ""
	if r.launchRoot != "" { // tests only: a fake file system root
		rel, ok := strings.CutPrefix(path, r.launchRoot+"/")
		if !ok {
			return "", "outside the test root"
		}
		root, path = r.launchRoot, "/"+rel
	}
	i := strings.LastIndexByte(path, '/')
	dir, base := path[:i], path[i+1:]
	if !hasSuffixFold(base, ".plist") || len(base) <= len(".plist") {
		return "", "not a .plist file"
	}
	switch {
	case strings.EqualFold(dir, "/Library/LaunchDaemons"):
		return "system", ""
	case strings.EqualFold(dir, "/Library/LaunchAgents"):
		uid, err := r.cfg.ConsoleUID()
		if err != nil || uid == 0 {
			return "", "" // no console user: quarantine only
		}
		return fmt.Sprintf("gui/%d", uid), ""
	case strings.EqualFold(dir, "/private/var/root/Library/LaunchAgents"):
		return "", ""
	}
	parts := strings.Split(dir, "/") // "", "Users", name, "Library", "LaunchAgents"
	if len(parts) == 5 && strings.EqualFold(parts[1], "Users") && parts[2] != "" && parts[2] != "Shared" &&
		strings.EqualFold(parts[3], "Library") && strings.EqualFold(parts[4], "LaunchAgents") {
		uid, err := dirOwner(root + "/Users/" + parts[2])
		if err != nil {
			return "", "cannot read the owner of the home directory: " + err.Error()
		}
		if uid == 0 {
			return "", "home directory owned by root"
		}
		return fmt.Sprintf("gui/%d", uid), ""
	}
	return "", "not directly in a LaunchAgents or LaunchDaemons directory"
}

// RemovePersistence handles a launch item plist written by an untrusted
// process (the event's file, its destination for a rename): it reads the
// label from the bound file, boots the job out of its launchd domain with
// /bin/launchctl when launchd has it loaded FROM THIS PLIST, then
// quarantines the plist. Guard rails: only plists directly in a
// LaunchAgents or LaunchDaemons directory; the writer must not be an Apple
// platform binary, seeded or unverified; the label must be plain and never
// com.apple.* or ZAAFVesper's own; a label that launchd maps to another
// plist (a borrowed label) is never booted out; plus every quarantine guard
// rail. It acts after the event: whatever the job already did stays done.
func (r *Responder) RemovePersistence(e *event.Event, rule, reason string) error {
	var run func() error
	run = func() error {
		return r.retryOnLimit(fileRetryKey(ActionRemovePersistence, rule, e, TargetFile), rule, reason, r.removePersistence(e, rule, reason), run)
	}
	return run()
}

func (r *Responder) removePersistence(e *event.Event, rule, reason string) error {
	p := procOf(e)
	d := Decision{Action: ActionRemovePersistence, PID: p.PID, Target: TargetFile, Name: p.Name, Exe: p.Exe, Reason: reason}
	path := ""
	if e != nil && e.File != nil {
		path, _, _, _ = fileTarget(e, TargetFile)
	}
	d.Path = path
	return r.act(d, rule, func(budget func() *result) result {
		if _, res := r.preflight(e, TargetFile, preUntrustedWriter); res != nil {
			return *res
		}
		path, dev, ino, why := fileTarget(e, TargetFile)
		if why != "" {
			return refused(OutcomeFileCheck, ErrFileCheck, "%s", why)
		}
		domain, why := r.launchDomain(path)
		if why != "" {
			return refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why)
		}
		dirfd, base, f, fi, res := r.openBound(path, dev, ino, false, maxPlistBytes, procOwners(e))
		if res != nil {
			return *res
		}
		defer closeFD(dirfd)
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxPlistBytes+1))
		if err != nil {
			return refused(OutcomeFileCheck, ErrFileCheck, "read: %v", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return refused(OutcomeFileCheck, ErrFileCheck, "seek: %v", err)
		}
		// A label that is refused is never booted out, but the plist is
		// still quarantined: it is the untrusted writer's file at a path
		// that is not protected (Apple's and ZAAFVesper's own plists are
		// refused by path before this point).
		label, lerr := PlistLabel(data)
		switch {
		case lerr != nil:
			label = ""
		case !labelRe.MatchString(label):
			lerr = fmt.Errorf("label %q is not a plain launchd label", label)
		case hasPrefixFold(label, "com.apple.") || strings.EqualFold(label, "com.apple"):
			lerr = fmt.Errorf("Apple label %q is never booted out", label)
		case strings.EqualFold(label, OwnLabel):
			lerr = errors.New("ZAAFVesper's own label is never booted out")
		}
		if res := budget(); res != nil {
			return *res
		}
		var notes []string
		bootFailed := false
		switch {
		case lerr != nil:
			notes = append(notes, lerr.Error()+"; nothing booted out")
		case domain == "":
			notes = append(notes, "no GUI domain for this location (no console user, or root's agents); nothing booted out")
		case r.cfg.DryRun:
			notes = append(notes, "would boot out "+domain+"/"+label+" if launchd loaded it from this plist")
		default:
			note, failed := r.bootout(domain, label, path)
			notes, bootFailed = append(notes, note), failed
		}
		if r.cfg.DryRun {
			return result{OutcomeDryRun, strings.Join(append(notes, fmt.Sprintf("would move %s into %s", path, r.cfg.VaultDir)), "; "), nil}
		}
		xattrs, skipped, xerr := readXattrs(int(f.Fd()))
		if xerr != nil {
			skipped = append(skipped, "(list failed: "+xerr.Error()+")")
		}
		rec := QuarantineRecord{Time: r.cfg.Now().UTC(), Action: ActionRemovePersistence, OriginalPath: path, Size: fi.Size,
			UID: fi.UID, GID: fi.GID, Mode: fi.Mode & 0o7777, Xattrs: xattrs, XattrsSkipped: skipped,
			Rule: rule, PID: e.Proc.PID, Exe: e.Proc.Exe, Label: label}
		v := Vault{Dir: r.cfg.VaultDir, RequireRootOwned: r.cfg.RequireRootOwned}
		id, err := v.store(f, fi, maxPlistBytes, rec)
		if err != nil {
			return result{OutcomeError, strings.Join(append(notes, "vault: "+err.Error()), "; "), fmt.Errorf("response: remove_persistence %s: %w", path, err)}
		}
		if err := unlinkBound(dirfd, base, fi); err != nil {
			return result{OutcomeError, strings.Join(append(notes, fmt.Sprintf("plist copied to the vault as %s but not removed: %v", id, err)), "; "),
				fmt.Errorf("response: remove_persistence %s: %w", path, err)}
		}
		notes = append(notes, "plist quarantined as "+id+" (restore: zaafvesper quarantine restore "+id[:12]+")"+linksNote(fi))
		if bootFailed {
			// The plist is gone, so launchd will not start the job again,
			// but it may still be running now.
			return result{OutcomePartial, strings.Join(notes, "; "), fmt.Errorf("response: remove_persistence %s: launchctl did not confirm the job is out", path)}
		}
		return result{OutcomePersistenceRemoved, strings.Join(notes, "; "), nil}
	})
}

// launchctlNotFound is the exit status of `launchctl print` for a service
// that is not loaded ("Could not find service").
const launchctlNotFound = 113

// bootout boots domain/label out of launchd when launchd reports it loaded
// from plistPath, and returns a note. failed is set when launchctl could
// not answer or the bootout itself failed (the job may still be loaded).
// Caller holds actMu.
func (r *Responder) bootout(domain, label, plistPath string) (note string, failed bool) {
	target := domain + "/" + label
	out, err := r.cfg.Runner(context.Background(), LaunchctlBin, []string{"print", target}, nil)
	var ee *ExitError
	switch {
	case errors.As(err, &ee) && ee.Code == launchctlNotFound:
		return "launchd has no job " + target + " loaded; nothing booted out", false
	case err != nil:
		return "launchctl print " + target + " failed (" + err.Error() + "); whether the job is loaded is unknown, nothing booted out", true
	}
	loadedFrom := launchctlPath(out)
	if loadedFrom == "" {
		return "launchctl print " + target + " shows no plist path; not booted out", true
	}
	if loadedFrom != plistPath {
		return fmt.Sprintf("label %s is loaded from %s, not from this plist (borrowed label); not booted out", target, loadedFrom), false
	}
	if _, err := r.cfg.Runner(context.Background(), LaunchctlBin, []string{"bootout", target}, nil); err != nil {
		return "launchctl bootout " + target + " failed: " + err.Error(), true
	}
	return "booted out " + target, false
}

// launchctlPath returns the first "path = ..." line of `launchctl print`.
func launchctlPath(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "path = "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// PlistLabel returns the top-level Label string of an XML or binary
// (bplist00) property list. A missing, non-string or repeated Label is an
// error.
func PlistLabel(b []byte) (string, error) {
	if bytes.HasPrefix(b, []byte("bplist00")) {
		return bplistLabel(b)
	}
	return xmlPlistLabel(b)
}

var errNoLabel = errors.New("no Label string at the top level")

// xmlPlistLabel reads <plist><dict>...<key>Label</key><string>x</string>.
func xmlPlistLabel(b []byte) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	depth, tokens := 0, 0
	inTopDict := false
	var label string
	found := 0
	expectLabel := false
	for {
		tokens++
		if tokens > 200000 {
			return "", errors.New("plist too complex")
		}
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("xml plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth == 1 && t.Name.Local != "plist":
				return "", errors.New("not a plist")
			case depth == 2:
				if t.Name.Local != "dict" {
					return "", errors.New("top level is not a dict")
				}
				inTopDict = true
			case depth == 3 && inTopDict && t.Name.Local == "key":
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return "", err
				}
				depth--
				expectLabel = k == "Label"
			case depth == 3 && inTopDict:
				if expectLabel {
					found++
					if t.Name.Local != "string" {
						return "", errors.New("Label is not a string")
					}
					if err := dec.DecodeElement(&label, &t); err != nil {
						return "", err
					}
					depth--
				}
				expectLabel = false
			}
		case xml.EndElement:
			depth--
		}
	}
	switch found {
	case 0:
		return "", errNoLabel
	case 1:
		return label, nil
	}
	return "", errors.New("Label appears more than once")
}

// bplistLabel reads the top-level Label of a binary property list.
func bplistLabel(b []byte) (string, error) {
	if len(b) < 8+32 {
		return "", errors.New("bplist: too short")
	}
	tr := b[len(b)-32:]
	offSize, refSize := int(tr[6]), int(tr[7])
	numObj := binary.BigEndian.Uint64(tr[8:16])
	top := binary.BigEndian.Uint64(tr[16:24])
	tableOff := binary.BigEndian.Uint64(tr[24:32])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObj == 0 || numObj > 1<<20 ||
		top >= numObj || tableOff >= uint64(len(b)-32) || tableOff+numObj*uint64(offSize) > uint64(len(b)-32) {
		return "", errors.New("bplist: bad trailer")
	}
	readN := func(p []byte) uint64 {
		var v uint64
		for _, c := range p {
			v = v<<8 | uint64(c)
		}
		return v
	}
	objOff := func(ref uint64) (int, error) {
		if ref >= numObj {
			return 0, errors.New("bplist: bad object reference")
		}
		o := readN(b[tableOff+ref*uint64(offSize) : tableOff+(ref+1)*uint64(offSize)])
		if o < 8 || o >= tableOff {
			return 0, errors.New("bplist: bad object offset")
		}
		return int(o), nil
	}
	// length decodes the count of an object at off (marker low nibble or a
	// following int object) and returns it with the offset of the payload.
	length := func(off int) (int, int, error) {
		n := int(b[off] & 0x0f)
		off++
		if n != 0x0f {
			return n, off, nil
		}
		if off >= len(b) || b[off]&0xf0 != 0x10 {
			return 0, 0, errors.New("bplist: bad length")
		}
		w := 1 << (b[off] & 0x0f)
		if w > 8 || off+1+w > len(b) {
			return 0, 0, errors.New("bplist: bad length")
		}
		v := readN(b[off+1 : off+1+w])
		if v > uint64(len(b)) {
			return 0, 0, errors.New("bplist: bad length")
		}
		return int(v), off + 1 + w, nil
	}
	str := func(ref uint64) (string, bool, error) {
		off, err := objOff(ref)
		if err != nil {
			return "", false, err
		}
		kind := b[off] & 0xf0
		if kind != 0x50 && kind != 0x60 {
			return "", false, nil
		}
		n, p, err := length(off)
		if err != nil {
			return "", false, err
		}
		if kind == 0x50 {
			if p+n > int(tableOff) {
				return "", false, errors.New("bplist: string out of range")
			}
			return string(b[p : p+n]), true, nil
		}
		if p+2*n > int(tableOff) {
			return "", false, errors.New("bplist: string out of range")
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[p+2*i:])
		}
		return string(utf16.Decode(u)), true, nil
	}
	off, err := objOff(top)
	if err != nil {
		return "", err
	}
	if b[off]&0xf0 != 0xd0 {
		return "", errors.New("bplist: top level is not a dict")
	}
	n, p, err := length(off)
	if err != nil {
		return "", err
	}
	if p+2*n*refSize > int(tableOff) {
		return "", errors.New("bplist: dict out of range")
	}
	ref := func(i int) uint64 { return readN(b[p+i*refSize : p+(i+1)*refSize]) }
	found := 0
	var label string
	for i := 0; i < n; i++ {
		k, ok, err := str(ref(i))
		if err != nil {
			return "", err
		}
		if !ok || k != "Label" {
			continue
		}
		v, ok, err := str(ref(n + i))
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("Label is not a string")
		}
		found++
		label = v
	}
	switch found {
	case 0:
		return "", errNoLabel
	case 1:
		return label, nil
	}
	return "", errors.New("Label appears more than once")
}
