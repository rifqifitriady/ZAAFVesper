//go:build darwin

package response

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// persistenceDoc is what remove_persistence handles on macOS.
const persistenceDoc = "launch item plists (bootout, then quarantine)"

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

// persist handles a launch item plist written by an untrusted process (the
// event's file, its destination for a rename): it reads the label from the
// bound file, boots the job out of its launchd domain with /bin/launchctl
// when launchd has it loaded FROM THIS PLIST, then quarantines the plist.
// Guard rails: only plists directly in a LaunchAgents or LaunchDaemons
// directory; the writer must not be an Apple platform binary, seeded or
// unverified; the label must be plain and never com.apple.* or
// ZAAFVesper's own; a label that launchd maps to another plist (a borrowed
// label) is never booted out; plus every quarantine guard rail. Caller
// holds actMu.
func (r *Responder) persist(e *event.Event, rule string, budget func() *result) result {
	if _, res := r.preflight(e, TargetFile, preUntrustedWriter); res != nil {
		return *res
	}
	path, b, why := fileTarget(e, TargetFile)
	if why != "" {
		return refused(OutcomeFileCheck, ErrFileCheck, "%s", why)
	}
	domain, why := r.launchDomain(path)
	if why != "" {
		return refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why)
	}
	dirfd, base, f, fi, res := r.openBound(path, b, false, maxPlistBytes, e)
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
	id, err := v.store(f, fi, maxPlistBytes, rec, "")
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
}
