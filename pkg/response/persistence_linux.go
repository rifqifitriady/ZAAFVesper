//go:build linux

package response

import (
	"context"
	"fmt"
	"strings"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// maxPersistBytes caps a unit, cron or rc file moved by remove_persistence.
const maxPersistBytes = 1 << 20

// persist handles a systemd unit, a cron file or a shell rc file written by
// an untrusted process (the event's file, its destination for a rename):
//
//   - systemd unit in /etc/systemd/system: when systemd has the unit
//     loaded FROM THIS FILE (systemctl show FragmentPath), it is disabled
//     and stopped (systemctl disable --now); a unit loaded from another
//     file (a borrowed name) and a protected unit (systemd-*, ssh, dbus,
//     cron, agents) are never stopped. The file is moved to the vault,
//     then systemd reloads its units (daemon-reload).
//   - systemd user unit (~/.config/systemd/user): moved to the vault; the
//     user's own manager is not told (it forgets the unit at its next
//     reload or login).
//   - cron file (/etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly},
//     /var/spool/cron[/crontabs]): moved to the vault; cron notices.
//     /etc/crontab is protected and refused.
//   - shell rc file (~/.bashrc, ~/.profile, ~/.zshrc and the like,
//     /etc/profile.d/*.sh): the whole file is moved to the vault, the
//     user's own lines included (restore puts it back).
//
// Guard rails: the writer must be untrusted (trustedWriter), the file
// bound to the event (openBound), plus every quarantine guard rail. Caller
// holds actMu.
func (r *Responder) persist(e *event.Event, rule string, budget func() *result) result {
	if _, res := r.preflight(e, TargetFile, preUntrustedWriter); res != nil {
		return *res
	}
	path, b, why := fileTarget(e, TargetFile)
	if why != "" {
		return refused(OutcomeFileCheck, ErrFileCheck, "%s", why)
	}
	logical := path
	if r.launchRoot != "" { // tests only: a fake file system root
		rel, ok := strings.CutPrefix(path, r.launchRoot+"/")
		if !ok {
			return refused(OutcomeProtectedPath, ErrProtectedPath, "outside the test root")
		}
		logical = "/" + rel
	}
	kind, unit, why := linuxPersistKind(logical)
	if why != "" {
		return refused(OutcomeProtectedPath, ErrProtectedPath, "%s", why)
	}
	if unit != "" && strings.HasPrefix(strings.ToLower(unit), ownUnit) {
		return refused(OutcomeLabel, ErrLabel, "ZAAFVesper's own unit %s", unit)
	}
	dirfd, base, f, fi, res := r.openBound(path, b, false, maxPersistBytes, e)
	if res != nil {
		return *res
	}
	defer closeFD(dirfd)
	defer f.Close()
	if res := budget(); res != nil {
		return *res
	}
	var notes []string
	stopFailed := false
	switch {
	case kind != persistSystemdSystem:
	case protectedUnit(unit) != "":
		notes = append(notes, protectedUnit(unit)+"; not stopped")
	case r.cfg.DryRun:
		notes = append(notes, "would disable and stop "+unit+" if systemd loaded it from this file")
	default:
		note, failed := r.stopUnit(unit, path)
		notes, stopFailed = append(notes, note), failed
	}
	if r.cfg.DryRun {
		return result{OutcomeDryRun, strings.Join(append(notes, fmt.Sprintf("would move the %s %s into %s", kind, path, r.cfg.VaultDir)), "; "), nil}
	}
	xattrs, skipped, xerr := readXattrs(int(f.Fd()))
	if xerr != nil {
		skipped = append(skipped, "(list failed: "+xerr.Error()+")")
	}
	rec := QuarantineRecord{Time: r.cfg.Now().UTC(), Action: ActionRemovePersistence, OriginalPath: path, Size: fi.Size,
		UID: fi.UID, GID: fi.GID, Mode: fi.Mode & 0o7777, Xattrs: xattrs, XattrsSkipped: skipped,
		Rule: rule, PID: e.Proc.PID, Exe: e.Proc.Exe, Label: unit}
	v := Vault{Dir: r.cfg.VaultDir, RequireRootOwned: r.cfg.RequireRootOwned}
	id, err := v.store(f, fi, maxPersistBytes, rec, "")
	if err != nil {
		return result{OutcomeError, strings.Join(append(notes, "vault: "+err.Error()), "; "), fmt.Errorf("response: remove_persistence %s: %w", path, err)}
	}
	if err := unlinkBound(dirfd, base, fi); err != nil {
		return result{OutcomeError, strings.Join(append(notes, fmt.Sprintf("%s copied to the vault as %s but not removed: %v", kind, id, err)), "; "),
			fmt.Errorf("response: remove_persistence %s: %w", path, err)}
	}
	notes = append(notes, kind+" moved to the vault as "+id+" (restore: zaafvesper quarantine restore "+id[:12]+")")
	switch kind {
	case persistSystemdSystem:
		if _, err := r.systemctl("daemon-reload"); err != nil {
			notes, stopFailed = append(notes, "systemctl daemon-reload failed: "+err.Error()), true
		} else {
			notes = append(notes, "systemd reloaded")
		}
	case persistSystemdUser:
		notes = append(notes, "the user's systemd manager was not reloaded: the unit stays known to it until its next reload or login")
	}
	if stopFailed {
		return result{OutcomePartial, strings.Join(notes, "; "), fmt.Errorf("response: remove_persistence %s: systemctl did not confirm every step", path)}
	}
	return result{OutcomePersistenceRemoved, strings.Join(notes, "; "), nil}
}

func (r *Responder) systemctl(args ...string) ([]byte, error) {
	return r.cfg.Runner(context.Background(), SystemctlBin, args, nil)
}

// stopUnit disables and stops unit when systemd has it loaded from
// unitPath. failed is set when systemctl could not answer or the stop
// failed. Caller holds actMu.
func (r *Responder) stopUnit(unit, unitPath string) (note string, failed bool) {
	out, err := r.systemctl("show", "--property=FragmentPath", "--value", "--", unit)
	if err != nil {
		return "systemctl show " + unit + " failed (" + err.Error() + "); whether it is loaded is unknown, nothing stopped", true
	}
	frag := strings.TrimSpace(string(out))
	switch {
	case frag == "":
		return "systemd has no unit " + unit + " loaded from a file; nothing stopped", false
	case frag != unitPath:
		return fmt.Sprintf("unit %s is loaded from %s, not from this file (borrowed name); not stopped", unit, frag), false
	}
	if _, err := r.systemctl("disable", "--now", "--no-reload", "--", unit); err != nil {
		return "systemctl disable --now " + unit + " failed: " + err.Error(), true
	}
	return "disabled and stopped " + unit, false
}
