//go:build zaafvesper_validate && linux

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

const (
	// vLocal is a documentation address (RFC 5737) the harness puts on a
	// dummy interface (zvtest0): the probe dials it, so blocking it never
	// touches the runner's real traffic.
	vLocal = "198.51.100.77"
	// vTestNet is a documentation address that routes nowhere.
	vTestNet = "192.0.2.10"
	vDummy   = "zvtest0"
	// vIsolationTTL is short so that the expiry is seen in the run.
	vIsolationTTL = 15 * time.Second
	// vPrefix names every unit, cron and profile file the harness creates
	// (never "zaafvesper", the sensor's own unit prefix, which is refused).
	vPrefix = "zv-validate-"
)

func validateTempRoot() string { return "/tmp" }

// waitState waits until pid is stopped (state T) or running again.
func waitState(pid int32, stopped bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil {
			s := string(b)
			if i := strings.LastIndexByte(s, ')'); i > 0 && i+2 < len(s) {
				if (s[i+2] == 'T' || s[i+2] == 't') == stopped {
					return true
				}
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// platformConfig: the dummy interface's address is one of this host's
// own and would never be blocked; it is left out of the own-address list
// (and only it), so that nftables can be shown to block it. The isolation
// time-to-live is short so that its expiry is seen.
func (h *vHarness) platformConfig(rc *response.Config) {
	rc.IsolationTTL = vIsolationTTL
	rc.LocalAddrs = func() ([]netip.Addr, error) {
		as, err := net.InterfaceAddrs()
		if err != nil {
			return nil, err
		}
		var out []netip.Addr
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap().String() != vLocal {
				out = append(out, p.Addr().Unmap())
			}
		}
		return out, nil
	}
}

func (h *vHarness) runPlatform() {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		say(h.stdout, "kernel %s (pidfd_open needs 5.3 or later)", strings.TrimSpace(string(b)))
	}
	h.untestable("requarantine", "all cases", "macOS only (com.apple.quarantine): refused-unsupported on Linux (run_linux.go supportedActions)")
	if err := h.r.StartResponse(); err != nil {
		say(h.stdout, "note: StartResponse: %v", err)
	}
	h.cleanup = append(h.cleanup, func() { _ = h.r.Close() })
	// The state directory did not exist when the run started
	// (platformAccidentGuard): everything in it is this run's.
	h.cleanup = append(h.cleanup, func() { _ = os.RemoveAll(response.DefaultStateDir) })
	h.quarantineCases()
	h.persistenceCases()
	h.isolateCases()
}

// birth returns the file's creation time (statx), formatted as Sysmon's
// CreationUtcTime.
func birth(path string) (string, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &st); err != nil {
		return "", err
	}
	if st.Mask&unix.STATX_BTIME == 0 {
		return "", errors.New("no birth time on this file system")
	}
	return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)).UTC().Format("2006-01-02 15:04:05.000"), nil
}

// sysmonFile is a Sysmon for Linux CreateFile event for path: no inode,
// the file's creation time, the writer's identity with no uid.
func sysmonFile(path string, w *event.Proc) (*event.Event, error) {
	b, err := birth(path)
	if err != nil {
		return nil, err
	}
	p := *w
	p.UID, p.EUID, p.Username = -1, -1, "root"
	return &event.Event{Name: event.CreateFile, Source: "sysmon", Proc: &p, File: &event.File{Path: path},
		Args: map[string]string{"creation_utc_time": b}}, nil
}

func (h *vHarness) quarantineCases() {
	say(h.stdout, "--- quarantine_file")
	dir := filepath.Join(h.dir, "q")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.untestable("quarantine_file", "setup", err.Error())
		return
	}
	w, err := h.writer()
	if err != nil {
		h.untestable("quarantine_file", "writer process", err.Error())
		return
	}
	path := filepath.Join(dir, "payload")
	body := []byte("zaafvesper validation payload " + randID() + "\n")
	if err := os.WriteFile(path, body, 0o750); err == nil {
		_ = os.Chmod(path, 0o750)
		_ = unix.Setxattr(path, "user.zaafvesper-validate", []byte("v1"), 0)
		e, err := sysmonFile(path, w)
		if err != nil {
			h.untestable("quarantine_file", "file bound by its creation time", err.Error())
			return
		}
		h.reset()
		err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: quarantine_file")
		moved := err == nil && !exists(path)
		h.record("quarantine_file", "file bound by creation time moved into "+response.DefaultVaultDir, expectAct, moved && h.decision().Outcome == response.OutcomeQuarantined,
			fmt.Sprintf("file gone=%v vault mode=%s", !exists(path), modeOf(response.DefaultVaultDir)))
		if moved {
			h.restoreCase("quarantine_file", path, func() string {
				b, _ := os.ReadFile(path)
				fi, _ := os.Stat(path)
				v := make([]byte, 8)
				n, _ := unix.Getxattr(path, "user.zaafvesper-validate", v)
				switch {
				case string(b) != string(body):
					return "content differs"
				case fi == nil || fi.Mode().Perm() != 0o750:
					return fmt.Sprintf("mode %v", fi.Mode())
				case n < 0 || string(v[:n]) != "v1":
					return "user extended attribute not restored"
				}
				return ""
			})
		}
	}
	// The executable of a running process (target process): bound to the
	// image the process runs (/proc/<pid>/exe) after its identity check.
	dropped := filepath.Join(dir, "dropped")
	if b, err := os.ReadFile(h.subject); err == nil && os.WriteFile(dropped, b, 0o755) == nil {
		s, err := h.spawnCmd(exec.Command(dropped, "validate-response", "sleeper", "--for", "2m"))
		var p *event.Proc
		if err == nil {
			p, err = procOf(s.pid)
		}
		if err != nil {
			h.untestable("quarantine_file", "executable of a running process (target process)", err.Error())
		} else {
			p.UID, p.EUID, p.Username = -1, -1, "root"
			e := h.r.BindExecutable(&event.Event{Name: event.CreateProcess, Source: "sysmon", Proc: p, Args: map[string]string{}})
			h.reset()
			err := h.r.QuarantineFile(e, response.TargetProcess, "validate-quarantine", "validation: dropped binary")
			running := !s.exited(500 * time.Millisecond)
			h.record("quarantine_file", "executable of a running process (target process, bound by /proc/<pid>/exe)", expectAct, err == nil && !exists(dropped),
				fmt.Sprintf("bound ino=%d file gone=%v process still running=%v (expected: quarantine does not stop it)", e.Proc.ExeIno, !exists(dropped), running))
		}
	}
	// Refused: protected system files, with their real creation times.
	for _, prot := range []string{"/etc/passwd", "/usr/bin/true", "/etc/crontab"} {
		if !exists(prot) {
			continue
		}
		e, err := sysmonFile(prot, w)
		if err != nil {
			h.untestable("quarantine_file", prot+" (protected path)", err.Error())
			continue
		}
		h.reset()
		err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: protected")
		h.record("quarantine_file", prot+" (protected path)", expectDeny, errors.Is(err, response.ErrProtectedPath) && exists(prot), "")
	}
	// Refused: the file was replaced after the event (another creation time).
	repl := filepath.Join(dir, "replaced")
	if os.WriteFile(repl, []byte("one"), 0o644) == nil {
		e, err := sysmonFile(repl, w)
		if err == nil {
			_ = os.Remove(repl)
			time.Sleep(2100 * time.Millisecond) // past the 2 s tolerance
			_ = os.WriteFile(repl, []byte("two"), 0o644)
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: replaced")
			h.record("quarantine_file", "file replaced since the event (creation time differs)", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(repl), "")
		}
	}
	// Refused: a second hard link (weak binding needs exactly one name).
	hl := filepath.Join(dir, "linked")
	if os.WriteFile(hl, []byte("x"), 0o644) == nil && os.Link(hl, hl+".2") == nil {
		if e, err := sysmonFile(hl, w); err == nil {
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: hard link")
			h.record("quarantine_file", "file with two names (hard link)", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(hl), "")
		}
	}
	// Refused: a symbolic link, and a directory link in the path.
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if os.WriteFile(target, []byte("t"), 0o644) == nil && os.Symlink(target, link) == nil {
		if e, err := sysmonFile(link, w); err == nil {
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: symlink")
			h.record("quarantine_file", "symbolic link", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(target) && exists(link), "")
		}
	}
	ldir := filepath.Join(h.dir, "dirlink")
	if os.Symlink(dir, ldir) == nil {
		if e, err := sysmonFile(target, w); err == nil {
			e.File.Path = filepath.Join(ldir, "target")
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: link in path")
			h.record("quarantine_file", "directory link in the path", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(target), "")
		}
	}
}

func modeOf(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%04o", fi.Mode().Perm())
}

func systemctl(args ...string) (string, error) { return run(response.SystemctlBin, args...) }

func (h *vHarness) persistenceCases() {
	say(h.stdout, "--- remove_persistence")
	w, err := h.writer()
	if err != nil {
		h.untestable("remove_persistence", "writer process", err.Error())
		return
	}
	// A loaded, running systemd unit written by an untrusted process.
	unit := vPrefix + randID() + ".service"
	upath := "/etc/systemd/system/" + unit
	h.cleanup = append(h.cleanup, func() {
		_, _ = systemctl("disable", "--now", unit)
		_ = os.Remove(upath)
		_, _ = systemctl("daemon-reload")
	})
	if err := os.WriteFile(upath, []byte("[Unit]\nDescription=ZAAFVesper validation\n[Service]\nExecStart=/bin/sleep 600\n[Install]\nWantedBy=multi-user.target\n"), 0o644); err != nil {
		h.untestable("remove_persistence", "systemd unit", err.Error())
	} else if out, err := systemctl("daemon-reload"); err != nil {
		h.untestable("remove_persistence", "systemd unit", "daemon-reload: "+out)
	} else if out, err := systemctl("enable", "--now", unit); err != nil {
		h.untestable("remove_persistence", "systemd unit", "enable --now: "+out)
	} else if e, err := sysmonFile(upath, w); err != nil {
		h.untestable("remove_persistence", "systemd unit", err.Error())
	} else {
		active := strings.TrimSpace(stdout(response.SystemctlBin, "is-active", unit))
		h.reset()
		err := h.r.RemovePersistence(e, "validate-persistence", "validation: systemd unit")
		after := strings.TrimSpace(stdout(response.SystemctlBin, "is-active", unit))
		load := strings.TrimSpace(stdout(response.SystemctlBin, "show", "--property=LoadState", "--value", unit))
		h.record("remove_persistence", "running systemd unit: disabled, stopped, moved, daemon-reload", expectAct,
			err == nil && active == "active" && after != "active" && !exists(upath) && load == "not-found",
			fmt.Sprintf("before=%s after=%s load=%s file gone=%v", active, after, load, !exists(upath)))
		if !exists(upath) {
			h.restoreCase("remove_persistence", upath, func() string {
				if !exists(upath) {
					return "unit file not back"
				}
				if a := strings.TrimSpace(stdout(response.SystemctlBin, "is-active", unit)); a == "active" {
					return "restore started the unit (it must not)"
				}
				return ""
			})
		}
	}
	// Refused: an administrator's own editor (system programs only).
	admin := "/etc/systemd/system/" + vPrefix + randID() + ".service"
	h.cleanup = append(h.cleanup, func() { _ = os.Remove(admin) })
	if os.WriteFile(admin, []byte("[Service]\nExecStart=/bin/true\n"), 0o644) == nil {
		if e, err := sysmonFile(admin, w); err == nil {
			e.Proc.Exe, e.Proc.Name = "/usr/bin/vim.basic", "vim.basic"
			e.Proc.Parent = &event.Proc{PID: 1000, Exe: "/usr/bin/bash"}
			e.Proc.Ancestors = []string{"/usr/bin/bash", "/usr/sbin/sshd"}
			h.reset()
			err = h.r.RemovePersistence(e, "validate-persistence", "validation: admin editor")
			h.record("remove_persistence", "unit written by a system editor under a system shell (trusted writer)", expectDeny,
				errors.Is(err, response.ErrProtected) && exists(admin), "")
		}
	}
	// Cron file, user crontab and profile.d script: moved.
	for _, c := range []struct{ kase, path string }{
		{"/etc/cron.d file", "/etc/cron.d/" + vPrefix + randID()},
		{"user crontab in /var/spool/cron/crontabs", "/var/spool/cron/crontabs/" + vPrefix + randID()},
		{"/etc/profile.d script", "/etc/profile.d/" + vPrefix + randID() + ".sh"},
	} {
		path := c.path
		h.cleanup = append(h.cleanup, func() { _ = os.Remove(path) })
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			h.untestable("remove_persistence", c.kase, err.Error())
			continue
		}
		if err := os.WriteFile(path, []byte("# ZAAFVesper validation\n"), 0o600); err != nil {
			h.untestable("remove_persistence", c.kase, err.Error())
			continue
		}
		e, err := sysmonFile(path, w)
		if err != nil {
			h.untestable("remove_persistence", c.kase, err.Error())
			continue
		}
		h.reset()
		err = h.r.RemovePersistence(e, "validate-persistence", "validation: "+c.kase)
		h.record("remove_persistence", c.kase, expectAct, err == nil && !exists(path) && h.decision().Outcome == response.OutcomePersistenceRemoved,
			fmt.Sprintf("file gone=%v", !exists(path)))
	}
	// Refused: /etc/crontab stays protected.
	if exists("/etc/crontab") {
		if e, err := sysmonFile("/etc/crontab", w); err == nil {
			h.reset()
			err = h.r.RemovePersistence(e, "validate-persistence", "validation: /etc/crontab")
			h.record("remove_persistence", "/etc/crontab (protected)", expectDeny, err != nil && strings.HasPrefix(h.decision().Outcome, "refused-") && exists("/etc/crontab"), "")
		}
	}
}

// nftSet lists the addresses in ZAAFVesper's two nftables sets.
func nftSet() map[string]bool {
	m := map[string]bool{}
	for _, set := range []string{"isolated4", "isolated6"} {
		out := stdout(response.NftBin, "list", "set", "inet", response.NftTable, set)
		for _, f := range strings.FieldsFunc(out, func(r rune) bool { return r == ' ' || r == ',' || r == '{' || r == '}' || r == '\n' || r == '\t' }) {
			if a, err := netip.ParseAddr(f); err == nil {
				m[a.String()] = true
			}
		}
	}
	return m
}

func (h *vHarness) isolateCases() {
	say(h.stdout, "--- isolate_process")
	if !exists(response.NftBin) {
		h.untestable("isolate_process", "all cases", response.NftBin+" is not installed on this runner")
		return
	}
	h.cleanup = append(h.cleanup, func() { _ = runQuiet("/usr/sbin/ip", "link", "del", vDummy) })
	for _, args := range [][]string{{"link", "add", vDummy, "type", "dummy"}, {"addr", "add", vLocal + "/32", "dev", vDummy}, {"link", "set", vDummy, "up"}} {
		if out, err := run("/usr/sbin/ip", args...); err != nil {
			h.untestable("isolate_process", "all cases", "dummy interface: "+out)
			return
		}
	}
	ln, err := net.Listen("tcp", vLocal+":0")
	if err != nil {
		h.untestable("isolate_process", "all cases", err.Error())
		return
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	never := []string{"127.0.0.1", "::1", "224.0.0.251"}
	if as, err := net.InterfaceAddrs(); err == nil {
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil && !p.Addr().IsLoopback() && p.Addr().String() != vLocal && p.Addr().Zone() == "" && !p.Addr().IsLinkLocalUnicast() {
				never = append(never, p.Addr().Unmap().String())
			}
		}
	}
	gws, _ := response.DefaultGateways()
	for _, g := range gws {
		never = append(never, g.String())
	}
	for _, r := range response.DefaultResolvers() {
		never = append(never, r.String())
	}
	h.isolateFlow(isoCase{probe: vLocal, port: port, extra: vTestNet, never: never, listed: nftSet, where: "nftables table inet " + response.NftTable,
		ttl: vIsolationTTL, cleared: func() (bool, string) {
			out, err := run(response.NftBin, "list", "table", "inet", response.NftTable)
			return err != nil, "nft list table after shutdown: " + strings.TrimSpace(out)
		}})
}

// platformAccidentGuard refuses where ZAAFVesper is installed or has state.
func platformAccidentGuard() error {
	for _, p := range []string{"/etc/systemd/system/zaafvesper.service", "/lib/systemd/system/zaafvesper.service", "/usr/lib/systemd/system/zaafvesper.service"} {
		if exists(p) {
			return fmt.Errorf("%s exists: ZAAFVesper is installed here; the harness runs only on a throw-away runner", p)
		}
	}
	if exists(response.DefaultStateDir) {
		return fmt.Errorf("%s exists: ZAAFVesper has state here; the harness runs only on a throw-away runner", response.DefaultStateDir)
	}
	if exists(response.NftBin) && runQuiet(response.NftBin, "list", "table", "inet", response.NftTable) == nil {
		return errors.New("the nftables table inet zaafvesper exists: a sensor is running here")
	}
	return nil
}
