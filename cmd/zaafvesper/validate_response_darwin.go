//go:build zaafvesper_validate && darwin

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

const (
	// vLabelPrefix names every launch item the harness creates.
	vLabelPrefix = "com.rifqifitriady.zaafvesper-validate."
	// vAlias is a loopback alias added by scripts/ci/d/live-response-macos.sh:
	// traffic to it never leaves the runner, so blocking it in pf cannot cut
	// the runner's own connectivity.
	vAlias = "10.254.254.2"
	// vTestNet is a documentation address (RFC 5737) that routes nowhere.
	vTestNet = "198.51.100.77"
	// vIsolationTTL is short so that the expiry is seen in the run.
	vIsolationTTL = 20 * time.Second
	sstop         = 4 // SSTOP, <sys/proc.h>
)

func validateTempRoot() string { return "/private/tmp" }

// waitState waits until pid is stopped (SSTOP) or running again.
func waitState(pid int32, stopped bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid)); err == nil {
			if (kp.Proc.P_stat == sstop) == stopped {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// platformConfig: the loopback alias of the isolation case is one of this
// Mac's own addresses and would never be blocked; it is left out of the
// own-address list (and only it), so that pf can be shown to block it.
// The isolation time-to-live is short so that its expiry is seen.
func (h *vHarness) platformConfig(rc *response.Config) {
	rc.IsolationTTL = vIsolationTTL
	rc.LocalAddrs = func() ([]netip.Addr, error) {
		as, err := net.InterfaceAddrs()
		if err != nil {
			return nil, err
		}
		var out []netip.Addr
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap().String() != vAlias {
				out = append(out, p.Addr().Unmap())
			}
		}
		return out, nil
	}
}

func (h *vHarness) runPlatform() {
	h.pfWasEnabled = pfEnabled()
	if err := h.r.StartResponse(); err != nil {
		say(h.stdout, "note: StartResponse: %v", err)
	}
	h.cleanup = append(h.cleanup, func() { _ = h.r.Close() })
	h.execIntoPlatform()
	h.quarantineCases()
	h.requarantineCases()
	h.persistenceCases()
	h.isolateCases()
}

func randID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func run(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

// stdout runs bin and returns its standard output only (pfctl writes
// notices such as "No ALTQ support in kernel" to stderr).
func stdout(bin string, args ...string) string {
	out, _ := exec.Command(bin, args...).Output()
	return string(out)
}

// pfEnabled reports whether pf is enabled (pfctl -s info).
func pfEnabled() bool {
	return strings.Contains(stdout(response.PfctlBin, "-s", "info"), "Status: Enabled")
}

// writer starts a test process to play the untrusted writer or remover of
// a file event and returns its event identity.
func (h *vHarness) writer() (*event.Proc, error) {
	s, err := h.spawn()
	if err != nil {
		return nil, err
	}
	return procOf(s.pid)
}

// mustEvent is fileEvent for cases whose setup just created path; a failure
// is a harness failure and panics (recorded as a failed result).
func (h *vHarness) mustEvent(name, path string, p *event.Proc) *event.Event {
	e, err := fileEvent(name, path, p)
	if err != nil {
		panic(fmt.Sprintf("event for %s: %v", path, err))
	}
	return e
}

func fileEvent(name, path string, p *event.Proc) (*event.Event, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return nil, err
	}
	return &event.Event{Name: name, Source: response.ESSource, Proc: p,
		File: &event.File{Path: path, Dev: uint64(uint32(st.Dev)), Ino: st.Ino}}, nil
}

// execIntoPlatform covers owner decision 1B: a process that was not a
// platform binary at detection and has exec'd into /bin/sleep since.
func (h *vHarness) execIntoPlatform() {
	say(h.stdout, "--- kill: exec into an Apple platform binary after detection")
	for _, c := range []struct {
		source, kase, expect string
	}{
		{response.ESSource, "exec into /bin/sleep after detection (eslogger event)", expectAct},
		{"fixture", "exec into /bin/sleep, platform flag not from eslogger", expectDeny},
	} {
		s, err := h.spawn("--exec-sleep-after", "2s")
		if err != nil {
			h.untestable("kill", c.kase, err.Error())
			continue
		}
		p, err := procOf(s.pid)
		if err != nil || p.IsPlatform {
			h.untestable("kill", c.kase, fmt.Sprintf("identity before exec: %v platform=%v", err, p != nil && p.IsPlatform))
			continue
		}
		execd := false
		for i := 0; i < 100 && !execd; i++ {
			if id, err := response.KernelIdentity(s.pid); err == nil && id.Exe == "/bin/sleep" && id.PlatformBinary() {
				execd = true
			} else {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if !execd {
			h.untestable("kill", c.kase, "the test process did not exec into /bin/sleep")
			continue
		}
		h.reset()
		err = h.r.KillEvent(&event.Event{Source: c.source, Proc: p}, "validate-exec", "validation: "+c.kase)
		if c.expect == expectAct {
			gone := s.exited(5 * time.Second)
			h.record("kill", c.kase, expectAct, err == nil && gone && strings.Contains(h.decision().Detail, "exec'd into an Apple platform binary"),
				fmt.Sprintf("exited=%v", gone))
		} else {
			alive := !s.exited(time.Second)
			h.record("kill", c.kase, expectDeny, errors.Is(err, response.ErrProtected) && alive, fmt.Sprintf("alive=%v", alive))
		}
	}
	// A process that was an Apple platform binary at detection.
	s, err := h.spawnCmd(exec.Command("/bin/sleep", "120"))
	if err != nil {
		h.untestable("kill", "Apple platform binary at detection", err.Error())
		return
	}
	p, err := procOf(s.pid)
	if err != nil || !p.IsPlatform {
		h.untestable("kill", "Apple platform binary at detection", fmt.Sprintf("csops: %v platform=%v", err, p != nil && p.IsPlatform))
		return
	}
	h.reset()
	err = h.r.KillEvent(&event.Event{Source: response.ESSource, Proc: p}, "validate-kill", "validation: platform binary")
	alive := !s.exited(time.Second)
	h.record("kill", "Apple platform binary at detection (/bin/sleep)", expectDeny, errors.Is(err, response.ErrProtected) && alive, fmt.Sprintf("alive=%v", alive))
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
	// Acted, then listed and restored with the real CLI.
	path := filepath.Join(dir, "payload")
	body := []byte("zaafvesper validation payload " + randID() + "\n")
	if err := os.WriteFile(path, body, 0o755); err == nil {
		_ = os.Chmod(path, 0o755)
		_ = unix.Setxattr(path, "com.rifqifitriady.validate", []byte("v1"), 0)
		e, err := fileEvent(event.CreateFile, path, w)
		if err == nil {
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: quarantine_file")
		}
		moved := err == nil && !exists(path)
		h.record("quarantine_file", "file moved into /var/db/zaafvesper/quarantine", expectAct, moved && h.decision().Outcome == response.OutcomeQuarantined, "")
		if moved {
			h.restoreCase("quarantine_file", path, func() string {
				b, _ := os.ReadFile(path)
				fi, _ := os.Stat(path)
				v := make([]byte, 8)
				n, _ := unix.Getxattr(path, "com.rifqifitriady.validate", v)
				switch {
				case string(b) != string(body):
					return "content differs"
				case fi == nil || fi.Mode().Perm() != 0o755:
					return fmt.Sprintf("mode %v", fi.Mode())
				case string(v[:n]) != "v1":
					return "extended attribute not restored"
				}
				return ""
			})
		}
	}
	// Acted: the dropped binary that ran (target process), as the built-in
	// rule does. The running process keeps running.
	dropped := filepath.Join(dir, "dropped")
	if b, err := os.ReadFile(h.subject); err == nil && os.WriteFile(dropped, b, 0o755) == nil {
		s, err := h.spawnCmd(exec.Command(dropped, "validate-response", "sleeper", "--for", "2m"))
		var p *event.Proc
		if err == nil {
			p, err = procOf(s.pid)
		}
		var st unix.Stat_t
		if err == nil {
			err = unix.Stat(dropped, &st)
		}
		if err != nil {
			h.untestable("quarantine_file", "executable of a running process (target process)", err.Error())
		} else {
			p.ExeDev, p.ExeIno = uint64(uint32(st.Dev)), st.Ino
			h.reset()
			err := h.r.QuarantineFile(&event.Event{Name: event.CreateProcess, Source: response.ESSource, Proc: p}, response.TargetProcess, "validate-quarantine", "validation: dropped binary")
			running := !s.exited(500 * time.Millisecond)
			h.record("quarantine_file", "executable of a running process (target process)", expectAct, err == nil && !exists(dropped),
				fmt.Sprintf("file gone=%v process still running=%v (expected: quarantine does not stop it)", !exists(dropped), running))
		}
	}
	// Refused: a protected system file, with its real identity.
	if e, err := fileEvent(event.WriteFile, "/usr/bin/true", w); err == nil {
		h.reset()
		err := h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: protected")
		h.record("quarantine_file", "/usr/bin/true (protected path)", expectDeny, errors.Is(err, response.ErrProtectedPath) && exists("/usr/bin/true"), "")
	}
	// Refused: the file was replaced after the event (dev/ino differ).
	repl := filepath.Join(dir, "replaced")
	if os.WriteFile(repl, []byte("one"), 0o644) == nil {
		e := h.mustEvent(event.CreateFile, repl, w)
		_ = os.Remove(repl)
		_ = os.WriteFile(repl, []byte("two"), 0o644)
		h.reset()
		err := h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: replaced")
		h.record("quarantine_file", "file replaced since the event", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(repl), "")
	}
	// Refused: a symbolic link (to a file the harness owns).
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if os.WriteFile(target, []byte("t"), 0o644) == nil && os.Symlink(target, link) == nil {
		e := h.mustEvent(event.CreateFile, link, w)
		h.reset()
		err := h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: symlink")
		h.record("quarantine_file", "symbolic link", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(target) && exists(link), "")
	}
}

// restoreCase finds path in `zaafvesper quarantine list`, restores it with
// `zaafvesper quarantine restore` and runs check on the result.
func (h *vHarness) restoreCase(action, path string, check func() string) {
	out, err := h.runSelf("quarantine", "list")
	id := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, path) {
			id = strings.Fields(line)[0]
			break
		}
	}
	if err != nil || id == "" {
		h.reset()
		h.record(action, "quarantine list shows it", expectAct, false, fmt.Sprintf("list: %v %q", err, out))
		return
	}
	h.reset()
	h.record(action, "zaafvesper quarantine list shows it", expectAct, true, "id "+id)
	out, err = h.runSelf("quarantine", "restore", id)
	why := "restore failed"
	if err == nil {
		why = check()
	}
	h.record(action, "zaafvesper quarantine restore puts it back", expectAct, err == nil && why == "", strings.TrimSpace(why+" "+out))
}

func (h *vHarness) requarantineCases() {
	say(h.stdout, "--- requarantine")
	w, err := h.writer()
	if err != nil {
		h.untestable("requarantine", "remover process", err.Error())
		return
	}
	for _, c := range []struct {
		kase, expect string
		remover      *event.Proc
	}{
		{"quarantine attribute stripped by an untrusted process", expectAct, w},
		{"stripped by Apple's xattr under a trusted parent", expectDeny, &event.Proc{PID: w.PID, PPID: 1, Exe: "/usr/bin/xattr", Name: "xattr",
			IsPlatform: true, UniqueID: w.UniqueID, StartTime: w.StartTime, UID: w.UID, EUID: w.EUID,
			Parent: &event.Proc{PID: 1, Exe: "/sbin/launchd", Name: "launchd", IsPlatform: true}}},
	} {
		path := filepath.Join(h.dir, "dl-"+randID())
		if err := os.WriteFile(path, []byte("downloaded"), 0o755); err != nil {
			h.untestable("requarantine", c.kase, err.Error())
			continue
		}
		_ = unix.Setxattr(path, response.QuarantineXattr, []byte("0083;00000000;Safari;"), 0)
		_ = unix.Removexattr(path, response.QuarantineXattr)
		e := h.mustEvent(event.DeleteXattr, path, c.remover)
		e.Args = map[string]string{"xattr": response.QuarantineXattr}
		h.reset()
		err := h.r.Requarantine(e, "validate-requarantine", "validation: "+c.kase)
		v := make([]byte, 64)
		n, xerr := unix.Getxattr(path, response.QuarantineXattr, v)
		if c.expect == expectAct {
			h.record("requarantine", c.kase, expectAct, err == nil && xerr == nil && strings.HasPrefix(string(v[:n]), "0001;"),
				fmt.Sprintf("attribute now %q", string(v[:max(n, 0)])))
		} else {
			h.record("requarantine", c.kase, expectDeny, err != nil && xerr != nil, "attribute stays absent")
		}
	}
}

func plistXML(label string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>` + label + `</string>
<key>ProgramArguments</key><array><string>/bin/sleep</string><string>600</string></array>
<key>RunAtLoad</key><true/></dict></plist>
`)
}

func loaded(domain, label string) bool {
	_, err := run(response.LaunchctlBin, "print", domain+"/"+label)
	return err == nil
}

// launchItem writes a test plist at path owned by uid and bootstraps it in
// domain unless load is false; cleanup boots it out and removes the file.
func (h *vHarness) launchItem(domain, path, label string, uid int, load bool) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.Write(plistXML(label))
	if werr == nil {
		werr = f.Chown(uid, 0)
	}
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	h.cleanup = append(h.cleanup, func() {
		_, _ = run(response.LaunchctlBin, "bootout", domain+"/"+label)
		_ = os.Remove(path)
	})
	if !load {
		return nil
	}
	if out, err := run(response.LaunchctlBin, "bootstrap", domain, path); err != nil {
		return fmt.Errorf("launchctl bootstrap %s: %v %s", domain, err, strings.TrimSpace(out))
	}
	if !loaded(domain, label) {
		return fmt.Errorf("launchctl print %s/%s: not loaded after bootstrap", domain, label)
	}
	return nil
}

func (h *vHarness) persistenceCases() {
	say(h.stdout, "--- remove_persistence")
	w, err := h.writer()
	if err != nil {
		h.untestable("remove_persistence", "writer process", err.Error())
		return
	}
	// System domain (LaunchDaemon), then restore with the CLI.
	label := vLabelPrefix + "d" + randID()
	path := "/Library/LaunchDaemons/" + label + ".plist"
	if err := h.launchItem("system", path, label, 0, true); err != nil {
		h.untestable("remove_persistence", "LaunchDaemon in the system domain", err.Error())
	} else {
		e := h.mustEvent(event.CreateFile, path, w)
		h.reset()
		err := h.r.RemovePersistence(e, "validate-persistence", "validation: LaunchDaemon")
		gone, out := !loaded("system", label), !exists(path)
		h.record("remove_persistence", "LaunchDaemon loaded in the system domain", expectAct,
			err == nil && gone && out && h.decision().Outcome == response.OutcomePersistenceRemoved,
			fmt.Sprintf("booted out=%v plist moved=%v", gone, out))
		if out {
			h.restoreCase("remove_persistence", path, func() string {
				if !exists(path) {
					return "plist not back"
				}
				if loaded("system", label) {
					return "restored plist was loaded again (it must not be)"
				}
				return ""
			})
		}
	}
	// Borrowed label: a second plist with the label of a loaded job.
	labelA := vLabelPrefix + "a" + randID()
	pathA := "/Library/LaunchDaemons/" + labelA + ".plist"
	pathB := "/Library/LaunchDaemons/" + vLabelPrefix + "b" + randID() + ".plist"
	if err := h.launchItem("system", pathA, labelA, 0, true); err != nil {
		h.untestable("remove_persistence", "borrowed label", err.Error())
	} else if err := h.launchItem("system", pathB, labelA, 0, false); err != nil {
		h.untestable("remove_persistence", "borrowed label", err.Error())
	} else {
		e := h.mustEvent(event.CreateFile, pathB, w)
		h.reset()
		err := h.r.RemovePersistence(e, "validate-persistence", "validation: borrowed label")
		stillLoaded := loaded("system", labelA)
		h.record("remove_persistence", "plist borrowing a loaded job's label: no bootout, plist quarantined", expectDeny,
			err == nil && stillLoaded && !exists(pathB) && strings.Contains(h.decision().Detail, "borrowed label"),
			fmt.Sprintf("real job still loaded=%v", stillLoaded))
	}
	// Refused: Apple tool writer under a trusted chain.
	labelT := vLabelPrefix + "t" + randID()
	pathT := "/Library/LaunchDaemons/" + labelT + ".plist"
	if err := h.launchItem("system", pathT, labelT, 0, true); err == nil {
		cp := &event.Proc{PID: w.PID, PPID: 1, Exe: "/bin/cp", Name: "cp", IsPlatform: true, UniqueID: w.UniqueID, StartTime: w.StartTime,
			Parent: &event.Proc{PID: 1, Exe: "/sbin/launchd", Name: "launchd", IsPlatform: true}}
		e := h.mustEvent(event.CreateFile, pathT, cp)
		h.reset()
		err := h.r.RemovePersistence(e, "validate-persistence", "validation: trusted chain")
		h.record("remove_persistence", "written by /bin/cp under a trusted chain", expectDeny,
			errors.Is(err, response.ErrProtected) && loaded("system", labelT) && exists(pathT), "")
	}
	// GUI domain of the console user (LaunchAgent).
	uid, home, err := consoleUser()
	if err != nil {
		h.untestable("remove_persistence", "LaunchAgent in the console user's gui domain", err.Error())
		return
	}
	dir, err := userDirNoFollow(home, uid, "Library", "LaunchAgents")
	if err != nil {
		h.untestable("remove_persistence", "LaunchAgent in the console user's gui domain", err.Error())
		return
	}
	labelG := vLabelPrefix + "g" + randID()
	pathG := filepath.Join(dir, labelG+".plist")
	domain := fmt.Sprintf("gui/%d", uid)
	if err := h.launchItem(domain, pathG, labelG, uid, true); err != nil {
		h.untestable("remove_persistence", "LaunchAgent in the console user's gui domain", err.Error())
		return
	}
	e := h.mustEvent(event.CreateFile, pathG, w)
	h.reset()
	err = h.r.RemovePersistence(e, "validate-persistence", "validation: LaunchAgent")
	gone := !loaded(domain, labelG)
	h.record("remove_persistence", "LaunchAgent loaded in "+domain, expectAct, err == nil && gone && !exists(pathG),
		fmt.Sprintf("booted out=%v plist moved=%v", gone, !exists(pathG)))
}

// consoleUser returns the console user's uid and home directory.
func consoleUser() (int, string, error) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, "", err
	}
	uid := int(fi.Sys().(*syscall.Stat_t).Uid)
	if uid == 0 {
		return 0, "", errors.New("no user is logged in at the console (the runner has no GUI session)")
	}
	ents, _ := os.ReadDir("/Users")
	for _, e := range ents {
		p := filepath.Join("/Users", e.Name())
		if st, err := os.Lstat(p); err == nil && st.IsDir() && int(st.Sys().(*syscall.Stat_t).Uid) == uid {
			return uid, p, nil
		}
	}
	return 0, "", fmt.Errorf("no home directory owned by uid %d", uid)
}

func (h *vHarness) isolateCases() {
	say(h.stdout, "--- isolate_process")
	if !hasAddr(vAlias) {
		h.untestable("isolate_process", "all cases", "loopback alias "+vAlias+" missing (scripts/ci/d/live-response-macos.sh adds it)")
		return
	}
	ln, err := net.Listen("tcp", vAlias+":0")
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
	dial := func() error {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if err := dial(); err != nil {
		h.untestable("isolate_process", "all cases", "the listener on the alias is not reachable before isolation: "+err.Error())
		return
	}
	p, err := h.writer()
	if err != nil {
		h.untestable("isolate_process", "test process", err.Error())
		return
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	observe := func(ip string) {
		h.r.Observe(&event.Event{Name: event.NetworkConnect, Source: "netpoll", Proc: p, Net: &event.Net{Proto: "tcp", Direction: "outbound", DstIP: ip, DstPort: 443}})
	}
	never := []string{"127.0.0.1", "17.253.144.10", "224.0.0.251"}
	if gw := defaultGateway(); gw != "" {
		never = append(never, gw)
	}
	never = append(never, resolvers()...)
	for _, ip := range append(never, vTestNet) {
		observe(ip)
	}
	var dport uint16
	_, _ = fmt.Sscan(port, &dport)
	e := &event.Event{Name: event.NetworkConnect, Source: "netpoll", Proc: p, Net: &event.Net{Proto: "tcp", Direction: "outbound", DstIP: vAlias, DstPort: dport}}
	h.reset()
	err = h.r.IsolateProcess(e, response.TargetProcess, "validate-isolate", "validation: isolate_process")
	table := pfTable()
	blocked := dial() != nil
	want := map[string]bool{vAlias: true, vTestNet: true}
	same := len(table) == len(want)
	for a := range table {
		same = same && want[a]
	}
	h.record("isolate_process", "peers blocked in pf (loopback alias, documentation address)", expectAct, err == nil && same && blocked,
		fmt.Sprintf("table=%v connection to the alias blocked=%v", keys(table), blocked))
	var leaked []string
	for _, a := range never {
		if table[a] {
			leaked = append(leaked, a)
		}
	}
	h.reset()
	h.record("isolate_process", "never-block set (gateway, DNS resolvers, loopback, Apple 17.0.0.0/8, multicast)", expectDeny, len(leaked) == 0,
		fmt.Sprintf("checked %v, blocked by mistake %v", never, leaked))
	// The CLI lists and releases.
	out, lerr := h.runSelf("isolation", "list")
	h.reset()
	h.record("isolate_process", "zaafvesper isolation list shows the address", expectAct, lerr == nil && strings.Contains(out, vAlias), strings.TrimSpace(out))
	out, rerr := h.runSelf("isolation", "release", vAlias)
	reach := dial() == nil
	h.reset()
	h.record("isolate_process", "zaafvesper isolation release lifts the block", expectAct, rerr == nil && reach && !pfTable()[vAlias],
		fmt.Sprintf("reachable again=%v %s", reach, strings.TrimSpace(out)))
	// Expiry after the time-to-live.
	time.Sleep(vIsolationTTL + time.Second)
	h.r.Tick(time.Now())
	h.reset()
	h.record("isolate_process", fmt.Sprintf("time-to-live expiry (%s in this run)", vIsolationTTL), expectAct, len(pfTable()) == 0, fmt.Sprintf("table now %v", keys(pfTable())))
	// Clean shutdown flushes the anchor and releases the pf enable
	// reference (pf returns to the state it had before the run).
	_ = h.r.Close()
	rules := strings.TrimSpace(stdout(response.PfctlBin, "-a", response.PFAnchor, "-s", "rules"))
	h.reset()
	h.record("isolate_process", "clean shutdown flushes the anchor", expectAct, rules == "", "rules left: "+rules)
	now := pfEnabled()
	h.reset()
	h.record("isolate_process", "clean shutdown releases the pf enable reference (pfctl -X)", expectAct, now == h.pfWasEnabled,
		fmt.Sprintf("pf enabled before the run=%v, after shutdown=%v", h.pfWasEnabled, now))
}

func hasAddr(ip string) bool {
	as, _ := net.InterfaceAddrs()
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().String() == ip {
			return true
		}
	}
	return false
}

func pfTable() map[string]bool {
	out := stdout(response.PfctlBin, "-a", response.PFAnchor, "-t", response.PFTable, "-T", "show")
	m := map[string]bool{}
	for _, f := range strings.Fields(out) {
		if _, err := netip.ParseAddr(f); err == nil {
			m[f] = true
		}
	}
	return m
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func defaultGateway() string {
	out, err := run(response.RouteBin, "-n", "get", "default")
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "gateway:"); ok {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				return a.String()
			}
		}
	}
	return ""
}

func resolvers() []string {
	b, _ := os.ReadFile("/private/var/run/resolv.conf")
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil && a.Zone() == "" {
				out = append(out, a.String())
			}
		}
	}
	return out
}

// platformAccidentGuard refuses where ZAAFVesper is installed or has state:
// the harness would flush the live sensor's pf anchor and write into its
// vault and isolation store.
func platformAccidentGuard() error {
	if exists(daemonPlistPath) {
		return fmt.Errorf("%s exists: ZAAFVesper is installed here; the harness runs only on a throw-away runner", daemonPlistPath)
	}
	if loaded("system", daemonLabel) {
		return errors.New("the ZAAFVesper LaunchDaemon is loaded here; the harness runs only on a throw-away runner")
	}
	if isos, err := (response.IsolationStore{Dir: response.DefaultStateDir}).Load(); err == nil && len(isos) > 0 {
		return errors.New("the isolation store holds addresses: a sensor has isolated something here")
	}
	if ents, err := os.ReadDir(response.DefaultVaultDir); err == nil && len(ents) > 0 {
		return errors.New("the quarantine vault is not empty: a sensor has quarantined files here")
	}
	return nil
}

// userDirNoFollow returns dir (under the console user's home) for writing as
// root, refusing a symbolic link or a folder that does not belong to uid on
// the way, and creating missing folders owned by uid.
func userDirNoFollow(home string, uid int, rel ...string) (string, error) {
	p := home
	for i := -1; i < len(rel); i++ {
		if i >= 0 {
			p = filepath.Join(p, rel[i])
			if err := os.Mkdir(p, 0o755); err == nil {
				if err := os.Lchown(p, uid, -1); err != nil {
					return "", err
				}
			} else if !os.IsExist(err) {
				return "", err
			}
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || int(fi.Sys().(*syscall.Stat_t).Uid) != uid {
			return "", fmt.Errorf("%s is a symbolic link, not a directory, or not owned by uid %d", p, uid)
		}
	}
	return p, nil
}
