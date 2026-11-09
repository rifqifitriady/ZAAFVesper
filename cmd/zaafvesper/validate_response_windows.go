//go:build zaafvesper_validate && windows

package main

import (
	"crypto/sha256"
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
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

const (
	// vProbe is a public anycast address the runner reaches on 443; the
	// harness blocks it for a few seconds to show the rule works (Windows
	// Firewall does not filter loopback traffic).
	vProbe = "1.1.1.1"
	// vTestNet is a documentation address that routes nowhere.
	vTestNet      = "192.0.2.10"
	vIsolationTTL = 15 * time.Second
	// vName prefixes every Run value, service and task the harness creates.
	vName = "ZVValidate"
)

func sysExec(string, []string) error { return errors.New("exec is not used on Windows") }

func exeSuffix() string { return ".exe" }

func validateTempRoot() string { return os.TempDir() }

// waitState waits until every thread of pid is suspended (stopped) or
// none is (running). Windows has no process state to read: each thread's
// suspend count is read by SuspendThread, which returns the previous count,
// and undone at once by ResumeThread. The heartbeat file of the sleeper
// (--beat) is reported alongside.
func waitState(pid int32, stopped bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		n, susp, err := threadStates(uint32(pid))
		if err == nil && n > 0 && (stopped && susp == n || !stopped && susp == 0) {
			return true
		}
		if time.Now().After(deadline) {
			beat := ""
			if v, ok := beatFiles.Load(pid); ok {
				a, _ := os.ReadFile(v.(string))
				time.Sleep(300 * time.Millisecond)
				b, _ := os.ReadFile(v.(string))
				beat = fmt.Sprintf(" heartbeat %q then %q", a, b)
			}
			say(os.Stderr, "waitState(%d, stopped=%v): %d threads, %d suspended, %v%s", pid, stopped, n, susp, err, beat)
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

var procSuspendThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("SuspendThread")

// threadStates counts the threads of pid and those with a suspend count
// above zero.
func threadStates(pid uint32) (n, suspended int, err error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, 0, err
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		h, oerr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if oerr != nil {
			continue
		}
		prev, _, _ := procSuspendThread.Call(uintptr(h))
		if int32(prev) != -1 {
			_, _ = windows.ResumeThread(h)
			n++
			if prev > 0 {
				suspended++
			}
		}
		windows.CloseHandle(h)
	}
	return n, suspended, nil
}

func (h *vHarness) platformConfig(rc *response.Config) { rc.IsolationTTL = vIsolationTTL }

func (h *vHarness) runPlatform() {
	h.untestable("kill", "Sysmon ProcessGuid binding", "done by the Sysmon source (pkg/source/sysmon Binder), which does not run here; the creation-time check it feeds is exercised above (workstream B validates Sysmon)")
	h.untestable("requarantine", "all cases", "macOS only (com.apple.quarantine): refused-unsupported on Windows (run_windows.go supportedActions)")
	if err := h.r.StartResponse(); err != nil {
		say(h.stdout, "note: StartResponse: %v", err)
	}
	h.cleanup = append(h.cleanup, func() { _ = h.r.Close() })
	h.cleanup = append(h.cleanup, func() { _ = os.RemoveAll(response.DefaultStateDir) })
	h.quarantineCases()
	h.runValueCases()
	h.serviceCases()
	h.taskCases()
	h.isolateCases()
}

// created returns a file's creation time as Sysmon prints CreationUtcTime.
func created(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return "", errors.New("no creation time")
	}
	return time.Unix(0, d.CreationTime.Nanoseconds()).UTC().Format("2006-01-02 15:04:05.000"), nil
}

func userName() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	acct, dom, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	return dom + `\` + acct
}

// sysmonFile is a Sysmon CreateFile event for path written by w.
func sysmonFile(path string, w *event.Proc) (*event.Event, error) {
	c, err := created(path)
	if err != nil {
		return nil, err
	}
	p := *w
	p.UID, p.EUID, p.Username = -1, -1, userName()
	return &event.Event{Name: event.CreateFile, Source: "sysmon", Proc: &p, File: &event.File{Path: path},
		Args: map[string]string{"creation_utc_time": c}}, nil
}

// vaultACL is icacls' view of the vault directory.
func vaultACL() (string, bool) {
	out, err := run(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), response.DefaultVaultDir)
	if err != nil {
		return out, false
	}
	ok := true
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), response.DefaultVaultDir))
		if !strings.Contains(line, ":(") {
			continue
		}
		if !strings.HasPrefix(line, `NT AUTHORITY\SYSTEM:`) && !strings.HasPrefix(line, `BUILTIN\Administrators:`) {
			ok = false
		}
	}
	return oneLine(out), ok
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
	path := filepath.Join(dir, "payload.exe")
	body := []byte("zaafvesper validation payload " + randID() + "\n")
	if os.WriteFile(path, body, 0o644) == nil {
		e, err := sysmonFile(path, w)
		if err != nil {
			h.untestable("quarantine_file", "file bound by creation time", err.Error())
		} else {
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: quarantine_file")
			moved := err == nil && !exists(path)
			acl, private := vaultACL()
			h.record("quarantine_file", "file bound by creation time moved into "+response.DefaultVaultDir+" (SYSTEM and Administrators only)", expectAct,
				moved && private && h.decision().Outcome == response.OutcomeQuarantined, fmt.Sprintf("file gone=%v icacls: %s", !exists(path), acl))
			if moved {
				h.restoreCase("quarantine_file", path, func() string {
					if b, _ := os.ReadFile(path); string(b) != string(body) {
						return "content differs"
					}
					return ""
				})
			}
		}
	}
	// The executable of a process that was killed first (the rule order
	// kill, quarantine_file): bound by the SHA-256 Sysmon reports.
	dropped := filepath.Join(dir, "dropped.exe")
	if b, err := os.ReadFile(h.subject); err == nil && os.WriteFile(dropped, b, 0o755) == nil {
		s, err := h.spawnCmd(exec.Command(dropped, "validate-response", "sleeper", "--for", "2m"))
		var p *event.Proc
		if err == nil {
			p, err = procOf(s.pid)
		}
		if err != nil {
			h.untestable("quarantine_file", "executable after kill (target process)", err.Error())
		} else {
			sum := sha256.Sum256(b)
			p.UID, p.EUID, p.Username, p.Integrity = -1, -1, userName(), "High"
			p.Hashes = "SHA1=0,MD5=0,SHA256=" + strings.ToUpper(hex.EncodeToString(sum[:])) + ",IMPHASH=0"
			e := &event.Event{Name: event.CreateProcess, Source: "sysmon", Proc: p, Args: map[string]string{}}
			_ = h.r.KillEvent(e, "validate-quarantine", "validation: kill before quarantine")
			_ = s.exited(5 * time.Second)
			time.Sleep(500 * time.Millisecond)
			h.reset()
			err := h.r.QuarantineFile(e, response.TargetProcess, "validate-quarantine", "validation: dropped binary")
			h.record("quarantine_file", "executable after kill (target process, bound by Sysmon's SHA-256)", expectAct, err == nil && !exists(dropped),
				fmt.Sprintf("file gone=%v", !exists(dropped)))
		}
	}
	// Refused: a protected system file.
	hosts := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	if e, err := sysmonFile(hosts, w); err == nil {
		h.reset()
		err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: protected")
		h.record("quarantine_file", hosts+" (protected path)", expectDeny, errors.Is(err, response.ErrProtectedPath) && exists(hosts), "")
	}
	// Refused: content that is not what Sysmon hashed.
	other := filepath.Join(dir, "other.exe")
	if os.WriteFile(other, []byte("other"), 0o755) == nil {
		p := *w
		p.Exe, p.UID, p.EUID, p.Username, p.Integrity = other, -1, -1, userName(), "High"
		p.Hashes = "SHA256=" + strings.Repeat("AB", 32)
		h.reset()
		err := h.r.QuarantineFile(&event.Event{Name: event.CreateProcess, Source: "sysmon", Proc: &p, Args: map[string]string{}}, response.TargetProcess, "validate-quarantine", "validation: hash")
		h.record("quarantine_file", "executable whose content is not the hash Sysmon reported", expectDeny,
			err != nil && exists(other) && strings.Contains(h.decision().Detail, "not the"), "")
	}
	// Refused: another creation time (the file was replaced). NTFS
	// tunneling gives a file created under a name deleted less than 15 s
	// before the old creation time, so the new file is made after 16 s.
	repl := filepath.Join(dir, "replaced.exe")
	if os.WriteFile(repl, []byte("one"), 0o644) == nil {
		if e, err := sysmonFile(repl, w); err == nil {
			_ = os.Remove(repl)
			time.Sleep(16 * time.Second)
			_ = os.WriteFile(repl, []byte("two"), 0o644)
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: replaced")
			h.record("quarantine_file", "file replaced since the event (creation time differs)", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(repl), "")
		}
	}
	// Refused: a junction in the path (mklink /J).
	target := filepath.Join(dir, "target.exe")
	j := filepath.Join(h.dir, "junction")
	if os.WriteFile(target, []byte("t"), 0o644) == nil {
		if out, err := run(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "mklink", "/J", j, dir); err != nil {
			h.untestable("quarantine_file", "junction in the path", out)
		} else if e, err := sysmonFile(target, w); err == nil {
			e.File.Path = filepath.Join(j, "target.exe")
			h.reset()
			err = h.r.QuarantineFile(e, response.TargetFile, "validate-quarantine", "validation: junction")
			h.record("quarantine_file", "junction in the path", expectDeny, errors.Is(err, response.ErrFileCheck) && exists(target), "")
		}
	}
}

func regOpen(hive registry.Key, key string) (registry.Key, error) {
	k, _, err := registry.CreateKey(hive, key, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	return k, err
}

const runKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

func (h *vHarness) runValueCases() {
	say(h.stdout, "--- remove_persistence: Run values")
	w, err := h.writer()
	if err != nil {
		h.untestable("remove_persistence", "writer process", err.Error())
		return
	}
	sid := ""
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		sid = u.User.Sid.String()
	}
	data := `"` + h.subject + `" validate-response sleeper`
	for _, c := range []struct {
		kase, hiveName, prefix string
		hive                   registry.Key
	}{
		{"HKLM Run value", "HKLM", "", registry.LOCAL_MACHINE},
		{"HKU\\<user SID> Run value (HKCU)", "HKU", sid + `\`, registry.USERS},
	} {
		name := vName + randID()
		k, err := regOpen(c.hive, c.prefix+runKey)
		if err != nil {
			h.untestable("remove_persistence", c.kase, err.Error())
			continue
		}
		hive, key := c.hive, c.prefix+runKey
		h.cleanup = append(h.cleanup, func() {
			if k, err := regOpen(hive, key); err == nil {
				_ = k.DeleteValue(name)
				k.Close()
			}
		})
		if err := k.SetStringValue(name, data); err != nil {
			k.Close()
			h.untestable("remove_persistence", c.kase, err.Error())
			continue
		}
		e := &event.Event{Name: event.RegistrySetValue, Source: "sysmon", Proc: w, Args: map[string]string{},
			Registry: &event.Registry{Key: c.hiveName + `\` + c.prefix + runKey + `\` + name, Value: name, Data: data}}
		h.reset()
		err = h.r.RemovePersistence(e, "validate-persistence", "validation: "+c.kase)
		_, _, gerr := k.GetStringValue(name)
		gone := errors.Is(gerr, registry.ErrNotExist)
		h.record("remove_persistence", c.kase+" set by an untrusted process: deleted, saved", expectAct, err == nil && gone, fmt.Sprintf("value gone=%v", gone))
		if gone && c.hiveName == "HKLM" {
			h.restoreCase("remove_persistence", e.Registry.Key, func() string {
				v, _, err := k.GetStringValue(name)
				if err != nil || v != data {
					return fmt.Sprintf("value not back (%v %q)", err, v)
				}
				return ""
			})
		}
		k.Close()
	}
	// Refused: the value changed since the event; and a trusted writer.
	name := vName + randID()
	k, err := regOpen(registry.LOCAL_MACHINE, runKey)
	if err != nil {
		return
	}
	defer k.Close()
	h.cleanup = append(h.cleanup, func() {
		if k, err := regOpen(registry.LOCAL_MACHINE, runKey); err == nil {
			_ = k.DeleteValue(name)
			k.Close()
		}
	})
	_ = k.SetStringValue(name, "now different")
	e := &event.Event{Name: event.RegistrySetValue, Source: "sysmon", Proc: w, Args: map[string]string{},
		Registry: &event.Registry{Key: `HKLM\` + runKey + `\` + name, Value: name, Data: data}}
	h.reset()
	err = h.r.RemovePersistence(e, "validate-persistence", "validation: changed")
	_, _, gerr := k.GetStringValue(name)
	h.record("remove_persistence", "Run value changed since the event", expectDeny, errors.Is(err, response.ErrFileCheck) && gerr == nil, "")
	_ = k.SetStringValue(name, data)
	tw := *w
	tw.Exe = filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe")
	tw.Parent = &event.Proc{PID: 1, Exe: filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")}
	e.Proc = &tw
	h.reset()
	err = h.r.RemovePersistence(e, "validate-persistence", "validation: trusted writer")
	_, _, gerr = k.GetStringValue(name)
	h.record("remove_persistence", "Run value set by reg.exe under cmd.exe (trusted writer)", expectDeny, errors.Is(err, response.ErrProtected) && gerr == nil, "")
}

func (h *vHarness) serviceCases() {
	say(h.stdout, "--- remove_persistence: services")
	m, err := mgr.Connect()
	if err != nil {
		h.untestable("remove_persistence", "services", err.Error())
		return
	}
	defer m.Disconnect()
	scm := &event.Proc{PID: 700, UniqueID: 1, StartTime: time.Now(), Exe: filepath.Join(os.Getenv("SystemRoot"), "System32", "services.exe"), UID: -1, EUID: -1}
	// The writer of a service key is the Service Control Manager; it is
	// judged by the program the service runs. Its identity is the real
	// services.exe process's.
	if pid := findPID("services.exe"); pid > 0 {
		if p, err := procOf(pid); err == nil {
			scm = p
		}
	}
	mk := func(name, exe string, args ...string) (string, error) {
		s, err := m.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, DisplayName: "ZAAFVesper validation"}, args...)
		if err != nil {
			return "", err
		}
		defer s.Close()
		h.cleanup = append(h.cleanup, func() {
			if s, err := m.OpenService(name); err == nil {
				_ = s.Delete()
				s.Close()
			}
		})
		c, err := s.Config()
		return c.BinaryPathName, err
	}
	present := func(name string) bool {
		// Query rights only: Defender's service denies more even to
		// administrators.
		h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS)
		if err == nil {
			_ = windows.CloseServiceHandle(h)
		}
		return err == nil
	}
	ev := func(name, data string) *event.Event {
		return &event.Event{Name: event.RegistrySetValue, Source: "sysmon", Proc: scm, Args: map[string]string{},
			Registry: &event.Registry{Key: `HKLM\System\CurrentControlSet\Services\` + name + `\ImagePath`, Value: "ImagePath", Data: data}}
	}
	name := vName + "Svc" + randID()
	if bin, err := mk(name, h.subject, "validate-response", "sleeper"); err != nil {
		h.untestable("remove_persistence", "service", err.Error())
	} else {
		h.reset()
		err := h.r.RemovePersistence(ev(name, bin), "validate-persistence", "validation: service")
		h.record("remove_persistence", "service running a program from a writable folder: deleted, saved", expectAct, err == nil && !present(name),
			fmt.Sprintf("service gone=%v", !present(name)))
		if !present(name) {
			h.restoreCase("remove_persistence", `HKLM\System\CurrentControlSet\Services\`+name+`\ImagePath`, func() string {
				if !present(name) {
					return "service not re-created"
				}
				return ""
			})
		}
	}
	sysName := vName + "Sys" + randID()
	if bin, err := mk(sysName, filepath.Join(os.Getenv("SystemRoot"), "System32", "svchost.exe"), "-k", "zvvalidate"); err == nil {
		h.reset()
		err := h.r.RemovePersistence(ev(sysName, bin), "validate-persistence", "validation: system service")
		h.record("remove_persistence", "service running a system program (svchost.exe)", expectDeny, errors.Is(err, response.ErrProtected) && present(sysName), "")
	}
	chName := vName + "Chg" + randID()
	if _, err := mk(chName, h.subject, "validate-response", "sleeper"); err == nil {
		h.reset()
		err := h.r.RemovePersistence(ev(chName, `C:\elsewhere\x.exe`), "validate-persistence", "validation: changed service")
		h.record("remove_persistence", "service whose command line changed since the event", expectDeny, errors.Is(err, response.ErrFileCheck) && present(chName), "")
	}
	h.reset()
	err = h.r.RemovePersistence(ev("WinDefend", `"C:\ProgramData\Microsoft\Windows Defender\platform\MsMpEng.exe"`), "validate-persistence", "validation: Defender")
	h.record("remove_persistence", "WinDefend (protected service)", expectDeny, errors.Is(err, response.ErrLabel) && present("WinDefend"), "")
}

func findPID(image string) int32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), image) {
			return int32(pe.ProcessID)
		}
	}
	return 0
}

func schtasks(args ...string) (string, error) { return run(response.SchtasksBin, args...) }

func (h *vHarness) taskCases() {
	say(h.stdout, "--- remove_persistence: scheduled tasks")
	tasks := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	svchost := &event.Proc{PID: 900, UniqueID: 1, StartTime: time.Now(), Exe: filepath.Join(os.Getenv("SystemRoot"), "System32", "svchost.exe"), UID: -1, EUID: -1}
	if pid := findPID("svchost.exe"); pid > 0 {
		if p, err := procOf(pid); err == nil {
			svchost = p
			svchost.UID, svchost.EUID = -1, -1
		}
	}
	mk := func(name, tr string) (string, error) {
		h.cleanup = append(h.cleanup, func() { _, _ = schtasks("/Delete", "/TN", name, "/F") })
		if out, err := schtasks("/Create", "/TN", name, "/TR", tr, "/SC", "ONCE", "/ST", "23:59", "/F"); err != nil {
			return "", errors.New(oneLine(out))
		}
		return filepath.Join(tasks, strings.TrimPrefix(name, `\`)), nil
	}
	queried := func(name string) bool { _, err := schtasks("/Query", "/TN", name); return err == nil }
	name := `\` + vName + `\T` + randID()
	if path, err := mk(name, `"`+h.subject+`" validate-response sleeper`); err != nil {
		h.untestable("remove_persistence", "scheduled task", err.Error())
	} else if e, err := sysmonFile(path, svchost); err != nil {
		h.untestable("remove_persistence", "scheduled task", err.Error())
	} else {
		h.reset()
		err := h.r.RemovePersistence(e, "validate-persistence", "validation: task")
		h.record("remove_persistence", "scheduled task running a program from a writable folder: deleted, saved", expectAct, err == nil && !queried(name) && !exists(path),
			fmt.Sprintf("task gone=%v file gone=%v", !queried(name), !exists(path)))
		if !queried(name) {
			h.restoreCase("remove_persistence", path, func() string {
				if !queried(name) {
					return "task not re-created"
				}
				return ""
			})
		}
	}
	sys := `\` + vName + `\S` + randID()
	if path, err := mk(sys, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")+" /c exit"); err == nil {
		if e, err := sysmonFile(path, svchost); err == nil {
			h.reset()
			err := h.r.RemovePersistence(e, "validate-persistence", "validation: system task")
			h.record("remove_persistence", "scheduled task running only a system program (cmd.exe)", expectDeny, errors.Is(err, response.ErrProtected) && queried(sys), "")
		}
	}
	ms := filepath.Join(tasks, "Microsoft", "Windows", "Defrag", "ScheduledDefrag")
	if e, err := sysmonFile(ms, svchost); err == nil {
		h.reset()
		err := h.r.RemovePersistence(e, "validate-persistence", "validation: Microsoft task")
		h.record("remove_persistence", `Windows' own task \Microsoft\Windows\Defrag\ScheduledDefrag`, expectDeny, errors.Is(err, response.ErrProtectedPath) && exists(ms), "")
	}
	h.cleanup = append(h.cleanup, func() { _ = os.Remove(filepath.Join(tasks, vName)) })
}

// fwRules lists the remote addresses of ZAAFVesper's Windows Firewall rules.
func fwRules() map[string]bool {
	out := stdout(response.NetshBin, "advfirewall", "firewall", "show", "rule", "name="+response.WinRuleName, "verbose")
	m := map[string]bool{}
	for _, f := range strings.Fields(out) {
		f = strings.TrimSuffix(strings.TrimSuffix(f, "/32"), "/128")
		if a, err := netip.ParseAddr(f); err == nil && !a.IsUnspecified() {
			m[a.Unmap().String()] = true
		}
	}
	// Local addresses ("Any") are not addresses; remote ones are listed.
	return m
}

func (h *vHarness) isolateCases() {
	say(h.stdout, "--- isolate_process")
	never := []string{"127.0.0.1", "::1", "224.0.0.251"}
	if as, err := net.InterfaceAddrs(); err == nil {
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil && !p.Addr().IsLoopback() && p.Addr().Zone() == "" && !p.Addr().IsLinkLocalUnicast() {
				never = append(never, p.Addr().Unmap().String())
			}
		}
	}
	gws, _ := response.DefaultGateways()
	for _, g := range gws {
		never = append(never, g.String())
	}
	for _, r := range response.DefaultResolvers() {
		if r.Zone() == "" && !r.IsLinkLocalUnicast() {
			never = append(never, r.String())
		}
	}
	h.isolateFlow(isoCase{probe: vProbe, port: "443", extra: vTestNet, never: never, listed: fwRules, where: "Windows Firewall rules " + response.WinRuleName,
		ttl: vIsolationTTL, cleared: func() (bool, string) {
			left := fwRules()
			return len(left) == 0, fmt.Sprintf("rules left for %v", keys(left))
		}})
}

// platformAccidentGuard refuses where the ZAAFVesper service is installed
// or has state.
func platformAccidentGuard() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+serviceName, registry.QUERY_VALUE)
	if err == nil {
		_ = k.Close()
		return errors.New("the ZAAFVesper service is installed here; the harness runs only on a throw-away runner")
	}
	if exists(response.DefaultStateDir) {
		return fmt.Errorf("%s exists: ZAAFVesper has state here; the harness runs only on a throw-away runner", response.DefaultStateDir)
	}
	return nil
}

// pidAlive reports whether pid exists: it can be opened, or opening it is
// denied (a protected or kernel process).
func pidAlive(pid int32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		defer windows.CloseHandle(h)
		var code uint32
		return windows.GetExitCodeProcess(h, &code) == nil && code == 259 // STILL_ACTIVE
	}
	return errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
