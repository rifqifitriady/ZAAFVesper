//go:build windows

package response

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Dry-run tests of the Windows actions (CK-09). They run in the
// live-response workflow's elevated unit-test step; on a Mac they are only
// compile-checked (GOOS=windows go test -c ./pkg/response).

func wVaultCount(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func (g *wrig) assertUntouched(what string) {
	g.t.Helper()
	if len(g.cmds) != 0 {
		g.t.Fatalf("%s: dry-run ran %q", what, g.cmds)
	}
	if n := wVaultCount(g.t, g.vault); n != 0 {
		g.t.Fatalf("%s: %d vault entries", what, n)
	}
	if g.r.Retries() != 0 {
		g.t.Fatalf("%s: retries=%d", what, g.r.Retries())
	}
}

func regEvent(key, data string) *event.Event {
	name, il := winUser()
	return &event.Event{Name: event.RegistrySetValue, Source: "sysmon", Args: map[string]string{},
		Proc:     &event.Proc{PID: 4242, UniqueID: 99, StartTime: time.Unix(1, 0), Exe: `C:\Users\Public\evil.exe`, UID: -1, EUID: -1, Username: name, Integrity: il},
		Registry: &event.Registry{Key: key, Data: data}}
}

func TestWindowsRemoveRunValueDryRun(t *testing.T) {
	const keyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	name := fmt.Sprintf("ZAAFDryRun%d", os.Getpid())
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Skipf("cannot open HKLM Run key for writing (not elevated): %v", err)
	}
	defer k.Close()
	const data = `C:\Users\Public\evil.exe`
	if err := k.SetStringValue(name, data); err != nil {
		t.Skipf("cannot set the test value: %v", err)
	}
	defer k.DeleteValue(name)

	g := newWRig(t, true)
	if err := g.r.RemovePersistence(regEvent(`HKLM\`+keyPath+`\`+name, data), "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	if d := g.last(); d.Outcome != OutcomeDryRun || !strings.Contains(d.Detail, "would delete the Run value") {
		t.Fatalf("%+v", d)
	}
	if got, _, err := k.GetStringValue(name); err != nil || got != data {
		t.Fatalf("registry value changed: %q %v", got, err)
	}
	g.assertUntouched("run value")
}

func TestWindowsRemoveServiceDryRun(t *testing.T) {
	m, err := mgr.Connect()
	if err != nil {
		t.Skipf("service control manager: %v", err)
	}
	defer m.Disconnect()
	name := fmt.Sprintf("ZAAFDryRunSvc%d", os.Getpid())
	const img = `C:\Users\Public\evil.exe`
	s, err := m.CreateService(name, img, mgr.Config{StartType: mgr.StartDisabled, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS})
	if err != nil {
		t.Skipf("cannot create the test service (not elevated): %v", err)
	}
	defer func() { s.Delete(); s.Close() }()

	g := newWRig(t, true)
	key := `HKLM\SYSTEM\CurrentControlSet\Services\` + name + `\ImagePath`
	if err := g.r.RemovePersistence(regEvent(key, img), "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	if d := g.last(); d.Outcome != OutcomeDryRun || !strings.Contains(d.Detail, "would stop and delete service") {
		t.Fatalf("%+v", d)
	}
	s2, err := m.OpenService(name)
	if err != nil {
		t.Fatalf("service gone after a dry-run: %v", err)
	}
	defer s2.Close()
	if cfg, err := s2.Config(); err != nil || cfg.BinaryPathName != img {
		t.Fatalf("service changed: %+v %v", cfg, err)
	}
	g.assertUntouched("service")
}

func TestWindowsRemoveTaskDryRun(t *testing.T) {
	g := newWRig(t, true)
	old := tasksDir
	tasksDir = filepath.Join(g.dir, "Tasks")
	defer func() { tasksDir = old }()
	p := filepath.Join(tasksDir, "evil")
	xml := `<?xml version="1.0" encoding="UTF-8"?><Task><Actions><Exec><Command>C:\Users\Public\evil.exe</Command></Exec></Actions></Task>`
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	b := winWrite2(t, p)
	_ = g.r.RemovePersistence(winEvent(p, b, `C:\Users\Public\evil.exe`), "r", "r")
	if d := g.last(); d.Outcome != OutcomeDryRun || !strings.Contains(d.Detail, "would delete scheduled task") {
		t.Fatalf("%+v", d)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != xml {
		t.Fatalf("task file changed: %v", err)
	}
	g.assertUntouched("task")
}

// winWrite2 returns the birth time of an existing file.
func winWrite2(t *testing.T, path string) time.Time {
	t.Helper()
	pfd, base, err := openParentNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFD(pfd)
	fi, err := fstatatInfo(pfd, base)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Birth
}

func TestWindowsQuarantineAndIsolateDryRun(t *testing.T) {
	g := newWRig(t, true)
	p := filepath.Join(g.dir, "drop", "payload.exe")
	b := winWrite(t, p)
	_ = g.r.QuarantineFile(winEvent(p, b, `C:\Users\Public\evil.exe`), TargetFile, "r", "r")
	if d := g.last(); d.Outcome != OutcomeDryRun || !wexists(p) {
		t.Fatalf("quarantine: %+v", d)
	}
	g.assertUntouched("quarantine")

	e := &event.Event{Name: event.NetworkConnect, Source: "sysmon", Args: map[string]string{},
		Proc: &event.Proc{PID: 5000, UniqueID: 55, StartTime: time.Unix(1, 0), Exe: `C:\Users\a\evil.exe`, UID: -1, EUID: -1},
		Net:  &event.Net{Direction: "outbound", SrcIP: "10.0.0.5", DstIP: "192.0.2.7"}}
	g.r.Observe(e)
	_ = g.r.IsolateProcess(e, TargetProcess, "r", "r")
	if d := g.last(); d.Outcome != OutcomeDryRun || !strings.Contains(d.Detail, "would block") {
		t.Fatalf("isolate: %+v", d)
	}
	g.assertUntouched("isolate") // no netsh run
}

// CK-42: DRIVE_REMOTE (and every non-local drive type) is refused.
func TestWindowsRemoteDriveRefused(t *testing.T) {
	for _, c := range []struct {
		typ   uint32
		local bool
	}{{windows.DRIVE_FIXED, true}, {windows.DRIVE_REMOVABLE, true}, {windows.DRIVE_RAMDISK, true},
		{windows.DRIVE_REMOTE, false}, {windows.DRIVE_CDROM, false}, {windows.DRIVE_UNKNOWN, false}, {windows.DRIVE_NO_ROOT_DIR, false}} {
		if localDriveType(c.typ) != c.local {
			t.Errorf("drive type %d: local=%v", c.typ, !c.local)
		}
	}
	old := driveTypeOf
	defer func() { driveTypeOf = old }()
	driveTypeOf = func(*uint16) uint32 { return windows.DRIVE_REMOTE }

	g := newWRig(t, false)
	p := filepath.Join(g.dir, "d", "f.exe")
	b := winWrite(t, p)
	_ = g.r.QuarantineFile(winEvent(p, b, `C:\Users\Public\evil.exe`), TargetFile, "r", "r")
	if d := g.last(); d.Outcome != OutcomeFileCheck || !strings.Contains(d.Detail, "not on a local file system") || !wexists(p) {
		t.Fatalf("%+v", d)
	}
}

// D10: an unreadable firewall state is unknown, not on; a missing key is
// Windows' default (on).
func TestWindowsFirewallStateFailsClosed(t *testing.T) {
	denied := windows.ERROR_ACCESS_DENIED
	val := func(v uint64, err error) func(string) (uint64, error) {
		return func(string) (uint64, error) { return v, err }
	}
	for _, c := range []struct {
		name string
		read func(string) (uint64, error)
		want fwStatus
	}{
		{"on", val(1, nil), fwOn},
		{"off", val(0, nil), fwOff},
		{"not configured", val(0, registry.ErrNotExist), fwOn},
		{"access denied", val(0, denied), fwUnknown},
		{"policy absent, local off", func(b string) (uint64, error) {
			if strings.Contains(b, "Policies") {
				return 0, registry.ErrNotExist
			}
			return 0, nil
		}, fwOff},
		{"policy absent, local unreadable", func(b string) (uint64, error) {
			if strings.Contains(b, "Policies") {
				return 0, registry.ErrNotExist
			}
			return 0, denied
		}, fwUnknown},
	} {
		if got := firewallState("PublicProfile", c.read); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}
