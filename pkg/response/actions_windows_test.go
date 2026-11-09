//go:build windows

package response

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// These tests run on a Windows runner (the live-response workflow runs
// them): real files, ACLs and process handles in a temp directory; netsh
// and schtasks are stubbed.

type wrig struct {
	t     *testing.T
	dir   string
	now   time.Time
	logs  []Decision
	cmds  []string
	run   func(bin string, args []string) ([]byte, error)
	r     *Responder
	vault string
	state string
}

func newWRig(t *testing.T) *wrig {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := &wrig{t: t, dir: d, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	g.state = filepath.Join(d, "state")
	g.vault = filepath.Join(g.state, "quarantine")
	pfd, base, err := openParentNoFollow(g.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := mkdirPrivate(pfd, base); err != nil {
		t.Fatal(err)
	}
	closeFD(pfd)
	g.r = New(Config{
		Now: func() time.Time { return g.now }, Log: func(dd Decision) { g.logs = append(g.logs, dd) },
		StateDir: g.state, VaultDir: g.vault,
		Runner: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
			g.cmds = append(g.cmds, filepath.Base(bin)+" "+strings.Join(args, " "))
			if g.run != nil {
				return g.run(bin, args)
			}
			return nil, nil
		},
		KillFunc:   func(int, syscall.Signal) error { return errors.New("no signals in tests") },
		LocalAddrs: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil },
		Gateways:   func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil },
		Resolvers:  func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.0.0.53")} },
	})
	return g
}

func (g *wrig) last() Decision {
	if len(g.logs) == 0 {
		g.t.Fatal("no decision")
	}
	return g.logs[len(g.logs)-1]
}

func winWrite(t *testing.T, path string) time.Time {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
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

func winEvent(path string, birth time.Time, exe string) *event.Event {
	e := &event.Event{Name: event.CreateFile, Source: "sysmon", Args: map[string]string{},
		Proc: &event.Proc{PID: 4242, UniqueID: 99, StartTime: time.Unix(1, 0), Exe: exe, UID: -1, EUID: -1},
		File: &event.File{Path: path}}
	if !birth.IsZero() {
		e.Args["creation_utc_time"] = birth.UTC().Format(sysmonTimeLayout)
	}
	return e
}

func wexists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestWindowsVaultIsPrivate(t *testing.T) {
	g := newWRig(t)
	fd, err := openDirNoFollow(g.state)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := fstatInfo(fd)
	if err := privateDir(fd, fi, false); err != nil {
		t.Fatalf("private dir refused: %v", err)
	}
	closeFD(fd)
	open := filepath.Join(g.dir, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err = openDirNoFollow(open)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFD(fd)
	fi, _ = fstatInfo(fd)
	if err := privateDir(fd, fi, false); err == nil {
		t.Fatal("a directory with an inherited ACL accepted as private")
	}
}

func TestWindowsQuarantineByCreationTime(t *testing.T) {
	g := newWRig(t)
	p := filepath.Join(g.dir, "drop", "payload.exe")
	b := winWrite(t, p)
	if err := g.r.QuarantineFile(winEvent(p, b, `C:\Users\x\AppData\Local\Temp\evil.exe`), TargetFile, "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	if g.last().Outcome != OutcomeQuarantined || wexists(p) {
		t.Fatalf("%+v", g.last())
	}
	v := Vault{Dir: g.vault}
	items, err := v.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("%v %+v", err, items)
	}
	if _, _, err := v.Restore(items[0].ID[:12]); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "evil" {
		t.Fatalf("restore %q %v", b, err)
	}
}

func TestWindowsQuarantineRefusals(t *testing.T) {
	g := newWRig(t)
	p := filepath.Join(g.dir, "d", "f.exe")
	b := winWrite(t, p)
	check := func(name string, e *event.Event, outcome string) {
		t.Helper()
		_ = g.r.QuarantineFile(e, TargetFile, "r-"+name, "r")
		if g.last().Outcome != outcome {
			t.Errorf("%s: %+v", name, g.last())
		}
		if !wexists(p) {
			t.Fatalf("%s: removed", name)
		}
	}
	check("no binding", winEvent(p, time.Time{}, `C:\evil.exe`), OutcomeFileCheck)
	check("other creation time", winEvent(p, b.Add(-time.Second), `C:\evil.exe`), OutcomeFileCheck)
	if err := os.Link(p, p+".2"); err == nil {
		check("two names", winEvent(p, b, `C:\evil.exe`), OutcomeFileCheck)
		_ = os.Remove(p + ".2")
	}
	j := filepath.Join(g.dir, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", j, filepath.Join(g.dir, "d")).CombinedOutput(); err == nil {
		check("junction in path", winEvent(filepath.Join(j, "f.exe"), b, `C:\evil.exe`), OutcomeFileCheck)
	} else {
		t.Logf("mklink /J: %v %s", err, out)
	}
	if err := os.Symlink(p, filepath.Join(g.dir, "d", "s.exe")); err == nil {
		check("symlink", winEvent(filepath.Join(g.dir, "d", "s.exe"), b, `C:\evil.exe`), OutcomeFileCheck)
	}
	check("stream", winEvent(p+":ads", b, `C:\evil.exe`), OutcomeProtectedPath)
	check("trailing dot", winEvent(p+".", b, `C:\evil.exe`), OutcomeProtectedPath)
	for _, prot := range []string{systemRoot + `\System32\drivers\etc\hosts`, `C:\Program Files\x.exe`, g.vault + `\x`, `\\server\share\x.exe`} {
		_ = g.r.QuarantineFile(winEvent(prot, b, `C:\evil.exe`), TargetFile, "r-prot", "r")
		if g.last().Outcome != OutcomeProtectedPath {
			t.Errorf("%s: %+v", prot, g.last())
		}
	}
	// The short (8.3) name of a directory is another path to the same file:
	// the final path differs, so it is refused.
	if short, err := shortPath(filepath.Join(g.dir, "d")); err == nil && !strings.EqualFold(short, filepath.Join(g.dir, "d")) {
		check("short name", winEvent(filepath.Join(short, "f.exe"), b, `C:\evil.exe`), OutcomeFileCheck)
	}
}

func shortPath(p string) (string, error) {
	u, _ := windows.UTF16PtrFromString(p)
	buf := make([]uint16, 1024)
	n, err := windows.GetShortPathName(u, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func TestWindowsTrustedWriter(t *testing.T) {
	for exe, trusted := range map[string]bool{
		`C:\Users\a\AppData\Local\Temp\evil.exe`: false,
		systemRoot + `\System32\reg.exe`:         true,
		systemRoot + `\Temp\x.exe`:               false,
		`C:\Program Files\Vendor\setup.exe`:      true,
		`C:\ProgramData\x.exe`:                   false,
	} {
		if got := trustedWriter(&event.Proc{Exe: exe}) != ""; got != trusted {
			t.Errorf("%s: trusted=%v", exe, got)
		}
	}
	p := &event.Proc{Exe: systemRoot + `\System32\reg.exe`, Parent: &event.Proc{Exe: `C:\Users\a\evil.exe`}}
	if trustedWriter(p) != "" {
		t.Fatal("reg.exe under an untrusted parent is trusted")
	}
}

func TestWindowsIsolateNetsh(t *testing.T) {
	g := newWRig(t)
	e := &event.Event{Name: event.NetworkConnect, Source: "sysmon", Args: map[string]string{},
		Proc: &event.Proc{PID: 5000, UniqueID: 55, StartTime: time.Unix(1, 0), Exe: `C:\Users\a\evil.exe`, UID: -1, EUID: -1},
		Net:  &event.Net{Direction: "outbound", SrcIP: "10.0.0.5", DstIP: "192.0.2.7"}}
	g.r.Observe(&event.Event{Name: event.NetworkConnect, Proc: e.Proc, Net: &event.Net{Direction: "outbound", DstIP: "10.0.0.1"}})
	g.run = func(bin string, args []string) ([]byte, error) {
		if args[2] == "delete" {
			return nil, &ExitError{Code: 1, Output: "No rules match the specified criteria."}
		}
		if args[2] == "show" {
			return nil, &ExitError{Code: 1, Output: "No rules match the specified criteria."}
		}
		return []byte("Ok."), nil
	}
	if err := g.r.IsolateProcess(e, TargetProcess, "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	joined := strings.Join(g.cmds, "|")
	if !strings.Contains(joined, "netsh.exe advfirewall firewall add rule name=ZAAFVesper-isolation dir=out action=block enable=yes profile=any remoteip=192.0.2.7") ||
		!strings.Contains(joined, "dir=in") || strings.Contains(joined, "10.0.0.1") {
		t.Fatalf("%q", g.cmds)
	}
	if g.last().Outcome != OutcomeIsolated && g.last().Outcome != OutcomePartial {
		t.Fatalf("%+v", g.last())
	}
	// A delete that fails while the rule is still listed is an error.
	g.run = func(bin string, args []string) ([]byte, error) {
		if args[2] == "delete" {
			return nil, &ExitError{Code: 1, Output: "Access is denied."}
		}
		return []byte("RemoteIP: 192.0.2.7/32\r\n"), nil
	}
	if err := g.r.fwDelete([]string{"192.0.2.7"}); err == nil {
		t.Fatal("failed delete reported as done")
	}
}

func TestWindowsSuspendResume(t *testing.T) {
	cmd := exec.Command("ping", "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := int32(cmd.Process.Pid)
	for _, sig := range []syscall.Signal{sigStop, sigCont} {
		if _, err := identify(pid); err != nil {
			t.Fatal(err)
		}
		if err := defaultKill(int(pid), sig); err != nil {
			t.Fatalf("signal %d: %v", sig, err)
		}
	}
	id, _ := identify(pid)
	rememberStamp(pid, id.UniqueID+1)
	if err := defaultKill(int(pid), sigStop); err == nil || !strings.Contains(err.Error(), "another process") {
		t.Fatalf("mismatched suspend: %v", err)
	}
	if _, err := identify(pid); err != nil {
		t.Fatal(err)
	}
	if err := defaultKill(int(pid), syscall.SIGTERM); err == nil {
		t.Fatal("SIGTERM accepted")
	}
}
