//go:build darwin

package main

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"golang.org/x/sys/unix"
)

func actionRule(id, name, cond, action string) string {
	return "name: " + name + "\nid: " + id + "\nversion: 1.0.0\ncondition: >\n  " + cond +
		"\noutput: \"%ps.exe\"\nseverity: high\naction: " + action + "\nmin-engine-version: 0.1.0\n"
}

// actionSensor builds a sensor with response on, every command stubbed and
// the state directory in a temp dir. Nothing outside the temp dir changes.
type actionSensor struct {
	s       *sensor
	dir     string
	cmds    []string
	signals []string
	errb    bytes.Buffer
}

func newActionSensor(t *testing.T, enable, dry bool, files map[string]string) *actionSensor {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	a := &actionSensor{dir: dir}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for k, v := range files {
		files[k] = strings.ReplaceAll(v, "TMPDIR", dir)
	}
	var out bytes.Buffer
	s, err := buildSensor(runOptions{
		rulesDir: rulesDir(t, files), rulesGiven: true, configPath: filepath.Join(dir, "none.yml"),
		noYara: true, enableResponse: enable, dryRunResponse: dry, jsonKeep: 8, captureKeep: 2,
		killFunc: func(pid int, sig syscall.Signal) error {
			a.signals = append(a.signals, strconv.Itoa(pid)+" "+unix.SignalName(sig))
			return nil
		},
		identify: func(pid int32) (response.Identity, error) {
			return response.Identity{CSKnown: true, StartTime: t0, Exe: "/private/tmp/p", UniqueID: uint64(pid), UniqueKnown: true}, nil
		},
		responseRunner: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
			a.cmds = append(a.cmds, strings.Join(append([]string{bin}, args...), " "))
			return nil, nil
		},
		responseStateDir:    state,
		responseAppleSigned: func(string) (bool, error) { return false, nil },
		responseLocalAddrs:  func() ([]netip.Addr, error) { return nil, nil },
	}, &out, &a.errb)
	if err != nil {
		t.Fatal(err)
	}
	s.p.enricher = nil // feed fully formed events
	a.s = s
	return a
}

func (a *actionSensor) proc(pid int32, exe string) *event.Proc {
	me := int64(os.Geteuid())
	return &event.Proc{PID: pid, PPID: 1, Exe: exe, Name: filepath.Base(exe), UniqueID: uint64(pid), UID: me, EUID: me,
		StartTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func statOf(t *testing.T, p string) (uint64, uint64) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return uint64(uint32(st.Dev)), st.Ino
}

// TestResponseActionsEndToEnd: rules with each action, through the
// pipeline's dispatch, with the response on.
func TestResponseActionsEndToEnd(t *testing.T) {
	a := newActionSensor(t, true, false, map[string]string{
		"q.yml": actionRule("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "Q", "evt.name = 'CreateProcess' and ps.exe startswith 'TMPDIR/drop/'", "[{name: quarantine_file, target: process}]"),
		"r.yml": actionRule("1f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "R", "evt.name = 'DeleteXattr'", "[{name: requarantine}]"),
		"i.yml": actionRule("2f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "I", "evt.name = 'NetworkConnect' and net.dport = 4444", "[{name: isolate_process}]"),
		"s.yml": actionRule("3f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "S", "evt.name = 'CreateProcess' and ps.name = 'osascript'", "[{name: suspend, target: parent}, {name: kill, target: parent}]"),
		"p.yml": actionRule("4f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "P", "evt.name = 'CreateFile' and file.path endswith '.plist'", "[{name: remove_persistence}]"),
	})
	p := a.s.p
	if !reflect.DeepEqual(a.cmds, []string{response.PfctlBin + " -a " + response.PFAnchor + " -F all"}) {
		t.Fatalf("start did not flush the anchor: %v", a.cmds)
	}
	// quarantine_file, target process.
	exe := filepath.Join(a.dir, "drop", "stage2")
	_ = os.MkdirAll(filepath.Dir(exe), 0o755)
	_ = os.WriteFile(exe, []byte("payload"), 0o755)
	pr := a.proc(4000, exe)
	pr.ExeDev, pr.ExeIno = statOf(t, exe)
	p.handle(&event.Event{Name: event.CreateProcess, Source: response.ESSource, Proc: pr}, false)
	p.responder.Wait()
	if _, err := os.Stat(exe); !os.IsNotExist(err) {
		t.Fatalf("executable not quarantined:\n%s", a.errb.String())
	}
	// requarantine.
	dl := filepath.Join(a.dir, "dl")
	_ = os.WriteFile(dl, []byte("x"), 0o644)
	dev, ino := statOf(t, dl)
	p.handle(&event.Event{Name: event.DeleteXattr, Source: response.ESSource, Proc: a.proc(4001, "/private/tmp/dropper"),
		File: &event.File{Path: dl, Dev: dev, Ino: ino}, Args: map[string]string{"xattr": response.QuarantineXattr}}, false)
	p.responder.Wait()
	if _, err := unix.Getxattr(dl, response.QuarantineXattr, nil); err != nil {
		t.Fatalf("not requarantined: %v\n%s", err, a.errb.String())
	}
	// isolate_process.
	p.handle(&event.Event{Name: event.NetworkConnect, Source: response.ESSource, Proc: a.proc(4002, "/private/tmp/implant"),
		Net: &event.Net{Direction: "outbound", DstIP: "203.0.113.5", DstPort: 4444}}, false)
	p.responder.Wait()
	if !strings.Contains(strings.Join(a.cmds, "\n"), "-T add 203.0.113.5") {
		t.Fatalf("not isolated: %v\n%s", a.cmds, a.errb.String())
	}
	// suspend then kill of the parent.
	child := a.proc(4004, "/usr/bin/osascript")
	child.PPID, child.Parent = 4003, a.proc(4003, "/Volumes/Setup/Setup.app/Contents/MacOS/Setup")
	p.handle(&event.Event{Name: event.CreateProcess, Source: response.ESSource, Proc: child}, false)
	if !reflect.DeepEqual(a.signals, []string{"4003 SIGSTOP", "4003 SIGKILL"}) {
		t.Fatalf("signals = %v", a.signals)
	}
	// remove_persistence reached (refused here: not a real launch item).
	p.handle(&event.Event{Name: event.CreateFile, Source: response.ESSource, Proc: a.proc(4005, "/private/tmp/dropper"),
		File: &event.File{Path: filepath.Join(a.dir, "x.plist"), Dev: 1, Ino: 2}}, false)
	p.responder.Wait()
	log := a.errb.String()
	for _, want := range []string{"response quarantined action=quarantine_file", "response requarantined action=requarantine",
		"response isolated action=isolate_process", "response suspended action=suspend", "response killed target=parent",
		"response refused-protected-path action=remove_persistence"} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %q:\n%s", want, log)
		}
	}
	// Tick, then a clean shutdown flushes the anchor and releases nothing else.
	p.responseTick(time.Now().Add(2 * time.Hour))
	a.cmds = nil
	_ = a.s.close()
	if len(a.cmds) == 0 || a.cmds[0] != response.PfctlBin+" -a "+response.PFAnchor+" -F all" {
		t.Fatalf("shutdown: %v", a.cmds)
	}
	// The vault holds the executable; the CLI lists and restores it.
	stateDir := filepath.Join(a.dir, "state")
	code, out, errs := runCLI(t, "quarantine", "list", "--state-dir", stateDir)
	if code != 0 || !strings.Contains(out, exe) || !strings.Contains(out, "quarantine_file") {
		t.Fatalf("quarantine list: %d %q %q", code, out, errs)
	}
	id := strings.Fields(out)[0]
	if code, out, errs := runCLI(t, "quarantine", "restore", id, "--state-dir", stateDir); code != 0 || !strings.Contains(out, "restored") {
		t.Fatalf("restore: %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(exe); string(b) != "payload" {
		t.Fatalf("restored content %q", b)
	}
	if code, out, _ := runCLI(t, "quarantine", "list", "--state-dir", stateDir); code != 0 || !strings.Contains(out, "empty") {
		t.Fatalf("list after restore: %q", out)
	}
}

func TestResponseActionsOffAndDryRun(t *testing.T) {
	files := func() map[string]string {
		return map[string]string{"r.yml": actionRule("5f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "R", "evt.name = 'DeleteXattr'", "[{name: requarantine}]")}
	}
	for _, c := range []struct{ enable, dry bool }{{false, false}, {true, true}, {false, true}} {
		a := newActionSensor(t, c.enable, c.dry, files())
		dl := filepath.Join(a.dir, "dl")
		_ = os.WriteFile(dl, []byte("x"), 0o644)
		dev, ino := statOf(t, dl)
		a.s.p.handle(&event.Event{Name: event.DeleteXattr, Source: response.ESSource, Proc: a.proc(4001, "/private/tmp/dropper"),
			File: &event.File{Path: dl, Dev: dev, Ino: ino}, Args: map[string]string{"xattr": response.QuarantineXattr}}, false)
		if a.s.p.responder != nil {
			a.s.p.responder.Wait()
			if c.dry && !strings.Contains(a.errb.String(), "response dry-run action=requarantine") {
				t.Fatalf("dry-run decision not logged:\n%s", a.errb.String())
			}
		}
		_ = a.s.close()
		if _, err := unix.Getxattr(dl, response.QuarantineXattr, nil); err == nil {
			t.Fatalf("enable=%v dry=%v changed the file", c.enable, c.dry)
		}
		if len(a.cmds) != 0 {
			t.Fatalf("enable=%v dry=%v ran %v", c.enable, c.dry, a.cmds)
		}
	}
}

// TestNoCommandsWithoutRoot: without root and without a test runner,
// pfctl and launchctl are never run.
func TestNoCommandsWithoutRoot(t *testing.T) {
	dir := rulesDir(t, map[string]string{"i.yml": actionRule("6f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", "I", "evt.name = 'NetworkConnect'", "[{name: isolate_process}]")})
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, enableResponse: true, jsonKeep: 8, captureKeep: 2,
		responseStateDir:   t.TempDir(),
		responseLocalAddrs: func() ([]netip.Addr, error) { return nil, nil }}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	s.p.enricher = nil
	s.p.handle(&event.Event{Name: event.NetworkConnect, Source: response.ESSource,
		Proc: &event.Proc{PID: 4002, PPID: 50, Exe: "/private/tmp/implant", UniqueID: 4002, StartTime: time.Now()},
		Net:  &event.Net{Direction: "outbound", DstIP: "203.0.113.5"}}, false)
	s.p.responder.Wait()
	_ = s.close()
	if !strings.Contains(errb.String(), "response commands run only as root") {
		t.Fatalf("expected the refusing runner:\n%s", errb.String())
	}
}

// TestBuiltinRuleActions: the shipped rules carry the W1 actions (macOS)
// and the v0.4 E actions (Linux, Windows).
func TestBuiltinRuleActions(t *testing.T) {
	rs, err := rules.LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"Binary dropped in a temp or shared folder and executed without developer identity": {"quarantine_file:process"},
		"Quarantine attribute removed by an untrusted process":                              {"requarantine"},
		"Launch Agent or Daemon written by an untrusted process":                            {"remove_persistence"},
		"Fake password prompt via osascript from untrusted origin":                          {"suspend:parent", "kill:parent"},
		"Cron job file created":                                 {"remove_persistence"},
		"Systemd unit file created outside the package manager": {"remove_persistence"},
		"Run value pointing into a temporary or public folder":  {"remove_persistence"},
	}
	found := 0
	for _, r := range rs.Rules {
		if w, ok := want[r.Name]; ok {
			found++
			if !reflect.DeepEqual(r.Actions(), w) {
				t.Fatalf("%s: actions %v, want %v", r.Name, r.Actions(), w)
			}
		} else if len(r.Action) > 0 {
			t.Fatalf("unexpected action on %s: %v", r.Name, r.Actions())
		}
	}
	if found != len(want) {
		t.Fatalf("found %d of %d rules", found, len(want))
	}
}

func TestIsolationCLI(t *testing.T) {
	state, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(state, 0o700)
	store := response.IsolationStore{Dir: state}
	if err := store.Save([]response.Isolation{{Addr: "203.0.113.5", Rule: "r1", Expires: time.Now().Add(time.Hour)},
		{Addr: "2001:db8::5", Rule: "r1", Expires: time.Now().Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	var cmds []string
	old := cliRunner
	cliRunner = func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
		cmds = append(cmds, strings.Join(append([]string{bin}, args...), " "))
		return nil, nil
	}
	defer func() { cliRunner = old }()
	code, out, _ := runCLI(t, "isolation", "list", "--state-dir", state)
	if code != 0 || !strings.Contains(out, "203.0.113.5") || !strings.Contains(out, "whole host") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, _, errs := runCLI(t, "isolation", "release", "1.2.3.4;pass", "--state-dir", state); code != 1 || len(cmds) != 0 {
		t.Fatalf("bad address: %d %q %v", code, errs, cmds)
	}
	if code, out, _ := runCLI(t, "isolation", "release", "203.0.113.5", "--state-dir", state); code != 0 || !strings.Contains(out, "released 1") {
		t.Fatalf("release: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, "isolation", "release", "all", "--state-dir", state); code != 0 || !strings.Contains(out, "2001:db8::5") {
		t.Fatalf("release all: %d %q", code, out)
	}
	want := []string{response.PfctlBin + " -a " + response.PFAnchor + " -t " + response.PFTable + " -T delete 203.0.113.5",
		response.PfctlBin + " -a " + response.PFAnchor + " -t " + response.PFTable + " -T flush"}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("cmds = %v", cmds)
	}
	if code, out, _ := runCLI(t, "isolation", "list", "--state-dir", state); code != 0 || !strings.Contains(out, "no isolated") {
		t.Fatalf("list after release: %q", out)
	}
	if code, _, _ := runCLI(t, "isolation", "frobnicate"); code != 2 {
		t.Fatal("unknown subcommand accepted")
	}
	if code, _, _ := runCLI(t, "quarantine"); code != 2 {
		t.Fatal("missing subcommand accepted")
	}
}
