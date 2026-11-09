//go:build linux

package response

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// lrig is a Linux responder wired to temp directories and a stubbed
// Runner: no test here runs nft or systemctl or sends a real signal.
type lrig struct {
	t      *testing.T
	now    time.Time
	dir    string
	logs   []Decision
	cmds   []string
	stdins []string
	run    func(bin string, args []string) ([]byte, error)
	r      *Responder
}

func newLRig(t *testing.T, dry bool) *lrig {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	g := &lrig{t: t, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC), dir: d}
	state := filepath.Join(d, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	g.r = New(Config{
		DryRun: dry, Now: func() time.Time { return g.now },
		Log:      func(dd Decision) { g.logs = append(g.logs, dd) },
		StateDir: state, VaultDir: filepath.Join(state, "quarantine"),
		Runner: func(_ context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
			g.cmds = append(g.cmds, strings.Join(append([]string{bin}, args...), " "))
			if stdin != nil {
				g.stdins = append(g.stdins, string(stdin))
			}
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
	g.r.launchRoot = d
	return g
}

func (g *lrig) last() Decision {
	if len(g.logs) == 0 {
		g.t.Fatal("no decision logged")
	}
	return g.logs[len(g.logs)-1]
}

func me(t *testing.T) string {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

// write creates path (and its directories) and returns its birth time,
// skipping the test where the file system records none.
func write(t *testing.T, path, data string) time.Time {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	fi, err := fstatInfo(fd)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Birth.IsZero() {
		t.Skip("this file system records no birth time (statx STATX_BTIME)")
	}
	return fi.Birth
}

// fileEvent is a Sysmon-for-Linux CreateFile event: no uid, a user name,
// no inode, a creation time.
func fileEvent(t *testing.T, path string, birth time.Time, exe string, parent string) *event.Event {
	p := &event.Proc{PID: 4242, PPID: 4241, UniqueID: 99, StartTime: time.Unix(1, 0), Exe: exe, Name: filepath.Base(exe), UID: -1, EUID: -1, Username: me(t)}
	if parent != "" {
		p.Parent = &event.Proc{PID: 4241, UniqueID: 98, Exe: parent}
	}
	e := &event.Event{Name: event.CreateFile, Source: "sysmon", Proc: p, File: &event.File{Path: path}, Args: map[string]string{}}
	if !birth.IsZero() {
		e.Args["creation_utc_time"] = birth.UTC().Format(sysmonTimeLayout)
	}
	return e
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestLinuxQuarantineByCreationTime(t *testing.T) {
	g := newLRig(t, false)
	p := filepath.Join(g.dir, "drop", "payload")
	b := write(t, p, "evil")
	if err := g.r.QuarantineFile(fileEvent(t, p, b, "/tmp/x/evil", ""), TargetFile, "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	if g.last().Outcome != OutcomeQuarantined || exists(p) {
		t.Fatalf("%+v exists=%v", g.last(), exists(p))
	}
	v := Vault{Dir: g.r.cfg.VaultDir}
	items, err := v.List()
	if err != nil || len(items) != 1 || items[0].Records[0].OriginalPath != p {
		t.Fatalf("%v %+v", err, items)
	}
	if _, _, err := v.Restore(items[0].ID[:12]); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "evil" {
		t.Fatalf("restore: %q %v", b, err)
	}
}

func TestLinuxQuarantineRefusals(t *testing.T) {
	g := newLRig(t, false)
	p := filepath.Join(g.dir, "d", "f")
	b := write(t, p, "x")
	check := func(name string, e *event.Event, outcome string) {
		t.Helper()
		_ = g.r.QuarantineFile(e, TargetFile, "r-"+name, "r")
		if got := g.last(); got.Outcome != outcome {
			t.Errorf("%s: %s %s", name, got.Outcome, got.Detail)
		}
		if !exists(p) {
			t.Fatalf("%s: file removed", name)
		}
	}
	check("no binding", fileEvent(t, p, time.Time{}, "/tmp/evil", ""), OutcomeFileCheck)
	check("other creation time", fileEvent(t, p, b.Add(-time.Hour), "/tmp/evil", ""), OutcomeFileCheck)
	if err := os.Link(p, p+".2"); err != nil {
		t.Fatal(err)
	}
	check("two names", fileEvent(t, p, b, "/tmp/evil", ""), OutcomeFileCheck)
	_ = os.Remove(p + ".2")
	link := filepath.Join(g.dir, "lnk")
	if err := os.Symlink(filepath.Join(g.dir, "d"), link); err != nil {
		t.Fatal(err)
	}
	check("link in path", fileEvent(t, filepath.Join(link, "f"), b, "/tmp/evil", ""), OutcomeFileCheck)
	if err := os.Symlink(p, filepath.Join(g.dir, "d", "s")); err != nil {
		t.Fatal(err)
	}
	check("symlink file", fileEvent(t, filepath.Join(g.dir, "d", "s"), b, "/tmp/evil", ""), OutcomeFileCheck)
	for _, prot := range []string{"/etc/passwd", "/usr/bin/true", "/etc/crontab", "/boot/vmlinuz", "/proc/1/environ", g.r.cfg.VaultDir + "/x"} {
		_ = g.r.QuarantineFile(fileEvent(t, prot, b, "/tmp/evil", ""), TargetFile, "r-prot", "r")
		if g.last().Outcome != OutcomeProtectedPath {
			t.Errorf("%s: %+v", prot, g.last())
		}
	}
	seeded := fileEvent(t, p, b, "/tmp/evil", "")
	seeded.Proc.UniqueID = 0
	check("no identity", seeded, OutcomeUnknown)
}

func TestLinuxQuarantineDryRunAndVaultMode(t *testing.T) {
	g := newLRig(t, true)
	p := filepath.Join(g.dir, "f")
	b := write(t, p, "x")
	_ = g.r.QuarantineFile(fileEvent(t, p, b, "/tmp/evil", ""), TargetFile, "r", "r")
	if g.last().Outcome != OutcomeDryRun || !exists(p) {
		t.Fatalf("%+v", g.last())
	}
	g = newLRig(t, false)
	p = filepath.Join(g.dir, "f")
	b = write(t, p, "x")
	if err := os.Mkdir(g.r.cfg.VaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = g.r.QuarantineFile(fileEvent(t, p, b, "/tmp/evil", ""), TargetFile, "r", "r")
	if g.last().Outcome != OutcomeError || !strings.Contains(g.last().Detail, "group or others") || !exists(p) {
		t.Fatalf("open vault: %+v", g.last())
	}
}

// A running copy of /bin/sleep is quarantined by target process: the
// image is bound through /proc/<pid>/exe after the identity check.
func TestLinuxQuarantineTargetProcess(t *testing.T) {
	g := newLRig(t, false)
	g.r.cfg.Identify = identify
	exe := filepath.Join(g.dir, "sleeper")
	src, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skip("no /bin/sleep")
	}
	if err := os.WriteFile(exe, src, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	time.Sleep(100 * time.Millisecond)
	id, err := identify(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	e := &event.Event{Name: event.CreateProcess, Source: "sysmon", Args: map[string]string{},
		Proc: &event.Proc{PID: int32(cmd.Process.Pid), UniqueID: id.UniqueID, StartTime: id.StartTime, Exe: exe, UID: -1, EUID: -1, Username: me(t)}}
	bound := g.r.BindExecutable(e)
	if bound.Proc.ExeIno == 0 || e.Proc.ExeIno != 0 {
		t.Fatalf("bind: %+v", bound.Proc)
	}
	if err := g.r.QuarantineFile(bound, TargetProcess, "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	if g.last().Outcome != OutcomeQuarantined || exists(exe) {
		t.Fatalf("%+v", g.last())
	}
	// The pid now names another incarnation: nothing is bound.
	other := *e.Proc
	other.UniqueID++
	if _, _, ok := g.r.liveExeID(&other); ok {
		t.Fatal("bound a different incarnation")
	}
}

func TestLinuxRemovePersistence(t *testing.T) {
	g := newLRig(t, false)
	unit := filepath.Join(g.dir, "etc/systemd/system/evil.service")
	b := write(t, unit, "[Service]\nExecStart=/tmp/evil\n")
	g.run = func(bin string, args []string) ([]byte, error) {
		if args[0] == "show" {
			return []byte(unit + "\n"), nil
		}
		return nil, nil
	}
	if err := g.r.RemovePersistence(fileEvent(t, unit, b, "/tmp/dropper", ""), "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	want := []string{SystemctlBin + " show --property=FragmentPath --value -- evil.service",
		SystemctlBin + " disable --now --no-reload -- evil.service", SystemctlBin + " daemon-reload"}
	if strings.Join(g.cmds, "|") != strings.Join(want, "|") || g.last().Outcome != OutcomePersistenceRemoved || exists(unit) {
		t.Fatalf("%q %+v", g.cmds, g.last())
	}

	// Borrowed name: loaded from another file, not stopped.
	g.cmds = nil
	b = write(t, unit, "x")
	g.run = func(bin string, args []string) ([]byte, error) {
		if args[0] == "show" {
			return []byte("/lib/systemd/system/evil.service\n"), nil
		}
		return nil, nil
	}
	_ = g.r.RemovePersistence(fileEvent(t, unit, b, "/tmp/dropper", ""), "r2", "r")
	if len(g.cmds) != 2 || strings.Contains(strings.Join(g.cmds, "|"), "disable") || !strings.Contains(g.last().Detail, "borrowed") {
		t.Fatalf("borrowed: %q %+v", g.cmds, g.last())
	}

	// Protected unit name: never asked about or stopped; the file goes.
	g.cmds = nil
	ssh := filepath.Join(g.dir, "etc/systemd/system/ssh.service")
	b = write(t, ssh, "x")
	_ = g.r.RemovePersistence(fileEvent(t, ssh, b, "/tmp/dropper", ""), "r3", "r")
	if strings.Join(g.cmds, "|") != SystemctlBin+" daemon-reload" || exists(ssh) || g.last().Outcome != OutcomePersistenceRemoved {
		t.Fatalf("ssh: %q %+v", g.cmds, g.last())
	}

	// systemctl failing makes the result partial.
	g.cmds = nil
	b = write(t, unit, "x")
	g.run = func(bin string, args []string) ([]byte, error) {
		if args[0] == "show" {
			return []byte(unit), nil
		}
		return nil, &ExitError{Code: 1, Output: "Failed"}
	}
	_ = g.r.RemovePersistence(fileEvent(t, unit, b, "/tmp/dropper", ""), "r4", "r")
	if g.last().Outcome != OutcomePartial || exists(unit) {
		t.Fatalf("partial: %+v", g.last())
	}
	g.run = nil

	// Cron and rc files: moved, no command run.
	g.cmds = nil
	for i, rel := range []string{"etc/cron.d/evil", "var/spool/cron/crontabs/bob", "home/bob/.bashrc", "etc/profile.d/evil.sh"} {
		p := filepath.Join(g.dir, rel)
		b := write(t, p, "x")
		_ = g.r.RemovePersistence(fileEvent(t, p, b, "/tmp/dropper", ""), "rc"+strconv.Itoa(i), "r")
		if g.last().Outcome != OutcomePersistenceRemoved || exists(p) {
			t.Fatalf("%s: %+v", rel, g.last())
		}
	}
	if len(g.cmds) != 0 {
		t.Fatalf("commands for cron/rc: %q", g.cmds)
	}
}

func TestLinuxRemovePersistenceRefusals(t *testing.T) {
	g := newLRig(t, false)
	unit := filepath.Join(g.dir, "etc/systemd/system/evil.service")
	b := write(t, unit, "x")
	cases := []struct {
		name, path, exe, parent, outcome string
	}{
		{"admin editor", unit, "/usr/bin/vim", "/usr/bin/bash", OutcomeWriterNotUntrusted},
		{"package manager", unit, "/usr/bin/dpkg", "/usr/bin/apt", OutcomeWriterNotUntrusted},
		{"system tool, parent unknown", unit, "/usr/bin/cp", "", OutcomeWriterNotUntrusted},
		{"not persistence", filepath.Join(g.dir, "home/bob/notes"), "/tmp/evil", "", OutcomeProtectedPath},
		{"own unit", filepath.Join(g.dir, "etc/systemd/system/zaafvesper.service"), "/tmp/evil", "", OutcomeLabel},
		{"crontab", filepath.Join(g.dir, "etc/crontab"), "/tmp/evil", "", OutcomeProtectedPath},
	}
	for _, c := range cases {
		_ = g.r.RemovePersistence(fileEvent(t, c.path, b, c.exe, c.parent), "r-"+c.name, "r")
		if g.last().Outcome != c.outcome {
			t.Errorf("%s: %+v", c.name, g.last())
		}
	}
	if !exists(unit) || len(g.cmds) != 0 {
		t.Fatalf("acted: %q", g.cmds)
	}
	// A system tool driven by an untrusted parent is untrusted.
	g.run = func(string, []string) ([]byte, error) { return nil, nil }
	_ = g.r.RemovePersistence(fileEvent(t, unit, b, "/usr/bin/cp", "/tmp/evil"), "r-chain", "r")
	if g.last().Outcome != OutcomePersistenceRemoved {
		t.Fatalf("chain: %+v", g.last())
	}
}

func netEv(dst string) *event.Event {
	return &event.Event{Name: event.NetworkConnect, Source: "sysmon", Args: map[string]string{},
		Proc: &event.Proc{PID: 5000, UniqueID: 55, StartTime: time.Unix(1, 0), Exe: "/tmp/evil", UID: -1, EUID: -1},
		Net:  &event.Net{Direction: "outbound", SrcIP: "10.0.0.5", DstIP: dst}}
}

func TestLinuxIsolate(t *testing.T) {
	g := newLRig(t, false)
	for _, ip := range []string{"10.0.0.1", "10.0.0.53", "127.0.0.1", "10.0.0.5"} {
		g.r.Observe(netEv(ip))
	}
	if err := g.r.IsolateProcess(netEv("192.0.2.7"), TargetProcess, "r", "r"); err != nil {
		t.Fatalf("%v %+v", err, g.last())
	}
	d := g.last()
	if d.Outcome != OutcomeIsolated || len(g.stdins) != 2 || g.stdins[0] != nftReplaceTable ||
		!strings.Contains(g.stdins[1], "{ 192.0.2.7 timeout 3600s }") || strings.Contains(g.stdins[1], "10.0.0.") {
		t.Fatalf("%+v %q", d, g.stdins)
	}
	for _, why := range []string{"10.0.0.1 (a default gateway", "10.0.0.53 (a DNS resolver", "10.0.0.5 (this host's address"} {
		if !strings.Contains(d.Detail, why) {
			t.Errorf("detail lacks %q: %s", why, d.Detail)
		}
	}
	for _, c := range g.cmds {
		if c != NftBin+" -f -" {
			t.Fatalf("command %q", c)
		}
	}
	isos, err := (IsolationStore{Dir: g.r.cfg.StateDir}).Load()
	if err != nil || len(isos) != 1 || isos[0].Addr != "192.0.2.7" {
		t.Fatalf("state %v %+v", err, isos)
	}
	g.now = g.now.Add(2 * time.Hour)
	g.r.Tick(g.now)
	if last := g.stdins[len(g.stdins)-1]; last != nftDeleteScript([]string{"192.0.2.7"}) || g.last().Outcome != OutcomeReleased {
		t.Fatalf("expiry %q %+v", last, g.last())
	}
	if err := g.r.Close(); err != nil || g.stdins[len(g.stdins)-1] != nftDropTable {
		t.Fatalf("close %v %q", err, g.stdins)
	}
	// Gateways unreadable: refused, nothing run.
	g = newLRig(t, false)
	g.r.cfg.Gateways = func() ([]netip.Addr, error) { return nil, errors.New("no /proc") }
	_ = g.r.IsolateProcess(netEv("192.0.2.8"), TargetProcess, "r", "r")
	if g.last().Outcome != OutcomeNoPeers || len(g.cmds) != 0 {
		t.Fatalf("fail closed: %+v %q", g.last(), g.cmds)
	}
}

func TestLinuxReleaseCLI(t *testing.T) {
	g := newLRig(t, false)
	_ = g.r.IsolateProcess(netEv("192.0.2.7"), TargetProcess, "r", "r")
	var cmds, stdins []string
	run := func(_ context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
		cmds = append(cmds, strings.Join(append([]string{bin}, args...), " "))
		stdins = append(stdins, string(stdin))
		return nil, nil
	}
	rel, err := ReleaseIsolation(IsolationStore{Dir: g.r.cfg.StateDir}, run, "192.0.2.7")
	if err != nil || len(rel) != 1 || cmds[0] != NftBin+" list table inet zaafvesper" || stdins[1] != nftDeleteScript([]string{"192.0.2.7"}) {
		t.Fatalf("%v %v %q %q", err, rel, cmds, stdins)
	}
	// No table (sensor gone): nothing to release, no error.
	gone := func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
		return nil, &ExitError{Code: 1, Output: "Error: No such file or directory"}
	}
	if _, err := ReleaseIsolation(IsolationStore{Dir: g.r.cfg.StateDir}, gone, "all"); err != nil {
		t.Fatal(err)
	}
}
