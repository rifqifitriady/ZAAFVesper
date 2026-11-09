package response

import (
	"context"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Platform-neutral parts of the Linux and Windows actions (persistkind.go,
// fwscript.go, winacl.go): tested on every platform.

func TestLinuxPersistKind(t *testing.T) {
	ok := map[string][2]string{
		"/etc/systemd/system/evil.service":         {persistSystemdSystem, "evil.service"},
		"/etc/systemd/system/a@b.timer":            {persistSystemdSystem, "a@b.timer"},
		"/home/bob/.config/systemd/user/x.service": {persistSystemdUser, "x.service"},
		"/root/.config/systemd/user/x.path":        {persistSystemdUser, "x.path"},
		"/etc/cron.d/evil":                         {persistCron, ""},
		"/etc/cron.hourly/evil":                    {persistCron, ""},
		"/var/spool/cron/crontabs/bob":             {persistCron, ""},
		"/var/spool/cron/bob":                      {persistCron, ""},
		"/etc/profile.d/evil.sh":                   {persistShellRC, ""},
		"/home/bob/.bashrc":                        {persistShellRC, ""},
		"/root/.profile":                           {persistShellRC, ""},
		"/home/bob/.zshrc":                         {persistShellRC, ""},
	}
	for p, want := range ok {
		kind, unit, why := linuxPersistKind(p)
		if why != "" || kind != want[0] || unit != want[1] {
			t.Errorf("%s: %q %q %q", p, kind, unit, why)
		}
	}
	for _, p := range []string{
		"/etc/crontab", "/etc/profile", "/etc/bash.bashrc", "/etc/systemd/system/multi-user.target.wants/x.service",
		"/etc/systemd/system/-x.service", "/etc/systemd/system/x.conf", "/etc/systemd/system/a b.service",
		"/lib/systemd/system/evil.service", "/var/spool/cron/crontabs", "/var/spool/cron/atjobs", "/etc/profile.d/x.csh",
		"/home/bob/.config/.bashrc", "/home/bob/notes.txt", "/tmp/.bashrc", "relative/.bashrc", "/etc/cron.d/../passwd",
		"/home//.bashrc", "/etc/cron.d/",
	} {
		if kind, _, why := linuxPersistKind(p); why == "" {
			t.Errorf("%s accepted as %s", p, kind)
		}
	}
	for u, prot := range map[string]bool{"ssh.service": true, "sshd.service": true, "systemd-journald.service": true,
		"dbus.service": true, "SysmonForLinux.service": true, "sysmon.service": true, "evil.service": false, "cron.service": true} {
		if (protectedUnit(u) != "") != prot {
			t.Errorf("protectedUnit(%s) = %q", u, protectedUnit(u))
		}
	}
}

func TestWinRunValue(t *testing.T) {
	h, k, n, why := winRunValue(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`)
	if why != "" || h != "HKLM" || k != `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` || n != "Evil" {
		t.Fatalf("%q %q %q %q", h, k, n, why)
	}
	h, k, n, why = winRunValue(`HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\RunOnce\a\b`)
	if why != "" || h != "HKU" || k != `S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` || n != `a\b` {
		t.Fatalf("%q %q %q %q", h, k, n, why)
	}
	if _, k, _, why := winRunValue(`hklm\software\wow6432node\microsoft\windows\currentversion\run\x`); why != "" || !strings.Contains(k, "WOW6432Node") {
		t.Fatalf("wow: %q %q", k, why)
	}
	for _, bad := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\x`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x`,
		`HKU\..\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x`, `HKU\S-1-5-21-1\..\Software\Microsoft\Windows\CurrentVersion\Run\x`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runx\y`, `HKLM\SYSTEM\CurrentControlSet\Services\x\ImagePath`, `nope`,
	} {
		if _, _, _, why := winRunValue(bad); why == "" {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestWinServiceAndTask(t *testing.T) {
	if n, why := winServiceImagePath(`HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath`); why != "" || n != "EvilSvc" {
		t.Fatalf("%q %q", n, why)
	}
	if n, why := winServiceImagePath(`HKLM\SYSTEM\ControlSet001\Services\a.b-c\ImagePath`); why != "" || n != "a.b-c" {
		t.Fatalf("%q %q", n, why)
	}
	for _, bad := range []string{`HKLM\System\CurrentControlSet\Services\x\Start`, `HKLM\System\CurrentControlSet\Services\x\Parameters\ImagePath`,
		`HKU\S-1-5-18\System\CurrentControlSet\Services\x\ImagePath`, `HKLM\System\Setup\Services\x\ImagePath`,
		`HKLM\System\CurrentControlSet\Services\x;y\ImagePath`} {
		if _, why := winServiceImagePath(bad); why == "" {
			t.Errorf("%s accepted", bad)
		}
	}
	for svc, prot := range map[string]bool{"WinDefend": true, "windefend": true, "Sysmon64": true, "SysmonDrv": true, "ZAAFVesper": true, "EvilSvc": false, "Schedule": true} {
		if (protectedService(svc) != "") != prot {
			t.Errorf("protectedService(%s) = %q", svc, protectedService(svc))
		}
	}
	for in, want := range map[string]string{
		`"C:\Program Files\X\x.exe" -k`:        `C:\Program Files\X\x.exe`,
		`C:\Users\a\AppData\evil.exe /run`:     `C:\Users\a\AppData\evil.exe`,
		`C:\Program Files\X\y.EXE arg`:         `C:\Program Files\X\y.EXE`,
		`%SystemRoot%\system32\svchost.exe -k`: `%SystemRoot%\system32\svchost.exe`,
		`\SystemRoot\System32\drivers\x.sys`:   `\SystemRoot\System32\drivers\x.sys`,
	} {
		if got := serviceImage(in); got != want {
			t.Errorf("serviceImage(%q) = %q", in, got)
		}
	}
	if got := expandSystemVars(`%SystemRoot%\system32\cmd.exe`, `C:\Windows`); got != `C:\Windows\system32\cmd.exe` {
		t.Errorf("expand: %q", got)
	}
	if got := expandSystemVars(`%APPDATA%\x.exe`, `C:\Windows`); got != `%APPDATA%\x.exe` {
		t.Errorf("expand other: %q", got)
	}
	tasks := `C:\Windows\System32\Tasks`
	if n, why := winTaskName(tasks+`\Evil\Updater`, tasks); why != "" || n != `\Evil\Updater` {
		t.Fatalf("%q %q", n, why)
	}
	for _, bad := range []string{tasks + `\Microsoft\Windows\Defrag\ScheduledDefrag`, tasks + `\microsoft\x`, tasks, tasks + `\`,
		`C:\Windows\System32\TasksX\a`, tasks + `\a\..\b`, tasks + `\a\\b`, `C:\Temp\a`} {
		if _, why := winTaskName(bad, tasks); why == "" {
			t.Errorf("%s accepted", bad)
		}
	}
	xmlText := `<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions Context="Author"><Exec><Command>C:\Users\a\evil.exe</Command><Arguments>-x</Arguments></Exec><Exec><Command> %windir%\system32\cmd.exe </Command></Exec></Actions></Task>`
	u := utf16.Encode([]rune(xmlText))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	cmds, err := taskCommands(b)
	if err != nil || !reflect.DeepEqual(cmds, []string{`C:\Users\a\evil.exe`, `%windir%\system32\cmd.exe`}) {
		t.Fatalf("%q %v", cmds, err)
	}
	if _, err := taskCommands([]byte("<Task><Actions>")); err == nil {
		t.Fatal("broken XML accepted")
	}
}

func TestNftScripts(t *testing.T) {
	if strings.Contains(nftRuleset, "flush ruleset") || strings.Count(nftRuleset, "table inet zaafvesper") != 1 {
		t.Fatal("ruleset must touch only its own table")
	}
	s := nftAddScript([]fwItem{{Addr: netip.MustParseAddr("192.0.2.7"), TTL: 1500 * time.Millisecond}, {Addr: netip.MustParseAddr("::ffff:198.51.100.1"), TTL: 0}, {Addr: netip.MustParseAddr("2001:db8::1"), TTL: time.Hour}})
	want := "add element inet zaafvesper isolated4 { 192.0.2.7 }\ndelete element inet zaafvesper isolated4 { 192.0.2.7 }\nadd element inet zaafvesper isolated4 { 192.0.2.7 timeout 2s }\n" +
		"add element inet zaafvesper isolated4 { 198.51.100.1 }\ndelete element inet zaafvesper isolated4 { 198.51.100.1 }\nadd element inet zaafvesper isolated4 { 198.51.100.1 timeout 1s }\n" +
		"add element inet zaafvesper isolated6 { 2001:db8::1 }\ndelete element inet zaafvesper isolated6 { 2001:db8::1 }\nadd element inet zaafvesper isolated6 { 2001:db8::1 timeout 3600s }\n"
	if s != want {
		t.Fatalf("add script:\n%s", s)
	}
	d := nftDeleteScript([]string{"192.0.2.7", "1.2.3.4;flush ruleset", "fe80::1%eth0", "2001:db8::1"})
	if d != "add element inet zaafvesper isolated4 { 192.0.2.7 }\ndelete element inet zaafvesper isolated4 { 192.0.2.7 }\n"+
		"add element inet zaafvesper isolated6 { 2001:db8::1 }\ndelete element inet zaafvesper isolated6 { 2001:db8::1 }\n" {
		t.Fatalf("delete script:\n%s", d)
	}
}

func TestNetshArgs(t *testing.T) {
	if got := netshRemoteList([]string{"::ffff:192.0.2.9", "2001:db8::5", "192.0.2.10", "192.0.2.9", "1.2.3.4;x", "fe80::1%eth0"}); got != "192.0.2.9,192.0.2.10,2001:db8::5" {
		t.Fatal(got)
	}
	if got := strings.Join(netshAddArgs("192.0.2.9,192.0.2.10", "out"), " "); got != "advfirewall firewall add rule name=ZAAFVesper-isolation dir=out action=block enable=yes profile=any remoteip=192.0.2.9,192.0.2.10" {
		t.Fatal(got)
	}
	if got := strings.Join(netshSetArgs("192.0.2.9", "in"), " "); got != "advfirewall firewall set rule name=ZAAFVesper-isolation dir=in new action=block enable=yes profile=any remoteip=192.0.2.9" {
		t.Fatal(got)
	}
	if got := strings.Join(netshDeleteArgs, " "); got != "advfirewall firewall delete rule name=ZAAFVesper-isolation" {
		t.Fatal(got)
	}
}

// netshStub records netsh runs and answers them like netsh: set and show
// fail with "No rules match" while no rule of that direction exists.
type netshStub struct {
	cmds  []string
	rules map[string]string // direction -> remoteip list
	deny  bool              // every change fails with "Access is denied."
}

func (n *netshStub) run(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
	n.cmds = append(n.cmds, strings.Join(args, " "))
	arg := func(k string) string {
		for _, a := range args {
			if v, ok := strings.CutPrefix(a, k+"="); ok {
				return v
			}
		}
		return ""
	}
	noRule := &ExitError{Code: 1, Output: "No rules match the specified criteria."}
	if n.deny && args[2] != "show" {
		return nil, &ExitError{Code: 1, Output: "Access is denied."}
	}
	switch args[2] {
	case "set":
		if _, ok := n.rules[arg("dir")]; !ok {
			return nil, noRule
		}
		n.rules[arg("dir")] = arg("remoteip")
	case "add":
		n.rules[arg("dir")] = arg("remoteip")
	case "delete":
		if len(n.rules) == 0 {
			return nil, noRule
		}
		n.rules = map[string]string{}
	case "show":
		if d := arg("dir"); d != "" {
			if _, ok := n.rules[d]; !ok {
				return nil, noRule
			}
		} else if len(n.rules) == 0 {
			return nil, noRule
		}
		return []byte("Rule Name: ZAAFVesper-isolation\r\n"), nil
	}
	return []byte("Ok."), nil
}

// TestNetshSyncBatches: Windows isolation keeps one rule per direction
// with the whole remoteip list, so a change of any size is two netsh runs
// (security review WS E finding 1: 256 expiring addresses meant up to 512
// netsh runs with a 10 s timeout each).
func TestNetshSyncBatches(t *testing.T) {
	n := &netshStub{rules: map[string]string{}}
	var addrs []string
	for i := 0; i < maxIsolated; i++ {
		addrs = append(addrs, netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(1 + i%250)}).String())
	}
	if err := netshSync(n.run, "netsh.exe", addrs); err != nil {
		t.Fatal(err)
	}
	// First time: set fails, show finds none, add, per direction.
	if len(n.cmds) != 6 || len(strings.Split(n.rules["out"], ",")) != maxIsolated || n.rules["in"] != n.rules["out"] {
		t.Fatalf("%d runs, rules %d", len(n.cmds), len(n.rules))
	}
	n.cmds = nil
	if err := netshSync(n.run, "netsh.exe", addrs[:1]); err != nil {
		t.Fatal(err)
	}
	if len(n.cmds) != 2 || n.rules["out"] != addrs[0] || n.rules["in"] != addrs[0] || !strings.Contains(n.cmds[0], " set rule ") {
		t.Fatalf("%q %v", n.cmds, n.rules)
	}
	n.cmds = nil
	if err := netshSync(n.run, "netsh.exe", nil); err != nil || len(n.rules) != 0 || len(n.cmds) != 1 {
		t.Fatalf("%v %q %v", err, n.cmds, n.rules)
	}
	// Deleting when nothing is there is not an error.
	if err := netshSync(n.run, "netsh.exe", nil); err != nil {
		t.Fatal(err)
	}
	// A rule that exists but cannot be changed is an error (it keeps its
	// old list), not a second rule.
	n = &netshStub{rules: map[string]string{"out": "192.0.2.7", "in": "192.0.2.7"}, deny: true}
	if err := netshSync(n.run, "netsh.exe", []string{"192.0.2.8"}); err == nil || strings.Contains(strings.Join(n.cmds, "|"), " add rule ") {
		t.Fatalf("%v %q", err, n.cmds)
	}
	if err := netshSync(n.run, "netsh.exe", nil); err == nil {
		t.Fatal("failed delete with a rule still listed reported as done")
	}
}

// TestASCIIFoldPrefix: trust decisions compare ASCII-only (WS E finding
// 3b): U+017F (long s) folds to s under Unicode simple folding.
func TestASCIIFoldPrefix(t *testing.T) {
	if !hasPrefixFold(`C:\Program Fileſ\x.exe`, `C:\Program Files\`) {
		t.Fatal("hasPrefixFold no longer folds U+017F; the protection direction relies on it")
	}
	for s, want := range map[string]bool{
		`C:\Program Files\x.exe`: true,
		`c:\PROGRAM FILES\x.exe`: true,
		`C:\Program Fileſ\x.exe`: false,
		`C:\Program FileS\x.exe`: true,
		`C:\Program File\x.exe`:  false,
		`C:\Program Files`:       false,
		`C:\Program Files\ü.exe`: true, // past the compared region
	} {
		if got := hasPrefixASCIIFold(s, `C:\Program Files\`); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
	if !equalASCIIFold(`C:\WINDOWS\system32\svchost.exe`, `C:\Windows\System32\svchost.exe`) ||
		equalASCIIFold(`C:\Windows\Syſtem32\svchost.exe`, `C:\Windows\System32\svchost.exe`) {
		t.Fatal("equalASCIIFold")
	}
}

// TestWinSystemImageFailsClosed: the Windows trust test (WS E finding 3):
// user-writable folders under C:\Windows are not system folders, nor are
// look-alike folders a user can create at the root of C:.
func TestWinSystemImageFailsClosed(t *testing.T) {
	progs := []string{`C:\Program Files`, `C:\Program Files (x86)`}
	def := `C:\ProgramData\Microsoft\Windows Defender\Platform`
	for exe, want := range map[string]bool{
		`C:\Windows\System32\reg.exe`:                                         true,
		`C:\WINDOWS\system32\svchost.exe`:                                     true,
		`C:\Windows\explorer.exe`:                                             true,
		`C:\Windows\SysWOW64\cmd.exe`:                                         true,
		`C:\Program Files\Vendor\app.exe`:                                     true,
		`C:\Program Files (x86)\Vendor\app.exe`:                               true,
		`C:\Program Files\Vendör\app.exe`:                                     true,
		`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`: true,
		// 3a: user-writable folders under the Windows directory.
		`C:\Windows\Tasks\evil.exe`:                                  false,
		`C:\Windows\Temp\evil.exe`:                                   false,
		`C:\Windows\tracing\evil.exe`:                                false,
		`C:\Windows\TRACING\evil.exe`:                                false,
		`C:\Windows\Registration\CRMLog\evil.exe`:                    false,
		`C:\Windows\System32\spool\drivers\color\evil.exe`:           false,
		`C:\Windows\System32\spool\PRINTERS\evil.exe`:                false,
		`C:\Windows\System32\FxsTmp\evil.exe`:                        false,
		`C:\Windows\System32\com\dmp\evil.exe`:                       false,
		`C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\e.exe`: false,
		`C:\Windows\System32\Tasks\evil.exe`:                         false,
		`C:\Windows\SysWOW64\Tasks\evil.exe`:                         false,
		`C:\Windows\debug\WIA\evil.exe`:                              false,
		`C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\evil.exe`:   false,
		`C:\ProgramData\Microsoft\Windows\evil.exe`:                  false,
		`C:\ProgramData\evil.exe`:                                    false,
		// Short names and non-ASCII under the Windows directory.
		`C:\Windows\REGIST~1\CRMLog\evil.exe`: false,
		`C:\Windows\Taſks\evil.exe`:           false,
		// 3b: look-alike folders at the root of C:.
		`C:\Program Fileſ\evil.exe`: false,
		`C:\Windowſ\System32\x.exe`: false,
		`C:\PROGRA~1\Vendor\x.exe`:  false,
		`C:\Users\a\evil.exe`:       false,
	} {
		if got := winSystemImage(exe, `C:\Windows`, progs, def); got != want {
			t.Errorf("%s: system=%v", exe, got)
		}
	}
}

// TestRegistryRetryKeys: two budget-refused registry removals of one rule
// (Run values and services carry no file) are retried separately (WS E
// finding 4; regression of the N2 decoy fix).
func TestRegistryRetryKeys(t *testing.T) {
	r := New(Config{Now: func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) }, Log: func(Decision) {}})
	proc := &event.Proc{PID: 4242, UniqueID: 7}
	reg := func(key, data string, p *event.Proc) *event.Event {
		return &event.Event{Name: event.RegistrySetValue, Proc: p, Registry: &event.Registry{Key: key, Data: data}}
	}
	run := `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\`
	evs := []*event.Event{
		reg(run+"Decoy1", `C:\Users\a\d1.exe`, proc),
		reg(run+"Real", `C:\Users\a\real.exe`, proc),
		reg(`HKLM\System\CurrentControlSet\Services\Evil\ImagePath`, `C:\Users\a\svc.exe`, proc),
		reg(run+"Real", `C:\Users\a\other.exe`, proc),                               // same value, other data
		reg(run+"Real", `C:\Users\a\real.exe`, &event.Proc{PID: 4243, UniqueID: 8}), // another writer
	}
	for _, e := range evs {
		_ = r.retryOnLimit(fileRetryKey(ActionRemovePersistence, "rule-run", e, TargetFile), "rule-run", "r", ErrRateLimited, func() error { return nil })
	}
	if n := r.Retries(); n != len(evs) {
		t.Fatalf("%d retries for %d refused registry removals", n, len(evs))
	}
	// The same event again is the same entry.
	_ = r.retryOnLimit(fileRetryKey(ActionRemovePersistence, "rule-run", evs[1], TargetFile), "rule-run", "r", ErrRateLimited, func() error { return nil })
	if n := r.Retries(); n != len(evs) {
		t.Fatalf("a repeat made a new entry: %d", n)
	}
}

func TestRouteParsers(t *testing.T) {
	r4 := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"eth1\t0010A8C0\tFE01A8C0\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	if got := parseProcNetRoute([]byte(r4)); !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.254")}) {
		t.Fatalf("v4 %v", got)
	}
	r6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" +
		"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
	if got := parseProcNetIPv6Route([]byte(r6)); !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("fe80::1")}) {
		t.Fatalf("v6 %v", got)
	}
	if got := parseResolvConf([]byte("# x\nnameserver 127.0.0.53\nnameserver ::ffff:10.0.0.2\nsearch a\nnameserver bad\n")); !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("10.0.0.2")}) {
		t.Fatalf("resolv %v", got)
	}
}

func TestPrivateACLProblem(t *testing.T) {
	ok := map[string]bool{SIDSystem: true, SIDAdministrators: true}
	good := []aclEntry{{Type: 0, SID: SIDSystem}, {Type: 0, SID: SIDAdministrators}, {Type: 1, SID: "S-1-1-0"}}
	if why := privateACLProblem(SIDAdministrators, true, true, good, ok); why != "" {
		t.Fatal(why)
	}
	cases := map[string]struct {
		owner         string
		dacl, protect bool
		aces          []aclEntry
	}{
		"user owner":   {"S-1-5-21-1-2-3-1001", true, true, good},
		"null dacl":    {SIDSystem, false, true, nil},
		"inherits":     {SIDSystem, true, false, good},
		"users allow":  {SIDSystem, true, true, append(good, aclEntry{Type: 0, SID: "S-1-5-32-545"})},
		"object ace":   {SIDSystem, true, true, append(good, aclEntry{Type: 5})},
		"callback ace": {SIDSystem, true, true, append(good, aclEntry{Type: 9, SID: SIDSystem})},
	}
	for name, c := range cases {
		if privateACLProblem(c.owner, c.dacl, c.protect, c.aces, ok) == "" {
			t.Errorf("%s accepted", name)
		}
	}
	if !strings.HasPrefix(privateSDDL, "O:BAD:P(") || strings.Count(privateSDDL, "(A;") != 2 {
		t.Fatalf("SDDL %s", privateSDDL)
	}
}

func TestHashOfAndBind(t *testing.T) {
	h := strings.Repeat("ab", 32)
	if got := hashOf("SHA1=00,MD5=11,SHA256="+strings.ToUpper(h)+",IMPHASH=22", "SHA256"); got != h {
		t.Fatalf("%q", got)
	}
	if hashOf("SHA256=xyz", "SHA256") != "" || hashOf("", "SHA256") != "" {
		t.Fatal("bad hash accepted")
	}
	if (fileBind{}).none() != true || (fileBind{Birth: time.Unix(1, 0)}).none() {
		t.Fatal("none")
	}
}

func TestDirOf(t *testing.T) {
	for in, want := range map[string]string{"/a/b": "/a", "/a": "/"} {
		if sep == "/" && dirOf(in) != want {
			t.Errorf("dirOf(%s) = %s", in, dirOf(in))
		}
	}
	if sep == `\` {
		for in, want := range map[string]string{`C:\a\b`: `C:\a`, `C:\a`: `C:\`} {
			if dirOf(in) != want {
				t.Errorf("dirOf(%s) = %s", in, dirOf(in))
			}
		}
	}
}

// TestTickHandsExpiryToWorker: 256 isolations expire at once while the
// worker is busy. Tick (on the event loop) returns at once and runs no
// firewall command; the worker then releases them all in one or two runs,
// and a second Tick queues no second upkeep (WS E finding 1: the Windows
// expiry ran netsh per address inside Tick).
func TestTickHandsExpiryToWorker(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var cmds []string
	r := New(Config{
		Now: func() time.Time { return now }, Log: func(Decision) {},
		StateDir: filepath.Join(t.TempDir(), "absent", "state"),
		Runner: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
			mu.Lock()
			cmds = append(cmds, bin+" "+strings.Join(args, " "))
			mu.Unlock()
			return nil, nil
		},
		LocalAddrs: func() ([]netip.Addr, error) { return nil, nil },
		Gateways:   func() ([]netip.Addr, error) { return nil, nil },
		Resolvers:  func() []netip.Addr { return nil },
	})
	r.fwLoaded = true
	for i := 0; i < maxIsolated; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(1 + i%250)}).String()
		r.isolated[a] = &Isolation{Addr: a, Added: now.Add(-time.Hour), Expires: now.Add(-time.Second), Rule: "r"}
	}
	r.StartWorker(4)
	defer r.StopWorker()
	gate, busy := make(chan struct{}), make(chan struct{})
	var open sync.Once
	release := func() { open.Do(func() { close(gate) }) }
	defer release()                            // before StopWorker (deferred above), so a failure does not hang
	if !r.Go(func() { close(busy); <-gate }) { // the worker is busy with a slow action
		t.Fatal("queue")
	}
	<-busy
	done := make(chan struct{})
	go func() {
		r.Tick(now)
		r.Tick(now.Add(2 * time.Second))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		release()
		t.Fatal("Tick blocked on the isolation expiry")
	}
	mu.Lock()
	ran := len(cmds)
	mu.Unlock()
	if ran != 0 {
		t.Fatalf("Tick ran %d commands on the event loop: %q", ran, cmds)
	}
	if w := r.work.Load(); len(w.ch) != 1 {
		t.Fatalf("%d upkeeps queued, want 1", len(w.ch))
	}
	release()
	r.Wait()
	if n := len(r.Isolations()); n != 0 {
		t.Fatalf("%d isolations left", n)
	}
	if len(cmds) < 1 || len(cmds) > 2 {
		t.Fatalf("expiry of %d addresses took %d firewall runs: %q", maxIsolated, len(cmds), cmds)
	}
}
