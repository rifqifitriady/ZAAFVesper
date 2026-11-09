package response

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
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
	a := netip.MustParseAddr("::ffff:192.0.2.9")
	if got := strings.Join(netshAddArgs(a, "out"), " "); got != "advfirewall firewall add rule name=ZAAFVesper-isolation dir=out action=block enable=yes profile=any remoteip=192.0.2.9" {
		t.Fatal(got)
	}
	if got := strings.Join(netshDeleteArgs(a), " "); got != "advfirewall firewall delete rule name=ZAAFVesper-isolation remoteip=192.0.2.9" {
		t.Fatal(got)
	}
	if got := strings.Join(netshDeleteArgs(netip.Addr{}), " "); got != "advfirewall firewall delete rule name=ZAAFVesper-isolation" {
		t.Fatal(got)
	}
	out := "Rule Name:   ZAAFVesper-isolation\r\nDirection:  Out\r\nRemoteIP:   192.0.2.9/32\r\n\r\nRemoteIP:   2001:db8::5/128\r\n"
	if !netshListsAddr(out, a) || !netshListsAddr(out, netip.MustParseAddr("2001:db8::5")) || netshListsAddr(out, netip.MustParseAddr("192.0.2.90")) {
		t.Fatal("netshListsAddr")
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
