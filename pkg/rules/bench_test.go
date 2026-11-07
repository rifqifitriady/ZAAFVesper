package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

// benchConditions are 30 realistic conditions (27 single-event, 3 sequences)
// shaped like the built-in rule set.
var benchConditions = []string{
	"create_file and file.path imatches ('/Users/*/Library/LaunchAgents/*.plist', '/Library/LaunchAgents/*.plist') and not ps.signing_id in ('com.apple.xpc.launchd')",
	"create_file and file.path imatches '/Library/LaunchDaemons/*.plist' and not ps.is_platform",
	"write_file and file.path imatches ('/Users/*/.zshrc', '/Users/*/.bash_profile', '/Users/*/.zprofile', '/etc/zshrc')",
	"create_file and file.path startswith '/Library/StartupItems/'",
	"spawn_process and ps.exe = '/usr/bin/osascript' and ps.cmdline icontains 'login item'",
	"spawn_process and ps.exe = '/usr/bin/crontab' and not ps.parent.exe in shells",
	"create_file and file.path startswith '/etc/emond.d/rules/'",
	"spawn_process and ps.exe = '/usr/bin/xattr' and ps.args in ('-d', '-c', '-rd') and ps.cmdline contains 'com.apple.quarantine'",
	"spawn_process and ps.exe = '/usr/sbin/spctl' and ps.args icontains ('--master-disable', '--global-disable')",
	"spawn_process and ps.env[DYLD_INSERT_LIBRARIES] != ''",
	"spawn_process and ps.exe = '/usr/bin/chflags' and ps.args = 'hidden'",
	"spawn_process and ps.exe in ('/usr/libexec/ApplicationFirewall/socketfilterfw', '/bin/launchctl') and ps.cmdline icontains ('--setglobalstate off', 'unload')",
	"delete_file and file.path imatches ('/var/log/*', '/private/var/log/*', '/Library/Logs/*')",
	"spawn_process and ps.exe = '/usr/bin/security' and ps.args in ('dump-keychain', 'find-generic-password', 'find-internet-password')",
	"open_file and file.path imatches '/Users/*/Library/Keychains/*' and not ps.is_platform",
	"spawn_process and ps.exe = '/usr/bin/osascript' and ps.cmdline icontains 'display dialog' and ps.cmdline icontains 'hidden answer'",
	"open_file and file.path imatches '/Users/*/.ssh/id_*' and not ps.name in ('ssh', 'ssh-agent', 'git')",
	"open_file and file.path imatches ('*/Google/Chrome/*/Login Data', '*/Firefox/Profiles/*/logins.json', '*/Cookies.binarycookies') and not ps.is_platform",
	"spawn_process and ps.exe = '/usr/sbin/screencapture' and ps.args = '-x'",
	"spawn_process and ps.cmdline icontains ('Little Snitch', 'LuLu', 'BlockBlock', 'KnockKnock') and ps.name in ('ps', 'pgrep', 'ls')",
	"spawn_process and ps.exe in shells and ps.parent.name in ('curl', 'wget')",
	"spawn_process and ps.exe = '/usr/bin/osascript' and ps.args = '-l' and ps.args = 'JavaScript' and not ps.parent.exe in shells",
	"open_process and not ps.is_signed and target.ps.pid != ps.pid",
	"spawn_process and ps.cmdline regex '(curl|wget)[^|]*\\|\\s*(ba|z)?sh'",
	"set_xattr and evt.arg[xattr] = 'com.apple.quarantine' and ps.exe imatches '/tmp/*'",
	"spawn_process and length(ps.args) > 20 and base(ps.exe) iin ('python3', 'perl', 'ruby')",
	"spawn_process and ps.ancestors imatches '*/Microsoft Word.app/*' and ps.exe in shells",
	`sequence maxspan 2m
	  |create_file and file.path imatches ('/tmp/*', '/Users/Shared/*')| by file.path
	  |spawn_process and not ps.is_signed| by ps.exe`,
	`sequence maxspan 30s by ps.ppid
	  |spawn_process and ps.exe = '/usr/sbin/system_profiler'|
	  |spawn_process and ps.exe = '/usr/bin/sw_vers'|`,
	`sequence maxspan 1m by ps.pid
	  |open_file and file.path imatches '/Users/*/Library/Keychains/*'|
	  |spawn_process and ps.exe in ('/usr/bin/curl', '/usr/bin/nc')|`,
}

func benchMacros(b *testing.B) *ql.Macros {
	m := ql.NewMacros()
	for name, ev := range map[string]string{
		"spawn_process": "CreateProcess", "create_file": "CreateFile", "write_file": "WriteFile",
		"open_file": "OpenFile", "delete_file": "DeleteFile", "open_process": "OpenProcess", "set_xattr": "SetXattr",
	} {
		if err := m.AddExpr(name, fmt.Sprintf("evt.name = '%s'", ev)); err != nil {
			b.Fatal(err)
		}
	}
	if err := m.AddList("shells", []any{"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"}); err != nil {
		b.Fatal(err)
	}
	return m
}

func benchEvents() []*event.Event {
	parent := &event.Proc{PID: 90, Exe: "/bin/zsh", Name: "zsh"}
	anc := []string{"/bin/zsh", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "/sbin/launchd"}
	proc := func(pid int32, exe string, args ...string) *event.Proc {
		return &event.Proc{PID: pid, PPID: 90, Exe: exe, Name: exe[len(exe)-3:], Args: args, Cmdline: fmt.Sprint(args),
			IsSigned: true, IsPlatform: true, SigningID: "com.apple.x", Parent: parent, Ancestors: anc}
	}
	return []*event.Event{
		{Name: event.CreateProcess, Proc: proc(100, "/bin/ls", "ls", "-la", "/tmp")},
		{Name: event.CreateProcess, Proc: proc(101, "/usr/bin/git", "git", "status")},
		{Name: event.OpenFile, Proc: proc(102, "/usr/bin/vim"), File: &event.File{Path: "/Users/a/project/main.go"}},
		{Name: event.OpenFile, Proc: proc(103, "/usr/sbin/mDNSResponder"), File: &event.File{Path: "/private/var/run/resolv.conf"}},
		{Name: event.WriteFile, Proc: proc(104, "/usr/bin/vim"), File: &event.File{Path: "/Users/a/project/main.go"}},
		{Name: event.CreateFile, Proc: proc(105, "/usr/bin/curl"), File: &event.File{Path: "/tmp/download.bin"}},
		{Name: event.CreateProcess, Proc: proc(106, "/usr/bin/osascript", "osascript", "-e", "display notification")},
		{Name: event.DeleteFile, Proc: proc(107, "/usr/bin/rm"), File: &event.File{Path: "/Users/a/tmp/x"}},
		{Name: event.OpenProcess, Proc: proc(108, "/usr/bin/lldb"), Target: &event.Proc{PID: 109, Exe: "/bin/sleep"}},
		{Name: event.SetXattr, Proc: proc(110, "/usr/bin/xattr"), File: &event.File{Path: "/Users/a/Downloads/x"}, Args: map[string]string{"xattr": "com.apple.metadata"}},
	}
}

// BenchmarkEngine measures Process over 30 rules (incl. 3 sequences) with
// events whose names those rules index. Target: >= 20 000 events/s.
func BenchmarkEngine(b *testing.B) {
	m := benchMacros(b)
	rs := &Ruleset{}
	for i, c := range benchConditions {
		r := &Rule{Name: fmt.Sprintf("bench %02d", i), ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
			Version: "1.0.0", Condition: c, Output: "%ps.exe %file.path", Severity: "low", MinEngineVersion: "0.1.0"}
		if err := r.Compile(m); err != nil {
			b.Fatalf("rule %d: %v", i, err)
		}
		rs.Rules = append(rs.Rules, r)
	}
	en := NewEngine(rs, Options{})
	evs := benchEvents()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		e := evs[i%len(evs)]
		e.Time = base.Add(time.Duration(i) * time.Millisecond)
		en.Process(e)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "events/s")
}
