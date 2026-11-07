package eslogger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

var update = flag.Bool("update", false, "rewrite testdata/eslogger/*.golden.json")

const fixtureDir = "../../../testdata/eslogger"

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), MaxLineSize)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			out = append(out, append([]byte(nil), sc.Bytes()...))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestGolden decodes every testdata/eslogger/<type>.jsonl and compares the
// result with <type>.golden.json. Run with -update to regenerate.
func TestGolden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(fixtureDir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in %s: %v", fixtureDir, err)
	}
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".jsonl")
		t.Run(name, func(t *testing.T) {
			var got []*event.Event
			for i, line := range readLines(t, path) {
				e, ok, err := Decode(line)
				if err != nil {
					t.Fatalf("line %d: %v", i+1, err)
				}
				if !ok {
					got = append(got, nil) // recorded so ignored lines are visible in the golden file
					continue
				}
				got = append(got, e)
			}
			out, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, '\n')
			golden := filepath.Join(fixtureDir, name+".golden.json")
			if *update {
				if err := os.WriteFile(golden, out, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test -update)", err)
			}
			if !bytes.Equal(out, want) {
				t.Errorf("decoded output differs from %s (run go test -update and review the diff)\n got: %s", golden, out)
			}
		})
	}
}

// TestEveryMappedTypeHasFixture keeps the fixtures complete as the table grows.
func TestEveryMappedTypeHasFixture(t *testing.T) {
	for _, et := range esTypes {
		path := filepath.Join(fixtureDir, et.name+".jsonl")
		lines := readLines(t, path)
		if len(lines) == 0 {
			t.Errorf("%s: empty fixture", et.name)
			continue
		}
		decodedOne := false
		for _, l := range lines {
			e, ok, err := Decode(l)
			if err != nil {
				t.Errorf("%s: %v", et.name, err)
			}
			if ok {
				decodedOne = true
				if e.Name != et.canonical {
					t.Errorf("%s: name %s, want %s", et.name, e.Name, et.canonical)
				}
			}
		}
		if !decodedOne {
			t.Errorf("%s: no line decodes to an event", et.name)
		}
	}
}

func decodeFixture(t *testing.T, name string, idx int) *event.Event {
	t.Helper()
	lines := readLines(t, filepath.Join(fixtureDir, name+".jsonl"))
	e, ok, err := Decode(lines[idx])
	if err != nil || !ok {
		t.Fatalf("%s[%d]: ok=%v err=%v", name, idx, ok, err)
	}
	return e
}

// TestRuleFields checks the fields detection rules rely on, through the same
// accessors the rule engine uses.
func TestRuleFields(t *testing.T) {
	type check struct {
		fixture string
		idx     int
		field   string // "root[key]" for indexed fields
		want    any
	}
	checks := []check{
		{"exec", 0, "evt.name", event.CreateProcess},
		{"exec", 0, "ps.exe", "/usr/bin/curl"},
		{"exec", 0, "ps.name", "curl"},
		{"exec", 0, "ps.pid", int64(4242)},
		{"exec", 0, "ps.ppid", int64(4100)},
		{"exec", 0, "ps.uuid", int64(4242<<32 | 4243)},
		{"exec", 0, "ps.args", []string{"curl", "-fsSL", "https://example.invalid/install.sh"}},
		{"exec", 0, "ps.cmdline", "curl -fsSL https://example.invalid/install.sh"},
		{"exec", 0, "ps.cwd", "/Users/alice"},
		{"exec", 0, "ps.signing_id", "com.apple.curl"},
		{"exec", 0, "ps.is_platform", true},
		{"exec", 0, "ps.is_signed", true},
		{"exec", 0, "ps.uid", int64(501)},
		{"exec", 0, "ps.tty", "/dev/ttys003"},
		{"exec", 0, "ps.cdhash", "5a1f4e3d2c1b0a99887766554433221100ffeedd"},
		{"exec", 0, "ps.env[DYLD_INSERT_LIBRARIES]", "/tmp/libinject.dylib"},
		{"exec", 0, "evt.arg[env.DYLD_INSERT_LIBRARIES]", "/tmp/libinject.dylib"},
		{"exec", 0, "evt.arg[prev_exe]", "/bin/zsh"},
		{"exec", 1, "ps.is_signed", false},
		{"exec", 1, "ps.is_platform", false},
		{"exec", 1, "ps.cdhash", ""},
		{"exec", 1, "ps.signing_id", ""},
		{"exec", 1, "evt.arg[script]", "/private/tmp/payload"},
		{"exec", 2, "ps.is_signed", false}, // ad-hoc + linker-signed
		{"exec", 2, "ps.signing_id", "tool-55554944a1b2"},
		{"exec", 3, "ps.is_signed", false}, // CS_SIGNED but not CS_VALID
		{"exec", 3, "ps.team_id", "ABCDE12345"},
		{"exec", 0, "ps.parent.pid", int64(4100)}, // parent_audit_token stub (pkg/ps completes it)
		{"fork", 0, "ps.pid", int64(4401)},
		{"fork", 0, "ps.ppid", int64(4100)},
		{"fork", 0, "evt.arg[parent_pid]", "4100"},
		{"exit", 0, "evt.arg[exit_status]", "256"},
		{"open", 0, "file.path", "/Users/alice/Library/Keychains/login.keychain-db"},
		{"open", 0, "evt.arg[open_access]", "read"},
		{"open", 1, "evt.arg[open_access]", "readwrite"},
		{"open", 1, "evt.arg[open_flags]", "3"},
		{"open", 1, "evt.arg[open_flag_names]", "FREAD|FWRITE"},
		{"create", 0, "file.path", "/Users/alice/Library/LaunchAgents/com.evil.agent.plist"},
		{"create", 1, "file.path", "/Library/LaunchDaemons/com.evil.daemon.plist"},
		{"create", 1, "file.mode", int64(0o644)},
		{"write", 0, "file.path", "/Users/alice/.zshrc"},
		{"write", 0, "evt.arg[via]", "write"},
		{"close", 0, "evt.name", event.WriteFile},
		{"close", 0, "evt.arg[via]", "close"},
		{"rename", 0, "file.path", "/private/tmp/x.plist"},
		{"rename", 0, "file.dest", "/Users/alice/Library/LaunchAgents/com.evil.plist"},
		{"rename", 1, "file.dest", "/Users/alice/b.txt"},
		{"unlink", 0, "file.path", "/var/log/system.log"},
		{"setextattr", 0, "evt.arg[xattr]", "com.apple.FinderInfo"},
		{"deleteextattr", 0, "evt.arg[xattr]", "com.apple.quarantine"},
		{"deleteextattr", 0, "file.path", "/Users/alice/Downloads/app.dmg"},
		{"setmode", 0, "evt.arg[mode]", "4755"},
		{"setmode", 0, "file.mode", int64(0o4755)},
		{"setowner", 0, "evt.arg[owner_uid]", "0"},
		{"setowner", 0, "evt.arg[owner_gid]", "0"},
		{"get_task", 0, "target.ps.exe", "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"},
		{"get_task", 0, "target.ps.pid", int64(312)},
		{"get_task", 0, "ps.exe", "/Users/Shared/injector"},
		{"get_task", 0, "evt.arg[task_type]", "task_for_pid"},
		{"signal", 0, "evt.arg[signal]", "9"},
		{"signal", 0, "evt.arg[signal_name]", "SIGKILL"},
		{"signal", 0, "target.ps.exe", "/usr/libexec/syspolicyd"},
		{"trace", 0, "target.ps.exe", "/usr/bin/curl"},
		{"trace", 0, "ps.team_id", "59GAB85EFG"},
		{"remote_thread_create", 0, "target.ps.name", "Safari"},
		{"btm_launch_item_add", 0, "ps.exe", "/Users/alice/Downloads/Installer"},
		{"btm_launch_item_add", 0, "evt.arg[reporter_exe]", "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Resources/backgroundtaskmanagementd"},
		{"btm_launch_item_add", 0, "evt.arg[launch_item_type]", "agent"},
		{"btm_launch_item_add", 0, "evt.arg[launch_item_path]", "/Users/alice/Library/LaunchAgents/com.example.updater.plist"},
		{"btm_launch_item_add", 0, "file.path", "/Users/alice/Library/LaunchAgents/com.example.updater.plist"},
		{"btm_launch_item_add", 0, "evt.arg[launch_item_exe]", "/Users/alice/Library/Application Support/Example/updater"},
		{"mount", 0, "evt.arg[mount_path]", "/Volumes/Installer"},
		{"mount", 0, "evt.arg[mount_from]", "/dev/disk4s2"},
		{"mount", 0, "evt.arg[mount_disposition]", "virtual"},
		{"kextload", 0, "evt.arg[kext_id]", "com.example.driver.Rootkit"},
		{"authentication", 0, "evt.arg[auth_type]", "od"},
		{"authentication", 0, "evt.arg[auth_success]", "false"},
		{"authentication", 0, "evt.arg[auth_record_name]", "alice"},
		{"authentication", 0, "ps.exe", "/usr/bin/dscl"},
		{"authentication", 1, "evt.arg[auth_type]", "touchid"},
		{"authentication", 1, "evt.arg[auth_uid]", "501"},
		{"authentication", 1, "evt.arg[instigator_pid]", "6000"},
		{"authentication", 1, "ps.exe", "/usr/libexec/biometrickitd"},
		{"sudo", 0, "evt.arg[sudo_command]", "/bin/cat /etc/sudoers"},
		{"sudo", 0, "evt.arg[sudo_success]", "false"},
		{"sudo", 0, "evt.arg[sudo_to_uid]", "0"},
		{"sudo", 0, "evt.arg[sudo_from_user]", "alice"},
		{"sudo", 0, "evt.arg[sudo_reject_plugin]", "sudoers"},
		{"tcc_modify", 0, "evt.arg[tcc_service]", "kTCCServiceSystemPolicyAllFiles"},
		{"tcc_modify", 0, "evt.arg[tcc_right]", "allowed"},
		{"tcc_modify", 0, "evt.arg[tcc_update_type]", "create"},
		{"tcc_modify", 0, "evt.arg[tcc_reason]", "user_set"},
		{"tcc_modify", 0, "evt.arg[tcc_identity]", "com.example.agent"},
		{"tcc_modify", 0, "ps.exe", "/usr/bin/tccutil"},
		{"tcc_modify", 0, "evt.arg[tcc_responsible_exe]", "/bin/zsh"},
		{"xp_malware_detected", 0, "evt.arg[xp_malware_identifier]", "OSX.AtomicStealer.A"},
		{"xp_malware_detected", 0, "file.path", "/Users/alice/Downloads/Installer.app/Contents/MacOS/Installer"},
	}
	for _, c := range checks {
		e := decodeFixture(t, c.fixture, c.idx)
		var got any
		if root, key, ok := strings.Cut(c.field, "["); ok {
			got = e.GetIndexed(root, strings.TrimSuffix(key, "]"))
		} else {
			if _, known := event.LookupField(c.field); !known {
				t.Fatalf("test uses unknown field %s", c.field)
			}
			got = e.Get(c.field)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s[%d] %s = %#v, want %#v", c.fixture, c.idx, c.field, got, c.want)
		}
	}
}

func TestDecodeIgnoredAndErrors(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		ok      bool
		wantErr bool
	}{
		{"empty", "", false, false},
		{"unmapped type", `{"event_type":120,"event":{"pty_grant":{"dev":1}},"process":{}}`, false, false},
		{"unmapped key no type", `{"event":{"lookup":{}}}`, false, false},
		{"unknown code no key", `{"event_type":999}`, false, false},
		{"close unmodified", `{"event_type":12,"event":{"close":{"modified":false,"target":{"path":"/a"}}}}`, false, false},
		{"close mapped writable only", `{"event_type":12,"event":{"close":{"modified":false,"was_mapped_writable":true,"target":{"path":"/a"}}}}`, false, false},
		{"type contradicts key", `{"event_type":9,"event":{"open":{}}}`, false, true},
		{"malformed", `{"event_type":9,`, false, true},
		{"not an object", `[1,2,3]`, false, true},
		{"key only", `{"event":{"unlink":{"target":{"path":"/x"}}}}`, true, false},
		{"type only", `{"event_type":32}`, true, false},
		{"renumbered type with known key", `{"event_type":4000,"event":{"unlink":{"target":{"path":"/x"}}}}`, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok, err := Decode([]byte(c.line))
			if (err != nil) != c.wantErr || ok != c.ok {
				t.Fatalf("ok=%v err=%v, want ok=%v wantErr=%v", ok, err, c.ok, c.wantErr)
			}
		})
	}
	big := make([]byte, MaxLineSize+1)
	if _, _, err := Decode(big); err == nil {
		t.Fatal("oversize line accepted")
	}
}

// TestTolerantDecoding feeds fields of the wrong type; the event must still
// decode, keeping every field that was usable.
func TestTolerantDecoding(t *testing.T) {
	line := `{"event_type":"9","time":12345,"global_seq_num":"77",
	  "process":"not-an-object",
	  "event":{"exec":{
	    "target":{"audit_token":{"pid":"4242","pidversion":7,"ruid":null,"euid":-2},
	              "ppid":1.0,"codesigning_flags":"0x20000001","is_platform_binary":1,
	              "cdhash":[1,2,255],"signing_id":{"data":"com.x"},"team_id":null,
	              "executable":{"path":"/bin/x","stat":"weird"},"tty":7,
	              "start_time":{"tv_sec":1,"tv_usec":5},"brand_new_field":{"a":[1]}},
	    "args":["x",1,null,true],"env":"nope","cwd":[],"script":null}}}`
	e, ok, err := Decode([]byte(line))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	p := e.Proc
	if p == nil || p.PID != 4242 || p.PIDVersion != 7 || p.Exe != "/bin/x" || p.Name != "x" {
		t.Fatalf("proc = %+v", p)
	}
	if !p.IsSigned || !p.IsPlatform || p.SigningID != "com.x" || p.CDHash != "0102ff" || p.TeamID != "" {
		t.Errorf("signing = %+v", p)
	}
	if p.EUID != 4294967294 {
		t.Errorf("euid %d", p.EUID)
	}
	if !slices.Equal(p.Args, []string{"x", "1", "", "true"}) {
		t.Errorf("args %q", p.Args)
	}
	if p.Env != nil || p.Cwd != "" || p.TTY != "" {
		t.Errorf("env/cwd/tty should be empty: %+v", p)
	}
	if e.Seq != 77 || e.Time.Unix() != 12345 || p.StartTime.UnixMicro() != 1_000_005 {
		t.Errorf("seq %d time %v start %v", e.Seq, e.Time, p.StartTime)
	}
	if _, has := e.Args["prev_exe"]; has {
		t.Error("prev_exe set without a message process")
	}
}

func TestESEventTypes(t *testing.T) {
	got := ESEventTypes([]string{event.CreateProcess, event.WriteFile, "Nope", event.SetXattr})
	want := []string{"close", "exec", "setextattr"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	got = ESEventTypesWithWrite([]string{event.WriteFile})
	if !slices.Equal(got, []string{"close", "write"}) {
		t.Errorf("with write: %v", got)
	}
	all := ESEventTypes(nil)
	if len(all) != len(esTypes)-1 { // all but "write"
		t.Errorf("all: %v", all)
	}
	// Every subscription name must be one eslogger actually accepts.
	listed := map[string]bool{}
	for _, n := range strings.Fields(esloggerListEvents) {
		listed[n] = true
	}
	for _, et := range esTypes {
		if !listed[et.name] {
			t.Errorf("%s not in eslogger --list-events", et.name)
		}
	}
	// Every canonical name except YaraMatch has a native source event.
	sup := SupportedEvents()
	for _, n := range []string{event.CreateProcess, event.Fork, event.TerminateProcess, event.OpenFile,
		event.CreateFile, event.WriteFile, event.RenameFile, event.DeleteFile, event.SetXattr,
		event.DeleteXattr, event.SetMode, event.SetOwner, event.OpenProcess, event.Signal, event.Ptrace,
		event.CreateRemoteThread, event.AddLaunchItem, event.Mount, event.LoadKext, event.Authenticate,
		event.Sudo, event.ModifyTCC, event.XProtectDetect} {
		if !slices.Contains(sup, n) {
			t.Errorf("canonical %s has no ES mapping", n)
		}
	}
}

// esloggerListEvents is `eslogger --list-events` on macOS 26.6.2 (104 events).
const esloggerListEvents = `access authentication authorization_judgement authorization_petition
btm_launch_item_add btm_launch_item_remove chdir chroot clone close copyfile create cs_invalidated
deleteextattr dup exchangedata exec exit fcntl file_provider_materialize file_provider_update fork
fsgetpath gatekeeper_user_override get_task get_task_inspect get_task_name get_task_read getattrlist
getextattr iokit_open kextload kextunload link listextattr login_login login_logout lookup
lw_session_lock lw_session_login lw_session_logout lw_session_unlock mmap mount mprotect
od_attribute_set od_attribute_value_add od_attribute_value_remove od_create_group od_create_user
od_delete_group od_delete_user od_disable_user od_enable_user od_group_add od_group_remove
od_group_set od_modify_password open openssh_login openssh_logout proc_check proc_suspend_resume
profile_add profile_remove pty_close pty_grant readdir readlink remote_thread_create remount rename
screensharing_attach screensharing_detach searchfs setacl setattrlist setegid seteuid setextattr
setflags setgid setmode setowner setregid setreuid settime setuid signal stat su sudo tcc_modify
trace truncate uipc_bind uipc_connect unlink unmount utimes write xp_malware_detected
xp_malware_remediated xpc_connect`

func TestExcluded(t *testing.T) {
	s := New(Config{ExcludePaths: []string{"/private/var/folders/", "/System/", "/dev", "relative/ignored", ""}, ExcludeSigning: []string{"com.apple.mdworker_shared", ""}})
	mk := func(name, path, dest, sid string) *event.Event {
		e := &event.Event{Name: name, Proc: &event.Proc{SigningID: sid, IsPlatform: sid != ""}}
		if path != "" || dest != "" {
			e.File = &event.File{Path: path, Dest: dest}
		}
		return e
	}
	cases := []struct {
		e    *event.Event
		want bool
	}{
		{mk(event.OpenFile, "/private/var/folders/x/y", "", ""), true},
		{mk(event.OpenFile, "/Users/a/x", "", ""), false},
		{mk(event.RenameFile, "/private/var/folders/x", "/Users/a/Library/LaunchAgents/x.plist", ""), false},
		{mk(event.RenameFile, "/private/var/folders/x", "/System/y", ""), true},
		{mk(event.OpenFile, "/Users/a/x", "", "com.apple.mdworker_shared"), true},
		{mk(event.CreateProcess, "", "", "com.apple.mdworker_shared"), false}, // lifecycle never dropped
		{mk(event.Fork, "", "", "com.apple.mdworker_shared"), false},
		{mk(event.TerminateProcess, "", "", "com.apple.mdworker_shared"), false},
		{mk(event.Mount, "/System/Volumes/x", "", ""), false}, // path filter is for file events only
		{mk(event.OpenFile, "/Users/a/x", "", ""), false},
		{mk(event.OpenFile, "/dev", "", ""), true},
		{mk(event.OpenFile, "/dev/null", "", ""), true},
		{mk(event.OpenFile, "/devil/x", "", ""), false},
		{mk(event.OpenFile, "/System", "", ""), true},
		{mk(event.OpenFile, "/Systemx/y", "", ""), false},
		{mk(event.OpenFile, "relative/ignored/x", "", ""), false},
		// signing ID exclusion needs a platform binary: an ad-hoc signer can pick any ID
		{&event.Event{Name: event.OpenFile, Proc: &event.Proc{SigningID: "com.apple.mdworker_shared"}, File: &event.File{Path: "/Users/a/x"}}, false},
		{&event.Event{Name: event.OpenFile, Proc: &event.Proc{IsPlatform: true}, File: &event.File{Path: "/Users/a/x"}}, false},
	}
	for i, c := range cases {
		if got := s.Excluded(c.e); got != c.want {
			t.Errorf("case %d (%s %+v): got %v", i, c.e.Name, c.e.File, got)
		}
	}
}

func TestConsumeLongLinesAndCounters(t *testing.T) {
	s := New(Config{ExcludePaths: []string{"/excluded/"}})
	var in bytes.Buffer
	in.WriteString(`{"event_type":32,"event":{"unlink":{"target":{"path":"/a"}}}}` + "\n")
	in.WriteString(`{"event_type":32,"event":{"unlink":{"target":{"path":"/excluded/b"}}}}` + "\n")
	in.WriteString("garbage\n\n")
	in.WriteString(`{"event_type":120,"event":{"pty_grant":{}}}` + "\n")
	in.WriteString(`{"event_type":32,"x":"` + strings.Repeat("A", MaxLineSize) + `"}` + "\n")
	in.WriteString(`{"event_type":32,"event":{"unlink":{"target":{"path":"/c"}}}}`) // no trailing newline
	out := make(chan *event.Event, 10)
	if err := s.consume(t.Context(), &in, out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var paths []string
	for e := range out {
		paths = append(paths, e.File.Path)
		if !e.Time.IsZero() {
			t.Error("time must come from the message only")
		}
	}
	if !slices.Equal(paths, []string{"/a", "/c"}) {
		t.Errorf("paths %v", paths)
	}
	st := s.Stats()
	want := map[string]uint64{"lines": 5, "decoded": 3, "ignored": 1, "decode_errors": 1,
		"oversize_lines": 1, "excluded": 1, "sent": 2, "restarts": 0}
	if !reflect.DeepEqual(st, want) {
		t.Errorf("stats %v want %v", st, want)
	}
}

func TestClassifyStderr(t *testing.T) {
	for msg, want := range map[string]error{
		"Failed to create ES client: Not permitted to create an ES Client, responsible process needs TCC Full Disk Access authorization (ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED)\n": ErrNoFullDiskAccess,
		"Failed to create ES client: Not privileged to create an ES client, need to be superuser (ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED)":                                         ErrNotRoot,
		"(ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS)": ErrTooManyClients,
	} {
		if err := classifyStderr(msg); err == nil || !strings.Contains(err.Error(), want.Error()) {
			t.Errorf("%q -> %v", msg, err)
		}
	}
	if classifyStderr("something else") != nil {
		t.Error("unexpected classification")
	}
}

func TestRunRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	err := New(Config{}).Run(t.Context(), nil, make(chan *event.Event))
	if err != ErrNotRoot {
		t.Fatalf("got %v", err)
	}
}

func TestArgsAreFixedTable(t *testing.T) {
	s := New(Config{SubscribeWrite: true})
	for _, a := range s.Args([]string{"; rm -rf /", event.CreateProcess, event.WriteFile}) {
		if _, ok := typeByName[a]; !ok {
			t.Errorf("argv element %q not from the fixed table", a)
		}
	}
}

func TestIsSigned(t *testing.T) {
	for flags, want := range map[uint32]bool{
		0:                                      false, // unsigned
		csSigned:                               false, // signature went invalid
		csSigned | csValid:                     true,
		0x26000001:                             true,  // platform binary
		csSigned | csValid | csAdhoc:           false, // ad hoc
		csSigned | csValid | csAdhoc | 0x20000: false, // linker-signed (CS_LINKER_SIGNED)
		csValid:                                false,
	} {
		if got := isSigned(flags); got != want {
			t.Errorf("isSigned(%#x) = %v, want %v", flags, got, want)
		}
	}
}

func TestExecArgsAndEnvCapped(t *testing.T) {
	big := strings.Repeat("A", 100<<10)
	line := `{"event_type":9,"event":{"exec":{"target":{"audit_token":{"pid":5,"pidversion":5},"executable":{"path":"/tmp/x"}},` +
		`"args":["x","` + big + `","after"],"env":["SMALL=1","BIG=` + big + `","LATER=2"]}}}`
	e, ok, err := Decode([]byte(line))
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	total := 0
	for _, a := range e.Proc.Args {
		total += len(a)
	}
	if total != MaxArgsBytes || len(e.Proc.Args) != 2 || e.Args["args_truncated"] != "true" {
		t.Errorf("args: n=%d total=%d marker=%q", len(e.Proc.Args), total, e.Args["args_truncated"])
	}
	envBytes := 0
	for k, v := range e.Proc.Env {
		envBytes += len(k) + len(v)
	}
	if envBytes != MaxEnvBytes || e.Proc.Env["SMALL"] != "1" || e.Args["env_truncated"] != "true" {
		t.Errorf("env: bytes=%d marker=%q", envBytes, e.Args["env_truncated"])
	}
	if _, has := e.Proc.Env["LATER"]; has {
		t.Error("env after the budget kept")
	}
	if len(e.Proc.Cmdline) > MaxArgsBytes+len(e.Proc.Args) {
		t.Errorf("cmdline %d bytes", len(e.Proc.Cmdline))
	}
	// Small exec: no markers.
	e, _, _ = Decode([]byte(`{"event_type":9,"event":{"exec":{"target":{"audit_token":{"pid":5},"executable":{"path":"/x"}},"args":["a"],"env":["K=V"]}}}`))
	if _, has := e.Args["args_truncated"]; has {
		t.Error("marker on small exec")
	}
}
