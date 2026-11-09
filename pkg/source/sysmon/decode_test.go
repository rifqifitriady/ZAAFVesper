package sysmon

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/sigmamap"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func fixtures(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob("testdata/*.xml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	sort.Strings(files)
	return files
}

// TestGolden decodes every fixture and compares the canonical event with
// its reviewed golden JSON (go test -run TestGolden -update rewrites them).
func TestGolden(t *testing.T) {
	for _, f := range fixtures(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		e, err := Decode(raw)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		got, err := json.MarshalIndent(e, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		golden := strings.TrimSuffix(f, ".xml") + ".golden.json"
		if *update {
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%s: %v (run with -update)", golden, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: decoded event differs from %s:\n%s", f, golden, got)
		}
	}
}

// TestEveryMappedIDHasFixture keeps MappedIDs and the fixtures in step.
func TestEveryMappedIDHasFixture(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range fixtures(t) {
		r, err := Parse(mustRead(t, f))
		if err != nil {
			t.Fatal(err)
		}
		if r.Provider == ProviderWindows {
			seen[itoa(r.EventID)] = true
		}
	}
	for _, id := range MappedIDs {
		if !seen[itoa(id)] {
			t.Errorf("no Windows fixture for event %d", id)
		}
	}
}

// TestSigmaFieldsResolve: every Sigma field of the event's category
// (pkg/sigmamap) that the fixture carries must resolve to a non-nil value
// on the decoded event, and the event must export under the Sysmon event id
// it came from. This ties the decoder to the shared contract.
func TestSigmaFieldsResolve(t *testing.T) {
	// The process table, not the decoder, fills these on a live sensor.
	tableOnly := map[string]bool{"ps.parent.username": false}
	sameID := map[int]int{26: 23, 19: 20, 21: 20}
	for _, f := range fixtures(t) {
		raw := mustRead(t, f)
		r, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		e, err := Map(r)
		if err != nil {
			t.Fatal(err)
		}
		want := r.EventID
		if w, ok := sameID[want]; ok {
			want = w
		}
		if got := sigmamap.SysmonEventIDs[e.Name]; got != want {
			t.Errorf("%s: %s exports as Sysmon %d, decoded from %d", f, e.Name, got, r.EventID)
		}
		cat := sigmamap.ForEvent(e.Name)
		if cat == nil {
			t.Errorf("%s: %s has no Sigma category", f, e.Name)
			continue
		}
		for sf, zf := range cat.Fields {
			v, ok := r.Data[sf]
			if !ok || v == "-" || v == "" || tableOnly[zf] {
				continue
			}
			var got event.Value
			if root, key, ok := splitIndexed(zf); ok {
				got = e.GetIndexed(root, key)
			} else {
				got = e.Get(zf)
			}
			if got == nil {
				t.Errorf("%s: Sigma %s.%s = %q but %s is nil", f, cat.Name, sf, v, zf)
			}
		}
		for sf, vals := range cat.Values {
			v, ok := r.Data[sf]
			if !ok {
				continue
			}
			vm, ok := vals[strings.ToLower(v)]
			if !ok {
				t.Errorf("%s: no value mapping for %s=%q", f, sf, v)
				continue
			}
			if got := e.Get(vm.Field); got != vm.Value {
				t.Errorf("%s: %s=%q should give %s=%q, got %v", f, sf, v, vm.Field, vm.Value, got)
			}
		}
	}
}

func splitIndexed(f string) (root, key string, ok bool) {
	i := strings.IndexByte(f, '[')
	if i < 0 || !strings.HasSuffix(f, "]") {
		return "", "", false
	}
	return f[:i], f[i+1 : len(f)-1], true
}

func TestDecodeDetails(t *testing.T) {
	e := decodeFile(t, "w01_process_create")
	p := e.Proc
	if e.Name != event.CreateProcess || e.Platform != event.PlatformWindows || e.Source != SourceName || e.Seq != 1001 {
		t.Fatalf("header: %+v", e)
	}
	if p.PID != 6228 || p.PPID != 5480 || p.Name != "powershell.exe" || p.Username != `CORP\alice` || p.UID != -1 {
		t.Fatalf("proc: %+v", p)
	}
	if p.Cmdline != `powershell.exe -NoProfile -EncodedCommand "SQBFAFgA"` || len(p.Args) != 4 || p.Args[3] != "SQBFAFgA" {
		t.Fatalf("cmdline %q args %q", p.Cmdline, p.Args)
	}
	if p.Product != "Microsoft® Windows® Operating System" || p.OriginalName != "PowerShell.EXE" || p.Integrity != "Medium" {
		t.Fatalf("version info: %+v", p)
	}
	if p.Parent == nil || p.Parent.PID != 5480 || p.Parent.Exe != `C:\Windows\System32\cmd.exe` || p.Parent.PIDVersion == 0 || p.PIDVersion == 0 || p.PIDVersion == p.Parent.PIDVersion {
		t.Fatalf("parent stub: %+v", p.Parent)
	}
	if e.Get("ps.parent.cmdline") != `"C:\Windows\system32\cmd.exe" /c run.bat` {
		t.Fatalf("parent cmdline %v", e.Get("ps.parent.cmdline"))
	}
	if !p.StartTime.Equal(e.Time) || e.Time.Format("15:04:05.000") != "10:00:00.123" {
		t.Fatalf("time %v start %v", e.Time, p.StartTime)
	}
	if _, ok := e.Args["rule_name"]; ok {
		t.Fatal(`RuleName "-" must be absent`)
	}

	n := decodeFile(t, "w03_network_accept")
	if n.Name != event.NetworkAccept || n.Net.Direction != "inbound" || n.Net.DstPort != 4444 {
		t.Fatalf("accept: %+v %+v", n, n.Net)
	}
	d := decodeFile(t, "w22_dns_query")
	if d.DNS.Query != "c2.example" || len(d.DNS.Answers) != 2 || d.DNS.Answers[1] != "::ffff:203.0.113.7" {
		t.Fatalf("dns: %+v", d.DNS)
	}
	r := decodeFile(t, "w13_registry_set_value")
	if r.Registry.Value != "Updater" || r.Registry.Data != `C:\Users\alice\AppData\Local\Temp\upd.exe` || r.Args["rule_name"] != "T1547.001" {
		t.Fatalf("registry: %+v %v", r.Registry, r.Args)
	}
	dv := decodeFile(t, "w12_registry_delete_value")
	if dv.Name != event.RegistryDeleteKey || dv.Registry.Value != "Updater" {
		t.Fatalf("delete value: %+v", dv.Registry)
	}
	m := decodeFile(t, "w07_image_load")
	if m.Module.Signed == nil || *m.Module.Signed || m.Get("image.signed") != false {
		t.Fatalf("image signed: %+v", m.Module)
	}
	a := decodeFile(t, "w10_process_access")
	if a.Target == nil || a.Target.PID != 720 || a.Target.Name != "lsass.exe" || a.Args["granted_access"] != "0x1010" {
		t.Fatalf("access: %+v %v", a.Target, a.Args)
	}
	l := decodeFile(t, "l01_process_create")
	if l.Platform != event.PlatformLinux || l.Proc.Name != "curl" || len(l.Proc.Args) != 3 || l.Proc.Integrity != "no level" {
		t.Fatalf("linux: %+v", l.Proc)
	}
}

func TestDecodeRejects(t *testing.T) {
	base := string(mustRead(t, "testdata/w05_process_terminate.xml"))
	cases := map[string]struct {
		in   string
		want error
	}{
		"too large":         {strings.Repeat(" ", MaxEventBytes+1), ErrTooLarge},
		"other provider":    {strings.Replace(base, ProviderWindows, "Microsoft-Windows-Security-Auditing", 1), ErrNotSysmon},
		"duplicate data":    {strings.Replace(base, `<Data Name="User">`, `<Data Name="Image">C:\x.exe</Data><Data Name="User">`, 1), ErrDuplicate},
		"dtd":               {`<!DOCTYPE Event [<!ENTITY a "aaaa">]>` + base, ErrMalformed},
		"entity":            {strings.Replace(base, "6228", "&a;", 1), ErrMalformed},
		"utf16 declaration": {`<?xml version="1.0" encoding="UTF-16"?>` + base, ErrMalformed},
		"element in data":   {strings.Replace(base, `<Data Name="User">`, `<Data Name="User"><b/>`, 1), ErrMalformed},
		"two roots":         {base + base, ErrMalformed},
		"wrong root":        {`<Events>` + base + `</Events>`, ErrMalformed},
		"truncated":         {base[:len(base)/2], ErrMalformed},
		"bad event id":      {strings.Replace(base, "<EventID>5</EventID>", "<EventID>x</EventID>", 1), ErrMalformed},
		"unsupported id":    {strings.Replace(base, "<EventID>5</EventID>", "<EventID>9</EventID>", 1), ErrUnsupported},
		"no time":           {strings.NewReplacer(`<Data Name="UtcTime">2026-11-08 10:00:09.000</Data>`, "", `SystemTime="2026-11-08T10:00:00.1234567Z"`, "").Replace(base), ErrMalformed},
		"deep":              {strings.Replace(base, "<Correlation/>", strings.Repeat("<a>", 9)+strings.Repeat("</a>", 9), 1), ErrMalformed},
		"field too long":    {strings.Replace(base, `<Data Name="User">`, `<Data Name="User">`+strings.Repeat("x", MaxFieldBytes+1), 1), ErrMalformed},
	}
	for name, c := range cases {
		if _, err := Decode([]byte(c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
	}
	net := string(mustRead(t, "testdata/w03_network_connect.xml"))
	if _, err := Decode([]byte(strings.Replace(net, ">true<", ">maybe<", 1))); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad Initiated: %v", err)
	}
	var b strings.Builder
	for i := 0; i < maxDataItems+1; i++ {
		b.WriteString(`<Data Name="k` + itoa(i) + `">v</Data>`)
	}
	many := strings.Replace(base, "<EventData>", "<EventData>"+b.String(), 1)
	if _, err := Decode([]byte(many)); !errors.Is(err, ErrMalformed) {
		t.Errorf("too many data items: %v", err)
	}
}

func TestGUIDVersion(t *testing.T) {
	if GUIDVersion("") != 0 || GUIDVersion("{00000000-0000-0000-0000-000000000000}") != 0 {
		t.Fatal("empty GUIDs must give 0")
	}
	a := GUIDVersion("{A1B2C3D4-0001-6731-6B01-000000001400}")
	if a == 0 || a != GUIDVersion("a1b2c3d4-0001-6731-6b01-000000001400") {
		t.Fatal("GUIDVersion must ignore case and braces")
	}
	if a == GUIDVersion("{a1b2c3d4-0001-6731-6b01-000000001401}") {
		t.Fatal("different GUIDs collide")
	}
}

func FuzzDecode(f *testing.F) {
	for _, file := range fixtures(f) {
		f.Add(mustRead(f, file))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := Decode(raw)
		if err != nil {
			if e != nil {
				t.Fatal("event with error")
			}
			return
		}
		if e.Name == "" || e.Platform == "" || e.Time.IsZero() {
			t.Fatalf("incomplete event %+v", e)
		}
		if _, err := json.Marshal(e); err != nil {
			t.Fatal(err)
		}
	})
}

func decodeFile(t *testing.T, name string) *event.Event {
	t.Helper()
	e, err := Decode(mustRead(t, "testdata/"+name+".xml"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return e
}

func mustRead(t testing.TB, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func itoa(i int) string { return strconv.Itoa(i) }
