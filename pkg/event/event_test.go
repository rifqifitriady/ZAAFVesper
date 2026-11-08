package event

import "testing"

func sample() *Event {
	parent := &Proc{PID: 1, Exe: "/sbin/launchd", Name: "launchd", IsPlatform: true}
	return &Event{
		Name: CreateFile,
		Proc: &Proc{PID: 42, PPID: 1, Exe: "/bin/bash", Name: "bash", Args: []string{"bash", "-c", "x"},
			Env: map[string]string{"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}, Parent: parent,
			Ancestors: []string{"/sbin/launchd"}},
		File: &File{Path: "/Users/a/Library/LaunchAgents/Evil.PLIST"},
		Args: map[string]string{"xattr": "com.apple.quarantine"},
	}
}

func TestGet(t *testing.T) {
	e := sample()
	cases := map[string]Value{
		"evt.name": "CreateFile", "evt.category": "file", "evt.pid": int64(42),
		"ps.exe": "/bin/bash", "ps.parent.name": "launchd", "ps.parent.is_platform": true,
		"file.name": "Evil.PLIST", "file.ext": ".plist", "file.dir": "/Users/a/Library/LaunchAgents",
	}
	for f, want := range cases {
		if got := e.Get(f); got != want {
			t.Errorf("%s = %#v, want %#v", f, got, want)
		}
	}
	if e.Get("target.ps.exe") != nil || e.Get("yara.rule") != nil || e.Get("nope") != nil {
		t.Error("absent fields must be nil")
	}
	if got := e.Get("ps.args").([]string); len(got) != 3 {
		t.Errorf("ps.args = %v", got)
	}
}

func TestIndexed(t *testing.T) {
	e := sample()
	if e.GetIndexed("evt.arg", "xattr") != "com.apple.quarantine" {
		t.Error("evt.arg")
	}
	if e.GetIndexed("ps.env", "DYLD_INSERT_LIBRARIES") != "/tmp/x.dylib" {
		t.Error("ps.env")
	}
	if e.GetIndexed("ps.parent.env", "X") != nil || e.GetIndexed("evt.arg", "missing") != nil {
		t.Error("absent indexed must be nil")
	}
}

func TestRegistryKinds(t *testing.T) {
	for _, f := range []string{"ps.exe", "ps.parent.signing_id", "target.ps.pid", "file.path", "yara.tags"} {
		if _, ok := LookupField(f); !ok {
			t.Errorf("missing field %s", f)
		}
	}
	if k, _ := LookupField("ps.is_platform"); k != KindBool {
		t.Error("kind")
	}
}

func TestCSCategoryNilWhenUnknown(t *testing.T) {
	e := &Event{Name: CreateProcess, Proc: &Proc{PID: 10}}
	if v := e.Get("ps.cs_category"); v != nil {
		t.Fatalf("unknown category = %v, want nil", v)
	}
	e.Proc.CSCategory = CSDeveloperID
	if v := e.Get("ps.cs_category"); v != CSDeveloperID {
		t.Fatalf("got %v", v)
	}
	if Category(SensorDegraded) != "sensor" {
		t.Fatal("SensorDegraded category")
	}
}

// TestNewFieldsNilWhenUnreported: optional attributes resolve to nil both
// when their struct is absent and when the struct carries zero values, so
// `not (...)` and `= 0` conditions cannot match unreported data.
func TestNewFieldsNilWhenUnreported(t *testing.T) {
	fields := []string{
		"evt.platform",
		"net.proto", "net.direction", "net.sip", "net.sport", "net.dip", "net.dport", "net.dhost",
		"dns.query", "dns.type", "dns.answers", "dns.status",
		"registry.key", "registry.value", "registry.data", "registry.new_key",
		"image.path", "image.signed", "image.signature", "image.signature_status", "image.hashes",
	}
	for _, p := range []string{"ps.", "ps.parent.", "target.ps."} {
		for _, a := range []string{"guid", "hashes", "integrity", "company", "product", "description", "original_name"} {
			fields = append(fields, p+a)
		}
	}
	absent := &Event{Name: NetworkConnect, Proc: &Proc{PID: 5, Parent: &Proc{PID: 1}}, Target: &Proc{PID: 7}}
	zero := &Event{Name: NetworkConnect, Proc: &Proc{PID: 5, Parent: &Proc{PID: 1}}, Target: &Proc{PID: 7},
		Net: &Net{}, DNS: &DNS{}, Registry: &Registry{}, Module: &Module{}}
	for _, f := range fields {
		if _, ok := LookupField(f); !ok {
			t.Errorf("%s: not registered", f)
			continue
		}
		if v := absent.Get(f); v != nil {
			t.Errorf("%s on absent struct = %#v, want nil", f, v)
		}
		if v := zero.Get(f); v != nil {
			if s, ok := v.([]string); !ok || len(s) != 0 {
				t.Errorf("%s on zero struct = %#v, want nil", f, v)
			}
		}
	}
	e := &Event{Net: &Net{DstPort: 443}}
	if v := e.Get("net.dport"); v != int64(443) {
		t.Fatalf("net.dport = %#v", v)
	}
}

// TestNamesCategorised: every canonical event has a category.
func TestNamesCategorised(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range Names() {
		if seen[n] {
			t.Errorf("duplicate %s", n)
		}
		seen[n] = true
		if Category(n) == "other" {
			t.Errorf("%s has no category", n)
		}
	}
}
