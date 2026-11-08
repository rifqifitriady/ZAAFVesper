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
