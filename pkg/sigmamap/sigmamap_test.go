package sigmamap

import (
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
)

func validField(f string) bool {
	if strings.HasPrefix(f, "evt.arg[") && strings.HasSuffix(f, "]") {
		return true
	}
	_, ok := event.LookupField(f)
	return ok
}

// TestTargetsExist: every mapped ZAAFVesper field and every canonical event
// exists, so the importer never emits a rule that fails to compile.
func TestTargetsExist(t *testing.T) {
	known := map[string]bool{}
	for _, n := range ql.KnownEvents() {
		known[n] = true
	}
	for name, c := range Categories {
		if c.Name != name || len(c.Events) == 0 {
			t.Errorf("%s: bad category", name)
		}
		for _, e := range c.Events {
			if !known[e] {
				t.Errorf("%s: unknown event %s", name, e)
			}
		}
		for sf, f := range c.Fields {
			if !validField(f) {
				t.Errorf("%s.%s -> %s: no such field", name, sf, f)
			}
		}
		for sf, vm := range c.Values {
			for v, m := range vm {
				if !validField(m.Field) {
					t.Errorf("%s.%s=%s -> %s: no such field", name, sf, v, m.Field)
				}
			}
		}
	}
	for ev, cat := range primary {
		if !known[ev] || Categories[cat] == nil {
			t.Errorf("primary %s -> %s invalid", ev, cat)
		}
	}
	for ev := range SysmonEventIDs {
		if !known[ev] {
			t.Errorf("event id for unknown event %s", ev)
		}
	}
}

func TestLookups(t *testing.T) {
	if f, ok := Field("process_creation", "CommandLine"); !ok || f != "ps.cmdline" {
		t.Fatal(f)
	}
	if c := ForEvent(event.RegistrySetValue); c == nil || c.Name != "registry_set" {
		t.Fatal("registry_set")
	}
	if ForEvent(event.Fork) != nil {
		t.Fatal("Fork has no Sigma category")
	}
	if Products["windows"] != event.PlatformWindows {
		t.Fatal("product")
	}
}

// TestOneSigmaNamePerTarget: within a category no two Sigma fields map to
// the same ZAAFVesper field, and every pair converts there and back.
func TestOneSigmaNamePerTarget(t *testing.T) {
	for name, c := range Categories {
		seen := map[string]string{}
		for sf, zf := range c.Fields {
			if prev, dup := seen[zf]; dup {
				t.Errorf("%s: %s and %s both map to %s", name, prev, sf, zf)
			}
			seen[zf] = sf
			back, ok := SigmaField(name, zf)
			if !ok || back != sf {
				t.Errorf("%s: %s -> %s -> %q", name, sf, zf, back)
			}
			if fwd, ok := Field(name, back); !ok || fwd != zf {
				t.Errorf("%s: round trip %s", name, sf)
			}
		}
		if len(ExportFields(name)) != len(c.Fields) {
			t.Errorf("%s: export map size", name)
		}
	}
	if ExportFields("nope") != nil {
		t.Fatal("unknown category")
	}
}

// TestEveryEventKnown: the event list used by the compiler is event.Names.
func TestEveryEventKnown(t *testing.T) {
	if len(ql.KnownEvents()) != len(event.Names()) {
		t.Fatal("compiler event list differs from event.Names")
	}
}
