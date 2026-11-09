package output

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

const schemaFile = "../../integrations/zaafelegia/schema/zaafvesper-elegia-v1.schema.json"

// TestElegiaRecordsMatchSchema encodes a rich event of every canonical event
// name (and the size-capped fallback) and validates each record against the
// published JSON Schema, so the schema and the encoder cannot drift apart.
func TestElegiaRecordsMatchSchema(t *testing.T) {
	raw, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	signed := true
	seen := map[string]bool{} // schema properties seen in some record
	t0 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	for _, name := range event.Names() {
		for _, platform := range []string{event.PlatformMacOS, event.PlatformWindows, ""} {
			e := &event.Event{Seq: 9, Time: t0, Name: name, Source: "test", Platform: platform,
				Proc: &event.Proc{PID: 10, PPID: 1, PIDVersion: 3, UniqueID: 99, Exe: "/bin/x", Name: "x", Cmdline: "x -a",
					Args: []string{"x", "-a"}, Cwd: "/", Username: "u", SigningID: "s", TeamID: "T", CSCategory: "platform",
					IsPlatform: true, IsSigned: true, Seeded: true, GUID: "{g}", Hashes: "SHA256=00", Integrity: "High",
					Parent: &event.Proc{PID: 1, UniqueID: 1, Exe: "/sbin/launchd", Cmdline: "launchd", SigningID: "l", TeamID: "P", IsPlatform: true}},
				Target:   &event.Proc{PID: 11, Exe: "/bin/t"},
				File:     &event.File{Path: "/tmp/f", Dest: "/tmp/g"},
				Net:      &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "10.0.0.1", SrcPort: 1, DstIP: "10.0.0.2", DstPort: 2},
				DNS:      &event.DNS{Query: "example.org", Answers: []string{"192.0.2.1"}},
				Registry: &event.Registry{Key: `HKLM\x`, Value: "v", Data: "d"},
				Module:   &event.Module{Path: "/lib/m", Signed: &signed},
				Args:     map[string]string{"identity": "unverified", "pipe_name": `\p`, "granted_access": "0x10"},
				Yara:     &event.Yara{Rule: "r", Target: "/tmp/f"}}
			for _, host := range []string{"", "mac-01"} {
				rec := encodeToMap(t, e, SigmaOptions{DefaultProduct: "macos", Host: host}, 0)
				if errs := validate(schema, schema, rec, "$"); len(errs) > 0 {
					t.Fatalf("%s/%s: record does not match the schema:\n%s\nrecord: %v", name, platform, strings.Join(errs, "\n"), rec)
				}
				markSeen(seen, "", rec)
			}
		}
	}
	// The other direction: every property the schema names explicitly is
	// emitted by some record (the truncated flag by the capped one below).
	seen["truncated"] = true
	for _, path := range declared(schema, "", schema) {
		if !seen[path] {
			t.Errorf("the schema declares %q but the encoder never emits it", path)
		}
	}
	// The size-capped fallback ("truncated": true) also matches.
	big := &event.Event{Name: event.CreateProcess, Platform: "macos", Proc: &event.Proc{PID: 1, Exe: "/bin/x", Cmdline: strings.Repeat("a", 9000)}}
	rec := encodeToMap(t, big, SigmaOptions{}, 4096)
	if rec["truncated"] != true {
		t.Fatalf("expected the capped form: %v", rec)
	}
	if errs := validate(schema, schema, rec, "$"); len(errs) > 0 {
		t.Fatalf("capped record: %s", strings.Join(errs, "\n"))
	}
	// And the validator itself rejects what the schema forbids.
	bad := map[string]any{"logsource": map[string]any{"product": "macos"}, "zaafvesper": map[string]any{"schema": "zaafvesper.elegia/1", "name": "x", "extra": 1}, "lowercase": 1}
	if errs := validate(schema, schema, bad, "$"); len(errs) < 2 {
		t.Fatalf("validator accepted a bad record: %v", errs)
	}
}

func encodeToMap(t *testing.T, e *event.Event, o SigmaOptions, max int) map[string]any {
	t.Helper()
	b, err := EncodeSigma(e, o, max)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// validate checks v against the subset of JSON Schema the record schema
// uses: type, required, properties, patternProperties, additionalProperties
// (boolean), const, enum, items, pattern, minimum and $ref to #/$defs.
func validate(root, s map[string]any, v any, at string) []string {
	if ref, ok := s["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		return validate(root, root["$defs"].(map[string]any)[name].(map[string]any), v, at)
	}
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, at+": "+fmt.Sprintf(format, args...)) }
	if c, ok := s["const"]; ok && fmt.Sprint(c) != fmt.Sprint(v) {
		fail("want const %v, got %v", c, v)
	}
	if en, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range en {
			found = found || fmt.Sprint(x) == fmt.Sprint(v)
		}
		if !found {
			fail("%v not in %v", v, en)
		}
	}
	if ty, ok := s["type"]; ok {
		var types []string
		switch x := ty.(type) {
		case string:
			types = []string{x}
		case []any:
			for _, y := range x {
				types = append(types, y.(string))
			}
		}
		okType := false
		for _, want := range types {
			okType = okType || jsonType(v, want)
		}
		if !okType {
			fail("type %T is not %v", v, types)
		}
	}
	if p, ok := s["pattern"].(string); ok {
		if str, isStr := v.(string); isStr && !regexp.MustCompile(p).MatchString(str) {
			fail("%q does not match %s", str, p)
		}
	}
	if mn, ok := s["minimum"].(float64); ok {
		if f, isNum := v.(float64); isNum && f < mn {
			fail("%v < minimum %v", f, mn)
		}
	}
	if arr, ok := v.([]any); ok {
		if it, has := s["items"].(map[string]any); has {
			for i, x := range arr {
				errs = append(errs, validate(root, it, x, fmt.Sprintf("%s[%d]", at, i))...)
			}
		}
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return errs
	}
	if req, has := s["required"].([]any); has {
		for _, r := range req {
			if _, present := obj[r.(string)]; !present {
				fail("missing required %q", r)
			}
		}
	}
	props, _ := s["properties"].(map[string]any)
	pats, _ := s["patternProperties"].(map[string]any)
	for k, x := range obj {
		if ps, has := props[k]; has {
			errs = append(errs, validate(root, ps.(map[string]any), x, at+"."+k)...)
			continue
		}
		matched := false
		for p, ps := range pats {
			if regexp.MustCompile(p).MatchString(k) {
				matched = true
				errs = append(errs, validate(root, ps.(map[string]any), x, at+"."+k)...)
			}
		}
		if !matched {
			if ap, has := s["additionalProperties"].(bool); has && !ap {
				fail("property %q is not allowed", k)
			}
		}
	}
	return errs
}

func jsonType(v any, want string) bool {
	switch want {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == float64(int64(f))
	case "number":
		_, ok := v.(float64)
		return ok
	}
	return false
}

// markSeen records every key path of rec ("zaafvesper.proc.pid").
func markSeen(seen map[string]bool, prefix string, v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for k, x := range m {
		seen[prefix+k] = true
		markSeen(seen, prefix+k+".", x)
	}
}

// declared lists the explicitly named property paths of a schema node
// (patternProperties, the open Sigma field set, are not listed).
func declared(root map[string]any, prefix string, s map[string]any) []string {
	if ref, ok := s["$ref"].(string); ok {
		s = root["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
	}
	var out []string
	props, _ := s["properties"].(map[string]any)
	for k, ps := range props {
		out = append(out, prefix+k)
		out = append(out, declared(root, prefix+k+".", ps.(map[string]any))...)
	}
	return out
}
