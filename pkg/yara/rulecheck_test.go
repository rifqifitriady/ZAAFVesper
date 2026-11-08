package yara

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestCheckRuleSource(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      error
	}{
		{"no imports", `rule a { strings: $a = "x" condition: $a }`, nil},
		{"allowed modules", "import \"pe\"\nimport \"math\"\nimport \"macho\"\nimport \"hash\"\nrule a { condition: true }", nil},
		{"import after a comment on the same line", `/* c */ import "math" rule a { condition: true }`, nil},
		{"magic in a comment", "// import \"magic\"\n/* import \"magic\" */\nrule a { condition: true }", nil},
		{"magic in a string", `rule a { strings: $a = "import \"magic\"" condition: $a }`, nil},
		{"magic in a regexp", `rule a { strings: $a = /import "magic"/ condition: $a }`, nil},
		{"sigil identifiers", `rule a { strings: $import = "x" condition: #import > 0 and @import[1] < 9 and !import[1] > 0 }`, nil},
		{"hex string with comment", "rule a { strings: $h = { 4D 5A // import \"magic\"\n ?? [2-4] /* x */ 00 } condition: $h }", nil},
		{"division is backslash", `rule a { condition: filesize \ 2 > 1 }`, nil},

		{"magic", "import \"magic\"\nrule a { condition: true }", errModuleNotAllowed},
		{"cuckoo", `import "cuckoo"`, errModuleNotAllowed},
		{"hidden behind a block comment", `rule a { condition: true } /* x */ import "magic"`, errModuleNotAllowed},
		{"comment between import and name", `import /* x */ "magic"`, errModuleNotAllowed},
		{"no whitespace", `import"magic"`, errModuleNotAllowed},
		{"tab and newlines", "\timport\n\n\"magic\"", errModuleNotAllowed},
		{"escape-encoded", `import "m\x61gic"`, errModuleNotAllowed},
		{"escaped quote inside", `import "pe\"`, errRuleSyntax},
		{"trailing space", `import "magic "`, errModuleNotAllowed},
		{"after a rule with a quote in a regexp", `rule a { strings: $a = /"/ condition: $a } import "magic"`, errModuleNotAllowed},
		{"after a regexp with an escaped slash", `rule a { strings: $a = /a\/"/ condition: $a } import "magic"`, errModuleNotAllowed},
		{"after a string with an escaped quote", `rule a { strings: $a = "\"" condition: $a } import "magic"`, errModuleNotAllowed},
		{"import with no name", `import pe`, errModuleNotAllowed},
		{"include", `include "other.yar"`, errInclude},
		{"include hidden after comment", `/* */include "/etc/zaafvesper/x.yar"`, errInclude},
		{"unterminated block comment", `/* import "magic"`, errRuleSyntax},
		{"unterminated string", `rule a { strings: $a = "abc`, errRuleSyntax},
		{"newline in string", "rule a { strings: $a = \"ab\n\" import \"magic\" }", errRuleSyntax},
		{"unterminated regexp", `rule a { strings: $a = /abc`, errRuleSyntax},
	} {
		err := checkRuleSource([]byte(tc.src))
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestDegradedHookRateLimited(t *testing.T) {
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	h := &degradedHook{now: func() time.Time { return now }}
	var got []string
	h.report(CondQueueFull, "", "before registration") // dropped: no fn
	h.set(func(c, d string) { got = append(got, c+":"+d) })
	h.report(CondExecReplaced, "100", "decoy") // reported
	h.report(CondExecReplaced, "100", "again") // same key, same minute: suppressed
	h.report(CondExecReplaced, "200", "real")  // other key: reported, carries the count
	h.report(CondQueueFull, "", "a")           // other condition: reported
	h.report(CondQueueFull, "", "b")           // suppressed
	now = now.Add(degradedEvery)               // a minute later
	h.report(CondQueueFull, "", "c")
	want := []string{
		CondExecReplaced + ":decoy",
		CondExecReplaced + ":real (1 more suppressed since last report)",
		CondQueueFull + ":a",
		CondQueueFull + ":c (1 more suppressed since last report)",
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	// The key table is a bounded LRU.
	for i := range 3 * maxDegradedKeys {
		h.report(CondSkippedNonLocal, strconv.Itoa(i), "x")
	}
	if h.lru.Len() > maxDegradedKeys || len(h.keys) > maxDegradedKeys {
		t.Fatalf("limiter holds %d/%d keys", h.lru.Len(), len(h.keys))
	}
}

func TestOnNonLocalMount(t *testing.T) {
	m := []string{"/Volumes/share", "/net/home"}
	for p, want := range map[string]bool{
		"/Volumes/share": true, "/Volumes/share/a/b": true, "/net/home/x": true,
		"/Volumes/shared/x": false, "/Volumes/sha": false, "/Users/alice/x": false,
	} {
		if onNonLocalMount(p, m) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
	if !onNonLocalMount("/anything", []string{"/"}) || onNonLocalMount("/x", nil) {
		t.Error("root / empty list")
	}
}
