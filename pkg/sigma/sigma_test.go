package sigma

import (
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/filter/ql"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"go.yaml.in/yaml/v3"
)

const baseRule = `title: Test rule
id: 3603f18a-ec15-43a1-9af2-d196c8a7fec6
status: test
description: A test.
author: Jane Doe
references:
    - https://example.org/rule
tags:
    - attack.discovery
    - attack.t1518.001
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/csrutil'
        CommandLine|contains: 'disable'
    condition: selection
falsepositives:
    - Unknown
level: medium
`

func convert(t *testing.T, src string) (*Result, error) {
	t.Helper()
	r, err := Parse([]byte(src))
	if err != nil {
		return nil, err
	}
	return Convert(r, Options{Source: "test/x.yml"})
}

func mustConvert(t *testing.T, src string) *Result {
	t.Helper()
	res, err := convert(t, src)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	return res
}

func loadRule(t *testing.T, data []byte) *rules.Rule {
	t.Helper()
	r := &rules.Rule{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(r); err != nil {
		t.Fatalf("decode: %v\n%s", err, data)
	}
	if err := r.Compile(nil); err != nil {
		t.Fatalf("compile: %v\n%s", err, data)
	}
	return r
}

func fire(t *testing.T, r *rules.Rule, e *event.Event) bool {
	t.Helper()
	n, err := rules.RunScenario(r, []*event.Event{e})
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func procEvent(exe, cmdline string) *event.Event {
	return &event.Event{Name: event.CreateProcess, Platform: event.PlatformMacOS,
		Proc: &event.Proc{PID: 10, Exe: exe, Cmdline: cmdline}}
}

func TestConvertBasic(t *testing.T) {
	res := mustConvert(t, baseRule)
	if res.ID != "3603f18a-ec15-43a1-9af2-d196c8a7fec6" || res.Platform != "macos" {
		t.Fatalf("id/platform: %+v", res)
	}
	r := loadRule(t, res.YAML)
	if r.Severity != "medium" || len(r.Platforms) != 1 || r.Platforms[0] != "macos" {
		t.Errorf("severity/platforms: %s %v", r.Severity, r.Platforms)
	}
	for k, v := range map[string]string{
		"sigma.id": "3603f18a-ec15-43a1-9af2-d196c8a7fec6", "sigma.author": "Jane Doe",
		"technique.id": "T1518.001", "tactic.id": "TA0007", "sigma.source": "test/x.yml",
	} {
		if r.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, r.Labels[k], v)
		}
	}
	if len(r.References) != 1 || !strings.Contains(r.Output, "Jane Doe") {
		t.Errorf("references %v / output %q must keep DRL attribution", r.References, r.Output)
	}
	if got := r.EventNames(); len(got) != 1 || got[0] != event.CreateProcess {
		t.Errorf("event names %v", got)
	}
	if !fire(t, r, procEvent("/usr/bin/csrutil", "csrutil DISABLE")) {
		t.Error("should fire (case-insensitive)")
	}
	if fire(t, r, procEvent("/usr/bin/csrutil", "csrutil status")) {
		t.Error("should not fire on status")
	}
	file := &event.Event{Name: event.CreateFile, Proc: &event.Proc{Exe: "/usr/bin/csrutil", Cmdline: "disable"}, File: &event.File{Path: "/tmp/x"}}
	if fire(t, r, file) {
		t.Error("process_creation rule must not fire on a file event")
	}
}

func TestConvertSkips(t *testing.T) {
	cases := []struct {
		name, from, to, kind, reason string
	}{
		{"product", "product: macos", "product: aws", KindUnsupported, "product"},
		{"no product", "    product: macos\n", "", KindUnsupported, "product is missing"},
		{"category", "category: process_creation", "category: ps_script", KindUnsupported, "category"},
		{"service", "    product: macos\n", "    product: macos\n    service: unified\n", KindUnsupported, "service"},
		{"field", "CommandLine|contains", "Hashes2|contains", KindUnsupported, "Hashes2"},
		{"aggregation", "condition: selection", "condition: selection | count() > 5", KindUnsupported, "aggregation"},
		{"unknown modifier", "CommandLine|contains", "CommandLine|bogus", KindInvalid, "unknown modifier"},
		{"base64", "CommandLine|contains", "CommandLine|base64", KindUnsupported, "base64"},
		{"undefined", "condition: selection", "condition: selection and other", KindInvalid, "not defined"},
		{"deprecated", "status: test", "status: deprecated", KindUnsupported, "deprecated"},
		{"lookahead", "CommandLine|contains: 'disable'", "CommandLine|re: '(?=x)y'", KindUnsupported, "RE2"},
		{"ipv6", "CommandLine|contains: 'disable'", "CommandLine|cidr: 'fd00::/8'", KindUnsupported, "IPv6"},
		{"2 of", "condition: selection", "condition: 2 of selection", KindUnsupported, "of is not supported"},
		{"timeframe", "    condition: selection", "    timeframe: 5m\n    condition: selection", KindUnsupported, "timeframe"},
		{"bad cidr", "CommandLine|contains: 'disable'", "CommandLine|cidr: 'nope'", KindInvalid, "not an IP"},
		{"null list", "CommandLine|contains: 'disable'", "CommandLine: ['', null]", KindInvalid, "null"},
		{"int on string op", "Image|endswith: '/csrutil'", "ProcessId|contains: '1'", KindUnsupported, "number"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := strings.Replace(baseRule, c.from, c.to, 1)
			if src == baseRule {
				t.Fatalf("replacement %q not applied", c.from)
			}
			_, err := convert(t, src)
			se := AsSkip(err)
			if se == nil {
				t.Fatal("converted, want skip")
			}
			if se.Kind != c.kind || !strings.Contains(se.Reason, c.reason) {
				t.Errorf("got %s: %s; want %s mentioning %q", se.Kind, se.Reason, c.kind, c.reason)
			}
		})
	}
}

func TestParseStrict(t *testing.T) {
	cases := map[string]string{
		"alias":        strings.Replace(baseRule, "title: Test rule", "title: &t Test rule\ndescription2: *t", 1),
		"duplicate":    strings.Replace(baseRule, "level: medium", "level: medium\nlevel: high", 1),
		"multi doc":    baseRule + "---\n" + baseRule,
		"not a map":    "- a\n- b\n",
		"no title":     strings.Replace(baseRule, "title: Test rule\n", "", 1),
		"bad level":    strings.Replace(baseRule, "level: medium", "level: severe", 1),
		"bad status":   strings.Replace(baseRule, "status: test", "status: done", 1),
		"tags type":    strings.Replace(baseRule, "tags:\n    - attack.discovery\n    - attack.t1518.001", "tags: attack.discovery", 1),
		"no condition": strings.Replace(baseRule, "    condition: selection\n", "", 1),
		"empty":        "",
		"correlation":  strings.Replace(baseRule, "level: medium", "level: medium\ncorrelation:\n    type: event_count", 1),
		"merge key":    strings.Replace(baseRule, "    selection:\n", "    selection:\n        <<: {a: b}\n", 1),
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: parsed, want error", name)
		}
	}
	deep := "title: x\nlogsource: {product: macos, category: process_creation}\ndetection:\n  condition: s\n  s: " + strings.Repeat("[", 40) + "a" + strings.Repeat("]", 40) + "\n"
	if _, err := Parse([]byte(deep)); err == nil || !strings.Contains(err.Error(), "deeper") {
		t.Errorf("deep nesting: %v", err)
	}
	big := strings.Repeat("a", MaxRuleBytes+1)
	if _, err := Parse([]byte(big)); err == nil {
		t.Error("oversize file parsed")
	}
	long := strings.Replace(baseRule, "'disable'", "'"+strings.Repeat("x", MaxValueLen+1)+"'", 1)
	if _, err := convert(t, long); err == nil {
		t.Error("oversize value converted")
	}
	// Custom top-level attributes are allowed by Sigma.
	if _, err := Parse([]byte(baseRule + "custom_field: 1\n")); err != nil {
		t.Errorf("custom attribute: %v", err)
	}
}

func TestDerivedIDAndLevel(t *testing.T) {
	src := strings.Replace(baseRule, "id: 3603f18a-ec15-43a1-9af2-d196c8a7fec6", "id: c001", 1)
	src = strings.Replace(src, "level: medium\n", "", 1)
	a := mustConvert(t, src)
	b := mustConvert(t, src)
	if a.ID != b.ID || a.ID == "c001" {
		t.Fatalf("derived id not stable: %s %s", a.ID, b.ID)
	}
	r := loadRule(t, a.YAML)
	if r.Severity != "low" || r.Labels["sigma.id"] != "c001" || len(a.Notes) < 2 {
		t.Errorf("severity %s, labels %v, notes %v", r.Severity, r.Labels, a.Notes)
	}
}

func TestAttackLabels(t *testing.T) {
	a := attackLabels([]string{"attack.defense-evasion", "attack.t1562.001", "attack.s0402", "cve.2024-1"})
	if a.labels["technique.id"] != "T1685" || a.labels["tactic.id"] != "TA0112" || a.labels["tactic.name"] != "Defense Impairment" {
		t.Errorf("revoked remap: %v", a.labels)
	}
	b := attackLabels([]string{"attack.defense_evasion", "attack.t1562.001", "attack.t1070.004"})
	if b.labels["technique.id"] != "T1685, T1070.004" || b.labels["tactic.id"] != "TA0005, TA0112" {
		t.Errorf("mixed: %v", b.labels)
	}
	for from, to := range map[string]string{"attack.t1070.001": "T1685.005", "attack.t1562.002": "T1685.001", "attack.t1562.012": "T1685.004", "attack.t1562.007": "T1686.001", "attack.t1562.009": "T1688"} {
		r := attackLabels([]string{"attack.defense-evasion", from})
		if r.labels["technique.id"] != to || r.labels["tactic.id"] != "TA0112" {
			t.Errorf("%s: %v", from, r.labels)
		}
	}
	c := attackLabels([]string{"attack.stealth", "attack.t1564.002"})
	if c.labels["tactic.name"] != "Stealth" {
		t.Errorf("stealth: %v", c.labels)
	}
	if d := attackLabels(nil); len(d.labels) != 0 {
		t.Errorf("no tags: %v", d.labels)
	}
	// The rule loader accepts the labels.
	src := strings.Replace(baseRule, "    - attack.t1518.001", "    - attack.t1562.004\n    - attack.t1059.004", 1)
	loadRule(t, mustConvert(t, src).YAML)
}

func TestWildcardsAndEscapes(t *testing.T) {
	for _, c := range []struct {
		val, mod string
		cased    bool
		op, want string
	}{
		{`abc`, "", false, "iin", "abc"},
		{`abc`, "", true, "in", "abc"},
		{`a*c`, "", false, "imatches", "a*c"},
		{`a*c`, "contains", false, "imatches", "*a*c*"},
		{`*abc`, "endswith", false, "imatches", "*abc"},
		{`a\*c`, "", false, "iin", "a*c"},
		{`a\*c*`, "", false, "regex", `(?si)^a\*c.*$`},
		{`a?c\?`, "startswith", true, "regex", `(?s)^a.c\?.*$`},
		{`C:\Tools\\*.exe`, "", false, "imatches", `C:\Tools\*.exe`},
	} {
		got := stringMatch(c.val, c.mod, c.cased)
		if got.op != c.op || got.val != c.want {
			t.Errorf("%q|%s cased=%v: got %s %q, want %s %q", c.val, c.mod, c.cased, got.op, got.val, c.op, c.want)
		}
	}
}

func TestWindash(t *testing.T) {
	v, err := windashVariants(" -s /x")
	if err != nil || len(v) != 25 {
		t.Fatalf("variants %d %v", len(v), err)
	}
	if v, _ := windashVariants("a-b"); len(v) != 1 {
		t.Errorf("dash inside a word must not expand: %v", v)
	}
	if _, err := windashVariants(" -a -b -c -d -e"); err == nil {
		t.Error("too many dashes accepted")
	}
}

func TestCIDRRegex(t *testing.T) {
	for _, c := range []struct {
		pfx       string
		in, notIn []string
	}{
		{"10.0.0.0/8", []string{"10.0.0.0", "10.255.255.255", "::ffff:10.1.2.3", "::FFFF:10.1.2.3"}, []string{"11.0.0.1", "10.1.2", "110.1.2.3", "10.1.2.3%1", "x10.1.2.3"}},
		{"172.16.0.0/12", []string{"172.16.0.1", "172.31.255.255"}, []string{"172.15.0.1", "172.32.0.1"}},
		{"192.168.1.128/25", []string{"192.168.1.128", "192.168.1.255"}, []string{"192.168.1.127", "192.168.1.25", "192.168.1.1"}},
		{"0.0.0.0/0", []string{"1.2.3.4", "255.255.255.255"}, []string{"256.1.1.1", "fe80::1", "a.b.c.d"}},
		{"10.1.2.3/32", []string{"10.1.2.3"}, []string{"10.1.2.30", "10.1.2.4"}},
	} {
		re := regexp.MustCompile(cidrRegex(netip.MustParsePrefix(c.pfx)))
		for _, s := range c.in {
			if !re.MatchString(s) {
				t.Errorf("%s should contain %s", c.pfx, s)
			}
		}
		for _, s := range c.notIn {
			if re.MatchString(s) {
				t.Errorf("%s should not contain %s", c.pfx, s)
			}
		}
	}
	// Exhaustive check of one non-octet boundary against netip.
	pfx := netip.MustParsePrefix("100.64.0.0/10")
	re := regexp.MustCompile(cidrRegex(pfx))
	for second := 0; second < 256; second++ {
		a := netip.AddrFrom4([4]byte{100, byte(second), 7, 9})
		if re.MatchString(a.String()) != pfx.Contains(a) {
			t.Errorf("%s: regex %v, netip %v", a, re.MatchString(a.String()), pfx.Contains(a))
		}
	}
}

func TestNetworkAndValueMapping(t *testing.T) {
	src := `title: Outbound to private range
id: 0b2f0f39-4b52-4e2e-9c0f-6a1f0e1d2a3b
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Initiated: 'true'
        DestinationIp|cidr: 10.0.0.0/8
        DestinationPort:
            - 4444
            - 8443
    condition: selection
level: high
`
	res := mustConvert(t, src)
	r := loadRule(t, res.YAML)
	if r.Platforms[0] != "windows" {
		t.Fatal(r.Platforms)
	}
	ev := func(dir, ip string, port uint16) *event.Event {
		return &event.Event{Name: event.NetworkConnect, Proc: &event.Proc{Exe: `C:\x.exe`},
			Net: &event.Net{Direction: dir, DstIP: ip, DstPort: port}}
	}
	if !fire(t, r, ev("outbound", "10.2.3.4", 4444)) {
		t.Errorf("should fire:\n%s", res.Condition)
	}
	for _, e := range []*event.Event{ev("inbound", "10.2.3.4", 4444), ev("outbound", "8.8.8.8", 4444), ev("outbound", "10.2.3.4", 80)} {
		if fire(t, r, e) {
			t.Errorf("should not fire on %+v", e.Net)
		}
	}
}

func TestKeywordsAndNullOnCategory(t *testing.T) {
	src := `title: Keywords
id: 6f3a1d5e-1c1b-4c7e-9a8d-2b9f2d1e0c11
logsource:
    product: linux
    category: process_creation
detection:
    keywords:
        - 'mimikatz'
    filter:
        ParentImage: null
    condition: keywords and not filter
level: low
`
	res := mustConvert(t, src)
	r := loadRule(t, res.YAML)
	e := &event.Event{Name: event.CreateProcess, Proc: &event.Proc{Exe: "/tmp/x", Cmdline: "run MIMIKATZ now",
		Parent: &event.Proc{Exe: "/bin/sh"}}}
	if !fire(t, r, e) {
		t.Errorf("keyword should fire:\n%s", res.Condition)
	}
	e.Proc.Parent = nil
	if fire(t, r, e) {
		t.Error("ParentImage null: filter holds, rule must not fire")
	}
}

func TestExistsAndBoolField(t *testing.T) {
	src := `title: Unsigned image
id: 9f1c2b3a-4d5e-4f60-8a7b-1c2d3e4f5a6b
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Signed: 'false'
        ImageLoaded|exists: true
    condition: selection
level: low
`
	res := mustConvert(t, src)
	r := loadRule(t, res.YAML)
	f := false
	if !fire(t, r, &event.Event{Name: event.ImageLoad, Proc: &event.Proc{}, Module: &event.Module{Path: `C:\a.dll`, Signed: &f}}) {
		t.Errorf("should fire:\n%s", res.Condition)
	}
	if fire(t, r, &event.Event{Name: event.ImageLoad, Proc: &event.Proc{}, Module: &event.Module{Path: `C:\a.dll`}}) {
		t.Error("Signed not reported: must not fire")
	}
}

func TestGeneratedQuotingRoundTrips(t *testing.T) {
	src := strings.Replace(baseRule, "'disable'", `"it's a \\ test"`, 1)
	res := mustConvert(t, src)
	r := loadRule(t, res.YAML)
	if !fire(t, r, procEvent("/usr/bin/csrutil", `x IT'S A \ TEST y`)) {
		t.Errorf("quote/backslash round trip:\n%s", res.Condition)
	}
}

func TestConditionGrammarErrors(t *testing.T) {
	names := []string{"sel_a", "sel_b", "_h"}
	for _, bad := range []string{"", "sel_a and", "(sel_a", "sel_a)", "sel_*", "1 of nothing*", "sel_a # x", "and sel_a"} {
		if _, err := parseCondition(bad, names); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	deep := strings.Repeat("(", 100) + "sel_a" + strings.Repeat(")", 100)
	if _, err := parseCondition(deep, names); err == nil {
		t.Error("deep parentheses accepted")
	}
	deepNot := strings.Repeat("not ", 100) + "sel_a"
	if _, err := parseCondition(deepNot, names); err == nil {
		t.Error("deep not accepted")
	}
	n, err := parseCondition("all of them", names)
	if err != nil {
		t.Fatal(err)
	}
	if of, ok := n.(condOf); !ok || len(of.names) != 2 {
		t.Errorf("them must exclude _h: %#v", n)
	}
}

func TestOutputConditionCompilesWithMacros(t *testing.T) {
	// Converted conditions must not depend on, or collide with, macros.
	m, err := ql.LoadMacrosWith(func(p string, max int64) ([]byte, error) { return os.ReadFile(p) }, "../../rules/macros/macros.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ql.Compile(mustConvert(t, baseRule).Condition, m); err != nil {
		t.Error(err)
	}
}

// Small inputs that would expand into huge conditions must be refused
// quickly, before the expansion is built (security review finding 1).
func TestAmplificationRefusedEarly(t *testing.T) {
	head := "title: amp\nlogsource: {product: windows, category: process_creation}\ndetection:\n"
	var b strings.Builder
	// 1. windash: many values, each with several flag dashes.
	b.WriteString(head + "  s:\n    CommandLine|windash|contains|all:\n")
	for i := 0; i < 19000; i++ {
		b.WriteString("      - '-a -b -c'\n")
	}
	b.WriteString("  condition: s\n")
	windash := b.String()
	// 2. one large search referenced many times.
	b.Reset()
	b.WriteString(head + "  s:\n    CommandLine|contains:\n")
	for i := 0; i < 8000; i++ {
		b.WriteString("      - 'abcdefghijklmnopqrstuvwxyz'\n")
	}
	b.WriteString("  condition: s" + strings.Repeat(" or s", 400) + "\n")
	refs := b.String()
	// 3. a long list of conditions.
	b.Reset()
	b.WriteString(head + "  s:\n    CommandLine|contains:\n")
	for i := 0; i < 2000; i++ {
		b.WriteString("      - 'abcdefghijklmnopqrstuvwxyz'\n")
	}
	b.WriteString("  condition:\n")
	for i := 0; i < 15000; i++ {
		b.WriteString("    - s\n")
	}
	condList := b.String()
	// 4. keywords over every field of the category.
	b.Reset()
	b.WriteString(head + "  k:\n")
	for i := 0; i < 15000; i++ {
		b.WriteString("    - 'abcdefghijklmnopqrstuvwxyz'\n")
	}
	b.WriteString("  condition: k\n")
	kw := b.String()
	for name, src := range map[string]string{"windash": windash, "references": refs, "condition list": condList, "keywords": kw} {
		if len(src) > MaxRuleBytes {
			t.Fatalf("%s: test input %d bytes is over the file limit", name, len(src))
		}
		start := time.Now()
		_, err := convert(t, src)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
		if se := AsSkip(err); se == nil || se.Kind != KindUnsupported || !strings.Contains(se.Reason, "longer than") {
			t.Errorf("%s: want unsupported (too long), got %v", name, err)
		}
	}
}

// A rule the loader would refuse for its size is skipped, not written
// (security review finding 2).
func TestOversizeOutputSkipped(t *testing.T) {
	var refs strings.Builder
	for i := 0; i < 8000; i++ {
		refs.WriteString("    - https://example.org/" + strings.Repeat("r", 90) + "\n")
	}
	src := strings.Replace(baseRule, "references:\n    - https://example.org/rule\n", "references:\n"+refs.String(), 1)
	src = strings.Replace(src, "author: Jane Doe", "author: "+strings.Repeat("a", 60000), 1)
	if len(src) > MaxRuleBytes {
		t.Fatalf("input %d bytes", len(src))
	}
	_, err := convert(t, src)
	if se := AsSkip(err); se == nil || !strings.Contains(se.Reason, "limit") {
		t.Errorf("want skip over the loader limit, got %v", err)
	}
}

// Branches the judge found unchecked on events: precedence of and over or,
// multi-value integer lists, and the regex fallback for a literal star next
// to a wildcard.
func TestEvaluatedEdgeBranches(t *testing.T) {
	src := `title: edges
id: 1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b
logsource:
    product: macos
    category: process_creation
detection:
    a:
        Image|endswith: '/a'
    b:
        CommandLine|contains: 'bee'
    c:
        ProcessId:
            - 7
            - 9
    d:
        CommandLine|contains: 'x\*y?z'
    condition: a and b or c or d
level: low
`
	res := mustConvert(t, src)
	r := loadRule(t, res.YAML)
	ev := func(exe, cmd string, pid int32) *event.Event {
		return &event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: pid, Exe: exe, Cmdline: cmd}}
	}
	for _, c := range []struct {
		e    *event.Event
		want bool
		why  string
	}{
		{ev("/bin/a", "bee", 1), true, "a and b"},
		{ev("/bin/a", "x", 1), false, "a alone (and binds tighter than or)"},
		{ev("/bin/q", "bee", 1), false, "b alone"},
		{ev("/bin/q", "", 7), true, "first int value"},
		{ev("/bin/q", "", 9), true, "second int value"},
		{ev("/bin/q", "", 8), false, "other int"},
		{ev("/bin/q", "1 X*Y1Z 2", 1), true, "literal star, ? wildcard, case-insensitive"},
		{ev("/bin/q", "xAy1z", 1), false, "star is literal, not a wildcard"},
		{ev("/bin/q", "x*yz", 1), false, "? needs one character"},
	} {
		if got := fire(t, r, c.e); got != c.want {
			t.Errorf("%s: fired=%v, want %v\n%s", c.why, got, c.want, res.Condition)
		}
	}
}
