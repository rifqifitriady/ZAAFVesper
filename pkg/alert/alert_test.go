package alert

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain /usr/bin/curl", "plain /usr/bin/curl"},
		{"a\x1b[31mred\x1b[0m", "a[31mred[0m"},
		{"tab\tnl\ncr\r", "tab nl cr "},
		{"nul\x00bel\x07del\x7f", "nulbeldel"},
		{"c1 \u0085\u009b csi", "c1  csi"},
		{"raw c1 byte \x9b", "raw c1 byte \ufffd"},
		{"bidi \u202eexe.txt\u202c \u2066x\u2069 \u200f", "bidi exe.txt x "},
		{"ünïcødé 日本", "ünïcødé 日本"},
		{"\x1b]0;title\x07", "]0;title"},
	}
	for _, c := range cases {
		if got := Sanitize(c.in); got != c.want {
			t.Errorf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add("a\x1b[2Jb\u202e\x9b")
	f.Fuzz(func(t *testing.T, s string) {
		out := Sanitize(s)
		for _, r := range out {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
				t.Fatalf("Sanitize(%q) kept control %U", s, r)
			}
		}
	})
}

func testAlert() *rules.Alert {
	return &rules.Alert{
		RuleID: "b921eb6f-1cba-4647-b1f1-39d336af2dd8", RuleName: "Launch\x1b[2J agent",
		Severity: "high", Output: "/tmp/\x1b]0;pwn\x07x created /Library/LaunchAgents/a.plist",
		Labels: map[string]string{"technique.id": "T1543.001", "technique.name": "Launch Agent"},
		Time:   time.Date(2026, 11, 7, 1, 2, 3, 0, time.UTC),
		Events: []*event.Event{{Seq: 5, Name: event.CreateFile,
			Proc: &event.Proc{PID: 10, PPID: 1, Exe: "/tmp/\x1b[31mevil", Cmdline: "evil\n--x", Parent: &event.Proc{Exe: "/bin/zsh"}},
			File: &event.File{Path: "/Library/LaunchAgents/a\u202e.plist"}}},
		Actions: []string{"kill"},
	}
}

func TestConsole(t *testing.T) {
	var buf bytes.Buffer
	if err := NewConsole(&buf, false).Send(testAlert()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsAny(out, "\x1b\x07\u202e") {
		t.Fatalf("console output contains control characters: %q", out)
	}
	for _, want := range []string{"2026-11-07T01:02:03Z HIGH", "technique.id=T1543.001", `technique.name="Launch Agent"`, "actions=kill", "pid=10", "parent=/bin/zsh", "file=/Library/LaunchAgents/a.plist"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "\n"); n != 3 {
		t.Errorf("expected 3 lines, got %d:\n%s", n, out)
	}
	buf.Reset()
	if err := NewConsole(&buf, true).Send(testAlert()); err != nil {
		t.Fatal(err)
	}
	// Only ZAAFVesper's own colour codes may appear.
	stripped := strings.ReplaceAll(strings.ReplaceAll(buf.String(), "\x1b[1;31m", ""), "\x1b[0m", "")
	if strings.Contains(stripped, "\x1b") {
		t.Fatalf("coloured output leaked an escape: %q", buf.String())
	}
}

func TestJSONL(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONL(&buf)
	a := testAlert()
	if err := s.Send(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	if strings.Contains(lines[0], "\x1b") {
		t.Fatal("raw ESC in JSONL")
	}
	var back rules.Alert
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil {
		t.Fatal(err)
	}
	if back.Output != a.Output || back.Events[0].Proc.Exe != a.Events[0].Proc.Exe || back.RuleID != a.RuleID {
		t.Fatalf("round trip lost data: %+v", back)
	}
}
