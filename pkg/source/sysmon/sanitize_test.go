package sysmon

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"plain":                   "plain",
		"bash \x01x":              "bash �x",
		"a\x1b[31m":               "a�[31m",
		"bad \xff utf8":           "bad � utf8",
		"ref &#x1; and &#27;":     "ref � and �",
		"keep &#x41; &#10; &amp;": "keep &#x41; &#10; &amp;",
		"tab\tcr\rlf\n":           "tab\tcr\rlf\n",
		"nonchar ￾":               "nonchar �",
		"broken &#xzz; ref":       "broken &#xzz; ref",
	}
	for in, want := range cases {
		if got := string(Sanitize([]byte(in))); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestControlCharactersDoNotDropEvents: an event whose command line holds
// control characters or invalid UTF-8 still decodes (security review #3).
func TestControlCharactersDoNotDropEvents(t *testing.T) {
	base := string(mustRead(t, "testdata/l01_process_create.xml"))
	for _, bad := range []string{"\x01", "\x1b[31m", "\xff\xfe", "&#x1;", "&#27;"} {
		in := strings.Replace(base, "curl -fsSL", "curl"+bad+" -fsSL", 1)
		e, err := Decode([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", bad, err)
		}
		if !strings.Contains(e.Proc.Cmdline, "�") || !utf8.ValidString(e.Proc.Cmdline) {
			t.Fatalf("%q: cmdline %q", bad, e.Proc.Cmdline)
		}
	}
}

func TestRepeatedHeaderRejected(t *testing.T) {
	base := string(mustRead(t, "testdata/w05_process_terminate.xml"))
	for name, in := range map[string]string{
		"event id":  strings.Replace(base, "<EventID>5</EventID>", "<EventID>1</EventID><EventID>5</EventID>", 1),
		"provider":  strings.Replace(base, "<EventID>", `<Provider Name="Microsoft-Windows-Sysmon"/><EventID>`, 1),
		"eventdata": strings.Replace(base, "</EventData>", "</EventData><EventData></EventData>", 1),
		"system":    strings.Replace(base, "<EventData>", "<System></System><EventData>", 1),
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: repeated element accepted", name)
		}
	}
}

func TestProvenanceFields(t *testing.T) {
	r, err := Parse(mustRead(t, "testdata/w01_process_create.xml"))
	if err != nil || r.ExecPID != 3160 || r.UserID != "S-1-5-18" {
		t.Fatalf("windows provenance %d %q %v", r.ExecPID, r.UserID, err)
	}
	r, err = Parse(mustRead(t, "testdata/l01_process_create.xml"))
	if err != nil || r.UserID != "0" {
		t.Fatalf("linux provenance %q %v", r.UserID, err)
	}
}

// TestLongestCommandLinesFit: two maximum-length command lines of '&' (each
// escaped to "&amp;") in one event 1 still decode (security review #4).
func TestLongestCommandLinesFit(t *testing.T) {
	base := string(mustRead(t, "testdata/w01_process_create.xml"))
	long := strings.Repeat("&amp;", 32767)
	in := strings.Replace(base, `powershell.exe -NoProfile -EncodedCommand &quot;SQBFAFgA&quot;`, long, 1)
	in = strings.Replace(in, `&quot;C:\Windows\system32\cmd.exe&quot; /c run.bat`, long, 1)
	if len(in) < 300<<10 {
		t.Fatalf("test event only %d bytes", len(in))
	}
	e, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Proc.Cmdline) != 32767 || e.Args["parent_command_line"] != strings.Repeat("&", 32767) {
		t.Fatalf("cmdline %d bytes", len(e.Proc.Cmdline))
	}
}
