package sysmonlinux

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
)

func line(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseLine(t *testing.T) {
	xml, err := os.ReadFile("../sysmon/testdata/l01_process_create.xml")
	if err != nil {
		t.Fatal(err)
	}
	msg := strings.TrimSpace(string(xml))
	cur := "s=0123abcd;i=1f2;b=89ab;m=12;t=5f;x=77"
	good := map[string]any{"__CURSOR": cur, "_UID": "0", "_SYSTEMD_UNIT": SysmonUnit, "SYSLOG_IDENTIFIER": "sysmon", "MESSAGE": msg}
	got, c, err := ParseLine(line(t, good))
	if err != nil || c != cur || string(got) != msg {
		t.Fatalf("good: %v %q", err, c)
	}
	e, err := sysmon.Decode(got)
	if err != nil || e.Name != event.CreateProcess || e.Platform != event.PlatformLinux {
		t.Fatalf("decode: %v %+v", err, e)
	}
	// MESSAGE as a byte array (journald does this for non-UTF-8 data).
	arr := make([]int, len(msg))
	for i := 0; i < len(msg); i++ {
		arr[i] = int(msg[i])
	}
	good["MESSAGE"] = arr
	if got, _, err := ParseLine(line(t, good)); err != nil || string(got) != msg {
		t.Fatalf("array: %v", err)
	}
	// A forged record from logger(1): another uid or unit.
	for _, f := range []map[string]any{
		{"__CURSOR": cur, "_UID": "1000", "_SYSTEMD_UNIT": SysmonUnit, "MESSAGE": msg},
		{"__CURSOR": cur, "_UID": "0", "_SYSTEMD_UNIT": "user@1000.service", "MESSAGE": msg},
		{"__CURSOR": cur, "MESSAGE": msg, "SYSLOG_IDENTIFIER": "sysmon"},
	} {
		if _, c, err := ParseLine(line(t, f)); !errors.Is(err, ErrUntrusted) || c != cur {
			t.Errorf("forged record accepted: %v %v", f, err)
		}
	}
	for _, m := range []any{nil, []int{300}, 42} {
		good["MESSAGE"] = m
		if _, _, err := ParseLine(line(t, good)); !errors.Is(err, ErrNoMessage) {
			t.Errorf("MESSAGE %v: %v", m, err)
		}
	}
	if _, _, err := ParseLine([]byte("{")); err == nil {
		t.Error("bad JSON accepted")
	}
}

func TestArgsAndCursor(t *testing.T) {
	a := Args("")
	if a[len(a)-3] != "--lines=0" || a[len(a)-2] != "_SYSTEMD_UNIT=sysmon.service" || a[len(a)-1] != "_UID=0" {
		t.Fatalf("args %q", a)
	}
	if got := Args("s=1;i=2"); got[5] != "--after-cursor=s=1;i=2" {
		t.Fatalf("cursor args %q", got)
	}
	for _, bad := range []string{"--lines=1", "s=1 --x", "s=1\n", strings.Repeat("a", 600), "s=1/../"} {
		if ValidCursor(bad) {
			t.Errorf("ValidCursor(%q)", bad)
		}
		if strings.Contains(strings.Join(Args(bad), " "), "after-cursor") {
			t.Errorf("Args used bad cursor %q", bad)
		}
	}
	for _, kv := range Env {
		if strings.HasPrefix(kv, "LD_") || strings.HasPrefix(kv, "SYSTEMD_PAGER=") && kv != "SYSTEMD_PAGER=" {
			t.Errorf("env %q", kv)
		}
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add([]byte(`{"__CURSOR":"s=1","_UID":"0","_SYSTEMD_UNIT":"sysmon.service","MESSAGE":[60,69]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, _, err := ParseLine(b)
		if err == nil && len(msg) > len(b) {
			t.Fatal("message longer than the line")
		}
	})
}
