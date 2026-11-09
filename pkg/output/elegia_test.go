//go:build unix

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestSigmaRecordNetwork(t *testing.T) {
	e := testAlert("").Events[0]
	b, err := EncodeSigma(e, SigmaOptions{DefaultProduct: "macos", Host: "mac-01"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"Image": "/bin/bash", "ProcessId": float64(42), "User": "rifqi", "DestinationIp": "203.0.113.9",
		"DestinationPort": float64(4444), "SourceIp": "10.0.0.5", "SourcePort": float64(50000), "Protocol": "tcp",
		"Initiated": "true", "EventID": float64(3), "UtcTime": "2026-11-09 10:00:00.000"}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %#v, want %#v (record %s)", k, m[k], v, b)
		}
	}
	ls := m["logsource"].(map[string]any)
	if ls["product"] != "macos" || ls["category"] != "network_connection" {
		t.Fatalf("logsource %v", ls)
	}
	if _, ok := m["CommandLine"]; ok {
		t.Fatal("network records carry no CommandLine (not a network_connection field)")
	}
	// Inbound maps to Initiated "false"; a process creation gets its own fields.
	e.Net.Direction = "inbound"
	if r := SigmaRecord(e, SigmaOptions{DefaultProduct: "macos"}); r["Initiated"] != "false" {
		t.Fatalf("inbound Initiated %v", r["Initiated"])
	}
	pc := &event.Event{Name: event.CreateProcess, Time: time.Unix(0, 0), Proc: &event.Proc{PID: 9, PPID: 8, Exe: "/usr/bin/curl",
		Cmdline: "curl x", Cwd: "/tmp", Parent: &event.Proc{PID: 8, Exe: "/bin/zsh", Cmdline: "-zsh"}}}
	r := SigmaRecord(pc, SigmaOptions{DefaultProduct: "macos"})
	for k, v := range map[string]any{"Image": "/usr/bin/curl", "CommandLine": "curl x", "CurrentDirectory": "/tmp",
		"ParentImage": "/bin/zsh", "ParentCommandLine": "-zsh", "ParentProcessId": int64(8), "EventID": 1} {
		if r[k] != v {
			t.Fatalf("%s = %#v want %#v", k, r[k], v)
		}
	}
	// No Sigma category: process identity only, no EventID.
	fk := SigmaRecord(&event.Event{Name: event.Fork, Proc: &event.Proc{PID: 3, Exe: "/bin/sh", Cmdline: "sh"}}, SigmaOptions{DefaultProduct: "macos"})
	if fk["Image"] != "/bin/sh" || fk["CommandLine"] != nil || fk["EventID"] != nil || fk["logsource"].(map[string]any)["category"] != nil {
		t.Fatalf("generic record %v", fk)
	}
}

func TestOCSFFinding(t *testing.T) {
	a := testAlert("bash connected out")
	b, err := EncodeOCSF(a, "0.2.0", SigmaOptions{DefaultProduct: "macos"}, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f["class_uid"] != float64(2004) || f["type_uid"] != float64(200401) || f["severity_id"] != float64(4) ||
		f["severity"] != "High" || f["time"] != float64(1794218400000) {
		t.Fatalf("finding %s", b)
	}
	for k, v := range map[string]any{"class_name": "Detection Finding", "category_uid": float64(2), "category_name": "Findings",
		"activity_id": float64(1), "activity_name": "Create", "status_id": float64(1), "status": "New", "message": "Test rule"} {
		if f[k] != v {
			t.Fatalf("%s = %#v, want %#v", k, f[k], v)
		}
	}
	md := f["metadata"].(map[string]any)
	if md["version"] != OCSFVersion || md["product"].(map[string]any)["name"] != "ZAAFVesper" {
		t.Fatalf("metadata %v", md)
	}
	if u := f["unmapped"].(map[string]any); u["source"] != "zaafvesper" || u["zaafvesper"].(map[string]any)["rule_id"] != "rule-1" {
		t.Fatalf("unmapped %v", u)
	}
	fi := f["finding_info"].(map[string]any)
	if fi["uid"] != "rule-1:5" || fi["title"] != "Test rule" {
		t.Fatalf("finding_info %v", fi)
	}
	types := fi["types"].([]any)
	if len(types) != 2 || types[0] != "attack.ta0002" || types[1] != "attack.t1059.004" {
		t.Fatalf("types %v", types)
	}
	ev := f["evidences"].([]any)[0].(map[string]any)["data"].(map[string]any)
	if ev["DestinationPort"] != float64(4444) {
		t.Fatalf("evidence %v", ev)
	}
	// Oversized: evidences shrink, then disappear, and the line fits.
	big := testAlert(strings.Repeat("o", 10000))
	for i := 0; i < 50; i++ {
		e := *big.Events[0]
		p := *e.Proc
		p.Cmdline = strings.Repeat("c", 3000)
		e.Proc = &p
		big.Events = append(big.Events, &e)
	}
	b, err = EncodeOCSF(big, "0.2.0", SigmaOptions{DefaultProduct: "macos"}, 6, 8192)
	if err != nil || len(b) > 8192 || !json.Valid(b) {
		t.Fatalf("oversized finding: %d bytes, %v", len(b), err)
	}
}

// slowWriter blocks until released.
type slowWriter struct {
	mu      sync.Mutex
	release chan struct{}
	buf     bytes.Buffer
}

func (w *slowWriter) Write(p []byte) (int, error) {
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func TestLineWriterBoundsAndCap(t *testing.T) {
	sw := &slowWriter{release: make(chan struct{})}
	var drops int
	lw := NewLineWriter(sw, LineWriterConfig{Name: "elegia", Queue: 4, OnDrop: func(string) { drops++ }})
	for i := 0; i < 100; i++ {
		lw.WriteLine([]byte(`{"a":1}`)) // never blocks
	}
	if lw.Stats()["dropped_slow_reader"] == 0 || drops == 0 {
		t.Fatalf("stats %v", lw.Stats())
	}
	close(sw.release)
	if err := lw.Close(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	lw.WriteLine([]byte("after close")) // no panic
	var out bytes.Buffer
	capped := 0
	lw2 := NewLineWriter(&out, LineWriterConfig{Name: "ocsf", MaxBytes: 20, OnCapped: func(string) { capped++ }})
	for i := 0; i < 5; i++ {
		lw2.WriteLine([]byte(`{"n":1}`))
	}
	_ = lw2.Close(time.Second)
	if out.Len() > 20 || capped != 1 || lw2.Stats()["dropped_after_cap"] == 0 {
		t.Fatalf("cap: %d bytes, capped %d, %v", out.Len(), capped, lw2.Stats())
	}
}
