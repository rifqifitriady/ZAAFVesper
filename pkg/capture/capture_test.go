package capture

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func readAll(t *testing.T, r *Reader) []*event.Event {
	t.Helper()
	var out []*event.Event
	for {
		e, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.rcap")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	evs := []*event.Event{
		{Seq: 1, Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Name: event.CreateProcess,
			Proc: &event.Proc{PID: 1, Exe: "/bin/sh", Args: []string{"sh", "-c", "<x> & y"}, Env: map[string]string{"A": "b"},
				Parent: &event.Proc{PID: 0, Exe: "/sbin/launchd"}}},
		{Seq: 2, Name: event.YaraMatch, Yara: &event.Yara{Rule: "r", Tags: []string{"stealer"}, Meta: map[string]string{"k": "v"}}},
	}
	var wg sync.WaitGroup
	for _, e := range evs {
		wg.Add(1)
		go func(e *event.Event) { defer wg.Done(); _ = w.Write(e) }(e)
	}
	wg.Wait()
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
	if err := w.Write(evs[0]); err == nil {
		t.Fatal("write after close accepted")
	}
	if w.Count() != 2 {
		t.Fatalf("Count = %d", w.Count())
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if _, err := Create(path); err == nil {
		t.Fatal("Create overwrote an existing capture")
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Format() != FormatEvents {
		t.Fatalf("format %s", r.Format())
	}
	got := readAll(t, r)
	if len(got) != 2 {
		t.Fatalf("read %d events", len(got))
	}
	for _, e := range got {
		if e.Name == event.CreateProcess && (e.Proc.Args[2] != "<x> & y" || e.Proc.Parent.Exe != "/sbin/launchd" || e.Proc.Env["A"] != "<redacted>") {
			t.Fatalf("lost data: %+v", e.Proc)
		}
		if e.Name == event.YaraMatch && e.Yara.Tags[0] != "stealer" {
			t.Fatalf("lost yara: %+v", e.Yara)
		}
	}
}

func TestPlainJSONLWithBadLines(t *testing.T) {
	r, err := Open("testdata/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got := readAll(t, r)
	if len(got) != 5 {
		t.Fatalf("read %d events, want 5", len(got))
	}
	st := r.Stats()
	if st["decode_errors"] != 1 || st["events"] != 5 || r.LastError() == nil {
		t.Fatalf("stats = %v, last = %v", st, r.LastError())
	}
	if got[2].Proc.Exe != "/tmp/payload" || got[2].Proc.IsSigned {
		t.Fatalf("event 3 = %+v", got[2].Proc)
	}
}

func TestGzipPlainEvents(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(`{"name":"Fork","seq":1}` + "\n" + `{"seq":2}` + "\n"))
	_ = gz.Close()
	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, r)
	if len(got) != 1 || r.Stats()["decode_errors"] != 1 {
		t.Fatalf("got %d events, stats %v", len(got), r.Stats())
	}
}

func TestDetectEslogger(t *testing.T) {
	// A raw eslogger line is recognised by its event_type key and decoded by
	// eslogger.Decode; ignored or undecodable lines are counted, not fatal.
	in := `{"event_type": 9999, "event": {}, "process": {}, "time": "2026-11-07T10:00:00.000000000Z"}` + "\n" + `garbage` + "\n"
	r, err := NewReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if r.Format() != FormatEslogger {
		t.Fatalf("format %s", r.Format())
	}
	got := readAll(t, r)
	st := r.Stats()
	if st["lines"] != 2 || uint64(len(got))+st["ignored"]+st["decode_errors"] != 2 {
		t.Fatalf("stats = %v, events = %d", st, len(got))
	}
}

func TestReaderErrors(t *testing.T) {
	if _, err := NewReader(strings.NewReader("not json\n")); err == nil {
		t.Fatal("non-JSON input accepted")
	}
	r, err := NewReader(strings.NewReader("\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("empty input: %v", err)
	}
	long := `{"name":"Fork","x":"` + strings.Repeat("a", MaxLineSize) + `"}` + "\n"
	r, err = NewReader(strings.NewReader(`{"name":"Fork"}` + "\n" + long))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("oversized line: %v", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file opened")
	}
}

func TestCreateRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "c.rcap")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(link); err == nil {
		t.Fatal("followed a planted symlink")
	}
}

func TestWriterLimitAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.SetMaxBytes(600)
	e := &event.Event{Seq: 1, Name: event.CreateProcess,
		Proc: &event.Proc{PID: 1, Exe: "/bin/sh", Env: map[string]string{"API_TOKEN": "s3cret", "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}}}
	var n int
	var err error
	for n = 0; n < 100; n++ {
		if err = w.Write(e); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrLimit) || !w.Full() || n == 0 || w.Bytes() > 600 {
		t.Fatalf("limit: n=%d err=%v full=%v bytes=%d", n, err, w.Full(), w.Bytes())
	}
	if err := w.Write(e); !errors.Is(err, ErrLimit) {
		t.Fatal("write after limit accepted")
	}
	if e.Proc.Env["API_TOKEN"] != "s3cret" {
		t.Fatal("caller's event modified")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, r)
	if len(got) != n {
		t.Fatalf("capture holds %d events, wrote %d", len(got), n)
	}
	env := got[0].Proc.Env
	if env["API_TOKEN"] != "<redacted>" || env["DYLD_INSERT_LIBRARIES"] != "/tmp/x.dylib" {
		t.Fatalf("env = %v", env)
	}

	buf.Reset()
	w = NewWriter(&buf)
	w.SetKeepEnv(true)
	_ = w.Write(e)
	_ = w.Close()
	r, _ = NewReader(&buf)
	if got := readAll(t, r); got[0].Proc.Env["API_TOKEN"] != "s3cret" {
		t.Fatal("keepEnv redacted")
	}
}
