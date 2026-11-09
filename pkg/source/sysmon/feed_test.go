package sysmon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestFeeder(t *testing.T) {
	create := mustRead(t, "testdata/w01_process_create.xml")
	file := mustRead(t, "testdata/w11_file_create.xml")
	withRec := func(b []byte, rec string) []byte {
		s := string(b)
		i := strings.Index(s, "<EventRecordID>")
		j := strings.Index(s, "</EventRecordID>")
		return []byte(s[:i] + "<EventRecordID>" + rec + s[j:])
	}
	f := NewFeeder([]string{event.CreateProcess}, nil)
	var reports []string
	f.OnDegraded(func(c, d string) { reports = append(reports, c+": "+d) })
	out := make(chan *event.Event, 8)
	ctx := context.Background()
	for _, raw := range [][]byte{withRec(create, "10"), withRec(file, "11"), withRec(create, "15"), []byte("<junk"), withRec(create, "16")} {
		if err := f.Handle(ctx, raw, out); err != nil {
			t.Fatal(err)
		}
	}
	if len(out) != 3 {
		t.Fatalf("sent %d, want 3 (the file event is filtered)", len(out))
	}
	st := f.Stats()
	if st["seq_gaps"] != 1 || st["events_missed"] != 3 || st["decode_errors"] != 1 || st["filtered"] != 1 {
		t.Fatalf("stats %v", st)
	}
	if len(reports) != 1 || !strings.Contains(reports[0], CondEventsDropped) || !strings.Contains(reports[0], "missed 3") {
		t.Fatalf("reports %q", reports)
	}
	// A second gap within a minute is counted, not reported.
	_ = f.Handle(ctx, withRec(create, "20"), out)
	if len(reports) != 1 || f.Stats()["events_missed"] != 6 {
		t.Fatalf("rate limit: %q %v", reports, f.Stats())
	}
	f.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_ = f.Handle(ctx, withRec(create, "22"), out)
	if len(reports) != 2 || !strings.Contains(reports[1], "1 earlier reports suppressed") {
		t.Fatalf("after window: %q", reports)
	}
	// A cancelled context stops a blocked send.
	full := make(chan *event.Event)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.Handle(cctx, withRec(create, "23"), full); err == nil {
		t.Fatal("blocked send did not return the context error")
	}
}
