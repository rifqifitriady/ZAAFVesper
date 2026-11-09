package sysmon

import (
	"context"
	"errors"
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
	out := make(chan *event.Event, 16)
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
	if len(reports) != 2 || !strings.Contains(reports[0], CondEventsDropped) || !strings.Contains(reports[0], "missed 3") ||
		!strings.Contains(reports[1], CondEventsUnreadable) {
		t.Fatalf("reports %q", reports)
	}
	// A second gap within a minute is counted, not reported.
	_ = f.Handle(ctx, withRec(create, "20"), out)
	if len(reports) != 2 || f.Stats()["events_missed"] != 6 {
		t.Fatalf("rate limit: %q %v", reports, f.Stats())
	}
	f.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_ = f.Handle(ctx, withRec(create, "22"), out)
	if len(reports) != 3 || !strings.Contains(reports[2], "1 earlier reports suppressed") {
		t.Fatalf("after window: %q", reports)
	}
	// A provenance check that fails drops the event and is reported.
	f.Trust = func(r *Record) error {
		if r.UserID != "S-1-5-18" {
			return errors.New("not LocalSystem")
		}
		return nil
	}
	before := len(out)
	forged := strings.Replace(string(withRec(create, "23")), `UserID="S-1-5-18"`, `UserID="S-1-5-21-1-2-3-1001"`, 1)
	_ = f.Handle(ctx, []byte(forged), out)
	_ = f.Handle(ctx, withRec(create, "24"), out)
	if len(out) != before+1 || f.Stats()["untrusted_events"] != 1 || !strings.Contains(reports[len(reports)-1], CondEventsUntrusted) {
		t.Fatalf("trust: sent %d, stats %v, reports %q", len(out)-before, f.Stats(), reports)
	}
	// A cancelled context stops a blocked send.
	f.Trust = nil
	full := make(chan *event.Event)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.Handle(cctx, withRec(create, "23"), full); err == nil {
		t.Fatal("blocked send did not return the context error")
	}
}

// TestFeederAppliesFix: Fix sees every decoded event, before the identity
// binding and before the event is sent (the Linux source corrects parents
// there).
func TestFeederAppliesFix(t *testing.T) {
	raw := mustRead(t, "testdata/l01_process_create.xml")
	var order []string
	b := NewBinder(func(int32) (Stamp, error) { order = append(order, "bind"); return Stamp{}, errors.New("none") }, time.Millisecond)
	f := NewFeeder(nil, b)
	f.Fix = func(e *event.Event) {
		order = append(order, "fix")
		e.Args["fixed"] = "yes"
	}
	out := make(chan *event.Event, 1)
	if err := f.Handle(context.Background(), raw, out); err != nil {
		t.Fatal(err)
	}
	e := <-out
	if e.Args["fixed"] != "yes" || len(order) != 2 || order[0] != "fix" || order[1] != "bind" {
		t.Fatalf("order %v args %v", order, e.Args)
	}
}
