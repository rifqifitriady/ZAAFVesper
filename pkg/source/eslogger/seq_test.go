package eslogger

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// TestSeqGapReported (F6): global_seq_num gaps in eslogger's output mean
// events were dropped before ZAAFVesper saw them. Lines that decode to
// nothing (an unmodified close) still use a number and must not look like a
// gap; a number that does not increase starts a new client's sequence.
// Fixture: global_seq_num 100 101(ignored close) 102 105 106 110 | 3 4 9.
func TestSeqGapReported(t *testing.T) {
	lines := readLines(t, filepath.Join(fixtureDir, "seqgap", "gaps.jsonl"))
	if len(lines) != 9 {
		t.Fatalf("fixture has %d lines", len(lines))
	}
	s := New(Config{})
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	s.degraded.now = func() time.Time { return now }
	var calls []string
	s.OnDegraded(func(c, d string) { calls = append(calls, c+": "+d) })
	out := make(chan *event.Event, 16)
	if err := s.consume(t.Context(), bytes.NewReader(bytes.Join(lines[:8], []byte("\n"))), out); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st["seq_gaps"] != 2 || st["events_missed"] != 5 || st["ignored"] != 2 {
		t.Fatalf("stats %v", st)
	}
	if len(calls) != 1 || calls[0] != CondEventsDropped+": missed 2 events (global_seq_num 103 to 104); 2 missed in total" {
		t.Fatalf("calls %q", calls)
	}
	now = now.Add(time.Minute) // the next gap is reported, carrying the suppressed one
	s.handleLine(t.Context(), lines[8], out)
	if len(calls) != 2 || !strings.Contains(calls[1], "missed 4 events (global_seq_num 5 to 8); 9 missed in total") ||
		!strings.Contains(calls[1], "(1 more suppressed since last report)") {
		t.Fatalf("calls %q", calls)
	}
}

// TestSeqResetOnRestart: each eslogger run is a new ES client, so the first
// line after a restart is never compared with the previous run.
func TestSeqResetOnRestart(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join(fixtureDir, "seqgap", "gaps.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{})
	s.lastSeq = 1 // as if a previous run had ended at 1
	bin := fakeESLogger(t, `head -n 1 "`+fixture+`"; exit 1`+"\n")
	_ = s.runOnce(t.Context(), bin, ESEventTypes(nil), make(chan *event.Event, 4))
	if st := s.Stats(); st["seq_gaps"] != 0 || s.lastSeq != 100 {
		t.Fatalf("stats %v last %d", st, s.lastSeq)
	}
}
