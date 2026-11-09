package response

import (
	"strings"
	"testing"
	"time"
)

func TestRefuseUnsupported(t *testing.T) {
	var logs []Decision
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	r := New(Config{Log: func(d Decision) { logs = append(logs, d) }, Now: func() time.Time { return now }})
	r.RefuseUnsupported("isolate_process", TargetProcess, 4242, "rule-1", "rule X", "action isolate_process is not supported on Linux (macOS only)")
	r.RefuseUnsupported("isolate_process", TargetProcess, 4242, "rule-1", "rule X", "action isolate_process is not supported on Linux (macOS only)")
	if len(logs) != 1 || logs[0].Outcome != OutcomeUnsupported || !strings.Contains(logs[0].Detail, "nothing was changed") {
		t.Fatalf("logs %+v", logs)
	}
	if st := r.Stats(); st["isolate_process "+OutcomeUnsupported] != 2 || st["log_suppressed"] != 1 {
		t.Fatalf("stats %v", st)
	}
}
