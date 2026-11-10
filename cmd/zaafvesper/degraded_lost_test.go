package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDegradedLostTelemetryNeverSuppressed: the conditions that say events
// were lost (from the eslogger, eBPF and Sysmon sources) pass the per-
// condition and the overall limit, even after another condition flooded
// the minute's budget (security review finding F10).
func TestDegradedLostTelemetryNeverSuppressed(t *testing.T) {
	for _, c := range []string{"es_events_dropped", "ebpf_events_dropped", "ebpf_events_unreadable", "sysmon_events_dropped"} {
		if !neverSuppressed[c] {
			t.Errorf("%s is limited", c)
		}
	}
	dir := rulesDir(t, map[string]string{"d.yml": degradedRule})
	var out, errb bytes.Buffer
	s, err := buildSensor(runOptions{rulesDir: dir, rulesGiven: true, configPath: filepath.Join(t.TempDir(), "none.yml"),
		noYara: true, jsonKeep: 8, captureKeep: 2}, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.p.deg.clock = func() time.Time { return now }
	for i := 0; i < 200; i++ { // a decoy flood uses up the minute
		s.p.degradedFrom("yara_exec_replaced", fmt.Sprintf("flood %d", i))
	}
	conds := []string{"ebpf_events_dropped", "ebpf_events_unreadable", "sysmon_events_dropped"}
	for _, c := range conds {
		for i := 0; i < 50; i++ {
			s.p.degradedFrom(c, fmt.Sprintf("lost %d", i))
		}
	}
	s.p.drainDegraded()
	_ = s.close()
	e := errb.String()
	for _, c := range conds {
		if n := strings.Count(e, "condition="+c); n != 50 {
			t.Errorf("%s: %d of 50 reports passed", c, n)
		}
	}
}
