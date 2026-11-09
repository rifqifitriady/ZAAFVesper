//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// replay --elegia-dir writes closed segments with schema v1 records and the
// given host, leaves no .part file, and its options do not leak into the
// next replay (they live in a package variable reset by cmdReplay).
func TestReplayElegiaDirAndHost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seg")
	var out, errb bytes.Buffer
	rc := cmdReplay([]string{"--rules", "../../rules", "--platform", "macos", "--elegia-dir", dir, "--elegia-host", "mac-07",
		"../../pkg/capture/testdata/eslogger_exec_tree.jsonl"}, &out, &errb)
	if rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	ents, _ := os.ReadDir(dir)
	n := 0
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".part") {
			t.Fatalf("open segment left: %s", e.Name())
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
			var m map[string]any
			if err := json.Unmarshal(l, &m); err != nil {
				t.Fatal(err)
			}
			if m["Computer"] != "mac-07" || m["zaafvesper"].(map[string]any)["schema"] != "zaafvesper.elegia/1" {
				t.Fatalf("record %v", m)
			}
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d records, want 2", n)
	}
	if replayElegia.active() {
		t.Fatal("replay's ZAAFElegia options leaked past cmdReplay")
	}
	// Bad combinations are refused before anything runs.
	for _, args := range [][]string{{"--elegia-dir", "-"}, {"--elegia-dir", dir, "--elegia-segment-bytes", "100", "--elegia-keep-bytes", "10"}} {
		errb.Reset()
		if rc := cmdReplay(append(args, "../../pkg/capture/testdata/eslogger_exec_tree.jsonl"), &out, &errb); rc != 2 {
			t.Fatalf("%v: rc %d, %s", args, rc, errb.String())
		}
	}
}
