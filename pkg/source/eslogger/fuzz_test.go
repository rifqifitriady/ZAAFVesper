package eslogger

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzDecode: Decode must never panic, and a decoded event always has a
// canonical name and the eslogger source tag.
func FuzzDecode(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(fixtureDir, "*.jsonl"))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"event_type":9,"event":{"exec":{"target":"x","args":{"a":1}}}}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		e, ok, err := Decode(line)
		if ok && (err != nil || e == nil || e.Name == "" || e.Source != "eslogger") {
			t.Fatalf("ok=%v err=%v e=%+v", ok, err, e)
		}
	})
}
