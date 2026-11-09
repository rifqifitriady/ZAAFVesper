//go:build unix

package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func listDir(t *testing.T, dir string) (closed, open []string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		switch {
		case strings.HasSuffix(e.Name(), ".ndjson.part"):
			open = append(open, e.Name())
		case strings.HasSuffix(e.Name(), ".ndjson"):
			closed = append(closed, e.Name())
		}
	}
	sort.Strings(closed)
	return closed, open
}

func TestSegmentsRotateBySizeAndAge(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "elegia")
	clk := &fakeClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	s, err := OpenSegments(dir, SegmentConfig{MaxBytes: 100, MaxAge: time.Minute, KeepBytes: 1 << 20, Now: clk.now}, false)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", fi.Mode().Perm())
	}
	line := []byte(`{"n":1,"pad":"` + strings.Repeat("x", 40) + `"}` + "\n")
	_, _ = s.Write(line)
	if s.Due() {
		t.Fatal("due after one small line")
	}
	closed, open := listDir(t, dir)
	if len(closed) != 0 || len(open) != 1 {
		t.Fatalf("closed %v open %v: the open segment must be a .part file", closed, open)
	}
	_, _ = s.Write(line)
	if !s.Due() {
		t.Fatal("not due at the size limit")
	}
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	clk.add(time.Second)
	_, _ = s.Write(line)
	clk.add(2 * time.Minute)
	if !s.Due() {
		t.Fatal("not due at the age limit")
	}
	_ = s.Rotate()
	if s.Due() {
		t.Fatal("due with no open segment")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	closed, open = listDir(t, dir)
	if len(closed) != 2 || len(open) != 0 {
		t.Fatalf("closed %v open %v", closed, open)
	}
	for _, f := range closed {
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", f, fi.Mode().Perm())
		}
	}
}

func TestSegmentsPruneAndCrashRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "elegia")
	clk := &fakeClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	s, err := OpenSegments(dir, SegmentConfig{MaxBytes: 10, KeepBytes: 250, Now: clk.now}, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_, _ = s.Write([]byte(fmt.Sprintf(`{"i":%d,"pad":"%s"}`+"\n", i, strings.Repeat("y", 80))))
		_ = s.Rotate()
		clk.add(time.Second)
	}
	closed, _ := listDir(t, dir)
	if len(closed) > 3 || s.Stats()["pruned"] == 0 {
		t.Fatalf("kept %d segments, stats %v", len(closed), s.Stats())
	}
	// The newest are kept.
	if b, _ := os.ReadFile(filepath.Join(dir, closed[len(closed)-1])); !bytes.Contains(b, []byte(`"i":9`)) {
		t.Fatalf("newest segment lost: %s", b)
	}
	// A crash leaves an open .part: the next start closes it.
	_, _ = s.Write([]byte(`{"crash":true}` + "\n"))
	s.mu.Lock()
	_ = s.cur.Close() // simulate the process dying without Close
	s.cur = nil
	s.mu.Unlock()
	if _, open := listDir(t, dir); len(open) != 1 {
		t.Fatalf("open %v", open)
	}
	s2, err := OpenSegments(dir, SegmentConfig{MaxBytes: 10, KeepBytes: 1 << 20, Now: clk.now}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	closed, open := listDir(t, dir)
	if len(open) != 0 || len(closed) == 0 {
		t.Fatalf("after restart: closed %v open %v", closed, open)
	}
	// Foreign files are never touched.
	_ = os.WriteFile(filepath.Join(dir, "notes.ndjson"), []byte("x\n"), 0o600)
	_ = s2.Rotate()
	if _, err := os.Stat(filepath.Join(dir, "notes.ndjson")); err != nil {
		t.Fatal("a foreign file was removed")
	}
}

func TestSegmentsDirSafety(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	_ = os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	_ = os.Symlink(real, link)
	if _, err := OpenSegments(link, SegmentConfig{}, false); err == nil {
		t.Fatal("symbolic link accepted as the segment directory")
	}
	_ = os.Chmod(real, 0o755)
	if _, err := OpenSegments(real, SegmentConfig{}, false); err == nil {
		t.Fatal("0755 segment directory accepted")
	}
}

// Through the LineWriter: every closed segment holds whole JSON lines, no
// line is split across segments, and none is lost.
func TestSegmentsThroughLineWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "elegia")
	s, err := OpenSegments(dir, SegmentConfig{MaxBytes: 2000, KeepBytes: 1 << 30}, false)
	if err != nil {
		t.Fatal(err)
	}
	lw := NewLineWriter(s, LineWriterConfig{Name: "elegia-dir"})
	const n = 500
	for i := 0; i < n; i++ {
		lw.WriteLine([]byte(fmt.Sprintf(`{"i":%d,"pad":"%s"}`, i, strings.Repeat("z", i%97))))
		if i%50 == 0 {
			time.Sleep(5 * time.Millisecond) // let the writer drain and rotate
		}
	}
	if err := lw.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	closed, open := listDir(t, dir)
	if len(open) != 0 || len(closed) < 3 {
		t.Fatalf("closed %d open %v", len(closed), open)
	}
	seen := map[int]bool{}
	for _, f := range closed {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if len(b) == 0 || b[len(b)-1] != '\n' {
			t.Fatalf("%s does not end with a newline", f)
		}
		for _, l := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
			var m struct{ I int }
			if err := json.Unmarshal(l, &m); err != nil {
				t.Fatalf("%s: broken line %q", f, l)
			}
			seen[m.I] = true
		}
	}
	if len(seen) != n {
		t.Fatalf("%d of %d lines found", len(seen), n)
	}
}
