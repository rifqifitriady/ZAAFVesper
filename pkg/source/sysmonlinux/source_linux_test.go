//go:build linux

package sysmonlinux

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
)

func TestReadStampSelf(t *testing.T) {
	st, err := ReadStamp(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if st.ID == 0 || st.Start.IsZero() {
		t.Fatalf("stamp %+v", st)
	}
	if d := st.Precise.Sub(st.Start); d < -1100*time.Millisecond || d > 1100*time.Millisecond {
		t.Fatalf("precise %v and btime-based %v differ by %v", st.Precise, st.Start, d)
	}
	if st.Precise.After(time.Now()) {
		t.Fatalf("start in the future: %v", st.Precise)
	}
}

func TestReadLines(t *testing.T) {
	xml, err := os.ReadFile("../sysmon/testdata/l01_process_create.xml")
	if err != nil {
		t.Fatal(err)
	}
	rec := func(uid, unit, cursor string) string {
		b, _ := json.Marshal(map[string]string{"__CURSOR": cursor, "_UID": uid, "_SYSTEMD_UNIT": unit, "MESSAGE": strings.TrimSpace(string(xml))})
		return string(b) + "\n"
	}
	input := rec("0", SysmonUnit, "s=1;i=1") +
		rec("1000", "user@1000.service", "s=1;i=2") + // forged with logger(1)
		strings.Repeat("x", MaxLineBytes+10) + "\n" + // oversize
		"not json\n" +
		rec("0", SysmonUnit, "s=1;i=4")
	s := New(Config{})
	feed := sysmon.NewFeeder(nil, nil)
	out := make(chan *event.Event, 4)
	if err := s.read(context.Background(), bufio.NewReaderSize(strings.NewReader(input), 4096), feed, out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || s.untrusted.Load() != 1 || s.oversize.Load() != 1 || s.badLines.Load() != 1 || s.cursor != "s=1;i=4" {
		t.Fatalf("out %d untrusted %d oversize %d bad %d cursor %q", len(out), s.untrusted.Load(), s.oversize.Load(), s.badLines.Load(), s.cursor)
	}
}

// TestTgidOfOwnThreads: every thread of this (multi-threaded Go) process
// maps to the process id, as FixThreadParent needs.
func TestTgidOfOwnThreads(t *testing.T) {
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	pid := int32(os.Getpid())
	threads := 0
	for _, e := range ents {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		g, err := procfs.Default.Tgid(int32(tid))
		if err != nil {
			continue // thread ended meanwhile
		}
		if g != pid {
			t.Fatalf("thread %d: tgid %d, want %d", tid, g, pid)
		}
		if int32(tid) != pid {
			threads++
		}
	}
	if threads == 0 {
		t.Skip("no thread other than the main one")
	}
}

// TestNewFeederFixesThreadParent: the feeder Run uses maps a real thread
// of this (multi-threaded Go) process, reported as a parent, to the process.
func TestNewFeederFixesThreadParent(t *testing.T) {
	pid := int32(os.Getpid())
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var tid int32
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil && int32(n) != pid {
			tid = int32(n)
			break
		}
	}
	if tid == 0 {
		t.Skip("no thread other than the main one")
	}
	f := newFeeder(nil)
	e := &event.Event{Name: event.CreateProcess, Time: time.Now(), Proc: &event.Proc{PID: 1 << 30, PPID: tid, Parent: &event.Proc{PID: tid}}}
	f.Fix(e)
	if e.Proc.PPID != pid || e.Args[ArgParentThread] != strconv.Itoa(int(tid)) {
		t.Fatalf("ppid %d (want %d), args %v", e.Proc.PPID, pid, e.Args)
	}
	// An event older than the thread: not attached.
	old := &event.Event{Name: event.CreateProcess, Time: time.Now().Add(-time.Hour), Proc: &event.Proc{PID: 1 << 30, PPID: tid, Parent: &event.Proc{PID: tid}}}
	f.Fix(old)
	if old.Proc.PPID != tid {
		t.Fatalf("thread newer than the event was attached: %+v", old.Proc)
	}
}
