package ps

import (
	"bufio"
	"os"
	"slices"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/eslogger"
)

// TestEsloggerFixturesThroughSnapshotter runs decoded eslogger fixture lines
// through the snapshotter and checks the parent fields rules depend on.
func TestEsloggerFixturesThroughSnapshotter(t *testing.T) {
	s := testSnap(MaxEntries)
	s.Enrich(ev(event.CreateProcess, 0, &event.Proc{PID: 1, PIDVersion: 1, Exe: "/sbin/launchd"}))
	s.Enrich(ev(event.CreateProcess, 0, &event.Proc{PID: 4000, PPID: 1, PIDVersion: 4000, Exe: "/usr/bin/login", UID: 0}))
	s.Enrich(ev(event.CreateProcess, 0, &event.Proc{PID: 4100, PPID: 4000, PIDVersion: 4100, Exe: "/bin/zsh", UID: 501,
		Parent: &event.Proc{PID: 4000, PIDVersion: 4000}}))

	f, err := os.Open("../../testdata/eslogger/exec.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, eslogger.MaxLineSize)
	if !sc.Scan() {
		t.Fatal("empty fixture")
	}
	e, ok, err := eslogger.Decode(sc.Bytes())
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	s.Enrich(e)
	if e.Get("ps.parent.exe") != "/bin/zsh" || e.Get("ps.parent.pid") != int64(4100) {
		t.Errorf("parent: %v %v", e.Get("ps.parent.exe"), e.Get("ps.parent.pid"))
	}
	if got := e.Get("ps.ancestors"); !slices.Equal(got.([]string), []string{"/bin/zsh", "/usr/bin/login", "/sbin/launchd"}) {
		t.Errorf("ancestors %v", got)
	}
	if e.Get("ps.username") != "alice" || e.Get("ps.exe") != "/usr/bin/curl" {
		t.Errorf("username/exe %v %v", e.Get("ps.username"), e.Get("ps.exe"))
	}
}
