package eslogger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// fakeESLogger writes an executable script standing in for eslogger. Test only.
func fakeESLogger(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("posix only")
	}
	p := filepath.Join(t.TempDir(), "eslogger")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunOnceStreamsAndReportsExit(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join(fixtureDir, "exec.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	// The fake echoes its argv to stderr so we can check it got the fixed argv.
	bin := fakeESLogger(t, `echo "argv:$*" >&2; cat "`+fixture+`"; exit 3`+"\n")
	var started []int32
	s := New(Config{OnStart: func(pid int32) { started = append(started, pid) }})
	if s.PID() != 0 {
		t.Fatal("pid before start")
	}
	out := make(chan *event.Event, 16)
	err = s.runOnce(t.Context(), bin, ESEventTypes([]string{event.CreateProcess}), out)
	if len(started) != 1 || started[0] <= 0 {
		t.Errorf("OnStart calls %v", started)
	}
	if s.PID() != 0 {
		t.Errorf("pid %d after exit", s.PID())
	}
	if err == nil || !strings.Contains(err.Error(), "argv:exec") || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("err = %v", err)
	}
	close(out)
	n := 0
	for e := range out {
		if e.Name != event.CreateProcess || e.Time.IsZero() {
			t.Errorf("event %+v", e)
		}
		n++
	}
	if n != len(readLines(t, fixture)) {
		t.Errorf("got %d events", n)
	}
}

func TestRunOnceFullDiskAccess(t *testing.T) {
	bin := fakeESLogger(t, `echo "Failed to create ES client: Not permitted to create an ES Client, responsible process needs TCC Full Disk Access authorization (ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED)" >&2; exit 1`+"\n")
	err := New(Config{}).runOnce(t.Context(), bin, []string{"exec"}, make(chan *event.Event, 1))
	if !errors.Is(err, ErrNoFullDiskAccess) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunOnceEnvIsMinimal(t *testing.T) {
	t.Setenv("ZAAFVESPER_TEST_LEAK", "leaked")
	bin := fakeESLogger(t, `env >&2; exit 1`+"\n")
	err := New(Config{}).runOnce(t.Context(), bin, []string{"exec"}, make(chan *event.Event, 1))
	if err == nil || strings.Contains(err.Error(), "ZAAFVESPER_TEST_LEAK") || !strings.Contains(err.Error(), "LANG=C") {
		t.Fatalf("environment leaked: %v", err)
	}
}

func TestValidateBinary(t *testing.T) {
	fake := fakeESLogger(t, "exit 0\n")
	if err := validateBinary(fake, 0); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("root + non-default binary: %v", err)
	}
	if err := validateBinary(fake, 501); err != nil {
		t.Errorf("non-root + test binary: %v", err)
	}
	if err := validateBinary("eslogger", 501); err == nil {
		t.Error("relative path accepted")
	}
	if err := validateBinary(filepath.Dir(fake), 501); err == nil {
		t.Error("directory accepted")
	}
	if _, err := os.Stat(DefaultBinary); err == nil {
		if err := validateBinary(DefaultBinary, 0); err != nil {
			t.Errorf("default binary as root: %v", err)
		}
	}
}

func TestPIDVisibleWhileRunning(t *testing.T) {
	bin := fakeESLogger(t, "sleep 5\n")
	s := New(Config{})
	got := make(chan int32, 1)
	s.cfg.OnStart = func(pid int32) { got <- s.PID() }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.runOnce(ctx, bin, []string{"exec"}, make(chan *event.Event, 1)) }()
	if pid := <-got; pid <= 0 {
		t.Fatalf("PID() during run = %d", pid)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("cancelled run returned %v", err)
	}
	if s.PID() != 0 {
		t.Errorf("pid %d after cancel", s.PID())
	}
}
