package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

func bigAlert(cmdlineLen int) *rules.Alert {
	return &rules.Alert{RuleID: "r1", RuleName: "R", Severity: "high", Output: "out", Time: time.Unix(1, 0).UTC(),
		Events: []*event.Event{{Name: event.CreateProcess, Proc: &event.Proc{PID: 7, Exe: "/tmp/x",
			Cmdline: strings.Repeat("A", cmdlineLen), Args: []string{strings.Repeat("é", cmdlineLen/4)}}}}}
}

func TestEncodeAlertCap(t *testing.T) {
	small := bigAlert(10)
	line, cut, err := EncodeAlert(small, DefaultMaxAlertBytes)
	if err != nil || cut || strings.Contains(string(line), "truncated") {
		t.Fatalf("small alert changed: %v %v %s", cut, err, line)
	}
	line, cut, err = EncodeAlert(bigAlert(1<<20), DefaultMaxAlertBytes)
	if err != nil || !cut || len(line) > DefaultMaxAlertBytes || line[len(line)-1] != '\n' {
		t.Fatalf("big alert: cut=%v err=%v len=%d", cut, err, len(line))
	}
	var a rules.Alert
	if err := json.Unmarshal(line, &a); err != nil {
		t.Fatalf("truncated alert is not valid JSON: %v", err)
	}
	if !a.Truncated || a.RuleID != "r1" || a.Events[0].Proc.PID != 7 || a.Events[0].Proc.Exe != "/tmp/x" ||
		!strings.HasSuffix(a.Events[0].Proc.Cmdline, truncMarker) {
		t.Fatalf("truncated alert lost its identity: %+v", a)
	}
	for _, r := range a.Events[0].Proc.Args[0] {
		if r == '�' {
			t.Fatal("cut inside a UTF-8 sequence")
		}
	}
	// Many small strings cannot be shortened enough: a stub is written.
	many := bigAlert(10)
	for i := 0; i < 20000; i++ {
		many.Events[0].Proc.Args = append(many.Events[0].Proc.Args, "abcdefgh")
	}
	line, cut, err = EncodeAlert(many, 4096)
	if err != nil || !cut || len(line) > 4096 {
		t.Fatalf("stub: cut=%v err=%v len=%d", cut, err, len(line))
	}
	if err := json.Unmarshal(line, &a); err != nil || !a.Truncated || a.RuleID != "r1" {
		t.Fatalf("stub: %v %+v", err, a)
	}
}

type closeBuf struct {
	bytes.Buffer
	closed bool
}

func (c *closeBuf) Close() error { c.closed = true; return nil }

func TestJSONLStopsAtCap(t *testing.T) {
	var buf closeBuf
	var notes []string
	j := NewJSONLOptions(&buf, JSONLOptions{MaxBytes: 1500, OnCapped: func(d string) { notes = append(notes, d) }})
	for i := 0; i < 10; i++ {
		if err := j.Send(bigAlert(200)); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Count(buf.String(), "\n")
	if buf.Len() > 1500 || lines == 0 || lines == 10 {
		t.Fatalf("cap not applied: %d bytes, %d lines", buf.Len(), lines)
	}
	// One notice when the cap is hit, then one per dropped alert (the
	// pipeline rate-limits them into SensorDegraded events).
	if len(notes) != 10-lines || !strings.Contains(notes[0], "not written") || !strings.Contains(notes[len(notes)-1], "dropped") {
		t.Fatalf("cap notices = %q", notes)
	}
	if st := j.Stats(); st["dropped_after_cap"] != uint64(10-lines) {
		t.Fatalf("stats = %v", st)
	}
}

func TestJSONLRotates(t *testing.T) {
	files := []*closeBuf{{}}
	var notes []string
	failNext := false
	now := time.Unix(1000, 0)
	j := NewJSONLOptions(files[0], JSONLOptions{MaxBytes: 1500, Now: func() time.Time { return now },
		Rotate: func() (io.Writer, error) {
			if failNext {
				return nil, errors.New("disk full")
			}
			f := &closeBuf{}
			files = append(files, f)
			return f, nil
		},
		OnCapped: func(d string) { notes = append(notes, d) }})
	for i := 0; i < 10; i++ {
		if err := j.Send(bigAlert(200)); err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for i, f := range files {
		if f.Len() > 1500 {
			t.Fatalf("file %d holds %d bytes", i, f.Len())
		}
		if closed := i < len(files)-1; f.closed != closed {
			t.Fatalf("file %d closed = %v", i, f.closed)
		}
		total += strings.Count(f.String(), "\n")
	}
	if len(files) < 3 || total != 10 || len(notes) != len(files)-1 || !strings.Contains(notes[0], "rotated") {
		t.Fatalf("files=%d alerts=%d notes=%q", len(files), total, notes)
	}
	// A failed rotation stops the sink; every drop is reported.
	failNext = true
	before := len(notes)
	for i := 0; i < 10; i++ {
		_ = j.Send(bigAlert(200))
	}
	dropped := j.Stats()["dropped_after_cap"]
	if dropped == 0 || uint64(len(notes)-before) != dropped || !strings.Contains(strings.Join(notes, "|"), "no new file can be opened (disk full)") {
		t.Fatalf("rotation failure: %q %v", notes, j.Stats())
	}
	// Inside the retry interval nothing is retried; after it, a new file is
	// opened and writing resumes.
	failNext = false
	nfiles := len(files)
	_ = j.Send(bigAlert(200))
	if len(files) != nfiles {
		t.Fatal("rotation retried inside RotateRetryEvery")
	}
	now = now.Add(RotateRetryEvery)
	if err := j.Send(bigAlert(200)); err != nil || len(files) != nfiles+1 || files[nfiles].Len() == 0 {
		t.Fatalf("did not resume: %v files=%d", err, len(files))
	}
}

func TestJSONLStartStopped(t *testing.T) {
	var notes []string
	now := time.Unix(1000, 0)
	var opened *closeBuf
	allow := false
	j := NewJSONLOptions(nil, JSONLOptions{StartStopped: true, StopReason: "budget full", Now: func() time.Time { return now },
		Rotate: func() (io.Writer, error) {
			if !allow {
				return nil, errors.New("budget still full")
			}
			opened = &closeBuf{}
			return opened, nil
		},
		OnCapped: func(d string) { notes = append(notes, d) }})
	if err := j.Send(bigAlert(10)); err != nil || len(notes) != 1 || !strings.Contains(notes[0], "budget full") {
		t.Fatalf("stopped sink: %v %q", err, notes)
	}
	allow = true
	now = now.Add(RotateRetryEvery)
	if err := j.Send(bigAlert(10)); err != nil || opened == nil || opened.Len() == 0 {
		t.Fatalf("not resumed: %v", err)
	}
	if err := j.Close(); err != nil || !opened.closed {
		t.Fatal("close")
	}
}

func TestDeduperPIDReuse(t *testing.T) {
	d := NewDeduper(10 * time.Second)
	t0 := time.Unix(1000, 0)
	mk := func(pidver uint32, start time.Time, at int64) *rules.Alert {
		return &rules.Alert{RuleID: "a", RuleName: "A", Time: time.Unix(at, 0),
			Events: []*event.Event{{Proc: &event.Proc{PID: 9, PIDVersion: pidver, StartTime: start}}}}
	}
	if !d.Allow(mk(1, t0, 0)) || d.Allow(mk(1, t0, 1)) {
		t.Fatal("same process not deduplicated")
	}
	if !d.Allow(mk(2, t0, 2)) {
		t.Fatal("pid reused with a new pidversion was suppressed")
	}
	if !d.Allow(mk(1, t0.Add(time.Second), 3)) {
		t.Fatal("pid reused with a new start time was suppressed")
	}
}

// paddedAlert is the security review's F6 case: 650 arguments of 100 bytes
// (and the matching command line), on a process with full identity.
func paddedAlert() *rules.Alert {
	args := make([]string, 650)
	for i := range args {
		args[i] = strings.Repeat("P", 100)
	}
	start := time.Date(2026, 11, 8, 10, 0, 0, 123456000, time.UTC)
	p := &event.Proc{PID: 4242, PPID: 4000, PIDVersion: 77, Exe: "/Users/a/.cache/agent", Name: "agent",
		CDHash: "0123456789abcdef0123456789abcdef01234567", SigningID: "agent", TeamID: "FAKETEAM01",
		CSCategory: event.CSLocalSigning, StartTime: start, Args: args, Cmdline: strings.Join(args, " "),
		Parent: &event.Proc{PID: 4000, Exe: "/bin/zsh", Name: "zsh"}}
	return &rules.Alert{RuleID: "r1", RuleName: "R", Severity: "critical", Output: "prompt by " + p.Cmdline,
		Time: start, Events: []*event.Event{{Name: event.CreateProcess, Proc: p}}}
}

func TestEncodePaddedAlertFastAndKeepsIdentity(t *testing.T) {
	a := paddedAlert()
	const runs = 50
	t0 := time.Now()
	var line []byte
	var cut bool
	var err error
	for i := 0; i < runs; i++ {
		line, cut, err = EncodeAlert(a, DefaultMaxAlertBytes)
	}
	per := time.Since(t0) / runs
	if err != nil || !cut || len(line) > DefaultMaxAlertBytes {
		t.Fatalf("cut=%v err=%v len=%d", cut, err, len(line))
	}
	if !raceEnabled && per > 2*time.Millisecond {
		t.Fatalf("padded alert takes %v to encode, want < 2ms", per)
	}
	var got rules.Alert
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	p, want := got.Events[0].Proc, a.Events[0].Proc
	if !got.Truncated || p.PID != want.PID || p.PPID != want.PPID || p.PIDVersion != want.PIDVersion || p.Exe != want.Exe ||
		p.Name != want.Name || p.CDHash != want.CDHash || p.SigningID != want.SigningID || p.TeamID != want.TeamID ||
		p.CSCategory != want.CSCategory || !p.StartTime.Equal(want.StartTime) || p.Parent == nil ||
		p.Parent.PID != 4000 || p.Parent.Exe != "/bin/zsh" {
		t.Fatalf("identity changed: %+v", p)
	}
	if len(p.Args) != firstPass.list || len(p.Cmdline) > firstPass.str+len(truncMarker) {
		t.Fatalf("not pre-capped: %d args, cmdline %d bytes", len(p.Args), len(p.Cmdline))
	}
	// The source alert is not modified.
	if len(a.Events[0].Proc.Args) != 650 || a.Truncated {
		t.Fatal("EncodeAlert modified its input")
	}
	t.Logf("padded alert: %v per encode, %d bytes", per, len(line))
}

func BenchmarkEncodePaddedAlert(b *testing.B) {
	a := paddedAlert()
	for i := 0; i < b.N; i++ {
		_, _, _ = EncodeAlert(a, DefaultMaxAlertBytes)
	}
}

// TestEncodeAlertStubKeepsIdentity: an alert too large even after the
// second pass (many events) is reduced to identities, never to nothing.
func TestEncodeAlertStubKeepsIdentity(t *testing.T) {
	a := paddedAlert()
	for i := 0; i < 40; i++ {
		e := *a.Events[0]
		a.Events = append(a.Events, &e)
	}
	line, cut, err := EncodeAlert(a, 32<<10)
	if err != nil || !cut {
		t.Fatal(err)
	}
	var got rules.Alert
	if err := json.Unmarshal(line, &got); err != nil || len(got.Events) != 41 || got.Events[40].Proc.Exe != "/Users/a/.cache/agent" ||
		got.Events[0].Proc.TeamID != "FAKETEAM01" || len(got.Events[0].Proc.Args) != 0 {
		t.Fatalf("stub: %v %d", err, len(got.Events))
	}
}

// TestEncodeCapsSigningFields (security New-5): a self-signed binary can
// carry a huge signing ID or Team ID; both are capped at 256 bytes, the
// rest of the identity stays exact.
func TestEncodeCapsSigningFields(t *testing.T) {
	a := paddedAlert()
	p := a.Events[0].Proc
	p.SigningID, p.TeamID = strings.Repeat("S", 100<<10), strings.Repeat("T", 1000)
	line, cut, err := EncodeAlert(a, DefaultMaxAlertBytes)
	if err != nil || !cut || len(line) > DefaultMaxAlertBytes {
		t.Fatalf("cut=%v err=%v len=%d", cut, err, len(line))
	}
	var got rules.Alert
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	gp := got.Events[0].Proc
	if len(gp.SigningID) != maxSigningField+len(truncMarker) || len(gp.TeamID) != maxSigningField+len(truncMarker) ||
		gp.Exe != p.Exe || gp.PID != p.PID || gp.CDHash != p.CDHash {
		t.Fatalf("signing fields: %d %d %+v", len(gp.SigningID), len(gp.TeamID), gp)
	}
	if s := identityProc(p); len(s.SigningID) > maxSigningField+len(truncMarker) {
		t.Fatal("stub keeps an uncapped signing id")
	}
}
