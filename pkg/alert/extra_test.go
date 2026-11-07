package alert

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

func envAlert() *rules.Alert {
	return &rules.Alert{RuleID: "r1", RuleName: "R", Time: time.Unix(100, 0),
		Events: []*event.Event{{Name: event.CreateProcess,
			Proc: &event.Proc{PID: 5, Env: map[string]string{"AWS_SECRET_ACCESS_KEY": "hunter2", "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"},
				Parent: &event.Proc{Env: map[string]string{"TOKEN": "t0k"}}},
			Target: &event.Proc{Env: map[string]string{"PASS": "p"}}}}}
}

func TestRedaction(t *testing.T) {
	a := envAlert()
	r := RedactAlert(a)
	p := r.Events[0].Proc
	if p.Env["AWS_SECRET_ACCESS_KEY"] != Redacted || p.Env["DYLD_INSERT_LIBRARIES"] != "/tmp/x.dylib" ||
		p.Parent.Env["TOKEN"] != Redacted || r.Events[0].Target.Env["PASS"] != Redacted {
		t.Fatalf("redaction: %+v", p)
	}
	if a.Events[0].Proc.Env["AWS_SECRET_ACCESS_KEY"] != "hunter2" {
		t.Fatal("original alert modified")
	}
	plain := &event.Event{Name: event.Fork, Proc: &event.Proc{PID: 1}}
	if RedactEvent(plain) != plain || RedactEvent(nil) != nil {
		t.Fatal("event without env should be returned as is")
	}

	var buf bytes.Buffer
	if err := NewJSONL(&buf).Send(a); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hunter2") || !strings.Contains(buf.String(), "AWS_SECRET_ACCESS_KEY") || !strings.Contains(buf.String(), "x.dylib") {
		t.Fatalf("JSONL redaction: %s", buf.String())
	}
	buf.Reset()
	if err := NewJSONLWith(&buf, true).Send(a); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "hunter2") {
		t.Fatal("keepEnv dropped values")
	}
}

func TestDeduper(t *testing.T) {
	d := NewDeduper(10 * time.Second)
	mk := func(rule string, pid int32, at int64) *rules.Alert {
		return &rules.Alert{RuleID: rule, RuleName: "name-" + rule, Time: time.Unix(at, 0),
			Events: []*event.Event{{Proc: &event.Proc{PID: pid}}}}
	}
	steps := []struct {
		a    *rules.Alert
		want bool
	}{
		{mk("a", 1, 0), true},
		{mk("a", 1, 5), false}, // same rule+pid within 10 s
		{mk("a", 2, 5), true},  // other pid
		{mk("b", 1, 5), true},  // other rule
		{mk("a", 1, 9), false},
		{mk("a", 1, 10), true}, // window passed (from the first delivery)
		{mk("a", 1, 15), false},
		{&rules.Alert{RuleID: "c", Time: time.Unix(1, 0)}, true}, // no events
	}
	for i, s := range steps {
		if got := d.Allow(s.a); got != s.want {
			t.Fatalf("step %d: Allow = %v", i, got)
		}
	}
	if d.Suppressed()["name-a"] != 3 {
		t.Fatalf("suppressed = %v", d.Suppressed())
	}
}

type blockingSink struct {
	mu      sync.Mutex
	release chan struct{}
	got     int
}

func (b *blockingSink) Send(*rules.Alert) error {
	<-b.release
	b.mu.Lock()
	b.got++
	b.mu.Unlock()
	return nil
}

func TestAsyncNeverBlocks(t *testing.T) {
	bs := &blockingSink{release: make(chan struct{})}
	a := NewAsync(bs, 4)
	start := time.Now()
	for i := 0; i < 100; i++ {
		_ = a.Send(envAlert())
	}
	if time.Since(start) > time.Second {
		t.Fatal("Send blocked on a stuck sink")
	}
	// One alert is held by the blocked goroutine, 4 are queued, the rest dropped.
	if d := a.Dropped(); d < 95 || d > 96 {
		t.Fatalf("dropped = %d", d)
	}
	if err := a.Close(50 * time.Millisecond); err == nil {
		t.Fatal("Close should report a blocked sink")
	}
	close(bs.release)
	if err := a.Close(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if uint64(bs.got)+a.Dropped() != 100 {
		t.Fatalf("delivered %d + dropped %d != 100", bs.got, a.Dropped())
	}
	if err := a.Send(envAlert()); err == nil {
		t.Fatal("Send after Close accepted")
	}
}
