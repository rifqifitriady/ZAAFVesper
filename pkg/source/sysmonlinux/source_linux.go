//go:build linux

package sysmonlinux

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/procfs"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmon"
)

// Restart policy for a journalctl that exits unexpectedly.
const (
	maxRestartsPerMinute = 5
	initialBackoff       = time.Second
	maxBackoff           = 30 * time.Second
	stderrTail           = 4 << 10
)

// Source reads Sysmon for Linux from journald.
type Source struct {
	cfg     Config
	feed    atomic.Pointer[sysmon.Feeder]
	pid     atomic.Int32
	pending func(string, string)
	cursor  string

	restarts, oversize, untrusted, badLines, otherMessages atomic.Uint64
}

// New returns the source.
func New(cfg Config) *Source { return &Source{cfg: cfg} }

// Name implements source.Source.
func (s *Source) Name() string { return Name }

// PID returns the running journalctl child's pid (0 when none), so the
// responder can protect it.
func (s *Source) PID() int32 { return s.pid.Load() }

// OnDegraded registers fn for sysmon.CondEventsDropped. Call it before Run.
func (s *Source) OnDegraded(fn func(condition, detail string)) { s.pending = fn }

// Stats implements source.Source.
func (s *Source) Stats() map[string]uint64 {
	f := s.feed.Load()
	if f == nil {
		f = sysmon.NewFeeder(nil, nil) // zero counters before Run
	}
	st := f.Stats()
	st["restarts"], st["oversize"] = s.restarts.Load(), s.oversize.Load()
	st["untrusted_records"], st["bad_lines"] = s.untrusted.Load(), s.badLines.Load()
	st["other_messages"] = s.otherMessages.Load()
	return st
}

// ReadStamp is the kernel identity reader for the Binder: the start time of
// pid in /proc/<pid>/stat. Start uses the boot time in /proc/stat (as the
// responder's identify does, so both give the same instant); Precise uses
// CLOCK_REALTIME - CLOCK_BOOTTIME now, which is exact to the tick.
func ReadStamp(pid int32) (sysmon.Stamp, error) {
	st, err := procfs.Default.Stat(pid)
	if err != nil {
		return sysmon.Stamp{}, err
	}
	bt, err := procfs.Default.BootTime()
	if err != nil {
		return sysmon.Stamp{}, err
	}
	precise, err := preciseStart(st.StartTicks)
	if err != nil {
		return sysmon.Stamp{}, err
	}
	return sysmon.Stamp{ID: st.StartTicks, Start: procfs.StartTime(bt, st.StartTicks), Precise: precise}, nil
}

// preciseStart turns a start time in ticks since boot into wall time with
// CLOCK_REALTIME - CLOCK_BOOTTIME read now (exact to the tick).
func preciseStart(ticks uint64) (time.Time, error) {
	var rt, bo unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &rt); err != nil {
		return time.Time{}, err
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bo); err != nil {
		return time.Time{}, err
	}
	boot := time.Unix(rt.Unix()).Add(-time.Duration(bo.Nano()))
	return boot.Add(time.Duration(ticks) * (time.Second / procfs.UserHZ)).UTC(), nil
}

// threadStartedAt is the start time of thread tid of process tgid
// (FixThreadParent's guard against a reused thread id).
func threadStartedAt(tgid, tid int32) (time.Time, error) {
	st, err := procfs.Default.TaskStat(tgid, tid)
	if err != nil {
		return time.Time{}, err
	}
	return preciseStart(st.StartTicks)
}

// newFeeder builds the feeder Run uses: identity binding, and the parent
// fix for Sysmon for Linux's thread ids.
func newFeeder(events []string) *sysmon.Feeder {
	feed := sysmon.NewFeeder(events, sysmon.NewBinder(ReadStamp, IdentityTolerance))
	feed.Fix = func(e *event.Event) { FixThreadParent(e, procfs.Default.Tgid, threadStartedAt, IdentityTolerance) }
	return feed
}

// Run follows the journal until ctx ends. journalctl is restarted (resuming
// after the last cursor read) when it exits, at most maxRestartsPerMinute
// times a minute.
func (s *Source) Run(ctx context.Context, events []string, out chan<- *event.Event) error {
	feed := newFeeder(events)
	if s.pending != nil {
		feed.OnDegraded(s.pending)
	}
	s.feed.Store(feed)
	backoff := initialBackoff
	var starts []time.Time
	for {
		now := time.Now()
		recent := starts[:0]
		for _, t := range starts {
			if now.Sub(t) < time.Minute {
				recent = append(recent, t)
			}
		}
		starts = append(recent, now)
		if len(starts) > maxRestartsPerMinute {
			return fmt.Errorf("sysmonlinux: journalctl exited %d times in a minute; giving up", len(starts)-1)
		}
		began := time.Now()
		err := s.runOnce(ctx, feed, out)
		if ctx.Err() != nil {
			return nil
		}
		s.restarts.Add(1)
		feed.Restarted(s.cursor != "")
		s.logf("journalctl exited (%v); restarting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if time.Since(began) > time.Minute {
			backoff = initialBackoff
		} else if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (s *Source) runOnce(ctx context.Context, feed *sysmon.Feeder, out chan<- *event.Event) error {
	cmd := exec.CommandContext(ctx, Journalctl, Args(s.cursor)...)
	cmd.Env = Env
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var errBuf tail
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", Journalctl, err)
	}
	pid := int32(cmd.Process.Pid)
	s.pid.Store(pid)
	defer s.pid.Store(0)
	if s.cfg.OnStart != nil {
		s.cfg.OnStart(pid)
	}
	rerr := s.read(ctx, bufio.NewReaderSize(stdout, 64<<10), feed, out)
	if rerr != nil {
		_ = cmd.Process.Kill()
	}
	werr := cmd.Wait()
	if msg := bytes.TrimSpace(errBuf.bytes()); len(msg) > 0 {
		s.logf("journalctl: %s", msg)
	}
	return errors.Join(rerr, werr)
}

// read consumes JSON lines, at most MaxLineBytes each.
func (s *Source) read(ctx context.Context, r *bufio.Reader, feed *sysmon.Feeder, out chan<- *event.Event) error {
	var line []byte
	skipping := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			switch {
			case skipping:
			case len(line)+len(chunk) > MaxLineBytes:
				s.oversize.Add(1)
				feed.Unreadable("journal line longer than MaxLineBytes")
				skipping, line = true, line[:0]
			default:
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 && !skipping {
			if herr := s.handle(ctx, bytes.TrimRight(line, "\r\n"), feed, out); herr != nil {
				return herr
			}
		}
		line, skipping = line[:0], false
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (s *Source) handle(ctx context.Context, line []byte, feed *sysmon.Feeder, out chan<- *event.Event) error {
	msg, cursor, err := ParseLine(line)
	if cursor != "" {
		s.cursor = cursor
	}
	switch {
	case errors.Is(err, ErrUntrusted):
		s.untrusted.Add(1)
		return nil
	case err != nil:
		s.badLines.Add(1)
		return nil
	case !bytes.HasPrefix(bytes.TrimSpace(msg), []byte("<Event")):
		s.otherMessages.Add(1) // Sysmon's own status lines, not events
		return nil
	}
	return feed.Handle(ctx, msg, out)
}

func (s *Source) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// tail keeps the last stderrTail bytes written to it.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > stderrTail {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-stderrTail:]...)
	}
	return len(p), nil
}

func (t *tail) bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.buf...)
}
