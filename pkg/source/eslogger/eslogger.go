// Package eslogger implements source.Source on top of /usr/bin/eslogger, the
// Endpoint Security logger that ships with macOS 13+. eslogger prints one JSON
// object per line, modelled on es_message_t; Decode maps each line onto the
// platform-neutral event.Event. See README.md for the field and evt.arg
// reference.
package eslogger

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// DefaultBinary is the eslogger shipped with macOS.
const DefaultBinary = "/usr/bin/eslogger"

// Errors Run returns without retrying.
var (
	ErrNotRoot          = errors.New("eslogger: must run as root (Endpoint Security needs superuser)")
	ErrNoFullDiskAccess = errors.New("eslogger: the responsible process lacks Full Disk Access; grant it to the terminal app (or to zaafvesper when run as a launch daemon) in System Settings > Privacy & Security > Full Disk Access")
	ErrTooManyClients   = errors.New("eslogger: too many Endpoint Security clients already exist")
)

// Restart policy for an eslogger that exits unexpectedly.
const (
	maxRestartsPerMinute = 5
	initialBackoff       = time.Second
	maxBackoff           = 30 * time.Second
	stderrTail           = 8 << 10
)

// Config configures the eslogger source.
type Config struct {
	// Binary defaults to /usr/bin/eslogger. When running as root only the
	// default is accepted (Run fails otherwise): a root sensor must not
	// execute a replaceable binary.
	Binary string
	// ExcludePaths are directory prefixes whose file events are dropped as
	// early as possible. "/dev" matches "/dev" and "/dev/..." but not "/devil".
	ExcludePaths []string
	// ExcludeSigning are signing IDs whose events are dropped, but only for
	// Apple platform binaries (is_platform): a signing ID alone is chosen by
	// whoever signs the code, ad-hoc signers included, so it is forgeable.
	ExcludeSigning []string
	// OnStart, if set, is called with the eslogger child pid on every
	// (re)start, so the caller can protect that pid (e.g. from kill actions).
	OnStart func(pid int32)

	// SubscribeWrite also subscribes to the per-syscall "write" event when
	// WriteFile is wanted. By default WriteFile comes from "close" with
	// modified=true only, which yields one event per modified file instead
	// of one per write(2).
	SubscribeWrite bool
	// Logf receives operational messages (restarts). Nil discards them.
	Logf func(format string, args ...any)
}

// Source is the eslogger-backed event source.
type Source struct {
	cfg          Config
	excludeSig   map[string]bool
	excludePaths []string
	pid          atomic.Int32

	lines, decoded, ignored, decodeErrors, oversize atomic.Uint64
	excluded, sent, restarts                        atomic.Uint64
	seqGaps, missed                                 atomic.Uint64

	// lastSeq is the last global_seq_num seen from the current eslogger
	// (one ES client); 0 = none yet. Only the reading goroutine uses it.
	lastSeq  uint64
	degraded degradedHook
}

// OnDegraded registers fn to be told when events were lost before reaching
// ZAAFVesper: CondEventsDropped, when global_seq_num (per ES client, so per
// eslogger run) skips numbers. fn is called synchronously from the goroutine
// reading eslogger's output, at most once a minute (the next report counts
// the suppressed ones); it must not block. nil unregisters.
func (s *Source) OnDegraded(fn func(condition, detail string)) {
	s.degraded.set(fn)
}

// checkSeq tracks global_seq_num and reports gaps. A number that does not
// increase starts a new sequence (a new client after a restart).
func (s *Source) checkSeq(seq uint64) {
	if seq == 0 {
		return // not reported by this eslogger
	}
	last := s.lastSeq
	s.lastSeq = seq
	if last == 0 || seq <= last+1 {
		return
	}
	n := seq - last - 1
	s.seqGaps.Add(1)
	s.missed.Add(n)
	s.degraded.report(CondEventsDropped, "", fmt.Sprintf("missed %d events (global_seq_num %d to %d); %d missed in total", n, last+1, seq-1, s.missed.Load()))
}

// New returns an eslogger source.
func New(cfg Config) *Source {
	if cfg.Binary == "" {
		cfg.Binary = DefaultBinary
	}
	s := &Source{cfg: cfg, excludeSig: map[string]bool{}}
	for _, id := range cfg.ExcludeSigning {
		if id != "" {
			s.excludeSig[id] = true
		}
	}
	for _, p := range cfg.ExcludePaths {
		if p = normPrefix(p); p != "" {
			s.excludePaths = append(s.excludePaths, p)
		}
	}
	return s
}

// normPrefix cleans an exclusion prefix: absolute paths only, no trailing
// slash (except "/" itself).
func normPrefix(p string) string {
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	return filepath.Clean(p)
}

// validateBinary enforces the eslogger binary rules: absolute path to a
// regular file, and only DefaultBinary when running as root (euid 0).
func validateBinary(bin string, euid int) error {
	if euid == 0 && bin != DefaultBinary {
		return fmt.Errorf("eslogger: refusing to run %q as root; only %s is allowed", bin, DefaultBinary)
	}
	if !filepath.IsAbs(bin) {
		return fmt.Errorf("eslogger: binary %q must be an absolute path", bin)
	}
	fi, err := os.Stat(bin)
	if err != nil {
		return fmt.Errorf("eslogger: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("eslogger: %s is not a regular file", bin)
	}
	return nil
}

// PID returns the pid of the running eslogger child, or 0 when none runs.
func (s *Source) PID() int32 { return s.pid.Load() }

func (s *Source) Name() string { return "eslogger" }

// Stats reports counters: lines, decoded, ignored (valid but unmapped),
// decode_errors, oversize_lines, excluded (early drops), sent, restarts,
// seq_gaps and events_missed (global_seq_num gaps and the events in them).
func (s *Source) Stats() map[string]uint64 {
	return map[string]uint64{
		"lines":          s.lines.Load(),
		"decoded":        s.decoded.Load(),
		"ignored":        s.ignored.Load(),
		"decode_errors":  s.decodeErrors.Load(),
		"oversize_lines": s.oversize.Load(),
		"excluded":       s.excluded.Load(),
		"sent":           s.sent.Load(),
		"restarts":       s.restarts.Load(),
		"seq_gaps":       s.seqGaps.Load(),
		"events_missed":  s.missed.Load(),
	}
}

// Args returns the exact argv (without argv[0]) Run passes to eslogger for the
// given canonical events. Every element comes from a fixed internal table.
func (s *Source) Args(events []string) []string {
	if s.cfg.SubscribeWrite {
		return ESEventTypesWithWrite(events)
	}
	return ESEventTypes(events)
}

// Run starts eslogger subscribed to the given canonical events and streams
// decoded events to out until ctx is cancelled (returns nil) or eslogger
// fails in a way a restart cannot fix (returns the error).
func (s *Source) Run(ctx context.Context, events []string, out chan<- *event.Event) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("eslogger: unsupported OS %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	bin := s.cfg.Binary
	if err := validateBinary(bin, os.Geteuid()); err != nil {
		return err
	}
	args := s.Args(events)
	if len(args) == 0 {
		return errors.New("eslogger: none of the requested events is supported")
	}

	var recent []time.Time
	backoff := initialBackoff
	for {
		started := time.Now()
		err := s.runOnce(ctx, bin, args, out)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrNotRoot) || errors.Is(err, ErrNoFullDiskAccess) || errors.Is(err, ErrTooManyClients) {
			return err
		}
		now := time.Now()
		if now.Sub(started) > time.Minute {
			backoff = initialBackoff
		}
		kept := recent[:0]
		for _, t := range recent {
			if now.Sub(t) < time.Minute {
				kept = append(kept, t)
			}
		}
		recent = kept
		if len(recent) >= maxRestartsPerMinute {
			return fmt.Errorf("eslogger: exited %d times within a minute, giving up: %w", len(recent)+1, err)
		}
		recent = append(recent, now)
		s.restarts.Add(1)
		s.logf("eslogger exited unexpectedly (%v); restarting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (s *Source) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// runOnce runs one eslogger process to completion.
func (s *Source) runOnce(ctx context.Context, bin string, args []string, out chan<- *event.Event) error {
	// Fixed argv, no shell. A minimal environment so nothing like DYLD_* from
	// the invoking shell reaches a root child. eslogger stays in ZAAFVesper's
	// process group on purpose: it suppresses events from its own process
	// group, which keeps ZAAFVesper's own file writes out of the stream.
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"}
	cmd.Dir = "/"
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	stderr := &tailBuffer{max: stderrTail}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("eslogger: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("eslogger: start: %w", err)
	}
	pid := int32(cmd.Process.Pid)
	s.pid.Store(pid)
	defer s.pid.CompareAndSwap(pid, 0)
	if s.cfg.OnStart != nil {
		s.cfg.OnStart(pid)
	}
	s.lastSeq = 0 // a new ES client numbers its messages afresh
	streamErr := s.consume(ctx, stdout, out)
	if streamErr != nil {
		// Stop eslogger if we stopped reading for any reason but ctx.
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if e := classifyStderr(stderr.String()); e != nil {
		return e
	}
	msg := strings.TrimSpace(stderr.String())
	switch {
	case streamErr != nil:
		return fmt.Errorf("eslogger: reading output: %w", streamErr)
	case waitErr != nil && msg != "":
		return fmt.Errorf("eslogger: %w: %s", waitErr, msg)
	case waitErr != nil:
		return fmt.Errorf("eslogger: %w", waitErr)
	case msg != "":
		return fmt.Errorf("eslogger: exited: %s", msg)
	}
	return errors.New("eslogger: exited with status 0")
}

// classifyStderr maps eslogger's es_new_client failure messages to errors
// that are not worth retrying.
func classifyStderr(s string) error {
	switch {
	case strings.Contains(s, "ERR_NOT_PERMITTED") || strings.Contains(s, "Full Disk Access"):
		return fmt.Errorf("%w (eslogger said: %s)", ErrNoFullDiskAccess, firstLine(s))
	case strings.Contains(s, "ERR_NOT_PRIVILEGED"):
		return fmt.Errorf("%w (eslogger said: %s)", ErrNotRoot, firstLine(s))
	case strings.Contains(s, "ERR_TOO_MANY_CLIENTS"):
		return fmt.Errorf("%w (eslogger said: %s)", ErrTooManyClients, firstLine(s))
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

// consume reads JSON lines from r until EOF, decoding, filtering and
// forwarding each. Lines longer than MaxLineSize are skipped and counted.
func (s *Source) consume(ctx context.Context, r io.Reader, out chan<- *event.Event) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var buf []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			if !tooLong {
				if len(buf)+len(chunk) > MaxLineSize+1 {
					tooLong, buf = true, buf[:0]
				} else {
					buf = append(buf, chunk...)
				}
			}
		}
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err != nil && err != io.EOF:
			return err
		}
		// A full line (or the final unterminated line at EOF).
		if tooLong {
			s.oversize.Add(1)
			tooLong = false
		} else if len(bytes.TrimSpace(buf)) > 0 {
			if !s.handleLine(ctx, buf, out) {
				return nil
			}
		}
		if cap(buf) > 4<<20 {
			buf = nil // do not pin a huge buffer after one big exec line
		} else {
			buf = buf[:0]
		}
		if err == io.EOF {
			return nil
		}
	}
}

// handleLine decodes and forwards one line; false means ctx was cancelled.
func (s *Source) handleLine(ctx context.Context, line []byte, out chan<- *event.Event) bool {
	s.lines.Add(1)
	var seq uint64
	e, ok, err := decode(line, &seq)
	if err == nil {
		s.checkSeq(seq) // ignored lines count too: they used a number
	}
	switch {
	case err != nil:
		s.decodeErrors.Add(1)
		return true
	case !ok:
		s.ignored.Add(1)
		return true
	}
	s.decoded.Add(1)
	if s.Excluded(e) {
		s.excluded.Add(1)
		return true
	}
	select {
	case out <- e:
		s.sent.Add(1)
		return true
	case <-ctx.Done():
		return false
	}
}

// Excluded reports whether the early ExcludePaths / ExcludeSigning filters
// drop e. Process lifecycle events (CreateProcess, Fork, TerminateProcess)
// are never dropped, because the process snapshotter needs every one of them
// to keep parent and ancestor information correct.
func (s *Source) Excluded(e *event.Event) bool {
	switch e.Name {
	case event.CreateProcess, event.Fork, event.TerminateProcess:
		return false
	}
	if e.Proc != nil && e.Proc.IsPlatform && s.excludeSig[e.Proc.SigningID] {
		return true
	}
	if e.File != nil && event.Category(e.Name) == "file" && len(s.excludePaths) > 0 {
		if !s.pathExcluded(e.File.Path) {
			return false
		}
		// A rename out of an excluded area into a watched one must survive.
		return e.File.Dest == "" || s.pathExcluded(e.File.Dest)
	}
	return false
}

func (s *Source) pathExcluded(p string) bool {
	if p == "" {
		return false
	}
	for _, pre := range s.excludePaths {
		if pre == "/" || p == pre || (strings.HasPrefix(p, pre) && p[len(pre)] == '/') {
			return true
		}
	}
	return false
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = append(t.b[:0], t.b[len(t.b)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}
