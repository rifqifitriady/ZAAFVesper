//go:build zaafvesper_validate

package main

// `zaafvesper validate-response` is the LIVE VALIDATION HARNESS of the
// response actions (v0.3 workstream D, docs/validation/response.md). It is
// not part of the normal CLI: it is compiled in only with the build tag
// zaafvesper_validate (release and package builds never have it), it is not
// in the usage text, and it refuses to run unless the environment variable
// ZAAFVESPER_VALIDATE_RESPONSE is "throwaway-runner" on a GitHub-hosted
// runner (GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted), with root
// (or an elevated administrator on Windows), and with no ZAAFVesper
// installed (platformAccidentGuard). These are guards against an accident,
// not a security boundary: the binary that has them is never shipped.
//
// It drives the real responder of pkg/response with no stubs: real signals,
// the real kernel identity reads, the real quarantine vault, /bin/launchctl
// and /sbin/pfctl, and the real `quarantine` and `isolation` subcommands.
// No event source runs on the runner, so each test event is built from the
// kernel's own identity of a process the harness started itself (a copy of
// this binary, `validate-response sleeper`). Every target is something the
// harness created: its own child processes, files in its own temporary
// directory, launch items labelled com.rifqifitriady.zaafvesper-validate.*,
// and documentation or loopback-alias addresses for pf. It changes nothing
// else, and it removes what it created when it ends.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

const (
	validateGuardEnv   = "ZAAFVESPER_VALIDATE_RESPONSE"
	validateGuardValue = "throwaway-runner"
	maxSleeper         = 10 * time.Minute
)

// Verdicts of docs/validation/response.md.
const (
	vActed     = "acted"
	vRefused   = "refused correctly"
	vFailed    = "failed"
	vUntested  = "not testable"
	expectAct  = "act"
	expectDeny = "refuse"
)

type vResult struct {
	Action  string `json:"action"`
	Case    string `json:"case"`
	Expect  string `json:"expect"`
	Outcome string `json:"outcome"`
	Verdict string `json:"verdict"`
	Detail  string `json:"detail"`
}

type vSubject struct {
	cmd  *exec.Cmd
	pid  int32
	done chan struct{}
}

func (s *vSubject) exited(within time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(within):
		return false
	}
}

type vHarness struct {
	dir     string // temporary directory: test files and the subject binary
	self    string // this binary
	subject string // the copy that runs as test process
	r       *response.Responder
	mu      sync.Mutex
	last    response.Decision
	logs    []string
	results []vResult
	subs    []*vSubject
	cleanup []func()
	// pfWasEnabled: pf's state before the run (macOS).
	pfWasEnabled bool
	closeOnce    sync.Once
	stdout       io.Writer
}

func init() { hiddenCommands["validate-response"] = cmdValidateResponse }

// validateGuard refuses unless this is a throw-away GitHub-hosted runner.
func validateGuard() error {
	switch {
	case os.Getenv(validateGuardEnv) != validateGuardValue:
		return errors.New("zaafvesper validate-response is the live validation harness of the response actions: it kills, suspends and quarantines test objects and changes pf and launchd. It runs only on a throw-away GitHub-hosted runner (set up by .github/workflows/live-response.yml)")
	case os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted":
		return errors.New("zaafvesper validate-response runs only on a GitHub-hosted runner (GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted)")
	}
	return nil
}

func cmdValidateResponse(args []string, stdout, stderr io.Writer) (code int) {
	if err := validateGuard(); err != nil {
		say(stderr, "%v", err)
		return 2
	}
	if len(args) > 0 && args[0] == "sleeper" {
		return validateSleeper(args[1:], stderr)
	}
	// The harness itself also refuses where ZAAFVesper is installed: it
	// would flush the live sensor's pf anchor and write into its vault.
	if err := platformAccidentGuard(); err != nil {
		say(stderr, "zaafvesper validate-response: %v", err)
		return 2
	}
	fs := newFlagSet("validate-response")
	out := fs.String("out", "", "write the results as JSON to this file")
	if !parseFlags(fs, args, stderr) {
		return 2
	}
	if err := checkPrivileges(); err != nil {
		say(stderr, "zaafvesper validate-response: %v", err)
		return 1
	}
	say(stdout, "=== ZAAFVesper LIVE VALIDATION HARNESS (response actions, %s/%s) ===", runtime.GOOS, runtime.GOARCH)
	h, err := newVHarness(stdout)
	if err != nil {
		say(stderr, "zaafvesper validate-response: %v", err)
		return 1
	}
	// A cancel (SIGINT, SIGTERM) or a panic still cleans up and reports.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() {
		if _, ok := <-stop; ok {
			say(stderr, "zaafvesper validate-response: interrupted; cleaning up")
			h.close()
			os.Exit(1)
		}
	}()
	func() {
		defer func() {
			if p := recover(); p != nil {
				h.results = append(h.results, vResult{Action: "harness", Case: "panic", Verdict: vFailed, Detail: fmt.Sprint(p)})
				say(stderr, "zaafvesper validate-response: panic: %v", p)
			}
		}()
		h.runCommon()
		h.runPlatform()
	}()
	h.close()
	h.writeTable(stdout)
	if *out != "" {
		b, _ := json.MarshalIndent(h.results, "", "  ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			say(stderr, "zaafvesper validate-response: %v", err)
			return 1
		}
	}
	for _, r := range h.results {
		if r.Verdict == vFailed {
			return 1
		}
	}
	return 0
}

// validateSleeper is the test process: it sleeps (at most maxSleeper), and
// with --exec-sleep-after it replaces itself with /bin/sleep after that
// delay (the exec-into-platform case). No other program can be run.
func validateSleeper(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sleeper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	d := fs.Duration("for", 2*time.Minute, "")
	after := fs.Duration("exec-sleep-after", -1, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *d > maxSleeper {
		*d = maxSleeper
	}
	if *after >= 0 {
		time.Sleep(min(*after, time.Minute))
		if err := sysExec("/bin/sleep", []string{"/bin/sleep", "120"}); err != nil {
			say(stderr, "sleeper: exec /bin/sleep: %v", err)
			return 1
		}
	}
	time.Sleep(*d)
	return 0
}

func newVHarness(stdout io.Writer) (*vHarness, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(validateTempRoot(), "zaafvesper-validate-")
	if err != nil {
		return nil, err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return nil, err
	}
	h := &vHarness{dir: dir, self: self, stdout: stdout}
	h.subject = filepath.Join(dir, "zv-subject"+exeSuffix())
	b, err := os.ReadFile(self)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(h.subject, b, 0o755); err != nil {
		return nil, err
	}
	rc := response.Config{
		Log: func(d response.Decision) {
			h.mu.Lock()
			h.last = d
			h.logs = append(h.logs, d.String())
			h.mu.Unlock()
			say(stdout, "    %s", d.String())
		},
		// Many cases run in one minute: the budgets are raised so that a
		// case is never refused for budget reasons (the budgets themselves
		// are covered by the unit tests).
		MaxPerRulePerMinute: 1000, MaxPerMinute: 1000,
		SuspendFor:       3 * time.Second,
		RequireRootOwned: runtime.GOOS != "windows",
		ProtectPaths:     []string{self},
	}
	h.platformConfig(&rc)
	h.r = response.New(rc)
	return h, nil
}

// close stops every test process still running, runs the platform cleanup
// and removes the temporary directory. It runs once.
func (h *vHarness) close() {
	h.closeOnce.Do(h.doClose)
}

func (h *vHarness) doClose() {
	for i := len(h.cleanup) - 1; i >= 0; i-- {
		h.cleanup[i]()
	}
	for _, s := range h.subs {
		select {
		case <-s.done:
		default:
			_ = s.cmd.Process.Kill()
			<-s.done
		}
	}
	_ = os.RemoveAll(h.dir)
}

// spawn starts a test process (the subject copy in sleeper mode) and waits
// until the kernel reports its identity.
func (h *vHarness) spawn(extra ...string) (*vSubject, error) {
	args := append([]string{"validate-response", "sleeper", "--for", "3m"}, extra...)
	return h.spawnCmd(exec.Command(h.subject, args...))
}

func (h *vHarness) spawnCmd(c *exec.Cmd) (*vSubject, error) {
	c.Stdout, c.Stderr = io.Discard, io.Discard
	if err := c.Start(); err != nil {
		return nil, err
	}
	s := &vSubject{cmd: c, pid: int32(c.Process.Pid), done: make(chan struct{})}
	go func() { _ = c.Wait(); close(s.done) }()
	h.subs = append(h.subs, s)
	for i := 0; i < 50; i++ {
		if _, err := response.KernelIdentity(s.pid); err == nil {
			return s, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s, fmt.Errorf("pid %d: no kernel identity", s.pid)
}

// procOf builds an event process from the kernel's identity of pid, as the
// process table would have recorded it.
func procOf(pid int32) (*event.Proc, error) {
	id, err := response.KernelIdentity(pid)
	if err != nil {
		return nil, err
	}
	me := int64(os.Geteuid())
	p := &event.Proc{PID: pid, PPID: int32(os.Getpid()), Exe: id.Exe, Name: filepath.Base(id.Exe), StartTime: id.StartTime,
		UniqueID: id.UniqueID, UID: me, EUID: me, IsPlatform: id.PlatformBinary(), IsSigned: id.PlatformBinary()}
	return p, nil
}

// source is the event source the host's events would come from.
func vSource() string {
	if runtime.GOOS == "darwin" {
		return response.ESSource
	}
	return "sysmon"
}

func (h *vHarness) decision() response.Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}

func (h *vHarness) reset() {
	h.mu.Lock()
	h.last = response.Decision{}
	h.mu.Unlock()
}

// record adds a result. ok is the harness's own check of the system state
// (process gone, file moved, ...); outcome is the responder's decision.
func (h *vHarness) record(action, kase, expect string, ok bool, detail string) {
	d := h.decision()
	v := vFailed
	switch {
	case ok && expect == expectAct:
		v = vActed
	case ok:
		v = vRefused
	}
	if d.Detail != "" {
		detail = strings.TrimSpace(detail + " | decision: " + d.Detail)
	}
	r := vResult{Action: action, Case: kase, Expect: expect, Outcome: d.Outcome, Verdict: v, Detail: detail}
	h.results = append(h.results, r)
	say(h.stdout, "[%s] %s / %s: outcome=%s %s", strings.ToUpper(v), action, kase, d.Outcome, detail)
}

func (h *vHarness) untestable(action, kase, why string) {
	h.results = append(h.results, vResult{Action: action, Case: kase, Verdict: vUntested, Detail: why})
	say(h.stdout, "[NOT TESTABLE] %s / %s: %s", action, kase, why)
}

// writeTable prints the results as a Markdown table (for the job summary).
func (h *vHarness) writeTable(w io.Writer) {
	say(w, "")
	say(w, "| Action | Case | Expected | Outcome | Result | Detail |")
	say(w, "|---|---|---|---|---|---|")
	for _, r := range h.results {
		detail := strings.ReplaceAll(r.Detail, "|", "/")
		if len(detail) > 300 {
			detail = detail[:300] + "..."
		}
		say(w, "| %s | %s | %s | %s | %s | %s |", r.Action, r.Case, r.Expect, r.Outcome, r.Verdict, detail)
	}
}

// runCommon runs the kill cases every platform supports, and suspend where
// the platform has it.
func (h *vHarness) runCommon() {
	say(h.stdout, "--- kill")
	// Acted: the process of the event, verified by the kernel identity.
	if s, err := h.spawn(); err != nil {
		h.untestable("kill", "subject process", err.Error())
	} else if p, err := procOf(s.pid); err != nil {
		h.untestable("kill", "kernel identity", err.Error())
	} else {
		h.reset()
		err := h.r.KillEvent(&event.Event{Source: vSource(), Proc: p}, "validate-kill", "validation: kill")
		gone := s.exited(5 * time.Second)
		h.record("kill", "test process, identity verified", expectAct, err == nil && gone && h.decision().Outcome == response.OutcomeKilled,
			fmt.Sprintf("pid %d exited=%v", s.pid, gone))
	}
	// Refused: the kernel unique id (start stamp) no longer matches.
	h.killRefused("kernel unique id differs (pid reused)", func(p *event.Proc) { p.UniqueID++ }, response.OutcomeMismatch)
	// Refused: the start time does not match.
	h.killRefused("start time differs", func(p *event.Proc) { p.StartTime = p.StartTime.Add(-2 * time.Second) }, response.OutcomeMismatch)
	// Refused: ZAAFVesper's own process (its pid is protected before any
	// kernel read; on Windows the kernel read also refuses its image).
	self := &event.Proc{PID: int32(os.Getpid()), Exe: h.self, Name: filepath.Base(h.self), UniqueID: 1, StartTime: time.Now()}
	if p, err := procOf(self.PID); err == nil {
		self = p
	}
	h.reset()
	err := h.r.KillEvent(&event.Event{Source: vSource(), Proc: self}, "validate-kill", "validation: kill self")
	h.record("kill", "the sensor's own process", expectDeny, errors.Is(err, response.ErrProtected), "")
	// Refused: pid 1 (launchd, init) or the Windows System process.
	pid := int32(1)
	if runtime.GOOS == "windows" {
		pid = 4
	}
	h.reset()
	err = h.r.KillEvent(&event.Event{Source: vSource(), Proc: &event.Proc{PID: pid, Exe: "system", UniqueID: 1, StartTime: time.Now()}}, "validate-kill", "validation: kill system")
	h.record("kill", fmt.Sprintf("system process (pid %d)", pid), expectDeny, err != nil && strings.HasPrefix(h.decision().Outcome, "refused-"), "")

	say(h.stdout, "--- suspend")
	if runtime.GOOS == "windows" {
		h.untestable("suspend", "all cases", "Windows has no SIGSTOP; the suspend action is refused before the responder (run_windows.go supportedActions)")
		return
	}
	if s, err := h.spawn(); err != nil {
		h.untestable("suspend", "subject process", err.Error())
	} else if p, err := procOf(s.pid); err != nil {
		h.untestable("suspend", "kernel identity", err.Error())
	} else {
		h.reset()
		err := h.r.SuspendEvent(&event.Event{Source: vSource(), Proc: p}, "validate-suspend", "validation: suspend")
		stopped := waitState(s.pid, true, 3*time.Second)
		h.record("suspend", "SIGSTOP of the test process", expectAct, err == nil && stopped && h.decision().Outcome == response.OutcomeSuspended,
			fmt.Sprintf("stopped=%v", stopped))
		time.Sleep(3500 * time.Millisecond)
		h.reset()
		h.r.Tick(time.Now())
		running := waitState(s.pid, false, 3*time.Second)
		h.record("suspend", "automatic resume after suspend_for (3 s)", expectAct, running && h.decision().Outcome == response.OutcomeResumed,
			fmt.Sprintf("running again=%v", running))
	}
	if s, err := h.spawn(); err != nil {
		h.untestable("suspend", "then kill", err.Error())
	} else if p, err := procOf(s.pid); err == nil {
		e := &event.Event{Source: vSource(), Proc: p}
		_ = h.r.SuspendEvent(e, "validate-suspend", "validation: suspend then kill")
		h.reset()
		err := h.r.KillEvent(e, "validate-suspend", "validation: suspend then kill")
		gone := s.exited(5 * time.Second)
		h.record("suspend", "suspend then kill (no resume afterwards)", expectAct, err == nil && gone && len(h.r.Suspended()) == 0,
			fmt.Sprintf("exited=%v pending resumes=%d", gone, len(h.r.Suspended())))
	}
	// Refused: a suspend of a process whose identity no longer matches.
	if s, err := h.spawn(); err == nil {
		if p, err := procOf(s.pid); err == nil {
			p.UniqueID++
			h.reset()
			err := h.r.SuspendEvent(&event.Event{Source: vSource(), Proc: p}, "validate-suspend", "validation: suspend mismatch")
			stopped := waitState(s.pid, true, time.Second)
			h.record("suspend", "kernel unique id differs", expectDeny, errors.Is(err, response.ErrMismatch) && !stopped, fmt.Sprintf("stopped=%v", stopped))
		}
	}
}

// killRefused starts a test process, alters its event identity with mod,
// and expects the kill to be refused with outcome and the process alive.
func (h *vHarness) killRefused(kase string, mod func(*event.Proc), outcome string) {
	s, err := h.spawn()
	if err != nil {
		h.untestable("kill", kase, err.Error())
		return
	}
	p, err := procOf(s.pid)
	if err != nil {
		h.untestable("kill", kase, err.Error())
		return
	}
	mod(p)
	h.reset()
	_ = h.r.KillEvent(&event.Event{Source: vSource(), Proc: p}, "validate-kill", "validation: "+kase)
	alive := !s.exited(time.Second)
	h.record("kill", kase, expectDeny, alive && h.decision().Outcome == outcome, fmt.Sprintf("process still alive=%v", alive))
}

// runSelf runs this binary's normal CLI (quarantine, isolation) as a child
// and returns its combined output.
func (h *vHarness) runSelf(args ...string) (string, error) {
	out, err := exec.Command(h.self, args...).CombinedOutput()
	return string(out), err
}
