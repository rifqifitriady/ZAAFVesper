//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/winevt"
)

// serviceName is the Windows service name (packaging/windows/README.md).
const serviceName = "ZAAFVesper"

var liveHint = "For live use install the Windows service (packaging/windows/README.md): sc.exe start " + serviceName

// checkPrivileges: reading the Sysmon channel, every process and killing
// need an elevated token (an administrator, or the LocalSystem service).
func checkPrivileges() error {
	tok := windows.GetCurrentProcessToken()
	if tok.IsElevated() {
		return nil
	}
	if u, err := tok.GetTokenUser(); err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return errors.New("needs an elevated administrator or the LocalSystem service account (the Sysmon event log channel requires it). Use 'zaafvesper replay' to test rules without it.")
}

func ignoreJobControlSignals() {}

// stdinIsTerminal reports whether standard input is a console.
func stdinIsTerminal() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}

// checkSourceBinary: the event log API is part of Windows; nothing to pin.
func checkSourceBinary(*config.Config) error { return nil }

// newSource builds the Windows event log source for Sysmon.
func newSource(_ *config.Config, _ *pipeline, stderr io.Writer) source.Source {
	return winevt.New(winevt.Config{Logf: func(format string, args ...any) {
		say(stderr, "sysmon: %s", fmt.Sprintf(format, args...))
	}})
}

// maxServiceLog bounds service.log; a larger one is moved to service.log.old
// at start.
const maxServiceLog = 64 << 20

// runAsService runs the sensor under the Service Control Manager when the
// process was started as a Windows service. A service has no console, so
// stdout alerts are off and messages go to <output-dir>\service.log; the
// service must therefore be configured with --output-dir.
func runAsService(o runOptions, stdout, stderr io.Writer) (int, bool) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return 0, false
	}
	if o.outputDir == "" {
		return 2, true // nowhere to write: the SCM reports the exit code
	}
	o.noConsole = true
	logw, err := openServiceLog(o.outputDir)
	if err != nil {
		return 1, true
	}
	defer logw.Close()
	h := &serviceHandler{o: o, stdout: io.Discard, log: logw}
	if err := svc.Run(serviceName, h); err != nil {
		say(logw, "zaafvesper service: %v", err)
		return 1, true
	}
	return h.code, true
}

func openServiceLog(dir string) (*os.File, error) {
	od, err := openOutputDir(dir, true)
	if err != nil {
		return nil, err
	}
	defer od.close()
	p := filepath.Join(od.path, "service.log")
	if size, ok := od.regularSize("service.log"); ok && size > maxServiceLog {
		_ = os.Remove(p + ".old")
		_ = os.Rename(p, p+".old")
	}
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

type serviceHandler struct {
	o      runOptions
	stdout io.Writer
	log    io.Writer
	code   int
}

// Execute implements svc.Handler: the sensor runs until Stop or Shutdown.
func (h *serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runSensor(ctx, h.o, h.stdout, h.log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				sayLines(h.log, "zaafvesper run: ", err.Error())
				h.code = 1
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						sayLines(h.log, "zaafvesper run: ", err.Error())
					}
				case <-time.After(20 * time.Second):
					say(h.log, "zaafvesper service: shutdown timed out")
				}
				return false, 0
			}
		}
	}
}

// platformOutputCheck refuses, at start-up and with a clear message, the
// outputs that cannot work on Windows yet: syslog and webhook forwarders and
// the ZAAFElegia/OCSF files are built on the Unix-only spool and append
// files (pkg/output/spool_windows.go), and a service has no stdout for
// --elegia-out -. Alerts still go to --output-dir.
func platformOutputCheck(n *netOutOptions) error {
	switch {
	case n.syslogAddr != "", n.webhookURL != "":
		return errors.New("--syslog and --webhook are not available on Windows yet (they need the on-disk spool); use --output-dir")
	case n.alertsOCSF != "":
		return errors.New("--alerts-ocsf is not available on Windows yet; use --output-dir")
	case n.elegiaOut != "" && n.elegiaOut != "-":
		return errors.New("--elegia-out FILE is not available on Windows yet; use --elegia-out - from a console")
	case n.elegiaOut == "-":
		if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
			return errors.New("--elegia-out - writes to stdout, which a Windows service does not have")
		}
	}
	return nil
}

// firewallAvailable: isolate_process uses Windows Firewall rules (netsh).
const firewallAvailable = true

// ownServicePaths: the sensor's files live under Program Files (protected)
// and the state directory (added by the responder).
var ownServicePaths []string

// supportedActions are the response actions implemented on Windows; only
// requarantine (it sets com.apple.quarantine) is macOS only and refused
// with a clear reason.
var supportedActions = map[string]bool{rules.ActionKill: true, rules.ActionSuspend: true, rules.ActionQuarantineFile: true,
	rules.ActionRemovePersistence: true, rules.ActionIsolateProcess: true}

func unsupportedAction(name string) string {
	if supportedActions[name] {
		return ""
	}
	return "action " + name + " is not supported on Windows (macOS only)"
}
