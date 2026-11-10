//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmonlinux"
)

var liveHint = "For live use install the systemd unit in packaging/linux and run: sudo systemctl enable --now zaafvesper"

// checkPrivileges: run needs root to read the system journal, /proc of
// every process and to kill.
func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("needs root (system journal, /proc and kill). Use 'zaafvesper replay' to test rules without root.")
	}
	return nil
}

func runAsService(runOptions, io.Writer, io.Writer) (int, bool) { return 0, false }

func ignoreJobControlSignals() {
	signal.Ignore(syscall.SIGHUP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
}

func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

// checkSourceBinary: as root, journalctl and every directory above it must
// be root-owned and not group/world writable, like the rules and config.
func checkSourceBinary(*config.Config) error {
	if err := config.CheckOwnership(sysmonlinux.Journalctl); err != nil {
		return fmt.Errorf("%s is not safe to run as root:\n%w", sysmonlinux.Journalctl, err)
	}
	return nil
}

// newSource builds the journald source for Sysmon for Linux. The current
// journalctl child is protected from kills through the responder's
// DynamicPIDs (the source's PID method), only while it runs, so a pid it
// leaves behind after a restart is not protected forever.
func newSource(_ *config.Config, _ *pipeline, stderr io.Writer) source.Source {
	return sysmonlinux.New(sysmonlinux.Config{
		Logf: func(format string, args ...any) {
			say(stderr, "sysmon: %s", fmt.Sprintf(format, args...))
		},
	})
}

// platformOutputCheck: every output works here.
func platformOutputCheck(*netOutOptions) error { return nil }

// firewallAvailable: isolate_process uses an nftables table.
const firewallAvailable = true

// ownServicePaths are the sensor's systemd unit and configuration
// directory: never quarantined or removed.
var ownServicePaths = []string{"/etc/systemd/system/zaafvesper.service", "/lib/systemd/system/zaafvesper.service",
	"/usr/lib/systemd/system/zaafvesper.service", "/etc/zaafvesper"}

// supportedActions are the response actions implemented on Linux; only
// requarantine (it sets com.apple.quarantine) is macOS only and refused
// with a clear reason.
var supportedActions = map[string]bool{rules.ActionKill: true, rules.ActionSuspend: true, rules.ActionQuarantineFile: true,
	rules.ActionRemovePersistence: true, rules.ActionIsolateProcess: true}

func unsupportedAction(name string) string {
	if supportedActions[name] {
		return ""
	}
	return "action " + name + " is not supported on Linux (macOS only)"
}
