//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/ebpf"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/sysmonlinux"
)

var liveHint = "For live use install the systemd unit in packaging/linux and run: sudo systemctl enable --now zaafvesper"

// Event sources on Linux (--source).
const (
	sourceEBPF   = "ebpf"
	sourceSysmon = "sysmon"
)

// linuxSource is the --source value. The default is the eBPF source, which
// needs no Sysmon. There is no automatic fallback: when the eBPF programs
// cannot run, run stops and says to use --source sysmon, so a sensor never
// silently runs on other telemetry than the one it was set up for.
var linuxSource = sourceEBPF

func registerSourceFlag(fs *flag.FlagSet) {
	linuxSource = sourceEBPF
	fs.Func("source", "event source: ebpf (kernel programs, no Sysmon needed; the default) or sysmon (Sysmon for Linux through the system journal)", func(v string) error {
		switch v {
		case sourceEBPF, sourceSysmon:
			linuxSource = v
			return nil
		}
		return fmt.Errorf("unknown source %q: use ebpf or sysmon", v)
	})
}

// checkPrivileges: run needs root to load the eBPF programs (or read the
// system journal), to read /proc of every process and to kill.
func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("needs root (eBPF programs or the system journal, /proc and kill). Use 'zaafvesper replay' to test rules without root.")
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

// checkSourceBinary: with --source sysmon, as root, journalctl and every
// directory above it must be root-owned and not group/world writable, like
// the rules and config. The eBPF source runs no other program.
func checkSourceBinary(*config.Config) error {
	if linuxSource != sourceSysmon {
		return nil
	}
	if err := config.CheckOwnership(sysmonlinux.Journalctl); err != nil {
		return fmt.Errorf("%s is not safe to run as root:\n%w", sysmonlinux.Journalctl, err)
	}
	return nil
}

// newSource builds the eBPF source, or with --source sysmon the journald
// source for Sysmon for Linux. The current journalctl child is protected
// from kills through the responder's DynamicPIDs (the source's PID method),
// only while it runs, so a pid it leaves behind after a restart is not
// protected forever.
func newSource(_ *config.Config, _ *pipeline, stderr io.Writer) source.Source {
	if linuxSource == sourceEBPF {
		return ebpf.New(ebpf.Config{
			Logf: func(format string, args ...any) {
				say(stderr, "%s", fmt.Sprintf(format, args...))
			},
		})
	}
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
