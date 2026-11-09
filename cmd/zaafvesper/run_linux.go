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
