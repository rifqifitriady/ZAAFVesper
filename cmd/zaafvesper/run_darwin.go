//go:build darwin

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
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/eslogger"
)

// liveHint tells a terminal user how live mode is meant to run.
var liveHint = "For live use install the package and load the LaunchDaemon: sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/" + daemonLabel + ".plist"

// checkPrivileges: run needs root, because eslogger does.
func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("needs root, because eslogger does (sudo zaafvesper run). Use 'zaafvesper replay' to test rules without root.")
	}
	return nil
}

// runAsService: macOS runs under launchd as a normal process.
func runAsService(runOptions, io.Writer, io.Writer) (int, bool) { return 0, false }

// ignoreJobControlSignals keeps a terminal from stopping or pausing the
// sensor: SIGHUP (terminal closed), SIGTSTP (^Z), SIGTTIN and SIGTTOU
// (background terminal I/O). SIGINT and SIGTERM still shut it down cleanly.
// The ignored dispositions are inherited by the eslogger child.
func ignoreJobControlSignals() {
	signal.Ignore(syscall.SIGHUP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
}

// stdinIsTerminal reports whether standard input is a terminal (run started
// from a shell rather than by launchd).
func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
	return err == nil
}

// checkSourceBinary refuses any eslogger binary but the system one as root.
func checkSourceBinary(cfg *config.Config) error { return pinnedEslogger(cfg.Eslogger.Binary) }

// newSource builds the eslogger source.
func newSource(cfg *config.Config, p *pipeline, stderr io.Writer) source.Source {
	return eslogger.New(eslogger.Config{
		Binary:         cfg.Eslogger.Binary,
		ExcludePaths:   cfg.Eslogger.ExcludePaths,
		ExcludeSigning: cfg.Eslogger.ExcludeSigning,
		SubscribeWrite: cfg.Source.SubscribeWrite,
		// Protect each eslogger child by pid as soon as it (re)starts.
		OnStart: func(pid int32) {
			if p.responder != nil {
				p.responder.Protect(pid)
			}
		},
		Logf: func(format string, args ...any) {
			say(stderr, "eslogger: %s", fmt.Sprintf(format, args...))
		},
	})
}

// platformOutputCheck: every output works here.
func platformOutputCheck(*netOutOptions) error { return nil }
