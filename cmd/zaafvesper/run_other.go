//go:build !darwin && !windows && !linux

package main

import (
	"errors"
	"flag"
	"io"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
)

// Other platforms (e.g. FreeBSD) have no event source: replay, rules and
// coverage work, run does not.

var liveHint = ""

func checkPrivileges() error {
	return errors.New("live mode is only available on macOS, Windows and Linux; use 'zaafvesper replay'")
}

func runAsService(runOptions, io.Writer, io.Writer) (int, bool) { return 0, false }

func ignoreJobControlSignals() {}

func stdinIsTerminal() bool { return false }

func checkSourceBinary(*config.Config) error { return nil }

func newSource(*config.Config, *pipeline, io.Writer) source.Source { return nil }

// platformOutputCheck: every output works here.
func platformOutputCheck(*netOutOptions) error { return nil }

// pfAvailable: pf (isolate_process) is macOS only.
const pfAvailable = false

// supportedActions are the response actions implemented on this platform; the
// others (quarantine_file, requarantine, remove_persistence and
// isolate_process use the quarantine attribute, launchctl and pf) are macOS
// only and are refused with a clear reason.
var supportedActions = map[string]bool{}

func unsupportedAction(name string) string {
	if supportedActions[name] {
		return ""
	}
	return "action " + name + " is not supported on this platform (macOS only)"
}

// registerSourceFlag: only one event source here, so there is no --source.
func registerSourceFlag(*flag.FlagSet) {}
