//go:build !darwin && !windows && !linux

package main

import (
	"errors"
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
