// Command artrun drives the live validation of workstream B (v0.3) on the
// Windows and Linux GitHub runners. It is CI tooling, not part of the
// sensor.
//
//	artrun run    -plan P -atomics DIR -out results.json
//	artrun report -plan P -results results.json -alerts DIR -rules DIR -platform windows|linux -run-url URL -out FILE.md
//
// run executes, in order, the tests of a plan: Atomic Red Team tests,
// taken verbatim from the pinned and hash-checked atomics YAML (the
// executor command with its input arguments at their defaults; no
// prerequisites are fetched), and documented inline equivalents for rules
// whose Atomic test needs a download or acts on something that must not be
// touched. report matches the sensor's alerts against the plan and writes
// one line per rule: fired, did not fire, or not tested (with the reason).
//
// Invoke-AtomicRedTeam is not used: it installs powershell-yaml from the
// PowerShell Gallery at whatever version is current, which the v0.3 rule
// "downloads are pinned and verified by hash" forbids.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: artrun run|report ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "artrun:", err)
		os.Exit(1)
	}
}
