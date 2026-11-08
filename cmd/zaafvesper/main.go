// Command zaafvesper is a macOS behaviour-detection sensor in the style of
// Fibratus: eslogger events -> process snapshot -> rules -> alerts.
package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/yara"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

// Default locations; `make package` sets them to /usr/local/etc/zaafvesper/... with
// -ldflags "-X main.defaultRulesDir=... -X main.defaultConfigPath=...".
var (
	defaultRulesDir   = "rules"
	defaultConfigPath = "configs/zaafvesper.yml"
)

const usage = `zaafvesper — macOS behaviour-detection sensor

usage:
  zaafvesper run [--rules dir] [--config file] [--capture out.rcap] [--capture-max-bytes n]
            [--json alerts.jsonl | --output-dir dir [--capture-in-dir] [--json-keep 8] [--capture-keep 2]]
            [--json-max-bytes n] [--keep-env] [--enable-response] [--dry-run-response]
            [--no-yara] [--dedup-window 10s] [--no-color] [--no-console]
  zaafvesper replay [--rules dir] [--config file] [--json alerts.jsonl] [--keep-env] [--no-color]
               [--platform macos|windows|linux|all (default: this host)]
               <file.rcap|events.jsonl|eslogger.jsonl>
  zaafvesper rules list|validate|test [--rules dir | dir] [--config file] [-v]
  zaafvesper coverage --navigator layer.json|- [--rules dir]
  zaafvesper version

run needs root (eslogger). replay, rules and coverage do not. The supported live
mode is the LaunchDaemon com.rifqifitriady.zaafvesper installed by the package that
'make package' builds; running in a terminal is for development only.
As root, zaafvesper refuses to start unless its binary, rules and configuration,
and every directory above them, are root-owned, not group/world writable and
free of write-granting ACLs (the package sets this up under /usr/local).
--output-dir writes a new alerts-<UTC time>.jsonl on every start and rotates it
at --json-max-bytes (default 256 MiB), keeping the newest --json-keep files;
an explicit --json file stops at the cap. Alerts over 64 KiB are truncated.
Captures and JSONL alerts keep environment variable names but redact values
(except DYLD_*) unless --keep-env is given.
The kill response is off unless --enable-response is given; --dry-run-response
only logs what would be killed and wins over --enable-response.`

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "%s", "missing command")
		sayLines(stderr, "", usage)
		return 2
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:], stdout, stderr)
	case "replay":
		return cmdReplay(args[1:], stdout, stderr)
	case "rules":
		return cmdRules(args[1:], stdout, stderr)
	case "coverage":
		return cmdCoverage(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		return cmdVersion(stdout)
	case "help", "-h", "--help":
		sayLines(stdout, "", usage)
		return 0
	}
	say(stderr, "unknown command %q", args[0])
	sayLines(stderr, "", usage)
	return 2
}

func cmdVersion(stdout io.Writer) int {
	ystatus := "compiled in"
	if sc, err := yara.New(yara.Config{}); errors.Is(err, yara.ErrDisabled) {
		ystatus = "not compiled in (build with -tags yara)"
	} else if sc != nil {
		_ = sc.Close()
	}
	say(stdout, "zaafvesper %s (rule engine %s, %s %s/%s, yara %s)", version, rules.EngineVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH, ystatus)
	return 0
}

// newFlagSet returns a flag set whose own error output is discarded: parse
// errors are printed sanitized by parseFlags.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) bool {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			sayLines(stderr, "", usage)
			return false
		}
		say(stderr, "zaafvesper %s: %v", fs.Name(), err)
		return false
	}
	return true
}

// loadConfig loads the config file. When the path was not given explicitly
// and the default file does not exist, an empty configuration is used.
func loadConfig(path string, explicit bool) (*config.Config, error) {
	if !explicit {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return config.Load("")
		}
	}
	return config.Load(path)
}

// flagSet reports whether a flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func isWithin(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && (len(rel) < 3 || rel[:3] != "../")
}

// resolveRulesDir picks --rules, then the config's rules_dir, then "rules".
func resolveRulesDir(flagVal string, given bool, cfg *config.Config) string {
	switch {
	case given:
		return flagVal
	case cfg != nil && cfg.RulesDir != "":
		return cfg.RulesDir
	}
	return flagVal
}
