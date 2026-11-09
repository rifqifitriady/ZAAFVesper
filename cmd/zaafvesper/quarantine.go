package main

import (
	"io"
	"path/filepath"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

// cliRunner is the Runner of the isolation CLI; tests replace it.
var cliRunner response.Runner = response.RunPinned

// stateDirFlag registers --state-dir (default response.DefaultStateDir).
// As root (an elevated administrator on Windows) the directory and the
// vault in it must be private to root (SYSTEM and Administrators).
func stateDirFlag(name string) (*stateDirOpts, func([]string, io.Writer) ([]string, bool)) {
	o := &stateDirOpts{}
	fs := newFlagSet(name)
	fs.StringVar(&o.dir, "state-dir", response.DefaultStateDir, "ZAAFVesper's state directory (the vault is its quarantine/ subdirectory)")
	// Flags may come before or after the positional argument.
	return o, func(args []string, stderr io.Writer) ([]string, bool) {
		var pos []string
		for {
			if !parseFlags(fs, args, stderr) {
				return nil, false
			}
			if fs.NArg() == 0 {
				return pos, true
			}
			pos = append(pos, fs.Arg(0))
			args = fs.Args()[1:]
		}
	}
}

type stateDirOpts struct{ dir string }

func (o *stateDirOpts) vault() response.Vault {
	return response.Vault{Dir: filepath.Join(o.dir, "quarantine"), RequireRootOwned: checkPrivileges() == nil}
}

func (o *stateDirOpts) store() response.IsolationStore {
	return response.IsolationStore{Dir: o.dir, RequireRootOwned: checkPrivileges() == nil}
}

// cmdQuarantine: zaafvesper quarantine list | restore <id>.
func cmdQuarantine(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "usage: zaafvesper quarantine list|restore <id> [--state-dir dir]")
		return 2
	}
	sub := args[0]
	o, parse := stateDirFlag("quarantine " + sub)
	rest, ok := parse(args[1:], stderr)
	if !ok {
		return 2
	}
	switch sub {
	case "list":
		if len(rest) != 0 {
			say(stderr, "zaafvesper quarantine list: unexpected argument %q", rest[0])
			return 2
		}
		items, err := o.vault().List()
		if err != nil {
			say(stderr, "zaafvesper quarantine list: %v", err)
			return 1
		}
		if len(items) == 0 {
			say(stdout, "quarantine vault %s is empty", o.vault().Dir)
			return 0
		}
		for _, it := range items {
			for i := len(it.Records) - 1; i >= 0; i-- {
				r := it.Records[i]
				line := "%s  %s  %-18s %8d bytes  %s  (rule %s, pid %d %s)"
				args := []any{it.ID[:16], r.Time.UTC().Format(time.RFC3339), r.Action, r.Size, r.OriginalPath, r.Rule, r.PID, r.Exe}
				if r.Label != "" {
					line += " label %s"
					args = append(args, r.Label)
				}
				say(stdout, line, args...)
			}
		}
		return 0
	case "restore":
		if len(rest) != 1 {
			say(stderr, "usage: zaafvesper quarantine restore <id> [--state-dir dir]")
			return 2
		}
		rec, warn, err := o.vault().Restore(rest[0])
		for _, w := range warn {
			say(stderr, "warning: %s", w)
		}
		if err != nil {
			say(stderr, "zaafvesper quarantine restore: %v", err)
			return 1
		}
		say(stdout, "restored %s to %s (mode %04o, owner %d:%d)", rec.ID[:16], rec.OriginalPath, rec.Mode&0o777, rec.UID, rec.GID)
		if rec.Label != "" {
			say(stdout, "the launch item %s is NOT loaded again; load it yourself if you trust it", rec.Label)
		}
		return 0
	}
	say(stderr, "unknown quarantine command %q (list, restore)", sub)
	return 2
}

// cmdIsolation: zaafvesper isolation list | release <addr|all>.
func cmdIsolation(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "usage: zaafvesper isolation list|release <address|all> [--state-dir dir]")
		return 2
	}
	sub := args[0]
	o, parse := stateDirFlag("isolation " + sub)
	rest, ok := parse(args[1:], stderr)
	if !ok {
		return 2
	}
	switch sub {
	case "list":
		if len(rest) != 0 {
			say(stderr, "zaafvesper isolation list: unexpected argument %q", rest[0])
			return 2
		}
		isos, err := o.store().Load()
		if err != nil {
			say(stderr, "zaafvesper isolation list: %v", err)
			return 1
		}
		if len(isos) == 0 {
			say(stdout, "no isolated address (%s)", response.FirewallName)
			return 0
		}
		for _, iso := range isos {
			say(stdout, "%s  until %s  (rule %s, pid %d %s)", iso.Addr, iso.Expires.UTC().Format(time.RFC3339), iso.Rule, iso.PID, iso.Exe)
		}
		say(stdout, "these addresses are blocked for the whole host (%s)", response.FirewallName)
		return 0
	case "release":
		if len(rest) != 1 {
			say(stderr, "usage: zaafvesper isolation release <address|all> [--state-dir dir]")
			return 2
		}
		rel, err := response.ReleaseIsolation(o.store(), cliRunner, rest[0])
		if err != nil {
			say(stderr, "zaafvesper isolation release: %v", err)
			return 1
		}
		say(stdout, "released %d address(es): %v", len(rel), rel)
		return 0
	}
	say(stderr, "unknown isolation command %q (list, release)", sub)
	return 2
}
