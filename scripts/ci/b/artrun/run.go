package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Result records one executed test.
type Result struct {
	ID         string    `json:"id"`
	NotRun     string    `json:"not_run,omitempty"` // why the test was not run
	Name       string    `json:"name,omitempty"`
	Kind       string    `json:"kind"` // atomic or inline
	Command    string    `json:"command"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	ExitCode   int       `json:"exit_code"`
	Error      string    `json:"error,omitempty"`
	Output     string    `json:"output,omitempty"`
	Prereqs    []string  `json:"prereqs_not_fetched,omitempty"`
	CleanupErr string    `json:"cleanup_error,omitempty"`
}

const (
	testTimeout = 60 * time.Second
	maxOutput   = 4 << 10
)

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	planPath := fs.String("plan", "", "test plan")
	atomics := fs.String("atomics", "", "folder holding <technique>.yaml files")
	out := fs.String("out", "results.json", "results file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadPlan(*planPath)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(*atomics)
	if err != nil {
		return err
	}
	var results []Result
	for _, t := range p.Tests {
		r := Result{ID: t.ID, Kind: "inline"}
		if missing := missingTools(t.Requires); missing != "" {
			r.NotRun = missing + " is not on this runner image"
			if t.Atomic != nil {
				r.Kind = "atomic"
			}
			results = append(results, r)
			fmt.Printf("%-40s not run: %s\n", t.ID, r.NotRun)
			if err := writeResults(*out, results); err != nil {
				return err
			}
			continue
		}
		step := t.Inline
		if t.Atomic != nil {
			r.Kind = "atomic"
			var name string
			step, name, r.Prereqs, err = resolveAtomic(abs, t.Atomic, p.Platform)
			r.Name = name
			if err != nil {
				r.Error = err.Error()
				results = append(results, r)
				fmt.Printf("%-40s ERROR %v\n", t.ID, err)
				if err := writeResults(*out, results); err != nil {
					return err
				}
				continue
			}
		}
		if t.Setup != nil {
			if _, out, err := execute(t.Setup.Executor, t.Setup.Command); err != nil {
				fmt.Printf("%-40s setup: %v %s\n", t.ID, err, out)
			}
		}
		r.Command = step.Command
		r.Start = time.Now().UTC()
		code, output, err := execute(step.Executor, step.Command)
		r.End = time.Now().UTC()
		r.ExitCode, r.Output = code, output
		if err != nil {
			r.Error = err.Error()
		}
		if step.Cleanup != "" {
			if _, out, err := execute(step.Executor, step.Cleanup); err != nil {
				r.CleanupErr = fmt.Sprintf("%v %s", err, out)
			}
		}
		fmt.Printf("%-40s exit=%d %s\n", t.ID, code, r.Error)
		results = append(results, r)
		// Written after every test, so a run that dies part way leaves the
		// results of the tests that ran (and report sees how many are missing).
		if err := writeResults(*out, results); err != nil {
			return err
		}
		time.Sleep(2 * time.Second) // keep the tests apart in the event stream
	}
	return writeResults(*out, results)
}

func writeResults(path string, results []Result) error {
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func missingTools(tools []string) string {
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			return t
		}
	}
	return ""
}

// execute runs command with an Atomic Red Team executor name. Multi-line
// commands are written to a script file, as Invoke-AtomicRedTeam does, so
// each line runs as its own command.
func execute(executor, command string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	dir, err := os.MkdirTemp("", "artrun-")
	if err != nil {
		return -1, "", err
	}
	defer os.RemoveAll(dir)
	var cmd *exec.Cmd
	switch executor {
	case "command_prompt":
		f := filepath.Join(dir, "t.cmd")
		if err := os.WriteFile(f, []byte("@echo off\r\n"+command), 0o600); err != nil {
			return -1, "", err
		}
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", f)
	case "powershell":
		f := filepath.Join(dir, "t.ps1")
		if err := os.WriteFile(f, []byte(command), 0o600); err != nil {
			return -1, "", err
		}
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f)
	case "sh", "bash":
		if runtime.GOOS == "windows" {
			return -1, "", fmt.Errorf("executor %s on Windows", executor)
		}
		cmd = exec.CommandContext(ctx, "/bin/"+executor, "-c", command)
	default:
		return -1, "", fmt.Errorf("unsupported executor %q", executor)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	out := buf.String()
	if len(out) > maxOutput {
		out = out[:maxOutput] + "...(truncated)"
	}
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("timed out after %s", testTimeout)
	}
	return code, out, err
}
