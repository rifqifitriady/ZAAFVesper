package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/sigma"
	"gopkg.in/yaml.v3"
)

// maxSigmaFiles bounds how many files one conversion reads.
const maxSigmaFiles = 50000

type sigmaItem struct {
	Source  string   `json:"source"`
	Output  string   `json:"output,omitempty"`
	ID      string   `json:"id,omitempty"`
	SigmaID string   `json:"sigma_id,omitempty"`
	Title   string   `json:"title,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

type sigmaSummary struct {
	Files       int `json:"files"`
	Converted   int `json:"converted"`
	Skipped     int `json:"skipped"`
	Invalid     int `json:"invalid"`
	Unsupported int `json:"unsupported"`
	Errors      int `json:"errors"`
}

type sigmaReport struct {
	Tool      string       `json:"tool"`
	Version   string       `json:"version"`
	Input     string       `json:"input"`
	Output    string       `json:"output"`
	Summary   sigmaSummary `json:"summary"`
	Converted []sigmaItem  `json:"converted"`
	Skipped   []sigmaItem  `json:"skipped"`
	// Errors are input or output problems (unreadable file, existing
	// output), not rule problems.
	Errors []sigmaItem `json:"errors"`
}

func cmdSigma(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "convert" {
		say(stderr, "zaafvesper sigma: expected convert")
		sayLines(stderr, "", usage)
		return 2
	}
	fs := newFlagSet("sigma convert")
	out := fs.String("o", "", "output rules directory")
	reportPath := fs.String("report", "", "write a JSON report to this file")
	force := fs.Bool("force", false, "replace existing rule files in the output directory")
	// Flags may come before or after the input path.
	var pos []string
	rest := args[1:]
	for {
		if !parseFlags(fs, rest, stderr) {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(pos) != 1 || *out == "" {
		say(stderr, "zaafvesper sigma convert: expected <sigma dir|file> -o <rules dir> [--report report.json] [--force]")
		return 2
	}
	rep, err := sigmaConvert(pos[0], *out, *force)
	if err != nil {
		sayLines(stderr, "zaafvesper sigma convert: ", err.Error())
		return 1
	}
	rep.Version = version
	printSigmaReport(stdout, rep)
	if *reportPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			sayLines(stderr, "zaafvesper sigma convert: report: ", err.Error())
			return 1
		}
		if err := writeReport(*reportPath, append(data, '\n')); err != nil {
			sayLines(stderr, "zaafvesper sigma convert: report: ", err.Error())
			return 1
		}
		say(stdout, "report written to %s", alert.Sanitize(*reportPath))
	}
	if rep.Summary.Errors > 0 {
		return 1
	}
	return 0
}

// sigmaInputs lists the Sigma files under in (or in itself). Symbolic links
// are never followed; they are reported as errors.
func sigmaInputs(in string) (root string, files []string, errs []sigmaItem, err error) {
	fi, err := os.Lstat(in)
	if err != nil {
		return "", nil, nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", nil, nil, fmt.Errorf("%s is a symbolic link (not followed)", in)
	}
	if fi.Mode().IsRegular() {
		return filepath.Dir(in), []string{in}, nil, nil
	}
	if !fi.IsDir() {
		return "", nil, nil, fmt.Errorf("%s is not a file or directory", in)
	}
	walkErr := filepath.WalkDir(in, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			errs = append(errs, sigmaItem{Source: p, Kind: "error", Reason: werr.Error()})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if p != in && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			errs = append(errs, sigmaItem{Source: p, Kind: "error", Reason: "symbolic link not followed"})
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		files = append(files, p)
		if len(files) > maxSigmaFiles {
			return fmt.Errorf("more than %d Sigma files under %s", maxSigmaFiles, in)
		}
		return nil
	})
	if walkErr != nil {
		return "", nil, nil, walkErr
	}
	sort.Strings(files)
	return in, files, errs, nil
}

// outName derives a safe rule file name from a Sigma file name: lower case,
// only [a-z0-9._-], ending in .yml.
func outName(src string) string {
	stem := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(src), ".yml"), ".yaml")
	var b strings.Builder
	for _, r := range strings.ToLower(stem) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), "_-")
	if s == "" {
		s = "sigma_rule"
	}
	if len(s) > 150 {
		s = s[:150]
	}
	return s + ".yml"
}

func sigmaConvert(in, outDir string, force bool) (*sigmaReport, error) {
	root, files, ioErrs, err := sigmaInputs(in)
	if err != nil {
		return nil, err
	}
	out, err := openOutDir(outDir)
	if err != nil {
		return nil, err
	}
	defer out.Close()
	existing := existingRuleIDs(outDir)
	rep := &sigmaReport{Tool: "zaafvesper sigma convert", Input: in, Output: outDir,
		Converted: []sigmaItem{}, Skipped: []sigmaItem{}, Errors: ioErrs}
	usedName := map[string]string{}
	usedID := map[string]string{}
	for _, f := range files {
		rel, err := filepath.Rel(root, f)
		if err != nil {
			rel = filepath.Base(f)
		}
		rel = filepath.ToSlash(rel)
		item := sigmaItem{Source: rel}
		data, err := config.SecureRead(f, sigma.MaxRuleBytes)
		if err != nil {
			item.Kind, item.Reason = "error", err.Error()
			rep.Errors = append(rep.Errors, item)
			continue
		}
		r, err := sigma.Parse(data)
		var res *sigma.Result
		if err == nil {
			item.SigmaID, item.Title = r.ID, r.Title
			res, err = sigma.Convert(r, sigma.Options{Source: rel})
		}
		if err != nil {
			se := sigma.AsSkip(err)
			item.Kind, item.Reason = se.Kind, se.Reason
			rep.Skipped = append(rep.Skipped, item)
			continue
		}
		name := outName(f)
		item.Output, item.ID, item.Notes = name, res.ID, res.Notes
		fail := func(reason string) {
			item.Kind, item.Reason = "error", reason
			rep.Errors = append(rep.Errors, item)
		}
		if prev, ok := usedName[name]; ok {
			fail("output file name " + name + " already used by " + prev)
			continue
		}
		if prev, ok := usedID[res.ID]; ok {
			fail("rule id " + res.ID + " already used by " + prev)
			continue
		}
		// A rule id already used by another file under -o would make the
		// whole rules tree fail to load.
		if prev, ok := existing[strings.ToLower(res.ID)]; ok && prev != name {
			fail("rule id " + res.ID + " is already used by " + filepath.Join(outDir, prev))
			continue
		}
		if force {
			err = replaceConverted(out, name, res.YAML)
		} else {
			err = createNew(out, name, res.YAML)
			if errors.Is(err, fs.ErrExist) {
				err = fmt.Errorf("%s already exists (use --force to replace it)", filepath.Join(outDir, name))
			}
		}
		if err != nil {
			fail(err.Error())
			continue
		}
		usedName[name], usedID[res.ID] = rel, rel
		rep.Converted = append(rep.Converted, item)
	}
	s := &rep.Summary
	s.Files, s.Converted, s.Skipped, s.Errors = len(files), len(rep.Converted), len(rep.Skipped), len(rep.Errors)
	for _, it := range rep.Skipped {
		if it.Kind == sigma.KindInvalid {
			s.Invalid++
		} else {
			s.Unsupported++
		}
	}
	return rep, nil
}

// openOutDir creates the output directory if needed, refuses a symbolic
// link or a non-directory, and opens it as an os.Root: every later write
// goes through that one directory handle, so swapping the directory (or a
// parent) for a symbolic link after the check cannot redirect the writes.
func openOutDir(dir string) (*os.Root, error) {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if fi, err = os.Lstat(dir); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("output %s is a symbolic link (not followed)", dir)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("output %s is not a directory", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(fi, opened) {
		root.Close()
		return nil, fmt.Errorf("output %s changed while it was being opened", dir)
	}
	return root, nil
}

// existingRuleIDs maps the ids of rule files already under dir (recursively,
// as the rule loader reads them) to their path relative to dir. Unreadable
// or malformed files are left to 'rules validate'.
func existingRuleIDs(dir string) map[string]string {
	ids := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (d.Name() == "macros" || d.Name() == "testdata" || d.Name() == "yara" || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			return nil
		}
		data, err := config.SecureRead(p, rules.MaxRuleFileSize)
		if err != nil {
			return nil
		}
		var r struct {
			ID string `yaml:"id"`
		}
		if yaml.Unmarshal(data, &r) == nil && r.ID != "" {
			rel, _ := filepath.Rel(dir, p)
			ids[strings.ToLower(r.ID)] = filepath.ToSlash(rel)
		}
		return nil
	})
	return ids
}

// createNew creates name in dir exclusively: it never replaces an existing
// file and never follows a symbolic link.
func createNew(dir *os.Root, name string, data []byte) error {
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		dir.Remove(name)
		return err
	}
	return f.Close()
}

// replaceConverted replaces name in dir only when it does not exist yet or
// is a regular file that the converter wrote (it starts with
// sigma.Header). Hand-written rules and symbolic links are refused.
func replaceConverted(dir *os.Root, name string, data []byte) error {
	return replaceIn(dir, name, data, func(f *os.File) error {
		head := make([]byte, len(sigma.Header))
		if _, err := io.ReadFull(f, head); err != nil || string(head) != sigma.Header {
			return fmt.Errorf("%s was not written by sigma convert; refusing to replace it", name)
		}
		return nil
	})
}

// replaceIn writes a temporary file in dir and renames it over name. An
// existing name must be a regular file accepted by check (nil: any regular
// file). Symbolic links are refused, never followed.
func replaceIn(dir *os.Root, name string, data []byte, check func(*os.File) error) error {
	fi, err := dir.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s exists and is not a regular file; refusing to replace it", name)
	case check != nil:
		f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = check(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	var tmp string
	var f *os.File
	for i := 0; ; i++ {
		tmp = fmt.Sprintf(".zaafvesper-%d-%d.tmp", os.Getpid(), i)
		f, err = dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
		if err == nil || !errors.Is(err, fs.ErrExist) || i > 100 {
			break
		}
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		dir.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		dir.Remove(tmp)
		return err
	}
	if err := dir.Rename(tmp, name); err != nil {
		dir.Remove(tmp)
		return err
	}
	return nil
}

// writeReport writes the JSON report through a handle on its directory,
// replacing only a regular file.
func writeReport(path string, data []byte) error {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return replaceIn(dir, filepath.Base(path), data, nil)
}

func printSigmaReport(w io.Writer, rep *sigmaReport) {
	s := rep.Summary
	say(w, "%d Sigma files: %d converted, %d skipped (%d invalid, %d unsupported), %d errors",
		s.Files, s.Converted, s.Skipped, s.Invalid, s.Unsupported, s.Errors)
	for _, it := range rep.Converted {
		say(w, "  OK    %s -> %s", alert.Sanitize(it.Source), alert.Sanitize(it.Output))
		for _, n := range it.Notes {
			say(w, "        note: %s", alert.Sanitize(n))
		}
	}
	for _, it := range rep.Skipped {
		say(w, "  SKIP  %s: %s: %s", alert.Sanitize(it.Source), it.Kind, alert.Sanitize(it.Reason))
	}
	for _, it := range rep.Errors {
		say(w, "  ERROR %s: %s", alert.Sanitize(it.Source), alert.Sanitize(it.Reason))
	}
	if s.Converted > 0 {
		say(w, "Converted rules have no test fixtures. 'zaafvesper rules test' fails for each one until")
		say(w, "you add <rules dir>/testdata/<rule file name>.yml with at least 1 match and 2 nomatch scenarios.")
	}
}
