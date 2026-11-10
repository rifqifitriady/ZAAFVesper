package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/output"
)

// ZAAFElegia event outputs shared by run and replay: --elegia-out (one
// stream or file) and --elegia-dir (rotating segment files for scheduled
// hunts). Records follow integrations/zaafelegia/schema (zaafvesper.elegia/1).

// Conditions of the SensorDegraded events the ZAAFElegia writers report.
const (
	condElegiaDropped = "elegia_out_dropped"
	condElegiaCapped  = "elegia_out_capped"
	condElegiaError   = "elegia_out_error"
	// The --elegia-dir writer: records dropped because its queue was full,
	// write errors, and the two conditions of the segment writer itself
	// (output.CondDirFull, output.CondDirError).
	condElegiaDirDropped = "elegia_dir_dropped"
	condElegiaDirError   = output.CondDirError
	condElegiaDirFull    = output.CondDirFull
	// Lower bounds: smaller segments only multiply files and directory work.
	minSegmentBytes = 4096
	minSegmentAge   = time.Second
)

const defaultElegiaMaxBytes = 1 << 30

type elegiaOptions struct {
	out       string // file or "-"
	outMax    int64
	dir       string
	segBytes  int64
	segAge    time.Duration
	keepBytes int64
	minKeep   time.Duration
	host      string // Computer in the records ("" in run: the hostname)
}

func (e *elegiaOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&e.out, "elegia-out", "", "stream every event as NDJSON with Sigma field names (schema zaafvesper.elegia/1) to this file (0600, appended across restarts), or - for stdout (console alerts then go to stderr)")
	fs.Int64Var(&e.outMax, "elegia-max-bytes", defaultElegiaMaxBytes, "cap of the --elegia-out file in bytes (not applied to stdout)")
	fs.StringVar(&e.dir, "elegia-dir", "", "write every event as NDJSON into rotating segment files in this directory (0700) for scheduled hunts: zaaf hunt DIR/*.ndjson")
	fs.Int64Var(&e.segBytes, "elegia-segment-bytes", output.DefaultSegmentBytes, "close an --elegia-dir segment at this size")
	fs.DurationVar(&e.segAge, "elegia-segment-age", output.DefaultSegmentAge, "close a non-empty --elegia-dir segment this long after it was opened")
	fs.Int64Var(&e.keepBytes, "elegia-keep-bytes", output.DefaultSegmentKeep, "keep at most this many bytes of closed --elegia-dir segments (oldest deleted first, but none younger than --elegia-min-keep); at least twice --elegia-segment-bytes")
	fs.DurationVar(&e.minKeep, "elegia-min-keep", output.DefaultSegmentMinKeep, "never delete a closed --elegia-dir segment younger than this, whatever --elegia-keep-bytes says; when the directory is over its cap and every old segment is younger, capture stops (records dropped and counted, SensorDegraded elegia_dir_full) instead of erasing evidence. 0 turns the floor off")
	fs.StringVar(&e.host, "elegia-host", "", "host name written as Computer in the ZAAFElegia records (run: default this machine's name; replay: none unless given, since a capture does not record its host)")
}

func (e *elegiaOptions) check() error {
	switch {
	case e.outMax <= 0:
		return errors.New("--elegia-max-bytes must be positive")
	case e.segBytes < minSegmentBytes || e.segAge < minSegmentAge || e.keepBytes <= 0:
		return fmt.Errorf("--elegia-segment-bytes must be at least %d, --elegia-segment-age at least %v, and --elegia-keep-bytes positive", minSegmentBytes, minSegmentAge)
	case e.minKeep < 0:
		return errors.New("--elegia-min-keep must not be negative (0 turns the floor off)")
	case e.dir != "" && e.keepBytes < 2*e.segBytes:
		return errors.New("--elegia-keep-bytes must be at least twice --elegia-segment-bytes, or the first closed segment already fills the directory")
	case len(e.host) > 255:
		return errors.New("--elegia-host is longer than 255 bytes")
	case e.dir == "-":
		return errors.New("--elegia-dir takes a directory; use --elegia-out - for stdout")
	}
	return e.checkDirPath()
}

// flagPath is a path given by another flag that must stay apart from the
// ZAAFElegia outputs.
type flagPath struct{ flag, path string }

// checkCollisions rejects --elegia-dir and --elegia-out paths that equal,
// contain or lie inside the paths of other outputs (file or directory,
// either direction), compared after making them absolute, cleaning them and
// resolving symbolic links as far as the paths exist. It touches nothing, so
// it runs at flag-check time, before any file or directory is created.
func (e *elegiaOptions) checkCollisions(others ...flagPath) error {
	mine := []flagPath{}
	if e.dir != "" && e.dir != "-" {
		mine = append(mine, flagPath{"--elegia-dir", e.dir})
	}
	if e.out != "" && e.out != "-" {
		mine = append(mine, flagPath{"--elegia-out", e.out})
	}
	all := append(append([]flagPath{}, mine...), others...)
	for i, a := range all {
		for j := i + 1; j < len(all); j++ {
			b := all[j]
			if a.path == "" || b.path == "" || (i >= len(mine) && j >= len(mine)) {
				continue // only pairs with at least one ZAAFElegia output
			}
			if samePathOrInside(a.path, b.path) {
				return fmt.Errorf("%s %q and %s %q are the same path or one is inside the other; give each output its own path", a.flag, a.path, b.flag, b.path)
			}
		}
	}
	return nil
}

// checkDirPath rejects an --elegia-dir that cannot be a directory, before
// anything is created: a path that exists as a file or a symbolic link, or
// that lies below a file.
func (e *elegiaOptions) checkDirPath() error {
	if e.dir == "" {
		return nil
	}
	abs, err := filepath.Abs(e.dir)
	if err != nil {
		return fmt.Errorf("--elegia-dir: %w", err)
	}
	for p := abs; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		switch {
		case err == nil && p == abs && fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("--elegia-dir %q is a symbolic link (not allowed); name the directory itself", e.dir)
		case err == nil && p == abs && !fi.IsDir():
			return fmt.Errorf("--elegia-dir %q exists and is not a directory", e.dir)
		case err == nil && p != abs && !fi.IsDir() && fi.Mode()&os.ModeSymlink == 0:
			return fmt.Errorf("--elegia-dir %q: %q is not a directory", e.dir, p)
		case err == nil:
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("--elegia-dir %q: %w", e.dir, err)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// canonPath makes p absolute and clean and resolves symbolic links in the
// part that exists, so two spellings of one place compare equal.
func canonPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	rest := ""
	for cur := abs; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(real, rest)
		}
		if cur == filepath.Dir(cur) {
			return abs
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// samePathOrInside reports whether a and b are the same path or one lies
// inside the other.
func samePathOrInside(a, b string) bool {
	a, b = canonPath(a), canonPath(b)
	return within(a, b) || within(b, a)
}

// within reports whether p is dir or below it.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// elegiaFlagHelp prints the flags of the ZAAFElegia outputs registered on
// fs, so that `run -h` and `replay -h` list them (the usage text names
// none). It reads the flag set, so a new flag cannot be forgotten.
func elegiaFlagHelp(fs *flag.FlagSet, w io.Writer) {
	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "elegia-") || f.Name == "alerts-ocsf" || f.Name == "ocsf-max-bytes" {
			names = append(names, f.Name)
		}
	})
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	say(w, "ZAAFElegia outputs (run and replay; --alerts-ocsf and --ocsf-max-bytes are run only):")
	for _, n := range names {
		f := fs.Lookup(n)
		def := ""
		if f.DefValue != "" && f.DefValue != "0" {
			def = " (default " + f.DefValue + ")"
		}
		say(w, "  --%s%s", n, def)
		say(w, "        %s", f.Usage)
	}
}

func (e *elegiaOptions) active() bool { return e.out != "" || e.dir != "" }

// consoleWriter is where console alerts go: stderr when --elegia-out - owns
// stdout.
func (e *elegiaOptions) consoleWriter(stdout, stderr io.Writer) io.Writer {
	if e.out == "-" {
		return stderr
	}
	return stdout
}

// elegiaWiring is what wire built: event taps, closers and counters.
type elegiaWiring struct {
	taps    []func(*event.Event)
	closers []func() error
	stats   map[string]func() map[string]uint64
}

// wire opens the configured writers. degraded receives the writers'
// SensorDegraded reports.
func (e *elegiaOptions) wire(asRoot bool, opts output.SigmaOptions, closeTimeout time.Duration, stdout, stderr io.Writer, degraded func(cond, detail string)) (*elegiaWiring, error) {
	w := &elegiaWiring{stats: map[string]func() map[string]uint64{}}
	if e.host != "" {
		opts.Host = output.Host(e.host)
	}
	add := func(name string, lw *output.LineWriter) {
		es := &output.ElegiaSink{W: lw, Options: opts}
		w.taps = append(w.taps, es.Event)
		w.closers = append(w.closers, func() error { return lw.Close(closeTimeout) })
		w.stats[name] = lw.Stats
	}
	if e.out != "" {
		var dst io.Writer = stdout
		maxBytes, written := int64(0), int64(0)
		where := "stdout"
		if e.out != "-" {
			// Appended across restarts (a LaunchDaemon restart must not
			// fail because the file exists); the cap covers the whole file.
			f, size, err := output.OpenAppendPrivate(e.out, asRoot)
			if err != nil {
				return nil, fmt.Errorf("--elegia-out: %w", err)
			}
			dst, maxBytes, written, where = f, e.outMax, size, f.Name()
		}
		add("elegia out", output.NewLineWriter(dst, output.LineWriterConfig{Name: "elegia-out", MaxBytes: maxBytes, Written: written,
			OnDrop:   func(d string) { degraded(condElegiaDropped, d) },
			OnCapped: func(d string) { degraded(condElegiaCapped, d) },
			OnError:  func(d string) { degraded(condElegiaError, d) }}))
		say(stderr, "output: every event as Sigma-named NDJSON (%s) to %s", output.ElegiaSchema, where)
	}
	if e.dir != "" {
		minKeep := e.minKeep
		if minKeep == 0 {
			minKeep = -1 // --elegia-min-keep 0: no floor
		}
		seg, err := output.OpenSegments(e.dir, output.SegmentConfig{MaxBytes: e.segBytes, MaxAge: e.segAge, KeepBytes: e.keepBytes,
			MinKeep: minKeep, OnDegraded: degraded}, asRoot)
		if err != nil {
			for _, c := range w.closers {
				_ = c()
			}
			return nil, fmt.Errorf("--elegia-dir: %w", err)
		}
		add("elegia dir", output.NewLineWriter(seg, output.LineWriterConfig{Name: "elegia-dir",
			OnDrop:  func(d string) { degraded(condElegiaDirDropped, d) },
			OnError: func(d string) { degraded(condElegiaDirError, d) }}))
		segStats := seg.Stats
		w.stats["elegia segments"] = segStats
		floor := fmt.Sprintf("never delete one younger than %v", e.minKeep)
		if e.minKeep == 0 {
			floor = "no retention floor: a flood can erase the oldest evidence"
		}
		say(stderr, "output: every event as Sigma-named NDJSON (%s) into segments in %s (close at %d bytes or %v, keep %d bytes, %s)",
			output.ElegiaSchema, e.dir, e.segBytes, e.segAge, e.keepBytes, floor)
	}
	return w, nil
}
