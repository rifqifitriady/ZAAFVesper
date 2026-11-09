package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
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
)

const defaultElegiaMaxBytes = 1 << 30

type elegiaOptions struct {
	out       string // file or "-"
	outMax    int64
	dir       string
	segBytes  int64
	segAge    time.Duration
	keepBytes int64
	host      string // Computer in the records ("" in run: the hostname)
}

func (e *elegiaOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&e.out, "elegia-out", "", "stream every event as NDJSON with Sigma field names (schema zaafvesper.elegia/1) to this file (0600, appended across restarts), or - for stdout (console alerts then go to stderr)")
	fs.Int64Var(&e.outMax, "elegia-max-bytes", defaultElegiaMaxBytes, "cap of the --elegia-out file in bytes (not applied to stdout)")
	fs.StringVar(&e.dir, "elegia-dir", "", "write every event as NDJSON into rotating segment files in this directory (0700) for scheduled hunts: zaaf hunt DIR/*.ndjson")
	fs.Int64Var(&e.segBytes, "elegia-segment-bytes", output.DefaultSegmentBytes, "close an --elegia-dir segment at this size")
	fs.DurationVar(&e.segAge, "elegia-segment-age", output.DefaultSegmentAge, "close a non-empty --elegia-dir segment this long after it was opened")
	fs.Int64Var(&e.keepBytes, "elegia-keep-bytes", output.DefaultSegmentKeep, "keep at most this many bytes of closed --elegia-dir segments (oldest deleted first)")
	fs.StringVar(&e.host, "elegia-host", "", "host name written as Computer in the ZAAFElegia records (run: default this machine's name; replay: none unless given, since a capture does not record its host)")
}

func (e *elegiaOptions) check() error {
	switch {
	case e.outMax <= 0:
		return errors.New("--elegia-max-bytes must be positive")
	case e.segBytes <= 0 || e.keepBytes <= 0 || e.segAge <= 0:
		return errors.New("--elegia-segment-bytes, --elegia-segment-age and --elegia-keep-bytes must be positive")
	case e.dir != "" && e.keepBytes < e.segBytes:
		return errors.New("--elegia-keep-bytes must be at least --elegia-segment-bytes, or a closed segment is deleted at once")
	case len(e.host) > 255:
		return errors.New("--elegia-host is longer than 255 bytes")
	case e.dir == "-":
		return errors.New("--elegia-dir takes a directory; use --elegia-out - for stdout")
	}
	return nil
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
			OnCapped: func(d string) { degraded(condElegiaCapped, d) }}))
		say(stderr, "output: every event as Sigma-named NDJSON (%s) to %s", output.ElegiaSchema, where)
	}
	if e.dir != "" {
		seg, err := output.OpenSegments(e.dir, output.SegmentConfig{MaxBytes: e.segBytes, MaxAge: e.segAge, KeepBytes: e.keepBytes}, asRoot)
		if err != nil {
			for _, c := range w.closers {
				_ = c()
			}
			return nil, fmt.Errorf("--elegia-dir: %w", err)
		}
		add("elegia dir", output.NewLineWriter(seg, output.LineWriterConfig{Name: "elegia-dir",
			OnDrop: func(d string) { degraded(condElegiaDropped, d) }}))
		segStats := seg.Stats
		w.stats["elegia segments"] = segStats
		say(stderr, "output: every event as Sigma-named NDJSON (%s) into segments in %s (close at %d bytes or %v, keep %d bytes)",
			output.ElegiaSchema, e.dir, e.segBytes, e.segAge, e.keepBytes)
	}
	return w, nil
}
