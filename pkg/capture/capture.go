// Package capture writes and reads ZAAFVesper captures (.rcap: gzip-compressed
// JSONL of normalized event.Event). The reader also accepts plain JSONL of
// events and raw eslogger JSONL (gzip or not), detected from the first line.
package capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/eslogger"
)

// MaxLineSize bounds one JSONL line (same limit as the eslogger source).
const MaxLineSize = 16 << 20

// Formats detected by the reader.
const (
	FormatEvents   = "events"   // normalized event.Event JSONL (already enriched)
	FormatEslogger = "eslogger" // raw eslogger output; needs decoding and enrichment
)

// DefaultMaxBytes is the default capture size limit (uncompressed JSONL bytes).
const DefaultMaxBytes = 2 << 30

// ErrLimit is returned by Write once the size limit is reached; the capture
// stays valid and holds every event written before.
var ErrLimit = errors.New("capture: size limit reached, capture stopped")

// Writer writes events as gzip JSONL. Safe for concurrent use.
//
// By default environment values are redacted (names kept, DYLD_* values
// kept); SetKeepEnv(true) stores them in full. The size limit counts
// uncompressed JSONL bytes, before gzip.
type Writer struct {
	mu       sync.Mutex
	closer   io.Closer // the file, when Create opened it
	gz       *gzip.Writer
	bw       *bufio.Writer
	n        uint64
	bytes    int64
	maxBytes int64
	full     bool
	keepEnv  bool
	closed   bool
}

// NewWriter writes a capture to w. Close finishes the gzip stream but does
// not close w.
func NewWriter(w io.Writer) *Writer {
	bw := bufio.NewWriterSize(w, 64<<10)
	return &Writer{gz: gzip.NewWriter(bw), bw: bw, maxBytes: DefaultMaxBytes}
}

// SetMaxBytes sets the limit on uncompressed bytes (<= 0: DefaultMaxBytes).
func (w *Writer) SetMaxBytes(n int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if n <= 0 {
		n = DefaultMaxBytes
	}
	w.maxBytes = n
}

// SetKeepEnv stores environment values in full instead of redacting them.
func (w *Writer) SetKeepEnv(keep bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.keepEnv = keep
}

// Bytes returns the uncompressed bytes written.
func (w *Writer) Bytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytes
}

// Full reports whether the size limit stopped the capture.
func (w *Writer) Full() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.full
}

// Create creates a new capture file with mode 0600. It refuses an existing
// path or a pre-planted symbolic link.
func Create(path string) (*Writer, error) {
	f, err := config.CreatePrivate(path)
	if err != nil {
		return nil, err
	}
	return NewFileWriter(f), nil
}

// NewFileWriter writes a capture to an already created file (for example
// one created fd-relative in the output directory). Close syncs and closes f.
func NewFileWriter(f *os.File) *Writer {
	w := NewWriter(f)
	w.closer = f
	return w
}

// Write appends one event.
func (w *Writer) Write(e *event.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("capture: write after close")
	}
	if w.full {
		return ErrLimit
	}
	if !w.keepEnv {
		e = alert.RedactEvent(e)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if w.bytes+int64(len(line)) > w.maxBytes {
		w.full = true
		return ErrLimit
	}
	if _, err := w.gz.Write(line); err != nil {
		return err
	}
	w.bytes += int64(len(line))
	w.n++
	return nil
}

// Flush pushes buffered data to the underlying writer (the gzip stream stays
// open, so a reader sees everything up to here after a crash).
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	if err := w.gz.Flush(); err != nil {
		return err
	}
	return w.bw.Flush()
}

// Count returns the number of events written.
func (w *Writer) Count() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

// Close finishes the gzip stream, flushes and closes the file if Create
// opened it. It is safe to call more than once.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	errs := []error{w.gz.Close(), w.bw.Flush()}
	if w.closer != nil {
		if f, ok := w.closer.(*os.File); ok {
			errs = append(errs, f.Sync())
		}
		errs = append(errs, w.closer.Close())
	}
	return errors.Join(errs...)
}

// Reader reads events from a capture, plain JSONL or raw eslogger JSONL.
type Reader struct {
	sc      *bufio.Scanner
	format  string
	first   []byte // first non-empty line, already read during detection
	closers []io.Closer
	lines   uint64
	events  uint64
	ignored uint64
	errs    uint64
	lastErr error
}

// Open opens a file for reading.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r.closers = append(r.closers, f)
	return r, nil
}

// NewReader detects compression and format from the start of r.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	rd := &Reader{}
	var src io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		rd.closers = append(rd.closers, gz)
		src = gz
	}
	rd.sc = bufio.NewScanner(src)
	rd.sc.Buffer(make([]byte, 0, 64<<10), MaxLineSize)
	for rd.sc.Scan() {
		line := bytes.TrimSpace(rd.sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("first line is not a JSON object: %w", err)
		}
		if _, ok := probe["event_type"]; ok {
			rd.format = FormatEslogger
		} else {
			rd.format = FormatEvents
		}
		rd.first = append([]byte(nil), line...)
		return rd, nil
	}
	if err := rd.sc.Err(); err != nil {
		return nil, err
	}
	rd.format = FormatEvents // empty input
	return rd, nil
}

// Format returns FormatEvents or FormatEslogger.
func (r *Reader) Format() string { return r.format }

// Next returns the next event, or io.EOF. Malformed lines and eslogger
// events ZAAFVesper ignores are counted and skipped, never fatal.
func (r *Reader) Next() (*event.Event, error) {
	for {
		var line []byte
		if r.first != nil {
			line, r.first = r.first, nil
		} else {
			if !r.sc.Scan() {
				if err := r.sc.Err(); err != nil {
					return nil, err
				}
				return nil, io.EOF
			}
			line = bytes.TrimSpace(r.sc.Bytes())
			if len(line) == 0 {
				continue
			}
		}
		r.lines++
		e, ok, err := r.decode(line)
		if err != nil {
			r.errs++
			r.lastErr = fmt.Errorf("line %d: %w", r.lines, err)
			continue
		}
		if !ok {
			r.ignored++
			continue
		}
		r.events++
		return e, nil
	}
}

func (r *Reader) decode(line []byte) (*event.Event, bool, error) {
	if r.format == FormatEslogger {
		return eslogger.Decode(line)
	}
	e := &event.Event{}
	if err := json.Unmarshal(line, e); err != nil {
		return nil, false, err
	}
	if e.Name == "" {
		return nil, false, errors.New("event has no name")
	}
	return e, true, nil
}

// Stats returns line, event, ignored and decode-error counters.
func (r *Reader) Stats() map[string]uint64 {
	return map[string]uint64{"lines": r.lines, "events": r.events, "ignored": r.ignored, "decode_errors": r.errs}
}

// LastError returns the most recent per-line decode error, if any.
func (r *Reader) LastError() error { return r.lastErr }

// Close releases the underlying readers.
func (r *Reader) Close() error {
	var errs []error
	for i := len(r.closers) - 1; i >= 0; i-- {
		errs = append(errs, r.closers[i].Close())
	}
	r.closers = nil
	return errors.Join(errs...)
}
