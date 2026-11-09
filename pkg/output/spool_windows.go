//go:build windows

package output

import (
	"errors"
	"os"
)

// The spool and OpenAppendPrivate are built on Unix directory descriptors
// (spool_unix.go). Windows has no equivalent here yet, and every forwarder
// (syslog, webhook) and file output (ZAAFElegia, OCSF) needs one of them, so
// on Windows those flags are refused at start-up (cmd/zaafvesper
// platformOutputCheck) and these stand-ins are never reached in normal use.

// Spool defaults (the same as spool_unix.go).
const (
	DefaultSpoolMaxBytes = 128 << 20
	maxSpoolFiles        = 4096
)

// ErrNoWindowsSpool is returned by OpenSpool and OpenAppendPrivate on Windows.
var ErrNoWindowsSpool = errors.New("output: the on-disk spool and append files are not available on Windows yet")

// Spool is not available on Windows (see ErrNoWindowsSpool).
type Spool struct{}

// OpenSpool always fails on Windows.
func OpenSpool(string, int64, bool) (*Spool, error) { return nil, ErrNoWindowsSpool }

// OpenAppendPrivate always fails on Windows.
func OpenAppendPrivate(string, bool) (*os.File, int64, error) { return nil, 0, ErrNoWindowsSpool }

func (s *Spool) Append([]Record) (int, error)      { return 0, ErrNoWindowsSpool }
func (s *Spool) Empty() bool                       { return true }
func (s *Spool) Oldest() (uint64, []Record, error) { return 0, nil, ErrNoWindowsSpool }
func (s *Spool) Remove(uint64) error               { return ErrNoWindowsSpool }
func (s *Spool) Stats() map[string]uint64          { return map[string]uint64{} }
func (s *Spool) Close() error                      { return nil }
