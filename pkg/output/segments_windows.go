//go:build windows

package output

import (
	"errors"
)

// Segments is not available on Windows yet: it is built on Unix directory
// descriptors, like the spool (spool_windows.go).
type Segments struct{}

var errSegmentsWindows = errors.New("--elegia-dir is not available on Windows yet")

// OpenSegments always fails on Windows.
func OpenSegments(string, SegmentConfig, bool) (*Segments, error) { return nil, errSegmentsWindows }

func (*Segments) Write([]byte) (int, error) { return 0, errSegmentsWindows }
func (*Segments) Due() bool                 { return false }
func (*Segments) Rotate() error             { return errSegmentsWindows }
func (*Segments) Close() error              { return nil }
func (*Segments) Stats() map[string]uint64  { return nil }
