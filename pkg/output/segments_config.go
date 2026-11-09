package output

import (
	"regexp"
	"time"
)

// Segment defaults (--elegia-dir).
const (
	DefaultSegmentBytes = 64 << 20
	DefaultSegmentAge   = 15 * time.Minute
	DefaultSegmentKeep  = 1 << 30
	// segmentStamp is fixed width, so names sort in time order.
	segmentStamp = "20060102T150405.000000000Z"
	segmentExt   = ".ndjson"
	partExt      = ".part"
)

// segmentName matches closed segments (and, with partExt, the open one).
var segmentName = regexp.MustCompile(`^events-(\d{8}T\d{6}\.\d{9}Z)(?:-(\d{1,3}))?\.ndjson(\.part)?$`)

// SegmentConfig configures a Segments writer.
type SegmentConfig struct {
	// MaxBytes closes a segment once it holds this many bytes (default
	// DefaultSegmentBytes); MaxAge closes a non-empty segment this long after
	// it was opened (default DefaultSegmentAge), so scheduled hunts see
	// recent events even when few arrive.
	MaxBytes int64
	MaxAge   time.Duration
	// KeepBytes bounds the closed segments kept; the oldest are deleted
	// first (default DefaultSegmentKeep).
	KeepBytes int64
	// Now is the clock (tests).
	Now func() time.Time
}
