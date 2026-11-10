package output

import (
	"regexp"
	"time"
)

// Segment defaults (--elegia-dir).
const (
	DefaultSegmentBytes = 64 << 20
	DefaultSegmentAge   = 15 * time.Minute
	DefaultSegmentKeep  = 8 << 30
	// DefaultSegmentMinKeep is the retention floor: a closed segment younger
	// than this is never deleted, whatever the size pressure (the 7-day floor
	// of the alert files, docs/security/open-findings.md M5).
	DefaultSegmentMinKeep = 7 * 24 * time.Hour
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
	// MinKeep is the retention floor (default DefaultSegmentMinKeep; a
	// negative value switches the floor off, which lets a flood erase the
	// oldest evidence). A closed segment younger than this is not deleted;
	// when that leaves the closed segments above KeepBytes, the writer stops
	// opening segments, drops new records (counted) and reports
	// CondDirFull until space is free.
	MinKeep time.Duration
	// OnDegraded receives the writer's problems: CondDirFull, CondDirError.
	// It is called with the writer's lock held and must not call back into
	// it.
	OnDegraded func(condition, detail string)
	// Now is the clock (tests).
	Now func() time.Time
}

// Conditions the segment writer reports through SegmentConfig.OnDegraded
// (SensorDegraded evt.arg[condition]).
const (
	CondDirFull  = "elegia_dir_full"
	CondDirError = "elegia_dir_error"
)
