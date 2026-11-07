// Package yara provides the YARA scanner (source.Scanner). The real scanner is
// built with -tags yara (cgo + libyara); without the tag New returns ErrDisabled.
package yara

import (
	"errors"
	"path"
	"strings"
)

// ErrDisabled is returned when ZAAFVesper was built without YARA support.
var ErrDisabled = errors.New("yara: support not compiled in (build with -tags yara)")

// Config configures the scanner.
type Config struct {
	RulesDir    string   // directory of *.yar / *.yara files
	Workers     int      // default 2
	MaxFileSize int64    // bytes, default 64 MiB
	TimeoutSec  int      // per scan, default 10
	WatchDirs   []string // glob prefixes whose CreateFile/WriteFile targets are scanned; nil = DefaultWatchDirs

	QueueSize    int  // pending scan jobs before Submit drops, default 1024
	ScanPlatform bool // also scan Apple platform binaries on CreateProcess (default: skip, they are SIP-protected and signed)
}

// Defaults.
const (
	DefaultWorkers     = 2
	DefaultMaxFileSize = 64 << 20
	DefaultTimeoutSec  = 10
	DefaultQueueSize   = 1024
)

// DefaultWatchDirs is used when Config.WatchDirs is nil. ES reports resolved
// paths, so /tmp appears as /private/tmp; both are listed.
var DefaultWatchDirs = []string{"/tmp", "/private/tmp", "/Users/*/Downloads", "/Users/Shared"}

// WithDefaults returns c with zero values replaced by the defaults.
func (c Config) WithDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = DefaultWorkers
	}
	if c.MaxFileSize <= 0 {
		c.MaxFileSize = DefaultMaxFileSize
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = DefaultTimeoutSec
	}
	if c.QueueSize <= 0 {
		c.QueueSize = DefaultQueueSize
	}
	if c.WatchDirs == nil {
		c.WatchDirs = DefaultWatchDirs
	}
	return c
}

// UnderWatchDir reports whether file p lies (at any depth) under one of the
// glob prefixes. Each prefix is matched segment by segment with path.Match,
// so "/Users/*/Downloads" covers "/Users/alice/Downloads/x/y.dmg" but a "*"
// never spans a "/". p must be absolute and clean; anything else is refused.
func UnderWatchDir(p string, globs []string) bool {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	ps := strings.Split(p, "/")[1:]
	for _, g := range globs {
		g = strings.TrimSuffix(path.Clean(g), "/")
		if !strings.HasPrefix(g, "/") {
			continue
		}
		gs := strings.Split(g, "/")[1:]
		if g == "/" || len(ps) <= len(gs) {
			continue // the watch dir itself is not a file under it
		}
		ok := true
		for i, seg := range gs {
			if m, err := path.Match(seg, ps[i]); err != nil || !m {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
