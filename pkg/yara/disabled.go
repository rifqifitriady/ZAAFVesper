//go:build !yara

package yara

import "github.com/rifqifitriady/ZAAFVesper/pkg/source"

// New returns ErrDisabled when built without the yara tag.
func New(cfg Config) (source.Scanner, error) { return nil, ErrDisabled }

// CheckLoadedImages has nothing to check without the yara tag: the binary
// then links no third-party library (pure Go).
func CheckLoadedImages() error { return nil }
