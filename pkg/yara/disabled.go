//go:build !yara

package yara

import (
	"context"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source"
)

// New returns ErrDisabled when built without the yara tag.
func New(cfg Config) (source.Scanner, error) { return nil, ErrDisabled }

// CheckLoadedImages has nothing to check without the yara tag: the binary
// then links no third-party library (pure Go).
func CheckLoadedImages() error { return nil }

// Scanner is the stub of the libyara scanner in builds without the yara tag,
// so code that names *yara.Scanner (or its OnDegraded method) compiles in
// both builds. New never returns one; every method is inert.
type Scanner struct{}

var _ source.Scanner = (*Scanner)(nil)

// Start always fails: there is no YARA support in this build.
func (*Scanner) Start(context.Context, chan<- *event.Event) error { return ErrDisabled }

// Submit does nothing.
func (*Scanner) Submit(*event.Event) {}

// Close does nothing.
func (*Scanner) Close() error { return nil }

// Stats reports nothing.
func (*Scanner) Stats() map[string]uint64 { return nil }

// OnDegraded does nothing: the stub never degrades.
func (*Scanner) OnDegraded(func(condition, detail string)) {}
