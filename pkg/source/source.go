// Package source defines the interface every event source implements.
package source

import (
	"context"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Source produces normalized events. Run blocks until ctx is cancelled or the
// source fails, sending each event to out. Sources must never close out.
type Source interface {
	Name() string
	// Run starts the source subscribed to the given canonical event names
	// (event.CreateProcess, ...). An empty set means "everything supported".
	Run(ctx context.Context, events []string, out chan<- *event.Event) error
	// Stats reports counters (decoded, dropped, decode_errors, ...).
	Stats() map[string]uint64
}

// Enricher augments events in place (process tree, usernames, ...). It is
// called on the single pipeline goroutine, in event order.
type Enricher interface {
	Enrich(e *event.Event)
}

// Scanner asynchronously inspects events (YARA). Matches are delivered as new
// events (event.YaraMatch) on the channel passed to Start.
type Scanner interface {
	Start(ctx context.Context, out chan<- *event.Event) error
	Submit(e *event.Event)
	Close() error
}
