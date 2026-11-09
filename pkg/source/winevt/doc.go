// Package winevt is the Windows event source: it subscribes to Sysmon's
// event log channel with EvtSubscribe (pull model), renders each event to
// XML with EvtRender and hands it to the shared Sysmon decoder
// (pkg/source/sysmon). wevtapi.dll is loaded from System32 through
// golang.org/x/sys/windows; there is no cgo. Everything but this file is
// Windows-only.
package winevt

import "time"

// Channel is Sysmon's event log channel.
const Channel = "Microsoft-Windows-Sysmon/Operational"

// Name is the source name (source.Source.Name).
const Name = "sysmon-winevt"

// IdentityTolerance is the Binder tolerance on Windows: Sysmon's UtcTime has
// millisecond resolution, the kernel creation time 100 ns.
const IdentityTolerance = 2 * time.Millisecond

// Config configures the source.
type Config struct {
	// Logf receives operational messages. Nil discards them.
	Logf func(format string, args ...any)
}
