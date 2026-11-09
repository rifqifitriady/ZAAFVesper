package sysmonlinux

// Config configures the source.
type Config struct {
	// OnStart, if set, is called with the journalctl child's pid on every
	// (re)start, so the caller can protect it from kill actions.
	OnStart func(pid int32)
	// Logf receives operational messages (restarts). Nil discards them.
	Logf func(format string, args ...any)
}
