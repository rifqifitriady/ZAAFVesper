// Package winproc wraps the few Windows process APIs ZAAFVesper uses
// (Toolhelp32 snapshot, OpenProcess, GetProcessTimes,
// QueryFullProcessImageName, NtQueryInformationProcess for the command
// line, IsProcessCritical, TerminateProcess) through golang.org/x/sys/windows,
// without cgo. Everything but this file is Windows-only.
package winproc

import "time"

// FiletimeEpochDelta is the number of 100 ns intervals between 1601-01-01
// (FILETIME epoch) and 1970-01-01.
const FiletimeEpochDelta = 116444736000000000

// FiletimeToTime converts a FILETIME value (100 ns since 1601, UTC).
func FiletimeToTime(ft uint64) time.Time {
	if ft < FiletimeEpochDelta {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-FiletimeEpochDelta)*100).UTC()
}
