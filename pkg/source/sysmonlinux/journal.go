// Package sysmonlinux is the Linux event source: it runs journalctl to
// follow the events Sysmon for Linux logs to journald and hands each one to
// the shared Sysmon decoder (pkg/source/sysmon). The journalctl path,
// argv and environment are fixed. Only journal records whose trusted fields
// (set by journald from the sender's credentials, not by the sender) say
// they came from root in sysmon.service are accepted, so a local user who
// logs a forged Sysmon XML line with logger(1) is ignored. The parsing in
// this file is platform-neutral; running journalctl is Linux-only.
package sysmonlinux

import (
	"encoding/json"
	"errors"
	"time"
)

// Fixed paths and names.
const (
	// Journalctl is the only journalctl ZAAFVesper runs (as root it must be
	// root-owned along its whole path, like every other file it trusts).
	Journalctl = "/usr/bin/journalctl"
	// SysmonUnit is the systemd unit Sysmon for Linux installs ("sysmon -i").
	SysmonUnit = "sysmon.service"
	// Name is the source name (source.Source.Name).
	Name = "sysmon-journald"
	// MaxLineBytes bounds one journal JSON line; longer lines are skipped.
	MaxLineBytes = 2 << 20
	// IdentityTolerance is the Binder tolerance on Linux: the start time in
	// /proc has 10 ms ticks and Sysmon's UtcTime 1 ms.
	IdentityTolerance = 20 * time.Millisecond
	maxCursorLen      = 512
)

// Env is journalctl's whole environment: no inherited variables (no
// SYSTEMD_PAGER, no LD_*), plain output.
var Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=", "SYSTEMD_LESS="}

// Args returns journalctl's argv (without argv[0]). The matches are on
// trusted journal fields: _SYSTEMD_UNIT and _UID are set by journald.
// --all keeps fields longer than 4096 bytes (long command lines) instead of
// printing them as null. With a cursor the journal resumes right after the
// last record read; without one it starts at the end.
func Args(cursor string) []string {
	a := []string{"--follow", "--output=json", "--all", "--no-pager", "--quiet"}
	if cursor != "" && ValidCursor(cursor) {
		a = append(a, "--after-cursor="+cursor)
	} else {
		a = append(a, "--lines=0")
	}
	return append(a, "_SYSTEMD_UNIT="+SysmonUnit, "_UID=0")
}

// ValidCursor accepts only the characters journald uses in cursors
// (s=…;i=…;b=…;m=…;t=…;x=…), so a cursor can never become another option.
func ValidCursor(c string) bool {
	if c == "" || len(c) > maxCursorLen || c[0] == '-' {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '=' || ch == ';') {
			return false
		}
	}
	return true
}

// Errors of ParseLine.
var (
	ErrUntrusted = errors.New("sysmonlinux: journal record not from root in " + SysmonUnit)
	ErrNoMessage = errors.New("sysmonlinux: journal record without MESSAGE")
)

type record struct {
	Cursor  string          `json:"__CURSOR"`
	UID     string          `json:"_UID"`
	Unit    string          `json:"_SYSTEMD_UNIT"`
	Message json.RawMessage `json:"MESSAGE"`
}

// ParseLine decodes one journalctl --output=json line. It returns the
// record's MESSAGE (journald prints a non-UTF-8 or binary field as an array
// of byte values) and its cursor. The cursor is returned even for a record
// that is refused, so resuming skips it.
func ParseLine(line []byte) (msg []byte, cursor string, err error) {
	var r record
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, "", err
	}
	if ValidCursor(r.Cursor) {
		cursor = r.Cursor
	}
	if r.UID != "0" || r.Unit != SysmonUnit {
		return nil, cursor, ErrUntrusted
	}
	if len(r.Message) == 0 || string(r.Message) == "null" {
		return nil, cursor, ErrNoMessage
	}
	var s string
	if err := json.Unmarshal(r.Message, &s); err == nil {
		return []byte(s), cursor, nil
	}
	var b []byte
	var nums []int
	if err := json.Unmarshal(r.Message, &nums); err != nil {
		return nil, cursor, ErrNoMessage
	}
	b = make([]byte, 0, len(nums))
	for _, n := range nums {
		if n < 0 || n > 255 {
			return nil, cursor, ErrNoMessage
		}
		b = append(b, byte(n))
	}
	return b, cursor, nil
}
