// Package nofollow opens a file for reading without following a symbolic
// link (or, on Windows, any reparse point) in the final path component.
// ZAAFVesper reads its configuration, macros and rules through it, so a
// link planted by another user cannot redirect a privileged read.
package nofollow

import "errors"

// ErrLink is returned (wrapped) when the final path component is a symbolic
// link or, on Windows, a reparse point (symbolic link, junction, mount point).
var ErrLink = errors.New("is a symbolic link or reparse point (not allowed)")
