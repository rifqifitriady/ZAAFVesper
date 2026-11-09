//go:build !darwin && !windows && !linux

package response

import "errors"

// identify is only implemented for macOS; elsewhere every kill is refused.
func identify(pid int32) (Identity, error) {
	return Identity{}, errors.New("process identity check not implemented on this platform")
}
