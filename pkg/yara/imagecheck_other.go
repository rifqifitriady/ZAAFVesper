//go:build yara && !darwin

package yara

import "errors"

// CheckLoadedImages is only implemented on macOS; elsewhere it fails closed.
func CheckLoadedImages() error {
	return errors.New("yara: loaded-image check is only implemented on macOS")
}
