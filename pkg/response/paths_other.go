//go:build !darwin && !linux && !windows

package response

import "time"

const (
	DefaultVaultDir = "/var/lib/zaafvesper/quarantine"
	DefaultStateDir = "/var/lib/zaafvesper"
)

var ProtectedFilePrefixes = []string{"/"}

var unprotectedUnder []string

var pinnedBins = map[string]bool{}

const birthTolerance = 0 * time.Second
