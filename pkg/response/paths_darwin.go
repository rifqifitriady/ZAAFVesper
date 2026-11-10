//go:build darwin

package response

import "time"

// Default directories of the vault and the isolation state.
const (
	DefaultVaultDir = "/private/var/db/zaafvesper/quarantine"
	DefaultStateDir = "/private/var/db/zaafvesper"
)

// ProtectedFilePrefixes are path prefixes no file action touches (compared
// with Unicode case folding: APFS is normally case-insensitive). /usr/local
// is the one exception under /usr.
var ProtectedFilePrefixes = []string{
	"/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/",
	"/private/var/db/", "/var/db/", "/private/etc/", "/etc/", "/dev/",
	"/Library/Application Support/com.apple.TCC/",
	"/Library/LaunchDaemons/com.apple.", "/Library/LaunchAgents/com.apple.",
}

// unprotectedUnder are exceptions to ProtectedFilePrefixes.
var unprotectedUnder = []string{"/usr/local/"}

var pinnedBins = map[string]bool{PfctlBin: true, LaunchctlBin: true, CodesignBin: true, RouteBin: true}

// birthTolerance: macOS events carry the inode, not a creation time.
const birthTolerance = 0 * time.Second
