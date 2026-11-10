//go:build linux

package response

import "time"

// Default directories of the vault and the isolation state.
const (
	DefaultVaultDir = "/var/lib/zaafvesper/quarantine"
	DefaultStateDir = "/var/lib/zaafvesper"
)

// ProtectedFilePrefixes are path prefixes no file action touches: the
// system and package-manager trees, kernel and device file systems, and
// /etc except the persistence directories remove_persistence handles
// (unprotectedUnder). Compared with case folding (stricter than Linux).
var ProtectedFilePrefixes = []string{
	"/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/boot/",
	"/etc/", "/dev/", "/proc/", "/sys/", "/run/", "/snap/",
	"/var/lib/dpkg/", "/var/lib/rpm/", "/var/lib/apt/", "/var/lib/dnf/", "/var/lib/snapd/", "/var/lib/systemd/",
	"/var/lib/zaafvesper/", "/opt/sysmon/",
}

// unprotectedUnder are exceptions to ProtectedFilePrefixes: /usr/local, the
// user-writable tmpfs directories /dev/shm and /run/user, and
// the cron, systemd and profile.d directories where an untrusted writer
// installs persistence. /etc/crontab, /etc/profile, /etc/bash.bashrc and
// every other file of /etc stay protected.
var unprotectedUnder = []string{
	"/usr/local/", "/dev/shm/", "/run/user/",
	"/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/",
	"/etc/systemd/system/", "/etc/profile.d/",
}

// Pinned binaries of the Linux actions.
const (
	NftBin       = "/usr/sbin/nft"
	SystemctlBin = "/usr/bin/systemctl"
)

var pinnedBins = map[string]bool{NftBin: true, SystemctlBin: true}

// birthTolerance is how far the file's birth time (statx) may be from the
// CreationUtcTime of a Sysmon for Linux file event.
const birthTolerance = 2 * time.Second
