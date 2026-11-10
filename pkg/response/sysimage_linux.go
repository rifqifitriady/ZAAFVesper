//go:build linux

package response

import "strings"

// systemDirs hold the programs of the system and of packages: only root
// can write there.
var systemDirs = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/opt/", "/snap/"}

// systemImage reports whether exe runs from a system directory.
func systemImage(exe string) bool {
	if checkCleanAbs(exe) != nil {
		return false
	}
	for _, d := range systemDirs {
		if strings.HasPrefix(exe, d) {
			return true
		}
	}
	return false
}
