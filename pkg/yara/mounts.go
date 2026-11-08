package yara

import "strings"

// onNonLocalMount reports whether the absolute path p lies on (or under) one
// of the mount points in mounts.
func onNonLocalMount(p string, mounts []string) bool {
	for _, m := range mounts {
		switch {
		case m == "":
		case m == "/":
			return true // the root itself is remote: everything is
		case p == m || strings.HasPrefix(p, m) && len(p) > len(m) && p[len(m)] == '/':
			return true
		}
	}
	return false
}
