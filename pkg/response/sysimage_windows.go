//go:build windows

package response

// systemImage reports whether exe runs from a directory only
// administrators can write: the Windows directory (not its Temp) and the
// program folders (ProtectedFilePrefixes).
func systemImage(exe string) bool {
	if checkCleanAbs(exe) != nil {
		return false
	}
	for _, ok := range unprotectedUnder {
		if hasPrefixFold(exe, ok) {
			return false
		}
	}
	for _, p := range ProtectedFilePrefixes {
		if hasPrefixFold(exe, p) {
			return true
		}
	}
	return false
}
