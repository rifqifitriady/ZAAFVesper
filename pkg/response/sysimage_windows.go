//go:build windows

package response

import "os"

// trustProgramDirs are the program folders of trust decisions: the
// system's own values (the service's environment comes from the system),
// or the defaults when none is set. A hard-coded C:\Program Files on
// another system drive could be a folder any user created.
var trustProgramDirs = func() []string {
	var out []string
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if d := os.Getenv(v); d != "" && checkCleanAbs(d) == nil {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		out = []string{`C:\Program Files`, `C:\Program Files (x86)`}
	}
	return out
}()

// trustDefenderDir is Microsoft Defender's platform folder, the one place
// under ProgramData whose programs count as system programs (the rest of
// ProgramData\Microsoft has user-writable folders such as
// Crypto\RSA\MachineKeys).
var trustDefenderDir = func() string {
	pd := os.Getenv("ProgramData")
	if pd == "" || checkCleanAbs(pd) != nil {
		pd = `C:\ProgramData`
	}
	return pd + `\Microsoft\Windows Defender\Platform`
}()

// systemImage reports whether exe runs from a folder only administrators
// can write, for trust decisions (winSystemImage: fail closed, ASCII-only
// comparison, the user-writable folders under the Windows directory
// excluded). The protection direction (protectedPath, which refuses to act
// on C:\Windows, the program folders, ProgramData\Microsoft) is wider and
// separate.
func systemImage(exe string) bool {
	if checkCleanAbs(exe) != nil {
		return false
	}
	return winSystemImage(exe, systemRoot, trustProgramDirs, trustDefenderDir)
}
