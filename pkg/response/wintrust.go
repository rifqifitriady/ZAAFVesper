package response

import (
	"strings"
	"unicode/utf8"
)

// winUserWritable are folders under the Windows directory that a standard
// user can write to (or create files in) on a default installation: the
// well-known AppLocker bypass list (Tasks, Temp, tracing, CRMLog, FxsTmp,
// com\dmp, the spool folders, MachineKeys, the task folders, debug, PLA).
// A program there is not a system program, whatever folder it is in.
// Relative to the Windows directory, with a trailing backslash.
var winUserWritable = []string{
	`Tasks\`, `Temp\`, `tracing\`, `Registration\CRMLog\`, `debug\`, `PLA\`,
	`System32\FxsTmp\`, `System32\com\dmp\`, `System32\Microsoft\Crypto\RSA\MachineKeys\`,
	`System32\spool\PRINTERS\`, `System32\spool\SERVERS\`, `System32\spool\drivers\color\`,
	`System32\Tasks\`, `System32\Tasks_Migrated\`,
	`SysWOW64\FxsTmp\`, `SysWOW64\com\dmp\`, `SysWOW64\Tasks\`, `SysWOW64\Tasks_Migrated\`,
}

// winSystemImage is the Windows test of trust decisions (remove_persistence
// refuses a system program as the writer, a service or a task that runs
// one): exe runs from a folder only administrators can write. It fails
// closed, unlike the protected-path test of the protection direction:
//
//   - only the Windows directory (sysRoot), the program folders
//     (programDirs) and the Defender platform folder under ProgramData
//     (defender) count, compared ASCII-only and case-insensitively
//     (hasPrefixASCIIFold): "C:\Program Fileſ\" (U+017F, a folder any user
//     can create at the root of C:) is not "C:\Program Files\";
//   - under the Windows directory the whole path must be ASCII with no
//     short (8.3) name ("~"): Windows' own programs have neither, and
//     neither can then dodge the deny-list;
//   - the user-writable folders under the Windows directory
//     (winUserWritable) are not system folders, compared both ASCII-only
//     and with Unicode folding (matching more is the safe side here).
//
// The caller has checked that exe is a clean absolute local path.
func winSystemImage(exe, sysRoot string, programDirs []string, defender string) bool {
	root := strings.TrimSuffix(sysRoot, `\`) + `\`
	if sysRoot != "" && hasPrefixASCIIFold(exe, root) {
		if !asciiOnly(exe) || strings.Contains(exe, "~") {
			return false
		}
		for _, w := range winUserWritable {
			if hasPrefixASCIIFold(exe, root+w) || hasPrefixFold(exe, root+w) {
				return false
			}
		}
		return true
	}
	if defender != "" && hasPrefixASCIIFold(exe, strings.TrimSuffix(defender, `\`)+`\`) {
		return true
	}
	for _, d := range programDirs {
		if d != "" && hasPrefixASCIIFold(exe, strings.TrimSuffix(d, `\`)+`\`) {
			return true
		}
	}
	return false
}

func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
