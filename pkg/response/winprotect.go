package response

import (
	"path/filepath"
	"strings"
)

// Windows image protection, kept free of Windows APIs so it is tested on
// every platform (identify_windows.go supplies the folders). A process is
// protected by the full path of its image, compared without regard to case
// as Windows does, never by its base name alone: malware named lsass.exe or
// Sysmon64.exe in a temporary folder is not protected (ATT&CK T1036.005).

// winProtectedSystem32 are critical or security images under
// %SystemRoot%\System32 (critical processes are also refused through
// IsProcessCritical).
var winProtectedSystem32 = []string{
	"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
	"lsass.exe", "lsaiso.exe", "fontdrvhost.exe", "dwm.exe",
}

// winSysmonImages are the images Sysmon installs into %SystemRoot%.
var winSysmonImages = []string{"Sysmon.exe", "Sysmon64.exe", "Sysmon64a.exe"}

// winFolders are the folders protectedWinImage needs.
type winFolders struct {
	SystemRoot, ProgramData, ProgramFiles, Self string
}

// protectedWinImage returns why the image at exe must not be killed, or "".
func protectedWinImage(exe string, f winFolders) string {
	clean := filepath.Clean(exe)
	eq := func(p string) bool { return p != "" && strings.EqualFold(clean, filepath.Clean(p)) }
	join := func(parts ...string) string { return strings.Join(parts, `\`) }
	if f.SystemRoot != "" {
		for _, n := range winProtectedSystem32 {
			if eq(join(f.SystemRoot, "System32", n)) {
				return "protected Windows system image " + n
			}
		}
		for _, n := range winSysmonImages {
			if eq(join(f.SystemRoot, n)) {
				return "Sysmon (the sensor's event source)"
			}
		}
	}
	if f.ProgramFiles != "" && eq(join(f.ProgramFiles, "Windows Defender", "MsMpEng.exe")) {
		return "Microsoft Defender"
	}
	if f.ProgramData != "" {
		dir := join(f.ProgramData, "Microsoft", "Windows Defender", "Platform") + `\`
		if len(clean) > len(dir) && strings.EqualFold(clean[:len(dir)], dir) && strings.EqualFold(clean[strings.LastIndexByte(clean, '\\')+1:], "MsMpEng.exe") {
			return "Microsoft Defender"
		}
	}
	if eq(f.Self) {
		return "ZAAFVesper itself"
	}
	return ""
}
