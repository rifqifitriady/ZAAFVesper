//go:build windows

package response

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

// sep is the path separator of the file actions' paths.
const sep = `\`

// Default directories of the vault and the isolation state. Both are
// created with a protected DACL that grants SYSTEM and Administrators only
// (privateDACL).
const (
	DefaultVaultDir = `C:\ProgramData\ZAAFVesper\quarantine`
	DefaultStateDir = `C:\ProgramData\ZAAFVesper`
)

// systemRoot is the Windows directory (C:\Windows), systemDir System32.
var systemRoot, systemDir = func() (string, string) {
	root, dir := `C:\Windows`, `C:\Windows\System32`
	if d, err := windows.GetSystemWindowsDirectory(); err == nil && d != "" {
		root = d
	}
	if d, err := windows.GetSystemDirectory(); err == nil && d != "" {
		dir = d
	}
	return root, dir
}()

// Pinned binaries of the Windows actions (System32).
var (
	NetshBin    = filepath.Join(systemDir, "netsh.exe")
	SchtasksBin = filepath.Join(systemDir, "schtasks.exe")
)

var pinnedBins = map[string]bool{NetshBin: true, SchtasksBin: true}

// ProtectedFilePrefixes are path prefixes no file action touches (compared
// case-insensitively): the Windows directory, the program folders, the
// boot and recovery folders, Microsoft's ProgramData. C:\Windows\Temp is
// the one exception (unprotectedUnder). Scheduled task files under
// System32\Tasks are never touched as files: remove_persistence deletes the
// task with schtasks.exe.
var ProtectedFilePrefixes = func() []string {
	out := []string{systemRoot + `\`, `C:\Windows\`, `C:\Boot\`, `C:\Recovery\`, `C:\System Volume Information\`,
		`C:\ProgramData\Microsoft\`, `C:\Program Files\`, `C:\Program Files (x86)\`}
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if d := os.Getenv(v); d != "" && checkCleanAbs(d) == nil {
			out = append(out, d+`\`)
		}
	}
	return out
}()

// unprotectedUnder are exceptions to ProtectedFilePrefixes.
var unprotectedUnder = []string{systemRoot + `\Temp\`}

// birthTolerance is how far the file's creation time may be from the
// CreationUtcTime of a Sysmon file event (Sysmon prints milliseconds).
const birthTolerance = time.Millisecond

// checkCleanAbs accepts only a plain local path: a drive letter, a
// backslash, clean components, no alternate data stream (no ':' after the
// drive), no component ending in a dot or a space (Windows would strip it,
// so two names would reach one file), no device or UNC prefix.
func checkCleanAbs(p string) error {
	bad := func() error { return fmt.Errorf("path %q is not a plain absolute local path", p) }
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' || !(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') {
		return bad()
	}
	if filepath.Clean(p) != p || strings.ContainsAny(p[2:], ":*?\"<>|/\x00") || !utf8.ValidString(p) {
		return bad()
	}
	for _, c := range strings.Split(p[3:], `\`) {
		if c == "" && len(p) > 3 {
			return bad()
		}
		if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return bad()
		}
	}
	return nil
}

// pinnedEnv: Windows programs need SystemRoot (Winsock, netsh helpers).
func pinnedEnv() []string { return []string{"SystemRoot=" + systemRoot} }
func pinnedDir() string   { return systemDir }

func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
