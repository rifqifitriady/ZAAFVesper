package response

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
)

// This file holds the platform-neutral classification of the persistence
// items remove_persistence handles on Linux and Windows, so that it is
// tested on every platform.

// Linux persistence kinds.
const (
	persistSystemdSystem = "systemd unit"
	persistSystemdUser   = "systemd user unit"
	persistCron          = "cron file"
	persistShellRC       = "shell rc file"
)

// unitRe is the systemd unit names remove_persistence accepts (the name
// becomes a systemctl argument after "--").
var unitRe = regexp.MustCompile(`^[A-Za-z0-9_:.@\\-]{1,240}\.(service|timer|socket|path)$`)

// protectedUnits are unit name prefixes that are never stopped: the
// system's own services, remote access, and the sensor. The unit file an
// untrusted writer put in /etc/systemd/system under such a name is still
// moved to the vault (the vendor unit applies again at the next start).
var protectedUnits = []string{"systemd-", "dbus", "ssh", "getty@", "serial-getty@", "user@", "user-runtime-dir@",
	"NetworkManager", "networking", "network", "polkit", "udisks", "cron", "rsyslog", "auditd", "snapd",
	"containerd", "docker", "kubelet", "sysmon", "multipathd", "cloud-", "walinuxagent", "google-", "amazon-ssm"}

// ownUnit is ZAAFVesper's own unit name prefix: refused outright.
const ownUnit = "zaafvesper"

// rcFiles are the shell start-up files of a home directory.
var rcFiles = map[string]bool{".bashrc": true, ".bash_profile": true, ".bash_login": true, ".profile": true,
	".zshrc": true, ".zprofile": true, ".zshenv": true, ".zlogin": true, ".bash_logout": true}

// linuxPersistKind returns what kind of persistence item the file at path
// is and its unit name (systemd), or why it is not one remove_persistence
// handles. Only files directly in the persistence directories qualify.
func linuxPersistKind(path string) (kind, unit, why string) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/") {
		return "", "", "not a clean absolute path"
	}
	i := strings.LastIndexByte(path, '/')
	dir, base := path[:i], path[i+1:]
	if base == "" || base == "." || base == ".." {
		return "", "", "no file name"
	}
	parts := strings.Split(dir, "/") // "", "home", user, ...
	switch {
	case dir == "/etc/systemd/system":
		if !unitRe.MatchString(base) || strings.HasPrefix(base, "-") {
			return "", "", "not a plain systemd unit name (.service, .timer, .socket, .path)"
		}
		return persistSystemdSystem, base, ""
	case dir == "/root/.config/systemd/user" || len(parts) == 6 && parts[1] == "home" && parts[2] != "" && parts[3] == ".config" && parts[4] == "systemd" && parts[5] == "user":
		if !unitRe.MatchString(base) || strings.HasPrefix(base, "-") {
			return "", "", "not a plain systemd unit name (.service, .timer, .socket, .path)"
		}
		return persistSystemdUser, base, ""
	case dir == "/etc/cron.d" || dir == "/etc/cron.hourly" || dir == "/etc/cron.daily" || dir == "/etc/cron.weekly" || dir == "/etc/cron.monthly" ||
		dir == "/var/spool/cron/crontabs" || dir == "/var/spool/cron":
		if dir == "/var/spool/cron" && (base == "crontabs" || base == "atjobs" || base == "atspool") {
			return "", "", "a cron spool directory, not a file"
		}
		return persistCron, "", ""
	case dir == "/etc/profile.d":
		if !strings.HasSuffix(base, ".sh") {
			return "", "", "not a .sh file of /etc/profile.d"
		}
		return persistShellRC, "", ""
	case rcFiles[base] && (dir == "/root" || len(parts) == 3 && parts[1] == "home" && parts[2] != ""):
		return persistShellRC, "", ""
	}
	return "", "", "not a systemd unit, cron file or shell rc file remove_persistence handles"
}

// protectedUnit returns why a unit must not be stopped, or "".
func protectedUnit(unit string) string {
	l := strings.ToLower(unit)
	for _, p := range protectedUnits {
		if strings.HasPrefix(l, strings.ToLower(p)) {
			return "unit " + unit + " is a system, remote-access or agent service (prefix " + p + ")"
		}
	}
	return ""
}

// Windows persistence kinds.
const (
	persistRunValue = "registry-value"
	persistService  = "service"
	persistTask     = "scheduled-task"
)

// runKeys are the Run and RunOnce keys (below HKLM or HKU\<SID>) whose
// values remove_persistence deletes.
var runKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
}

var sidRe = regexp.MustCompile(`^S-1-5(-[0-9]{1,10}){1,14}$`)

// winRunValue splits a Sysmon TargetObject of a Run/RunOnce value
// ("HKLM\SOFTWARE\...\Run\name", "HKU\S-1-5-21-...\SOFTWARE\...\Run\name")
// into its hive ("HKLM" or "HKU"), the key below the hive and the value
// name (which may hold backslashes: everything after the fixed key).
func winRunValue(target string) (hive, key, name, why string) {
	hive, rest, ok := strings.Cut(target, `\`)
	if !ok {
		return "", "", "", "not a registry path"
	}
	prefix := ""
	switch strings.ToUpper(hive) {
	case "HKLM":
		hive = "HKLM"
	case "HKU":
		hive = "HKU"
		sid, r2, ok := strings.Cut(rest, `\`)
		if !ok || !sidRe.MatchString(sid) {
			return "", "", "", "not a user hive HKU\\<SID>"
		}
		prefix, rest = sid+`\`, r2
	default:
		return "", "", "", "hive " + hive + " is not HKLM or HKU"
	}
	for _, k := range runKeys {
		if len(rest) > len(k)+1 && strings.EqualFold(rest[:len(k)], k) && rest[len(k)] == '\\' {
			name = rest[len(k)+1:]
			if name == "" || strings.ContainsRune(name, 0) {
				return "", "", "", "no value name"
			}
			return hive, prefix + k, name, ""
		}
	}
	return "", "", "", "not a value of a Run or RunOnce key"
}

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.\-$ ]{1,256}$`)

// winServiceImagePath returns the service name of a Sysmon TargetObject
// of a service's ImagePath ("HKLM\System\CurrentControlSet\Services\<name>\ImagePath",
// any ControlSet00n), or why it is not one.
func winServiceImagePath(target string) (name, why string) {
	parts := strings.Split(target, `\`)
	if len(parts) != 6 || !strings.EqualFold(parts[0], "HKLM") || !strings.EqualFold(parts[1], "SYSTEM") ||
		!strings.EqualFold(parts[3], "Services") || !strings.EqualFold(parts[5], "ImagePath") {
		return "", "not the ImagePath value of a service key"
	}
	cs := strings.ToLower(parts[2])
	if cs != "currentcontrolset" && !(strings.HasPrefix(cs, "controlset") && len(cs) == len("controlset001")) {
		return "", "not a control set"
	}
	if !serviceNameRe.MatchString(parts[4]) {
		return "", "service name " + parts[4] + " is not plain"
	}
	return parts[4], ""
}

// protectedServices are service names (case-insensitive prefixes) that
// are never stopped or deleted: Windows security and core services,
// Sysmon, and the sensor.
var protectedServices = []string{"WinDefend", "WdNisSvc", "WdFilter", "WdBoot", "Sense", "SecurityHealthService", "MpsSvc", "BFE",
	"EventLog", "Sysmon", "SysmonDrv", "ZAAFVesper", "TrustedInstaller", "wuauserv", "RpcSs", "RpcEptMapper", "DcomLaunch",
	"LanmanServer", "LanmanWorkstation", "Dnscache", "Dhcp", "nsi", "NlaSvc", "Netlogon", "SamSs", "LSM", "Schedule",
	"WinRM", "TermService", "sshd", "W32Time", "CryptSvc", "gpsvc", "ProfSvc", "Winmgmt", "WindowsAzureGuestAgent", "RdAgent"}

func protectedService(name string) string {
	for _, p := range protectedServices {
		if hasPrefixFold(name, p) {
			return "service " + name + " is a protected system service (" + p + ")"
		}
	}
	return ""
}

// serviceImage returns the program of a service's ImagePath: the quoted
// first token, or the text up to the first ".exe" (unquoted paths with
// spaces), or the first word. Kernel paths (\SystemRoot\..., \??\...) and
// relative paths are returned as they are (they are never plain absolute).
func serviceImage(binPath string) string {
	s := strings.TrimSpace(binPath)
	if strings.HasPrefix(s, `"`) {
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			return s[1 : 1+i]
		}
		return s[1:]
	}
	if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		return s[:i+4]
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// winTaskName returns the scheduled task name ("\Folder\Name") of a file
// under the Tasks directory, or why it is not one remove_persistence
// handles. Tasks under \Microsoft\ are Windows' own and refused.
func winTaskName(path, tasksDir string) (name, why string) {
	if len(path) <= len(tasksDir)+1 || !strings.EqualFold(path[:len(tasksDir)], tasksDir) || path[len(tasksDir)] != '\\' {
		return "", "not a task file under " + tasksDir
	}
	rel := path[len(tasksDir)+1:]
	for _, c := range strings.Split(rel, `\`) {
		if c == "" || c == "." || c == ".." || strings.ContainsAny(c, "\x00\"*?<>|:/") {
			return "", "task name " + rel + " is not plain"
		}
	}
	if hasPrefixFold(rel, `Microsoft\`) {
		return "", "Windows' own task \\" + rel
	}
	return `\` + rel, ""
}

// taskCommands returns the <Command> values of a task definition's Exec
// actions. The XML is UTF-16 (with a byte order mark) as the Task
// Scheduler writes it, or UTF-8.
func taskCommands(b []byte) ([]string, error) {
	text, err := decodeTaskXML(b)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Actions struct {
			Exec []struct {
				Command string `xml:"Command"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	d := xml.NewDecoder(strings.NewReader(text))
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil } // already decoded
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("task definition: %w", err)
	}
	var out []string
	for _, x := range doc.Actions.Exec {
		out = append(out, strings.TrimSpace(x.Command))
	}
	return out, nil
}

func decodeTaskXML(b []byte) (string, error) {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		if len(b)%2 != 0 {
			return "", fmt.Errorf("task definition: odd UTF-16 length")
		}
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
		}
		return string(utf16.Decode(u)), nil
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return string(b[3:]), nil
	}
	return string(b), nil
}

// expandSystemVars expands %SystemRoot% and %windir% (the variables a
// command of the system's own can rely on); any other %VAR% is left as it
// is, so the command does not count as a system program.
func expandSystemVars(s, systemRoot string) string {
	for _, v := range []string{"%SystemRoot%", "%windir%"} {
		for {
			i := strings.Index(strings.ToLower(s), strings.ToLower(v))
			if i < 0 {
				break
			}
			s = s[:i] + systemRoot + s[i+len(v):]
		}
	}
	return s
}
