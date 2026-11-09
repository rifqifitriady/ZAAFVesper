// Package sysmon decodes Sysmon events (Windows Sysmon and Sysmon for
// Linux, which share the event schema and the XML rendering) into
// ZAAFVesper's canonical events. It is platform-neutral: the Windows event
// log source (pkg/source/winevt) and the journald source
// (pkg/source/sysmonlinux) both feed it, and replay can use it anywhere.
// See README.md for the event and field mapping and its sources.
package sysmon

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/winproc"
)

// Provider names (System/Provider/@Name) and the platform each implies.
const (
	ProviderWindows = "Microsoft-Windows-Sysmon"
	ProviderLinux   = "Linux-Sysmon"
)

var providers = map[string]string{ProviderWindows: event.PlatformWindows, ProviderLinux: event.PlatformLinux}

// SourceName is event.Event.Source of decoded events.
const SourceName = "sysmon"

// utcTimeLayout is the layout of Sysmon's UtcTime fields.
const utcTimeLayout = "2006-01-02 15:04:05.000"

// MappedIDs lists the Sysmon event IDs Decode maps (W4).
var MappedIDs = []int{1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 25, 26}

// Decode parses and maps one event. Event IDs Sysmon emits that have no
// canonical event (2, 4, 9, 16, 24, 27-29, 255) return ErrUnsupported.
func Decode(raw []byte) (*event.Event, error) {
	r, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return Map(r)
}

// Map maps a parsed record onto a canonical event.
func Map(r *Record) (*event.Event, error) {
	platform, ok := providers[r.Provider]
	if !ok {
		return nil, ErrNotSysmon
	}
	m := mapper{d: r.Data, platform: platform}
	e := &event.Event{Seq: r.RecordID, Source: SourceName, Platform: platform, Args: map[string]string{"sysmon_event_id": strconv.Itoa(r.EventID)}}
	e.Time = m.time("UtcTime")
	if e.Time.IsZero() {
		e.Time = r.SystemTime
	}
	if e.Time.IsZero() {
		return nil, fmt.Errorf("%w: event %d has no UtcTime or SystemTime", ErrMalformed, r.EventID)
	}
	switch r.EventID {
	case 1:
		e.Name = event.CreateProcess
		p := m.proc("ProcessId", "ProcessGuid", "Image", "User")
		p.Cmdline = m.s("CommandLine")
		p.Args = m.args(p.Cmdline)
		p.Cwd = m.s("CurrentDirectory")
		p.Hashes = m.s("Hashes")
		p.Integrity = m.s("IntegrityLevel")
		p.Company = m.s("Company")
		p.Product = m.s("Product")
		p.Description = m.s("Description")
		p.OriginalName = m.s("OriginalFileName")
		p.StartTime = e.Time
		par := m.proc("ParentProcessId", "ParentProcessGuid", "ParentImage", "ParentUser")
		par.Cmdline = m.s("ParentCommandLine")
		p.PPID = par.PID
		if par.PID > 0 {
			p.Parent = par // stub: pid and incarnation (pidversion from the GUID)
		}
		e.Proc = p
		m.arg(e, "logon_id", "LogonId")
		m.arg(e, "logon_guid", "LogonGuid")
		m.arg(e, "terminal_session_id", "TerminalSessionId")
		m.arg(e, "file_version", "FileVersion")
		// The parent as Sysmon saw it at creation, also when the process
		// table does not know the parent (ps.parent.* then resolves to nil).
		m.arg(e, "parent_image", "ParentImage")
		m.arg(e, "parent_command_line", "ParentCommandLine")
		m.arg(e, "parent_user", "ParentUser")
	case 3:
		in, err := m.boolean("Initiated")
		if err != nil {
			return nil, err
		}
		e.Name, e.Proc = event.NetworkConnect, m.proc("ProcessId", "ProcessGuid", "Image", "User")
		n := &event.Net{Proto: strings.ToLower(m.s("Protocol")), SrcIP: m.s("SourceIp"), DstIP: m.s("DestinationIp"),
			SrcPort: m.port("SourcePort"), DstPort: m.port("DestinationPort"), DstHost: m.s("DestinationHostname"), Direction: "outbound"}
		if !in {
			e.Name, n.Direction = event.NetworkAccept, "inbound"
		}
		e.Net = n
		m.arg(e, "source_hostname", "SourceHostname")
		m.arg(e, "source_port_name", "SourcePortName")
		m.arg(e, "destination_port_name", "DestinationPortName")
	case 5:
		e.Name, e.Proc = event.TerminateProcess, m.proc("ProcessId", "ProcessGuid", "Image", "User")
	case 6:
		e.Name, e.Module = event.DriverLoad, m.module()
	case 7:
		e.Name, e.Proc, e.Module = event.ImageLoad, m.proc("ProcessId", "ProcessGuid", "Image", "User"), m.module()
		// Version resource of the loaded image (not of the process).
		m.arg(e, "file_version", "FileVersion")
		m.arg(e, "description", "Description")
		m.arg(e, "product", "Product")
		m.arg(e, "company", "Company")
		m.arg(e, "original_file_name", "OriginalFileName")
	case 8:
		e.Name = event.CreateRemoteThread
		e.Proc = m.proc("SourceProcessId", "SourceProcessGuid", "SourceImage", "SourceUser")
		e.Target = m.proc("TargetProcessId", "TargetProcessGuid", "TargetImage", "TargetUser")
		m.arg(e, "new_thread_id", "NewThreadId")
		m.arg(e, "start_address", "StartAddress")
		m.arg(e, "start_module", "StartModule")
		m.arg(e, "start_function", "StartFunction")
	case 10:
		// Event 10 spells the GUID fields "SourceProcessGUID" (upper case).
		e.Name = event.OpenProcess
		e.Proc = m.proc("SourceProcessId", "SourceProcessGUID", "SourceImage", "SourceUser")
		e.Target = m.proc("TargetProcessId", "TargetProcessGUID", "TargetImage", "TargetUser")
		m.arg(e, "granted_access", "GrantedAccess")
		m.arg(e, "call_trace", "CallTrace")
		m.arg(e, "source_thread_id", "SourceThreadId")
	case 11:
		e.Name, e.Proc, e.File = event.CreateFile, m.proc("ProcessId", "ProcessGuid", "Image", "User"), &event.File{Path: m.s("TargetFilename")}
		m.arg(e, "creation_utc_time", "CreationUtcTime")
	case 12, 13, 14:
		e.Proc = m.proc("ProcessId", "ProcessGuid", "Image", "User")
		et := m.s("EventType")
		reg := &event.Registry{Key: m.s("TargetObject")}
		switch {
		case r.EventID == 13:
			e.Name, reg.Data, reg.Value = event.RegistrySetValue, m.s("Details"), lastComponent(reg.Key)
		case r.EventID == 14:
			e.Name, reg.NewKey = event.RegistryRename, m.s("NewName")
		case strings.HasPrefix(et, "Create"):
			e.Name = event.RegistryCreateKey
		case strings.HasPrefix(et, "Delete"):
			e.Name = event.RegistryDeleteKey
			if et == "DeleteValue" {
				reg.Value = lastComponent(reg.Key)
			}
		default:
			return nil, fmt.Errorf("%w: event 12 with EventType %q", ErrMalformed, et)
		}
		e.Registry = reg
		m.arg(e, "event_type", "EventType")
	case 15:
		e.Name, e.Proc, e.File = event.FileStreamCreate, m.proc("ProcessId", "ProcessGuid", "Image", "User"), &event.File{Path: m.s("TargetFilename")}
		m.arg(e, "hash", "Hash")
		m.arg(e, "contents", "Contents")
		m.arg(e, "creation_utc_time", "CreationUtcTime")
	case 17, 18:
		e.Name = event.PipeCreate
		if r.EventID == 18 {
			e.Name = event.PipeConnect
		}
		e.Proc = m.proc("ProcessId", "ProcessGuid", "Image", "User")
		m.arg(e, "pipe_name", "PipeName")
		m.arg(e, "event_type", "EventType")
	case 19, 20, 21:
		// WMI events carry no process; User is the account that made the change.
		e.Name, e.Proc = event.WMIEvent, &event.Proc{UID: -1, EUID: -1, Username: m.s("User")}
		for _, k := range [][2]string{{"event_type", "EventType"}, {"operation", "Operation"}, {"event_namespace", "EventNamespace"},
			{"name", "Name"}, {"query", "Query"}, {"type", "Type"}, {"destination", "Destination"}, {"consumer", "Consumer"}, {"filter", "Filter"}} {
			m.arg(e, k[0], k[1])
		}
	case 22:
		e.Name, e.Proc = event.DNSQuery, m.proc("ProcessId", "ProcessGuid", "Image", "User")
		e.DNS = &event.DNS{Query: m.s("QueryName"), Status: m.s("QueryStatus"), Answers: answers(m.s("QueryResults"))}
	case 23, 26:
		e.Name, e.Proc, e.File = event.DeleteFile, m.proc("ProcessId", "ProcessGuid", "Image", "User"), &event.File{Path: m.s("TargetFilename")}
		m.arg(e, "hashes", "Hashes")
		m.arg(e, "is_executable", "IsExecutable")
		m.arg(e, "archived", "Archived")
	case 25:
		e.Name, e.Proc = event.ProcessTamper, m.proc("ProcessId", "ProcessGuid", "Image", "User")
		m.arg(e, "type", "Type")
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupported, r.EventID)
	}
	m.arg(e, "rule_name", "RuleName")
	return e, nil
}

type mapper struct {
	d        map[string]string
	platform string
}

// s returns a field; Sysmon writes "-" for an unknown value, which is
// treated as absent.
func (m mapper) s(k string) string {
	v := m.d[k]
	if v == "-" {
		return ""
	}
	return v
}

func (m mapper) arg(e *event.Event, key, field string) {
	if v := m.s(field); v != "" {
		e.Args[key] = v
	}
}

func (m mapper) time(k string) time.Time {
	v := m.s(k)
	if v == "" {
		return time.Time{}
	}
	t, err := time.ParseInLocation(utcTimeLayout, v, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (m mapper) port(k string) uint16 {
	n, err := strconv.ParseUint(m.s(k), 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

func (m mapper) boolean(k string) (bool, error) {
	switch strings.ToLower(m.s(k)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%w: %s is %q, want true or false", ErrMalformed, k, m.d[k])
}

func (m mapper) pid(k string) int32 {
	n, err := strconv.ParseUint(strings.TrimSpace(m.s(k)), 10, 31)
	if err != nil {
		return 0
	}
	return int32(n)
}

// proc builds a process from the four identity fields an event carries.
// Sysmon reports no numeric uid, so UID and EUID are -1 (unknown); the
// account is in Username ("DOMAIN\user" on Windows, the user name on Linux).
func (m mapper) proc(pidKey, guidKey, imageKey, userKey string) *event.Proc {
	p := &event.Proc{PID: m.pid(pidKey), UID: -1, EUID: -1, GUID: m.s(guidKey), Exe: m.s(imageKey), Username: m.s(userKey)}
	p.PIDVersion = GUIDVersion(p.GUID)
	p.Name = m.base(p.Exe)
	return p
}

func (m mapper) module() *event.Module {
	mod := &event.Module{Path: m.s("ImageLoaded"), Signature: m.s("Signature"), SignatureStatus: m.s("SignatureStatus"), Hashes: m.s("Hashes")}
	if b, err := m.boolean("Signed"); err == nil {
		mod.Signed = &b
	}
	return mod
}

// args splits a command line: Microsoft C runtime rules on Windows, white
// space on Linux (Sysmon for Linux joins argv with spaces, so an argument
// that held a space cannot be recovered). ps.cmdline keeps the exact string.
func (m mapper) args(cmdline string) []string {
	if cmdline == "" {
		return nil
	}
	if m.platform == event.PlatformWindows {
		return winproc.SplitCommandLine(cmdline, maxArgs)
	}
	f := strings.Fields(cmdline)
	if len(f) > maxArgs {
		f = f[:maxArgs]
	}
	return f
}

const maxArgs = 1024

func (m mapper) base(p string) string {
	if p == "" {
		return ""
	}
	sep := "/"
	if m.platform == event.PlatformWindows {
		if i := strings.LastIndexAny(p, `\/`); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	if i := strings.LastIndex(p, sep); i >= 0 {
		return p[i+1:]
	}
	return p
}

func lastComponent(key string) string {
	if i := strings.LastIndexByte(key, '\\'); i >= 0 {
		return key[i+1:]
	}
	return ""
}

// answers splits QueryResults ("type:  5 cname.example;::ffff:192.0.2.1;").
func answers(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ";") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// GUIDVersion derives a non-zero 32-bit incarnation number from a Sysmon
// ProcessGuid (FNV-1a over the lower-case GUID without braces), used as
// Proc.PIDVersion so the process table tells a recycled pid from the
// process that had it before. 0 for an empty or all-zero GUID.
func GUIDVersion(guid string) uint32 {
	g := strings.ToLower(strings.Trim(strings.TrimSpace(guid), "{}"))
	if strings.Trim(g, "0-") == "" {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(g))
	v := h.Sum32()
	if v == 0 {
		v = 1
	}
	return v
}
