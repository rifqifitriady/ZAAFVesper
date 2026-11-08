// Package event defines ZAAFVesper's platform-neutral event model. It is the shared
// contract between event sources, the process snapshotter, the YARA scanner and
// the rule engine. Changes here affect every package; keep them deliberate.
package event

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Canonical event names (evt.name). Sources map native events onto these.
const (
	CreateProcess      = "CreateProcess"
	Fork               = "Fork"
	TerminateProcess   = "TerminateProcess"
	OpenFile           = "OpenFile"
	CreateFile         = "CreateFile"
	WriteFile          = "WriteFile"
	RenameFile         = "RenameFile"
	DeleteFile         = "DeleteFile"
	SetXattr           = "SetXattr"
	DeleteXattr        = "DeleteXattr"
	SetMode            = "SetMode"
	SetOwner           = "SetOwner"
	OpenProcess        = "OpenProcess"
	Signal             = "Signal"
	Ptrace             = "Ptrace"
	CreateRemoteThread = "CreateRemoteThread"
	AddLaunchItem      = "AddLaunchItem"
	Mount              = "Mount"
	LoadKext           = "LoadKext"
	Authenticate       = "Authenticate"
	Sudo               = "Sudo"
	ModifyTCC          = "ModifyTCC"
	XProtectDetect     = "XProtectDetect"
	YaraMatch          = "YaraMatch"
	// SensorDegraded is synthetic: ZAAFVesper emits it when its own
	// telemetry is degraded (process-table pressure, capped output, dropped
	// events). evt.arg[condition] names the condition, evt.arg[detail]
	// describes it. Never subscribed at a source.
	SensorDegraded = "SensorDegraded"

	// Network (macOS: socket polling; Windows/Linux: Sysmon 3 and 22).
	NetworkConnect = "NetworkConnect" // outbound connection
	NetworkAccept  = "NetworkAccept"  // listening socket or inbound connection
	DNSQuery       = "DNSQuery"

	// Windows and Linux (Sysmon). macOS kernel extensions stay LoadKext.
	ImageLoad         = "ImageLoad"
	DriverLoad        = "DriverLoad"
	RegistryCreateKey = "RegistryCreateKey"
	RegistryDeleteKey = "RegistryDeleteKey"
	RegistrySetValue  = "RegistrySetValue"
	RegistryRename    = "RegistryRename"
	PipeCreate        = "PipeCreate"
	PipeConnect       = "PipeConnect"
	WMIEvent          = "WMIEvent"
	ProcessTamper     = "ProcessTamper"
	FileStreamCreate  = "FileStreamCreate"
)

// Platforms (evt.platform).
const (
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
)

// Code-signing validation categories (ps.cs_category), from Endpoint
// Security's es_cs_validation_category_t (macOS 15+). Empty means the source
// did not report one; the field then resolves to nil, so trust conditions
// that require a category fail closed.
const (
	CSInvalid      = "invalid"
	CSPlatform     = "platform"
	CSTestFlight   = "testflight"
	CSDevelopment  = "development"
	CSAppStore     = "app_store"
	CSEnterprise   = "enterprise"
	CSDeveloperID  = "developer_id"
	CSLocalSigning = "local_signing"
	CSRosetta      = "rosetta"
	CSOOPJIT       = "oopjit"
	CSNone         = "none"
)

// Category groups event names (evt.category).
func Category(name string) string {
	switch name {
	case CreateProcess, Fork, TerminateProcess, OpenProcess, Signal, Ptrace, CreateRemoteThread:
		return "process"
	case OpenFile, CreateFile, WriteFile, RenameFile, DeleteFile, SetXattr, DeleteXattr, SetMode, SetOwner:
		return "file"
	case AddLaunchItem, LoadKext, Mount, ModifyTCC:
		return "system"
	case Authenticate, Sudo:
		return "auth"
	case XProtectDetect, YaraMatch:
		return "threat"
	case SensorDegraded:
		return "sensor"
	case NetworkConnect, NetworkAccept, DNSQuery:
		return "network"
	case ImageLoad, DriverLoad:
		return "module"
	case RegistryCreateKey, RegistryDeleteKey, RegistrySetValue, RegistryRename:
		return "registry"
	case PipeCreate, PipeConnect:
		return "pipe"
	case WMIEvent:
		return "wmi"
	case ProcessTamper:
		return "process"
	case FileStreamCreate:
		return "file"
	}
	return "other"
}

// Proc describes a process. Parent is a shallow copy (its own Parent is nil).
type Proc struct {
	PID  int32 `json:"pid" yaml:"pid"`
	PPID int32 `json:"ppid" yaml:"ppid"`
	// OriginalPPID is the parent at fork time (es_process_t.original_ppid).
	// It differs from PPID when the process was reparented, e.g. to launchd
	// by a double fork. Zero when unknown (the field then resolves to nil).
	OriginalPPID int32  `json:"original_ppid,omitempty" yaml:"original_ppid,omitempty"`
	PIDVersion   uint32 `json:"pidversion,omitempty" yaml:"pidversion,omitempty"`
	UUID         uint64 `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// UniqueID is the kernel's per-boot unique process id (p_uniqueid, from
	// proc_info PROC_PIDUNIQIDENTIFIERINFO), read when the process table
	// first sees the process. Zero when unknown. The responder compares it
	// right before a kill.
	UniqueID uint64 `json:"unique_id,omitempty" yaml:"unique_id,omitempty"`
	// AncestorsUntrusted is set by the process table: true when any known
	// ancestor (up to launchd) is neither an Apple platform binary nor a
	// verified vendor identity (team_id with cs_category developer_id or
	// app_store), or when the ancestor chain is incomplete.
	AncestorsUntrusted bool     `json:"ancestors_untrusted,omitempty" yaml:"ancestors_untrusted,omitempty"`
	Exe                string   `json:"exe" yaml:"exe"`
	Name               string   `json:"name" yaml:"name"`
	Cmdline            string   `json:"cmdline,omitempty" yaml:"cmdline,omitempty"`
	Args               []string `json:"args,omitempty" yaml:"args,omitempty"`
	Cwd                string   `json:"cwd,omitempty" yaml:"cwd,omitempty"`
	UID                int64    `json:"uid" yaml:"uid"`
	EUID               int64    `json:"euid" yaml:"euid"`
	Username           string   `json:"username,omitempty" yaml:"username,omitempty"`
	SigningID          string   `json:"signing_id,omitempty" yaml:"signing_id,omitempty"`
	TeamID             string   `json:"team_id,omitempty" yaml:"team_id,omitempty"`
	CDHash             string   `json:"cdhash,omitempty" yaml:"cdhash,omitempty"`
	IsPlatform         bool     `json:"is_platform" yaml:"is_platform"`
	IsSigned           bool     `json:"is_signed" yaml:"is_signed"`
	// CSCategory is the code-signing validation category (CS* constants);
	// empty when the source does not report it.
	CSCategory string `json:"cs_category,omitempty" yaml:"cs_category,omitempty"`
	// Seeded marks a process learned at start-up from the kernel
	// (kern.procargs2) rather than from an exec event; its identity is
	// unverified and response never acts on it.
	Seeded bool `json:"seeded,omitempty" yaml:"seeded,omitempty"`
	// Executable file identity at exec time (from the source's stat of the
	// executable). Zero when unknown. Used to bind scans and kills to the
	// file that actually ran, not whatever is at the path later.
	ExeDev     uint64            `json:"exe_dev,omitempty" yaml:"exe_dev,omitempty"`
	ExeIno     uint64            `json:"exe_ino,omitempty" yaml:"exe_ino,omitempty"`
	ExeCtimeNs int64             `json:"exe_ctime_ns,omitempty" yaml:"exe_ctime_ns,omitempty"` // st_ctime, Unix ns
	TTY        string            `json:"tty,omitempty" yaml:"tty,omitempty"`
	StartTime  time.Time         `json:"start_time,omitempty" yaml:"start_time,omitempty"`
	Env        map[string]string `json:"env,omitempty" yaml:"env,omitempty"`
	Parent     *Proc             `json:"parent,omitempty" yaml:"parent,omitempty"`
	Ancestors  []string          `json:"ancestors,omitempty" yaml:"ancestors,omitempty"`
	// Windows and Linux (Sysmon) process attributes; empty on macOS, and the
	// rule fields then resolve to nil.
	GUID         string `json:"guid,omitempty" yaml:"guid,omitempty"`
	Hashes       string `json:"hashes,omitempty" yaml:"hashes,omitempty"`
	Integrity    string `json:"integrity,omitempty" yaml:"integrity,omitempty"`
	Company      string `json:"company,omitempty" yaml:"company,omitempty"`
	Product      string `json:"product,omitempty" yaml:"product,omitempty"`
	Description  string `json:"description,omitempty" yaml:"description,omitempty"`
	OriginalName string `json:"original_name,omitempty" yaml:"original_name,omitempty"`
}

// File describes the file object of a file event.
type File struct {
	Path string `json:"path" yaml:"path"`
	Dest string `json:"dest,omitempty" yaml:"dest,omitempty"` // rename/link destination
	Mode uint32 `json:"mode,omitempty" yaml:"mode,omitempty"`
	Size int64  `json:"size,omitempty" yaml:"size,omitempty"`
	// File identity as reported by the source (zero when unknown), used to
	// bind scans to the file the event was about.
	Dev     uint64 `json:"dev,omitempty" yaml:"dev,omitempty"`
	Ino     uint64 `json:"ino,omitempty" yaml:"ino,omitempty"`
	CtimeNs int64  `json:"ctime_ns,omitempty" yaml:"ctime_ns,omitempty"`
}

// Yara carries the result of a YARA signature match (evt.name = YaraMatch).
type Yara struct {
	Rule      string            `json:"rule" yaml:"rule"`
	Namespace string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Tags      []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Meta      map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
	Target    string            `json:"target" yaml:"target"` // scanned file path
}

// Net describes a network connection (NetworkConnect, NetworkAccept).
type Net struct {
	Proto     string `json:"proto,omitempty" yaml:"proto,omitempty"`         // tcp, udp
	Direction string `json:"direction,omitempty" yaml:"direction,omitempty"` // outbound, inbound, listen
	SrcIP     string `json:"sip,omitempty" yaml:"sip,omitempty"`
	SrcPort   uint16 `json:"sport,omitempty" yaml:"sport,omitempty"`
	DstIP     string `json:"dip,omitempty" yaml:"dip,omitempty"`
	DstPort   uint16 `json:"dport,omitempty" yaml:"dport,omitempty"`
	DstHost   string `json:"dhost,omitempty" yaml:"dhost,omitempty"` // resolved name when known
}

// DNS describes a name lookup (DNSQuery).
type DNS struct {
	Query   string   `json:"query" yaml:"query"`
	Type    string   `json:"type,omitempty" yaml:"type,omitempty"`
	Answers []string `json:"answers,omitempty" yaml:"answers,omitempty"`
	Status  string   `json:"status,omitempty" yaml:"status,omitempty"`
}

// Registry describes a Windows registry change (Registry* events).
type Registry struct {
	Key    string `json:"key" yaml:"key"`
	Value  string `json:"value,omitempty" yaml:"value,omitempty"`
	Data   string `json:"data,omitempty" yaml:"data,omitempty"`
	NewKey string `json:"new_key,omitempty" yaml:"new_key,omitempty"`
}

// Module describes a loaded image or driver (ImageLoad, DriverLoad).
type Module struct {
	Path            string `json:"path" yaml:"path"`
	Signed          *bool  `json:"signed,omitempty" yaml:"signed,omitempty"`
	Signature       string `json:"signature,omitempty" yaml:"signature,omitempty"`
	SignatureStatus string `json:"signature_status,omitempty" yaml:"signature_status,omitempty"`
	Hashes          string `json:"hashes,omitempty" yaml:"hashes,omitempty"`
}

// Event is one normalized system event.
type Event struct {
	Seq    uint64            `json:"seq" yaml:"seq"`
	Time   time.Time         `json:"time" yaml:"time"`
	Name   string            `json:"name" yaml:"name"`
	Source string            `json:"source,omitempty" yaml:"source,omitempty"` // e.g. "eslogger", "yara", "fixture"
	Proc   *Proc             `json:"proc,omitempty" yaml:"proc,omitempty"`
	Target *Proc             `json:"target,omitempty" yaml:"target,omitempty"` // target process (get_task, signal, ptrace)
	File   *File             `json:"file,omitempty" yaml:"file,omitempty"`
	Args   map[string]string `json:"args,omitempty" yaml:"args,omitempty"` // evt.arg[key]
	Yara   *Yara             `json:"yara,omitempty" yaml:"yara,omitempty"`
	// Platform is the source platform (Platform* constants); empty in old
	// captures and fixtures, where evt.platform resolves to nil.
	Platform string    `json:"platform,omitempty" yaml:"platform,omitempty"`
	Net      *Net      `json:"net,omitempty" yaml:"net,omitempty"`
	DNS      *DNS      `json:"dns,omitempty" yaml:"dns,omitempty"`
	Registry *Registry `json:"registry,omitempty" yaml:"registry,omitempty"`
	Module   *Module   `json:"module,omitempty" yaml:"module,omitempty"`
}

// Value is the result of resolving a field: string, int64, bool or []string.
// A nil Value means the field is absent on this event.
type Value = any

// FieldKind is the static type of a field, used by the rule compiler.
type FieldKind int

const (
	KindString FieldKind = iota
	KindInt
	KindBool
	KindStrings
)

type fieldDef struct {
	kind FieldKind
	get  func(*Event) Value
}

func procField(sel func(*Event) *Proc, get func(*Proc) Value) func(*Event) Value {
	return func(e *Event) Value {
		p := sel(e)
		if p == nil {
			return nil
		}
		return get(p)
	}
}

func fileField(get func(*File) Value) func(*Event) Value {
	return func(e *Event) Value {
		if e.File == nil {
			return nil
		}
		return get(e.File)
	}
}

func yaraField(get func(*Yara) Value) func(*Event) Value {
	return func(e *Event) Value {
		if e.Yara == nil {
			return nil
		}
		return get(e.Yara)
	}
}

// procKinds lists every per-process attribute and its kind. Each is exposed
// under the ps., ps.parent. and target.ps. prefixes.
var procKinds = map[string]FieldKind{
	"pid": KindInt, "ppid": KindInt, "uuid": KindInt, "exe": KindString,
	"name": KindString, "cmdline": KindString, "args": KindStrings, "cwd": KindString,
	"uid": KindInt, "euid": KindInt, "username": KindString, "signing_id": KindString,
	"team_id": KindString, "cdhash": KindString, "is_platform": KindBool,
	"is_signed": KindBool, "tty": KindString, "ancestors": KindStrings,
	"cs_category": KindString, "original_ppid": KindInt,
	"ancestors_untrusted": KindBool,
	"guid":                KindString, "hashes": KindString, "integrity": KindString, "company": KindString,
	"product": KindString, "description": KindString, "original_name": KindString,
}

func procGetter(attr string) func(*Proc) Value {
	switch attr {
	case "pid":
		return func(p *Proc) Value { return int64(p.PID) }
	case "ppid":
		return func(p *Proc) Value { return int64(p.PPID) }
	case "uuid":
		return func(p *Proc) Value { return int64(p.UUID) }
	case "exe":
		return func(p *Proc) Value { return p.Exe }
	case "name":
		return func(p *Proc) Value { return p.Name }
	case "cmdline":
		return func(p *Proc) Value { return p.Cmdline }
	case "args":
		return func(p *Proc) Value { return p.Args }
	case "cwd":
		return func(p *Proc) Value { return p.Cwd }
	case "uid":
		return func(p *Proc) Value { return p.UID }
	case "euid":
		return func(p *Proc) Value { return p.EUID }
	case "username":
		return func(p *Proc) Value { return p.Username }
	case "signing_id":
		return func(p *Proc) Value { return p.SigningID }
	case "team_id":
		return func(p *Proc) Value { return p.TeamID }
	case "cdhash":
		return func(p *Proc) Value { return p.CDHash }
	case "is_platform":
		return func(p *Proc) Value { return p.IsPlatform }
	case "is_signed":
		return func(p *Proc) Value { return p.IsSigned }
	case "tty":
		return func(p *Proc) Value { return p.TTY }
	case "ancestors":
		return func(p *Proc) Value { return p.Ancestors }
	case "guid":
		return func(p *Proc) Value { return nonEmpty(p.GUID) }
	case "hashes":
		return func(p *Proc) Value { return nonEmpty(p.Hashes) }
	case "integrity":
		return func(p *Proc) Value { return nonEmpty(p.Integrity) }
	case "company":
		return func(p *Proc) Value { return nonEmpty(p.Company) }
	case "product":
		return func(p *Proc) Value { return nonEmpty(p.Product) }
	case "description":
		return func(p *Proc) Value { return nonEmpty(p.Description) }
	case "original_name":
		return func(p *Proc) Value { return nonEmpty(p.OriginalName) }
	case "ancestors_untrusted":
		return func(p *Proc) Value { return p.AncestorsUntrusted }
	case "original_ppid":
		return func(p *Proc) Value {
			if p.OriginalPPID == 0 {
				return nil
			}
			return int64(p.OriginalPPID)
		}
	case "cs_category":
		return func(p *Proc) Value {
			if p.CSCategory == "" {
				return nil
			}
			return p.CSCategory
		}
	}
	panic("event: unknown proc attribute " + attr)
}

// fields is the registry of every field name a rule may reference.
var fields = map[string]fieldDef{}

func init() {
	fields["evt.name"] = fieldDef{KindString, func(e *Event) Value { return e.Name }}
	fields["evt.category"] = fieldDef{KindString, func(e *Event) Value { return Category(e.Name) }}
	fields["evt.seq"] = fieldDef{KindInt, func(e *Event) Value { return int64(e.Seq) }}
	fields["evt.source"] = fieldDef{KindString, func(e *Event) Value { return e.Source }}
	fields["evt.pid"] = fieldDef{KindInt, procField(func(e *Event) *Proc { return e.Proc }, procGetter("pid"))}

	selectors := map[string]func(*Event) *Proc{
		"ps.": func(e *Event) *Proc { return e.Proc },
		"ps.parent.": func(e *Event) *Proc {
			if e.Proc == nil {
				return nil
			}
			return e.Proc.Parent
		},
		"target.ps.": func(e *Event) *Proc { return e.Target },
	}
	for prefix, sel := range selectors {
		for attr, kind := range procKinds {
			fields[prefix+attr] = fieldDef{kind, procField(sel, procGetter(attr))}
		}
	}

	fields["file.path"] = fieldDef{KindString, fileField(func(f *File) Value { return f.Path })}
	fields["file.name"] = fieldDef{KindString, fileField(func(f *File) Value { return filepath.Base(f.Path) })}
	fields["file.dir"] = fieldDef{KindString, fileField(func(f *File) Value { return filepath.Dir(f.Path) })}
	fields["file.ext"] = fieldDef{KindString, fileField(func(f *File) Value { return strings.ToLower(filepath.Ext(f.Path)) })}
	fields["file.dest"] = fieldDef{KindString, fileField(func(f *File) Value { return f.Dest })}
	fields["file.mode"] = fieldDef{KindInt, fileField(func(f *File) Value { return int64(f.Mode) })}
	fields["file.size"] = fieldDef{KindInt, fileField(func(f *File) Value { return f.Size })}

	fields["yara.rule"] = fieldDef{KindString, yaraField(func(y *Yara) Value { return y.Rule })}
	fields["yara.namespace"] = fieldDef{KindString, yaraField(func(y *Yara) Value { return y.Namespace })}
	fields["yara.tags"] = fieldDef{KindStrings, yaraField(func(y *Yara) Value { return y.Tags })}
	fields["yara.target"] = fieldDef{KindString, yaraField(func(y *Yara) Value { return y.Target })}

	fields["evt.platform"] = fieldDef{KindString, func(e *Event) Value { return nonEmpty(e.Platform) }}

	netF := func(get func(*Net) Value) func(*Event) Value {
		return func(e *Event) Value {
			if e.Net == nil {
				return nil
			}
			return get(e.Net)
		}
	}
	fields["net.proto"] = fieldDef{KindString, netF(func(n *Net) Value { return nonEmpty(n.Proto) })}
	fields["net.direction"] = fieldDef{KindString, netF(func(n *Net) Value { return nonEmpty(n.Direction) })}
	fields["net.sip"] = fieldDef{KindString, netF(func(n *Net) Value { return nonEmpty(n.SrcIP) })}
	fields["net.sport"] = fieldDef{KindInt, netF(func(n *Net) Value { return nonZeroPort(n.SrcPort) })}
	fields["net.dip"] = fieldDef{KindString, netF(func(n *Net) Value { return nonEmpty(n.DstIP) })}
	fields["net.dport"] = fieldDef{KindInt, netF(func(n *Net) Value { return nonZeroPort(n.DstPort) })}
	fields["net.dhost"] = fieldDef{KindString, netF(func(n *Net) Value { return nonEmpty(n.DstHost) })}

	dnsF := func(get func(*DNS) Value) func(*Event) Value {
		return func(e *Event) Value {
			if e.DNS == nil {
				return nil
			}
			return get(e.DNS)
		}
	}
	fields["dns.query"] = fieldDef{KindString, dnsF(func(d *DNS) Value { return nonEmpty(d.Query) })}
	fields["dns.type"] = fieldDef{KindString, dnsF(func(d *DNS) Value { return nonEmpty(d.Type) })}
	fields["dns.answers"] = fieldDef{KindStrings, dnsF(func(d *DNS) Value { return d.Answers })}
	fields["dns.status"] = fieldDef{KindString, dnsF(func(d *DNS) Value { return nonEmpty(d.Status) })}

	regF := func(get func(*Registry) Value) func(*Event) Value {
		return func(e *Event) Value {
			if e.Registry == nil {
				return nil
			}
			return get(e.Registry)
		}
	}
	fields["registry.key"] = fieldDef{KindString, regF(func(r *Registry) Value { return nonEmpty(r.Key) })}
	fields["registry.value"] = fieldDef{KindString, regF(func(r *Registry) Value { return nonEmpty(r.Value) })}
	fields["registry.data"] = fieldDef{KindString, regF(func(r *Registry) Value { return nonEmpty(r.Data) })}
	fields["registry.new_key"] = fieldDef{KindString, regF(func(r *Registry) Value { return nonEmpty(r.NewKey) })}

	modF := func(get func(*Module) Value) func(*Event) Value {
		return func(e *Event) Value {
			if e.Module == nil {
				return nil
			}
			return get(e.Module)
		}
	}
	fields["image.path"] = fieldDef{KindString, modF(func(m *Module) Value { return nonEmpty(m.Path) })}
	fields["image.signed"] = fieldDef{KindBool, modF(func(m *Module) Value {
		if m.Signed == nil {
			return nil
		}
		return *m.Signed
	})}
	fields["image.signature"] = fieldDef{KindString, modF(func(m *Module) Value { return nonEmpty(m.Signature) })}
	fields["image.signature_status"] = fieldDef{KindString, modF(func(m *Module) Value { return nonEmpty(m.SignatureStatus) })}
	fields["image.hashes"] = fieldDef{KindString, modF(func(m *Module) Value { return nonEmpty(m.Hashes) })}
}

// nonZeroPort maps port 0 (unreported) to nil.
func nonZeroPort(p uint16) Value {
	if p == 0 {
		return nil
	}
	return int64(p)
}

// Names returns every canonical event name, sorted. The rule compiler and
// the Sigma map use it, so the list lives in one place.
func Names() []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

var names = []string{
	CreateProcess, Fork, TerminateProcess, OpenFile, CreateFile, WriteFile, RenameFile, DeleteFile,
	SetXattr, DeleteXattr, SetMode, SetOwner, OpenProcess, Signal, Ptrace, CreateRemoteThread,
	AddLaunchItem, Mount, LoadKext, Authenticate, Sudo, ModifyTCC, XProtectDetect, YaraMatch,
	SensorDegraded, NetworkConnect, NetworkAccept, DNSQuery, ImageLoad, DriverLoad,
	RegistryCreateKey, RegistryDeleteKey, RegistrySetValue, RegistryRename,
	PipeCreate, PipeConnect, WMIEvent, ProcessTamper, FileStreamCreate,
}

// nonEmpty maps "" to nil (absent), so comparisons on an unreported
// attribute are false under the rule language's nil semantics.
func nonEmpty(s string) Value {
	if s == "" {
		return nil
	}
	return s
}

// LookupField reports whether name is a known static field and its kind.
// Indexed fields (evt.arg[x], ps.env[x], ps.parent.env[x], yara.meta[x]) are
// handled by IndexedField.
func LookupField(name string) (FieldKind, bool) {
	d, ok := fields[name]
	return d.kind, ok
}

// FieldNames returns all static field names (unsorted).
func FieldNames() []string {
	out := make([]string, 0, len(fields))
	for k := range fields {
		out = append(out, k)
	}
	return out
}

// IndexedRoots are the field roots that accept a [key] suffix.
var IndexedRoots = []string{"evt.arg", "ps.env", "ps.parent.env", "yara.meta"}

// Get resolves a static field on the event. Unknown or absent fields yield nil.
func (e *Event) Get(name string) Value {
	d, ok := fields[name]
	if !ok || d.get == nil {
		return nil
	}
	return d.get(e)
}

// GetIndexed resolves root[key], e.g. GetIndexed("evt.arg", "signal").
// Always returns a string value or nil.
func (e *Event) GetIndexed(root, key string) Value {
	var m map[string]string
	switch root {
	case "evt.arg":
		m = e.Args
	case "ps.env":
		if e.Proc != nil {
			m = e.Proc.Env
		}
	case "ps.parent.env":
		if e.Proc != nil && e.Proc.Parent != nil {
			m = e.Proc.Parent.Env
		}
	case "yara.meta":
		if e.Yara != nil {
			m = e.Yara.Meta
		}
	}
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	return v
}
