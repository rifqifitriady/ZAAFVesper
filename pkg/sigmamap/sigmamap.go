// Package sigmamap maps Sigma log sources and field names onto ZAAFVesper's
// canonical events and rule fields. It is data only, shared by the Sigma
// importer (Sigma -> ZAAFVesper) and the ZAAFElegia / SIEM exporters
// (ZAAFVesper -> Sigma field names). Part of the shared contract: change it
// deliberately, and keep TestTargetsExist green.
package sigmamap

import (
	"sort"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// Category is one Sigma log source category.
type Category struct {
	Name string
	// Events are the canonical events this category covers.
	Events []string
	// Fields maps a Sigma field name to a ZAAFVesper field: a static field
	// (event.LookupField) or an indexed one such as "evt.arg[pipe_name]".
	Fields map[string]string
	// Values translates special Sigma values for a field, e.g. Initiated
	// "true" -> net.direction "outbound". Keyed by Sigma field.
	Values map[string]map[string]ValueMapping
}

// ValueMapping replaces a Sigma field comparison by a comparison on another
// ZAAFVesper field with another value.
type ValueMapping struct {
	Field string
	Value string
}

// Products maps Sigma logsource.product to evt.platform.
var Products = map[string]string{
	"macos":   event.PlatformMacOS,
	"windows": event.PlatformWindows,
	"linux":   event.PlatformLinux,
}

func merge(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

var proc = map[string]string{
	"Image":       "ps.exe",
	"ProcessId":   "ps.pid",
	"ProcessGuid": "ps.guid",
	"User":        "ps.username",
}

var procCreate = map[string]string{
	"CommandLine":       "ps.cmdline",
	"CurrentDirectory":  "ps.cwd",
	"ParentImage":       "ps.parent.exe",
	"ParentCommandLine": "ps.parent.cmdline",
	"ParentProcessId":   "ps.ppid",
	"ParentProcessGuid": "ps.parent.guid",
	"ParentUser":        "ps.parent.username",
	"OriginalFileName":  "ps.original_name",
	"Hashes":            "ps.hashes",
	"IntegrityLevel":    "ps.integrity",
	"Company":           "ps.company",
	"Product":           "ps.product",
	"Description":       "ps.description",
}

var registry = map[string]string{
	"TargetObject": "registry.key",
	"Details":      "registry.data",
	"NewName":      "registry.new_key",
	"EventType":    "evt.arg[event_type]",
}

var module = map[string]string{
	"ImageLoaded":     "image.path",
	"Signed":          "image.signed",
	"Signature":       "image.signature",
	"SignatureStatus": "image.signature_status",
	"Hashes":          "image.hashes",
}

var sourceTarget = map[string]string{
	"SourceImage":     "ps.exe",
	"SourceProcessId": "ps.pid",
	"SourceUser":      "ps.username",
	"TargetImage":     "target.ps.exe",
	"TargetProcessId": "target.ps.pid",
	"TargetUser":      "target.ps.username",
}

// Categories is keyed by Sigma category name.
var Categories = map[string]*Category{
	"process_creation":    {Events: []string{event.CreateProcess}, Fields: merge(proc, procCreate)},
	"process_termination": {Events: []string{event.TerminateProcess}, Fields: merge(proc)},
	"file_event":          {Events: []string{event.CreateFile, event.WriteFile}, Fields: merge(proc, map[string]string{"TargetFilename": "file.path"})},
	"file_delete":         {Events: []string{event.DeleteFile}, Fields: merge(proc, map[string]string{"TargetFilename": "file.path"})},
	"file_rename":         {Events: []string{event.RenameFile}, Fields: merge(proc, map[string]string{"SourceFilename": "file.path", "TargetFilename": "file.dest"})},
	"network_connection": {
		Events: []string{event.NetworkConnect, event.NetworkAccept},
		Fields: merge(proc, map[string]string{
			"DestinationIp": "net.dip", "DestinationPort": "net.dport", "DestinationHostname": "net.dhost",
			"SourceIp": "net.sip", "SourcePort": "net.sport", "Protocol": "net.proto",
		}),
		Values: map[string]map[string]ValueMapping{"Initiated": {
			"true":  {Field: "net.direction", Value: "outbound"},
			"false": {Field: "net.direction", Value: "inbound"},
		}},
	},
	"dns_query":            {Events: []string{event.DNSQuery}, Fields: merge(proc, map[string]string{"QueryName": "dns.query", "QueryResults": "dns.answers", "QueryStatus": "dns.status"})},
	"image_load":           {Events: []string{event.ImageLoad}, Fields: merge(proc, module)},
	"driver_load":          {Events: []string{event.DriverLoad, event.LoadKext}, Fields: merge(module)},
	"registry_add":         {Events: []string{event.RegistryCreateKey}, Fields: merge(proc, registry)},
	"registry_delete":      {Events: []string{event.RegistryDeleteKey}, Fields: merge(proc, registry)},
	"registry_set":         {Events: []string{event.RegistrySetValue}, Fields: merge(proc, registry)},
	"registry_rename":      {Events: []string{event.RegistryRename}, Fields: merge(proc, registry)},
	"registry_event":       {Events: []string{event.RegistryCreateKey, event.RegistryDeleteKey, event.RegistrySetValue, event.RegistryRename}, Fields: merge(proc, registry)},
	"create_remote_thread": {Events: []string{event.CreateRemoteThread}, Fields: merge(sourceTarget, map[string]string{"SourceProcessGuid": "ps.guid", "TargetProcessGuid": "target.ps.guid", "StartAddress": "evt.arg[start_address]", "StartModule": "evt.arg[start_module]", "StartFunction": "evt.arg[start_function]"})},
	"process_access":       {Events: []string{event.OpenProcess}, Fields: merge(sourceTarget, map[string]string{"SourceProcessGUID": "ps.guid", "TargetProcessGUID": "target.ps.guid", "GrantedAccess": "evt.arg[granted_access]", "CallTrace": "evt.arg[call_trace]"})},
	"pipe_created":         {Events: []string{event.PipeCreate, event.PipeConnect}, Fields: merge(proc, map[string]string{"PipeName": "evt.arg[pipe_name]", "EventType": "evt.arg[event_type]"})},
	"wmi_event": {Events: []string{event.WMIEvent}, Fields: map[string]string{
		"User": "ps.username", "EventType": "evt.arg[event_type]", "Operation": "evt.arg[operation]",
		"EventNamespace": "evt.arg[event_namespace]", "Name": "evt.arg[name]", "Query": "evt.arg[query]",
		"Type": "evt.arg[type]", "Destination": "evt.arg[destination]", "Consumer": "evt.arg[consumer]", "Filter": "evt.arg[filter]",
	}},
	"process_tampering":  {Events: []string{event.ProcessTamper}, Fields: merge(proc, map[string]string{"Type": "evt.arg[type]"})},
	"create_stream_hash": {Events: []string{event.FileStreamCreate}, Fields: merge(proc, map[string]string{"TargetFilename": "file.path", "Hash": "evt.arg[hash]", "Contents": "evt.arg[contents]"})},
}

// exportFields is the reverse of Category.Fields: ZAAFVesper field -> Sigma
// field, per category. Built once; a category must not map two Sigma
// fields onto one ZAAFVesper field (TestOneSigmaNamePerTarget), so the
// reverse is unambiguous and stable.
var exportFields = map[string]map[string]string{}

func init() {
	for name, c := range Categories {
		c.Name = name
		rev := map[string]string{}
		for sf, zf := range c.Fields {
			rev[zf] = sf
		}
		exportFields[name] = rev
	}
}

// SigmaField maps a ZAAFVesper field of a category back to its Sigma field
// name (for the ZAAFElegia and SIEM exporters).
func SigmaField(category, zvField string) (string, bool) {
	f, ok := exportFields[category][zvField]
	return f, ok
}

// ExportFields returns the ZAAFVesper -> Sigma field map of a category
// (a copy), or nil for an unknown category.
func ExportFields(category string) map[string]string {
	rev, ok := exportFields[category]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(rev))
	for k, v := range rev {
		out[k] = v
	}
	return out
}

// primary is the category used when exporting an event; registry events
// export under their specific category, not registry_event.
var primary = map[string]string{
	event.CreateProcess: "process_creation", event.TerminateProcess: "process_termination",
	event.CreateFile: "file_event", event.WriteFile: "file_event", event.DeleteFile: "file_delete",
	event.RenameFile: "file_rename", event.NetworkConnect: "network_connection", event.NetworkAccept: "network_connection",
	event.DNSQuery: "dns_query", event.ImageLoad: "image_load", event.DriverLoad: "driver_load", event.LoadKext: "driver_load",
	event.RegistryCreateKey: "registry_add", event.RegistryDeleteKey: "registry_delete",
	event.RegistrySetValue: "registry_set", event.RegistryRename: "registry_rename",
	event.CreateRemoteThread: "create_remote_thread", event.OpenProcess: "process_access",
	event.PipeCreate: "pipe_created", event.PipeConnect: "pipe_created", event.WMIEvent: "wmi_event",
	event.ProcessTamper: "process_tampering", event.FileStreamCreate: "create_stream_hash",
}

// ForEvent returns the Sigma category an event exports under, or nil when
// the event has no Sigma equivalent (e.g. Fork, SetXattr, YaraMatch).
func ForEvent(name string) *Category { return Categories[primary[name]] }

// SysmonEventIDs gives the Sysmon-compatible EventID an event exports with
// (0: none).
var SysmonEventIDs = map[string]int{
	event.CreateProcess: 1, event.NetworkConnect: 3, event.NetworkAccept: 3, event.TerminateProcess: 5,
	event.DriverLoad: 6, event.LoadKext: 6, event.ImageLoad: 7, event.CreateRemoteThread: 8, event.OpenProcess: 10,
	event.CreateFile: 11, event.WriteFile: 11, event.RegistryCreateKey: 12, event.RegistryDeleteKey: 12,
	event.RegistrySetValue: 13, event.RegistryRename: 14, event.FileStreamCreate: 15, event.PipeCreate: 17,
	event.PipeConnect: 18, event.WMIEvent: 20, event.DNSQuery: 22, event.DeleteFile: 23, event.ProcessTamper: 25,
}

// Field maps a Sigma field of a category to a ZAAFVesper field.
func Field(category, sigmaField string) (string, bool) {
	c := Categories[category]
	if c == nil {
		return "", false
	}
	f, ok := c.Fields[sigmaField]
	return f, ok
}

// CategoryNames returns the supported categories, sorted.
func CategoryNames() []string {
	out := make([]string, 0, len(Categories))
	for k := range Categories {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
