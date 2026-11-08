package eslogger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// MaxLineSize is the largest eslogger JSON line ZAAFVesper accepts (16 MiB).
const MaxLineSize = 16 << 20

// Code-signing flags from <kern/cs_blobs.h> (Kernel.framework, macOS 26 SDK).
const (
	csValid  = 0x00000001 // CS_VALID: dynamically valid
	csAdhoc  = 0x00000002 // CS_ADHOC: ad hoc signed (linker-signed binaries carry it too)
	csSigned = 0x20000000 // CS_SIGNED: process has a signature (may have gone invalid)
)

// isSigned is ZAAFVesper's ps.is_signed: a real, still-valid signature. Unsigned,
// ad-hoc and linker-signed code (CS_LINKER_SIGNED 0x20000 implies CS_ADHOC)
// and signatures that went invalid all count as not signed.
func isSigned(flags uint32) bool {
	return flags&csSigned != 0 && flags&csValid != 0 && flags&csAdhoc == 0
}

// Bounds on per-event detail copied out of exec, so a hostile process with a
// huge argv or environment cannot make ZAAFVesper retain it (every exec is kept in
// the process table). Truncation sets evt.arg[args_truncated] /
// evt.arg[env_truncated] to "true".
const (
	MaxArgsBytes = 64 << 10 // total bytes of argv kept per exec
	MaxEnvBytes  = 16 << 10 // total bytes of environment (keys + values) kept per exec
	maxEnvVars   = 512
	maxArgs      = 4096
	// MaxIdentityBytes caps signing_id and team_id. Real ones are short
	// (a Team ID is 10 characters); an ad-hoc signer chooses its signing ID
	// freely, so a huge one must not be copied into every event and alert.
	MaxIdentityBytes = 256
)

// esType describes one ES notify event ZAAFVesper maps.
type esType struct {
	name      string // eslogger short name == key under "event"
	code      int    // ES_EVENT_TYPE_NOTIFY_* value from ESTypes.h (macOS 26 SDK)
	canonical string // event.* canonical name
}

// esTypes is the mapping of spec §4.1. Integer codes were read from the SDK by
// compiling a probe against EndpointSecurity.h (see README.md).
var esTypes = []esType{
	{"exec", 9, event.CreateProcess},
	{"open", 10, event.OpenFile},
	{"fork", 11, event.Fork},
	{"close", 12, event.WriteFile}, // only when modified / mapped writable
	{"create", 13, event.CreateFile},
	{"exit", 15, event.TerminateProcess},
	{"get_task", 16, event.OpenProcess},
	{"kextload", 17, event.LoadKext},
	{"mount", 22, event.Mount},
	{"rename", 25, event.RenameFile},
	{"setextattr", 27, event.SetXattr},
	{"setmode", 29, event.SetMode},
	{"setowner", 30, event.SetOwner},
	{"signal", 31, event.Signal},
	{"unlink", 32, event.DeleteFile},
	{"write", 33, event.WriteFile},
	{"deleteextattr", 70, event.DeleteXattr},
	{"trace", 96, event.Ptrace},
	{"remote_thread_create", 97, event.CreateRemoteThread},
	{"authentication", 111, event.Authenticate},
	{"xp_malware_detected", 112, event.XProtectDetect},
	{"btm_launch_item_add", 124, event.AddLaunchItem},
	{"sudo", 131, event.Sudo},
	{"tcc_modify", 147, event.ModifyTCC},
}

var (
	typeByCode = map[int]esType{}
	typeByName = map[string]esType{}
)

func init() {
	for _, t := range esTypes {
		typeByCode[t.code] = t
		typeByName[t.name] = t
	}
}

// SupportedEvents returns every canonical name this source can produce.
func SupportedEvents() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range esTypes {
		if !seen[t.canonical] {
			seen[t.canonical] = true
			out = append(out, t.canonical)
		}
	}
	sort.Strings(out)
	return out
}

// ESEventTypes maps canonical event names to eslogger subscription names.
// An empty input means every supported event. Unknown names are ignored.
// WriteFile subscribes to "close" only (one event per modified file); use
// ESEventTypesWithWrite to also subscribe to the per-syscall "write" event.
func ESEventTypes(canonical []string) []string {
	return esEventTypes(canonical, false)
}

// ESEventTypesWithWrite is ESEventTypes plus "write" when WriteFile is wanted.
func ESEventTypesWithWrite(canonical []string) []string {
	return esEventTypes(canonical, true)
}

func esEventTypes(canonical []string, withWrite bool) []string {
	want := map[string]bool{}
	all := len(canonical) == 0
	for _, c := range canonical {
		want[c] = true
	}
	var out []string
	for _, t := range esTypes {
		if !all && !want[t.canonical] {
			continue
		}
		if t.name == "write" && !withWrite {
			continue
		}
		out = append(out, t.name)
	}
	sort.Strings(out)
	return out
}

// Decode parses one eslogger JSON line into a normalized event. ok=false means
// the line was valid but carries an event type ZAAFVesper ignores (or a close
// without modification). Unknown and missing fields never cause an error;
// only malformed JSON, an oversized line, or an event_type that contradicts
// the event key does.
func Decode(line []byte) (e *event.Event, ok bool, err error) {
	return decode(line, nil)
}

// decode is Decode that also stores the message's global_seq_num in *gseq
// (when gseq is not nil and the line parsed), whether or not the event is
// kept, so the source can detect sequence gaps across ignored lines too.
func decode(line []byte, gseq *uint64) (e *event.Event, ok bool, err error) {
	if len(line) > MaxLineSize {
		return nil, false, fmt.Errorf("eslogger: line of %d bytes exceeds %d", len(line), MaxLineSize)
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil, false, nil
	}
	if line[0] != '{' {
		return nil, false, errors.New("eslogger: line is not a JSON object")
	}
	var m rawMessage
	if err := unmarshalLenient(line, &m); err != nil {
		return nil, false, fmt.Errorf("eslogger: %w", err)
	}
	if gseq != nil {
		*gseq = uint64(m.GlobalSeqNum)
	}

	// Identify the event by its integer type and cross-check with the key.
	var key string
	var payload json.RawMessage
	for k, v := range m.Event {
		if key == "" || k < key { // deterministic if more than one key
			key, payload = k, v
		}
	}
	t, known := typeByName[key]
	if m.EventType != nil {
		code := int(*m.EventType)
		tc, codeKnown := typeByCode[code]
		switch {
		case codeKnown && key != "" && tc.name != key:
			return nil, false, fmt.Errorf("eslogger: event_type %d (%s) contradicts event key %q", code, tc.name, key)
		case codeKnown:
			t, known = tc, true
		case key == "":
			return nil, false, nil // unmapped type and no key to go by
		case known:
			// Integer not in our table but the key is: a renumbered SDK.
			// Trust the key; the name is what eslogger subscribes by.
		}
	}
	if !known {
		return nil, false, nil
	}
	if len(payload) == 0 || !isObject(payload) {
		payload = []byte("{}")
	}

	e = &event.Event{
		Seq:      uint64(m.GlobalSeqNum),
		Time:     jtimeT(m.Time),
		Name:     t.canonical,
		Source:   "eslogger",
		Platform: event.PlatformMacOS,
		Proc:     m.Process.toProc(),
	}
	if e.Seq == 0 {
		e.Seq = uint64(m.SeqNum)
	}
	d := decoder{e: e, msg: &m}
	keep, err := d.detail(t.name, payload)
	if err != nil {
		return nil, false, fmt.Errorf("eslogger: %s: %w", t.name, err)
	}
	if !keep {
		return nil, false, nil
	}
	d.capIdentity(e.Proc, "")
	d.capIdentity(e.Target, "target_")
	if m.Version > 0 && m.Version < csCategoryMinVersion {
		// The field does not exist before version 10; whatever is there is
		// not a category. Unknown stays unknown (nil), so trust fails closed.
		for _, p := range []*event.Proc{e.Proc, e.Target} {
			if p != nil {
				p.CSCategory = ""
			}
		}
	}
	if len(e.Args) == 0 {
		e.Args = nil
	}
	return e, true, nil
}

type decoder struct {
	e   *event.Event
	msg *rawMessage
}

func (d *decoder) arg(k, v string) {
	if d.e.Args == nil {
		d.e.Args = map[string]string{}
	}
	d.e.Args[k] = v
}

func (d *decoder) argNonEmpty(k, v string) {
	if v != "" {
		d.arg(k, v)
	}
}

func (d *decoder) argInt(k string, v int64) { d.arg(k, strconv.FormatInt(v, 10)) }

func (d *decoder) argBool(k string, v bool) { d.arg(k, strconv.FormatBool(v)) }

// capIdentity cuts p's signing_id and team_id to MaxIdentityBytes and marks
// evt.arg[<prefix>signing_id_truncated] / [<prefix>team_id_truncated].
func (d *decoder) capIdentity(p *event.Proc, prefix string) {
	if p == nil {
		return
	}
	if len(p.SigningID) > MaxIdentityBytes {
		p.SigningID = strings.Clone(p.SigningID[:MaxIdentityBytes])
		d.arg(prefix+"signing_id_truncated", "true")
	}
	if len(p.TeamID) > MaxIdentityBytes {
		p.TeamID = strings.Clone(p.TeamID[:MaxIdentityBytes])
		d.arg(prefix+"team_id_truncated", "true")
	}
}

// actor makes the instigating process the event's Proc for events that a
// system daemon reports on someone else's behalf (btm, tcc, authentication),
// keeping the reporting daemon in evt.arg[reporter_exe].
func (d *decoder) actor(inst *rawProcess, tok *rawToken) {
	if d.e.Proc != nil {
		d.arg("reporter_exe", d.e.Proc.Exe)
	}
	if p := inst.toProc(); p != nil {
		d.e.Proc = p
		return
	}
	if tok != nil && tok.PID != 0 {
		d.argInt("instigator_pid", int64(tok.PID))
	}
}

func (d *decoder) detail(name string, payload []byte) (bool, error) {
	e := d.e
	switch name {
	case "exec":
		var x evExec
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		if e.Proc != nil {
			d.arg("prev_exe", e.Proc.Exe)
		}
		if p := x.Target.toProc(); p != nil {
			e.Proc = p
		}
		if e.Proc == nil {
			return true, nil
		}
		args, argsCut := capArgs(x.Args, MaxArgsBytes)
		e.Proc.Args = args
		e.Proc.Cmdline = strings.Join(args, " ") // <= MaxArgsBytes + len(args)
		if argsCut {
			d.arg("args_truncated", "true")
		}
		if x.Cwd != nil {
			e.Proc.Cwd = string(x.Cwd.Path)
		}
		var envCut bool
		e.Proc.Env, envCut = envMap(x.Env, MaxEnvBytes)
		if envCut {
			d.arg("env_truncated", "true")
		}
		for k, v := range e.Proc.Env {
			if strings.HasPrefix(k, "DYLD_") {
				d.arg("env."+k, v)
			}
		}
		if x.Script != nil {
			d.argNonEmpty("script", string(x.Script.Path))
		}
		if s := string(x.DyldExecPath); s != "" && s != e.Proc.Exe {
			d.arg("dyld_exec_path", s)
		}
	case "fork":
		var x evFork
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		if e.Proc != nil {
			d.argInt("parent_pid", int64(e.Proc.PID))
		}
		if p := x.Child.toProc(); p != nil {
			e.Proc = p
		}
	case "exit":
		var x evExit
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.argInt("exit_status", int64(x.Stat))
	case "open":
		var x evOpen
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		e.File = x.File.toFile()
		d.argInt("open_flags", int64(x.FFlag))
		d.arg("open_access", openAccess(int64(x.FFlag)))
		d.arg("open_flag_names", openFlagNames(int64(x.FFlag)))
	case "create":
		var x evCreate
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		path, mode := x.Destination.path()
		e.File = &event.File{Path: path}
		if f := x.Destination.ExistingFile.toFile(); f != nil {
			e.File = f
		}
		if mode != 0 {
			e.File.Mode = uint32(mode)
		}
	case "write", "close", "unlink", "setextattr", "deleteextattr", "setmode", "setowner":
		var x evTarget
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		if name == "close" {
			if !x.Modified {
				return false, nil // includes was_mapped_writable-only closes
			}
			d.arg("via", "close")
		}
		e.File = x.Target.toFile()
		if e.File == nil {
			e.File = &event.File{}
		}
		switch name {
		case "write":
			d.arg("via", "write")
		case "setextattr", "deleteextattr":
			d.arg("xattr", string(x.Extattr))
		case "setmode":
			if x.Mode != nil {
				m := uint32(*x.Mode) & 0o7777
				d.arg("mode", fmt.Sprintf("%04o", m))
				e.File.Mode = m
			}
		case "setowner":
			if x.UID != nil {
				d.argInt("owner_uid", int64(uint32(*x.UID)))
			}
			if x.GID != nil {
				d.argInt("owner_gid", int64(uint32(*x.GID)))
			}
		}
	case "rename":
		var x evRename
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		e.File = x.Source.toFile()
		if e.File == nil {
			e.File = &event.File{}
		}
		e.File.Dest, _ = x.Destination.path()
	case "get_task", "signal", "trace", "remote_thread_create":
		var x evProcTarget
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		e.Target = x.Target.toProc()
		switch name {
		case "get_task":
			if x.Type != nil {
				d.arg("task_type", enumName(getTaskTypes, int64(*x.Type)))
			}
		case "signal":
			if x.Sig != nil {
				d.argInt("signal", int64(*x.Sig))
				d.argNonEmpty("signal_name", signalName(int64(*x.Sig)))
			}
			if p := x.Instigator.toProc(); p != nil && e.Proc != nil && p.PID != e.Proc.PID {
				d.arg("instigator_exe", p.Exe)
				d.argInt("instigator_pid", int64(p.PID))
			}
		}
	case "btm_launch_item_add":
		var x evBTMAdd
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.actor(x.Instigator, x.InstigatorToken)
		if x.Item != nil {
			d.arg("launch_item_type", enumName(btmItemTypes, int64(x.Item.ItemType)))
			d.argNonEmpty("launch_item_url", string(x.Item.ItemURL))
			p := urlPath(string(x.Item.ItemURL))
			d.argNonEmpty("launch_item_path", p)
			d.argNonEmpty("launch_item_app", urlPath(string(x.Item.AppURL)))
			d.argBool("launch_item_legacy", bool(x.Item.Legacy))
			d.argBool("launch_item_managed", bool(x.Item.Managed))
			d.argInt("launch_item_uid", int64(uint32(x.Item.UID)))
			if p != "" {
				e.File = &event.File{Path: p}
			}
		}
		d.argNonEmpty("launch_item_exe", string(x.ExecutablePath))
		if p := x.App.toProc(); p != nil {
			d.arg("app_exe", p.Exe)
		}
	case "mount":
		var x evMount
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		if x.Statfs != nil {
			d.argNonEmpty("mount_path", string(x.Statfs.MntOnName))
			d.argNonEmpty("mount_from", string(x.Statfs.MntFromName))
			d.argNonEmpty("mount_fstype", string(x.Statfs.FSTypeName))
			if s := string(x.Statfs.MntOnName); s != "" {
				e.File = &event.File{Path: s}
			}
		}
		if x.Disposition != nil {
			d.arg("mount_disposition", enumName(mountDispositions, int64(*x.Disposition)))
		}
	case "kextload":
		var x evKextload
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.arg("kext_id", string(x.Identifier))
	case "authentication":
		var x evAuthentication
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.arg("auth_type", enumName(authTypes, int64(x.Type)))
		d.argBool("auth_success", bool(x.Success))
		switch dd := x.Data; {
		case dd.OD != nil:
			d.actor(dd.OD.Instigator, dd.OD.InstigatorToken)
			d.argNonEmpty("auth_record_type", string(dd.OD.RecordType))
			d.argNonEmpty("auth_record_name", string(dd.OD.RecordName))
			d.argNonEmpty("auth_node_name", string(dd.OD.NodeName))
			d.argNonEmpty("auth_db_path", string(dd.OD.DBPath))
		case dd.TouchID != nil:
			d.actor(dd.TouchID.Instigator, dd.TouchID.InstigatorToken)
			d.arg("auth_touchid_mode", enumName(touchIDModes, int64(dd.TouchID.TouchIDMode)))
			if dd.TouchID.HasUID {
				d.argInt("auth_uid", int64(uint32(dd.TouchID.UID)))
			}
		case dd.Token != nil:
			d.actor(dd.Token.Instigator, dd.Token.InstigatorToken)
			d.argNonEmpty("auth_pubkey_hash", string(dd.Token.PubkeyHash))
			d.argNonEmpty("auth_token_id", string(dd.Token.TokenID))
			d.argNonEmpty("auth_kerberos_principal", string(dd.Token.KerberosPrincipal))
		case dd.AutoUnlock != nil:
			d.argNonEmpty("auth_username", string(dd.AutoUnlock.Username))
			d.arg("auth_auto_unlock_type", enumName(autoUnlockTypes, int64(dd.AutoUnlock.Type)))
		}
	case "sudo":
		var x evSudo
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.argBool("sudo_success", bool(x.Success))
		d.argNonEmpty("sudo_command", string(x.Command))
		if x.HasFromUID {
			d.argInt("sudo_from_uid", int64(uint32(x.FromUID)))
		}
		d.argNonEmpty("sudo_from_user", string(x.FromUsername))
		if x.HasToUID {
			d.argInt("sudo_to_uid", int64(uint32(x.ToUID)))
		}
		d.argNonEmpty("sudo_to_user", string(x.ToUsername))
		if x.RejectInfo != nil {
			d.argNonEmpty("sudo_reject_plugin", string(x.RejectInfo.PluginName))
			d.argNonEmpty("sudo_reject_message", string(x.RejectInfo.FailureMessage))
		}
	case "tcc_modify":
		var x evTCCModify
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.actor(x.Instigator, x.InstigatorToken)
		d.arg("tcc_service", string(x.Service))
		d.argNonEmpty("tcc_identity", string(x.Identity))
		d.arg("tcc_identity_type", enumName(tccIdentityTypes, int64(x.IdentityType)))
		d.arg("tcc_update_type", enumName(tccUpdateTypes, int64(x.UpdateType)))
		d.arg("tcc_right", enumName(tccRights, int64(x.Right)))
		d.arg("tcc_reason", enumName(tccReasons, int64(x.Reason)))
		if p := x.Responsible.toProc(); p != nil {
			d.arg("tcc_responsible_exe", p.Exe)
		}
	case "xp_malware_detected":
		var x evXPMalwareDetected
		if err := unmarshalLenient(payload, &x); err != nil {
			return false, err
		}
		d.argNonEmpty("xp_malware_identifier", string(x.MalwareIdentifier))
		d.argNonEmpty("xp_signature_version", string(x.SignatureVersion))
		d.argNonEmpty("xp_incident_identifier", string(x.IncidentIdentifier))
		d.argNonEmpty("xp_detected_path", string(x.DetectedPath))
		d.argNonEmpty("xp_detected_executable", string(x.DetectedExecutable))
		if s := string(x.DetectedPath); s != "" {
			e.File = &event.File{Path: s}
		}
	default:
		return false, errors.New("no decoder")
	}
	return true, nil
}

// toProc converts an es_process_t; nil in, nil out.
func (p *rawProcess) toProc() *event.Proc {
	if p == nil || (p.Executable == nil && p.AuditToken.PID == 0) {
		return nil // absent, or a non-object value encoding/json skipped
	}
	out := &event.Proc{
		PID:  int32(p.AuditToken.PID),
		PPID: int32(p.PPID),
		// Parent at fork time; differs from PPID after reparenting (double
		// fork to launchd). Rules read it as ps.original_ppid.
		OriginalPPID: int32(p.OriginalPPID),
		PIDVersion:   uint32(p.AuditToken.PIDVersion),
		UID:          int64(uint32(p.AuditToken.RUID)),
		EUID:         int64(uint32(p.AuditToken.EUID)),
		SigningID:    string(p.SigningID),
		TeamID:       string(p.TeamID),
		CDHash:       string(p.CDHash),
		IsPlatform:   bool(p.IsPlatformBinary),
		IsSigned:     isSigned(uint32(p.CodesigningFlags)),
		StartTime:    jtimeT(p.StartTime),
	}
	if out.PID != 0 || out.PIDVersion != 0 {
		out.UUID = uint64(uint32(out.PID))<<32 | uint64(out.PIDVersion)
	}
	if p.CSCategory != nil {
		out.CSCategory = enumName(csCategories, int64(*p.CSCategory))
	}
	if p.Executable != nil {
		out.Exe = string(p.Executable.Path)
		out.Name = filepath.Base(out.Exe)
		if out.Exe == "" {
			out.Name = ""
		}
		// Executable identity at exec time, so later consumers (YARA, kill)
		// can check they act on the file that ran, not whatever is at the
		// path now. dev_t is 32-bit on Darwin.
		if st := p.Executable.Stat; st != nil {
			out.ExeDev = uint64(uint32(st.Dev))
			out.ExeIno = uint64(st.Ino)
			if ct := time.Time(st.Ctime); !ct.IsZero() {
				out.ExeCtimeNs = ct.UnixNano()
			}
		}
	}
	if p.TTY != nil {
		out.TTY = string(p.TTY.Path)
	}
	// Parent stub from parent_audit_token (message version >= 4): only pid
	// and pidversion. pkg/ps uses it to verify the parent incarnation and
	// replaces it with the full parent (or nil when unknown).
	if t := p.ParentToken; t != nil && t.PID > 0 {
		out.Parent = &event.Proc{PID: int32(t.PID), PIDVersion: uint32(t.PIDVersion)}
		out.Parent.UUID = uint64(uint32(out.Parent.PID))<<32 | uint64(out.Parent.PIDVersion)
	}
	return out
}

func (f *rawFile) toFile() *event.File {
	if f == nil {
		return nil
	}
	out := &event.File{Path: string(f.Path)}
	if f.Stat != nil {
		out.Mode = uint32(f.Stat.Mode)
		out.Size = int64(f.Stat.Size)
		// Identity of the file the event is about (dev_t is 32-bit on
		// Darwin), so a later scan can check it reads that file.
		out.Dev = uint64(uint32(f.Stat.Dev))
		out.Ino = uint64(f.Stat.Ino)
		if ct := time.Time(f.Stat.Ctime); !ct.IsZero() {
			out.CtimeNs = ct.UnixNano()
		}
	}
	return out
}

// path returns the destination path of a create/rename union and the mode of
// a new_path destination.
func (d *rawDestination) path() (string, int64) {
	if d.ExistingFile != nil && d.ExistingFile.Path != "" {
		return string(d.ExistingFile.Path), 0
	}
	if np := d.NewPath; np != nil {
		dir := ""
		if np.Dir != nil {
			dir = string(np.Dir.Path)
		}
		name := string(np.Filename)
		switch {
		case dir == "":
			return name, int64(np.Mode)
		case name == "":
			return dir, int64(np.Mode)
		}
		return strings.TrimSuffix(dir, "/") + "/" + name, int64(np.Mode)
	}
	return "", 0
}

func jtimeT(t jtime) time.Time { return time.Time(t) }

// capArgs keeps at most maxArgs arguments and budget bytes in total. A cut
// argument is cloned so the original (possibly huge) string is not retained.
func capArgs(in []string, budget int) ([]string, bool) {
	if len(in) == 0 {
		return nil, false
	}
	cut := len(in) > maxArgs
	out := make([]string, 0, min(len(in), maxArgs))
	for _, a := range in[:min(len(in), maxArgs)] {
		if len(a) > budget {
			cut = true
			if budget > 0 {
				out = append(out, strings.Clone(a[:budget]))
			}
			break
		}
		budget -= len(a)
		out = append(out, a)
	}
	return out, cut
}

// envMap parses KEY=VALUE strings, keeping at most maxEnvVars entries and
// budget bytes of keys plus values. Cut values are cloned.
func envMap(env []string, budget int) (map[string]string, bool) {
	if len(env) == 0 {
		return nil, false
	}
	m := make(map[string]string, min(len(env), maxEnvVars))
	cut := false
	for _, kv := range env {
		if len(m) >= maxEnvVars {
			cut = true
			break
		}
		k, v, found := strings.Cut(kv, "=")
		if !found || k == "" {
			continue
		}
		if len(k)+len(v) > budget {
			cut = true
			if len(k) < budget {
				m[strings.Clone(k)] = strings.Clone(v[:budget-len(k)])
			}
			break
		}
		budget -= len(k) + len(v)
		// k and v are substrings of kv; clone so kv's other bytes are not pinned.
		m[strings.Clone(k)] = strings.Clone(v)
	}
	if len(m) == 0 {
		return nil, cut
	}
	return m, cut
}

// openFlagBits are the kernel fflag bits from <sys/fcntl.h> that rules care about.
var openFlagBits = []struct {
	bit  int64
	name string
}{
	{0x1, "FREAD"}, {0x2, "FWRITE"}, {0x4, "O_NONBLOCK"}, {0x8, "O_APPEND"},
	{0x100, "O_NOFOLLOW"}, {0x200, "O_CREAT"}, {0x400, "O_TRUNC"}, {0x800, "O_EXCL"},
	{0x8000, "O_EVTONLY"}, {0x200000, "O_SYMLINK"}, {0x1000000, "O_CLOEXEC"},
}

// openFlagNames renders an open fflag symbolically, e.g. "FWRITE|O_CREAT|O_TRUNC".
func openFlagNames(fflag int64) string {
	var parts []string
	for _, f := range openFlagBits {
		if fflag&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, "|")
}

// openAccess renders the FREAD (0x1) / FWRITE (0x2) bits of an open fflag.
func openAccess(fflag int64) string {
	r, w := fflag&0x1 != 0, fflag&0x2 != 0
	switch {
	case r && w:
		return "readwrite"
	case w:
		return "write"
	case r:
		return "read"
	}
	return "none"
}

// urlPath turns a file:// URL (as BTM reports item_url/app_url) into a path;
// anything else is returned unchanged.
func urlPath(s string) string {
	if !strings.HasPrefix(s, "file://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.Path == "" {
		return s
	}
	return u.Path
}
