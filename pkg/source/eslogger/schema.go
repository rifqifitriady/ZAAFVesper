package eslogger

import (
	"encoding/json"
	"errors"
)

// Raw eslogger JSON shapes. Field names mirror the C members of es_message_t
// and the es_event_*_t structs in the macOS SDK
// (EndpointSecurity/ESMessage.h, ESTypes.h); C unions are rendered by
// eslogger as nested objects keyed by the union member name
// (e.g. "destination": {"existing_file": {...}}, "from_uid": {"uid": 0}).
// Only members ZAAFVesper uses are declared; everything else is ignored.

type rawMessage struct {
	Version       jnum                       `json:"version"`
	SchemaVersion jnum                       `json:"schema_version"`
	Time          jtime                      `json:"time"`
	MachTime      jnum                       `json:"mach_time"`
	SeqNum        jnum                       `json:"seq_num"`
	GlobalSeqNum  jnum                       `json:"global_seq_num"`
	ActionType    jnum                       `json:"action_type"`
	EventType     *jnum                      `json:"event_type"`
	Process       *rawProcess                `json:"process"`
	Event         map[string]json.RawMessage `json:"event"`
}

// rawToken mirrors audit_token_t as eslogger renders it.
type rawToken struct {
	PID        jnum `json:"pid"`
	PIDVersion jnum `json:"pidversion"`
	EUID       jnum `json:"euid"`
	RUID       jnum `json:"ruid"`
	EGID       jnum `json:"egid"`
	RGID       jnum `json:"rgid"`
	ASID       jnum `json:"asid"`
	AUID       jnum `json:"auid"`
}

type rawStat struct {
	Dev   jnum  `json:"st_dev"`
	Ino   jnum  `json:"st_ino"`
	Mode  jnum  `json:"st_mode"`
	Size  jnum  `json:"st_size"`
	UID   jnum  `json:"st_uid"`
	GID   jnum  `json:"st_gid"`
	Ctime jtime `json:"st_ctimespec"`
}

// rawFile mirrors es_file_t.
type rawFile struct {
	Path          jstr     `json:"path"`
	PathTruncated jbool    `json:"path_truncated"`
	Stat          *rawStat `json:"stat"`
}

// rawProcess mirrors es_process_t.
type rawProcess struct {
	AuditToken       rawToken  `json:"audit_token"`
	PPID             jnum      `json:"ppid"`
	OriginalPPID     jnum      `json:"original_ppid"`
	GroupID          jnum      `json:"group_id"`
	SessionID        jnum      `json:"session_id"`
	CodesigningFlags jnum      `json:"codesigning_flags"`
	IsPlatformBinary jbool     `json:"is_platform_binary"`
	IsESClient       jbool     `json:"is_es_client"`
	CDHash           jhex      `json:"cdhash"`
	SigningID        jstr      `json:"signing_id"`
	TeamID           jstr      `json:"team_id"`
	Executable       *rawFile  `json:"executable"`
	TTY              *rawFile  `json:"tty"`
	StartTime        jtime     `json:"start_time"`
	ResponsibleToken *rawToken `json:"responsible_audit_token"`
	ParentToken      *rawToken `json:"parent_audit_token"`
	// CSCategory is es_cs_validation_category_t (message version >= 10).
	// A pointer, so an absent or null field stays distinguishable from 0
	// (ES_CS_VALIDATION_CATEGORY_INVALID).
	CSCategory *jnum `json:"cs_validation_category"`
}

// rawDestination mirrors the destination union of es_event_create_t and
// es_event_rename_t.
type rawDestination struct {
	ExistingFile *rawFile `json:"existing_file"`
	NewPath      *struct {
		Dir      *rawFile `json:"dir"`
		Filename jstr     `json:"filename"`
		Mode     jnum     `json:"mode"`
	} `json:"new_path"`
}

// Per-event payloads (the single value under "event").

type evExec struct {
	Target       *rawProcess `json:"target"`
	DyldExecPath jstr        `json:"dyld_exec_path"`
	Script       *rawFile    `json:"script"`
	Cwd          *rawFile    `json:"cwd"`
	Args         jstrs       `json:"args"`
	Env          jstrs       `json:"env"`
	LastFD       jnum        `json:"last_fd"`
}

type evFork struct {
	Child *rawProcess `json:"child"`
}

type evExit struct {
	Stat jnum `json:"stat"`
}

type evOpen struct {
	FFlag jnum     `json:"fflag"`
	File  *rawFile `json:"file"`
}

type evCreate struct {
	DestinationType jnum           `json:"destination_type"`
	Destination     rawDestination `json:"destination"`
}

type evTarget struct { // write, unlink, close, setextattr, deleteextattr, setmode, setowner
	Target            *rawFile `json:"target"`
	ParentDir         *rawFile `json:"parent_dir"`
	Modified          jbool    `json:"modified"`
	WasMappedWritable jbool    `json:"was_mapped_writable"`
	Extattr           jstr     `json:"extattr"`
	Mode              *jnum    `json:"mode"`
	UID               *jnum    `json:"uid"`
	GID               *jnum    `json:"gid"`
}

type evRename struct {
	Source          *rawFile       `json:"source"`
	DestinationType jnum           `json:"destination_type"`
	Destination     rawDestination `json:"destination"`
}

type evProcTarget struct { // get_task, signal, trace, remote_thread_create
	Target     *rawProcess `json:"target"`
	Type       *jnum       `json:"type"`
	Sig        *jnum       `json:"sig"`
	Instigator *rawProcess `json:"instigator"`
}

type evBTMAdd struct {
	Instigator      *rawProcess `json:"instigator"`
	App             *rawProcess `json:"app"`
	InstigatorToken *rawToken   `json:"instigator_token"`
	Item            *struct {
		ItemType jnum  `json:"item_type"`
		Legacy   jbool `json:"legacy"`
		Managed  jbool `json:"managed"`
		UID      jnum  `json:"uid"`
		ItemURL  jstr  `json:"item_url"`
		AppURL   jstr  `json:"app_url"`
	} `json:"item"`
	ExecutablePath jstr `json:"executable_path"`
}

type evMount struct {
	Statfs *struct {
		MntOnName   jstr `json:"f_mntonname"`
		MntFromName jstr `json:"f_mntfromname"`
		FSTypeName  jstr `json:"f_fstypename"`
	} `json:"statfs"`
	Disposition *jnum `json:"disposition"`
}

type evKextload struct {
	Identifier jstr `json:"identifier"`
}

type authInstigator struct {
	Instigator      *rawProcess `json:"instigator"`
	InstigatorToken *rawToken   `json:"instigator_token"`
}

type evAuthentication struct {
	Success jbool `json:"success"`
	Type    jnum  `json:"type"`
	Data    struct {
		OD *struct {
			authInstigator
			RecordType jstr `json:"record_type"`
			RecordName jstr `json:"record_name"`
			NodeName   jstr `json:"node_name"`
			DBPath     jstr `json:"db_path"`
		} `json:"od"`
		TouchID *struct {
			authInstigator
			TouchIDMode jnum  `json:"touchid_mode"`
			HasUID      jbool `json:"has_uid"`
			UID         jnum  `json:"uid"`
		} `json:"touchid"`
		Token *struct {
			authInstigator
			PubkeyHash        jstr `json:"pubkey_hash"`
			TokenID           jstr `json:"token_id"`
			KerberosPrincipal jstr `json:"kerberos_principal"`
		} `json:"token"`
		AutoUnlock *struct {
			Username jstr `json:"username"`
			Type     jnum `json:"type"`
		} `json:"auto_unlock"`
	} `json:"data"`
}

type evSudo struct {
	Success    jbool `json:"success"`
	RejectInfo *struct {
		PluginName     jstr `json:"plugin_name"`
		PluginType     jnum `json:"plugin_type"`
		FailureMessage jstr `json:"failure_message"`
	} `json:"reject_info"`
	HasFromUID   jbool `json:"has_from_uid"`
	FromUID      jnum  `json:"from_uid"`
	FromUsername jstr  `json:"from_username"`
	HasToUID     jbool `json:"has_to_uid"`
	ToUID        jnum  `json:"to_uid"`
	ToUsername   jstr  `json:"to_username"`
	Command      jstr  `json:"command"`
}

type evTCCModify struct {
	Service          jstr        `json:"service"`
	Identity         jstr        `json:"identity"`
	IdentityType     jnum        `json:"identity_type"`
	UpdateType       jnum        `json:"update_type"`
	InstigatorToken  *rawToken   `json:"instigator_token"`
	Instigator       *rawProcess `json:"instigator"`
	ResponsibleToken *rawToken   `json:"responsible_token"`
	Responsible      *rawProcess `json:"responsible"`
	Right            jnum        `json:"right"`
	Reason           jnum        `json:"reason"`
}

type evXPMalwareDetected struct {
	SignatureVersion   jstr `json:"signature_version"`
	MalwareIdentifier  jstr `json:"malware_identifier"`
	IncidentIdentifier jstr `json:"incident_identifier"`
	DetectedPath       jstr `json:"detected_path"`
	DetectedExecutable jstr `json:"detected_executable"`
}

// unmarshalLenient decodes b into v. A JSON value of the wrong type for a Go
// field is skipped (encoding/json keeps decoding the rest and reports only
// the first type error), so such errors are dropped; syntax errors are not.
func unmarshalLenient(b []byte, v any) error {
	err := json.Unmarshal(b, v)
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return nil
	}
	return err
}
