package eslogger

import "strconv"

// Enum renderings. Values follow the declaration order in ESTypes.h of the
// macOS 26 SDK. Unknown values render as their decimal number so a rule can
// still match them.

var getTaskTypes = []string{"task_for_pid", "expose_task", "identity_token"} // es_get_task_type_t

var btmItemTypes = []string{"user_item", "app", "login_item", "agent", "daemon"} // es_btm_item_type_t

var mountDispositions = []string{"external", "internal", "network", "virtual", "nullfs", "unknown"} // es_mount_disposition_t

var authTypes = []string{"od", "touchid", "token", "auto_unlock"} // es_authentication_type_t

var touchIDModes = []string{"verification", "identification"} // es_touchid_mode_t

var autoUnlockTypes = []string{"", "machine_unlock", "auth_prompt"} // es_auto_unlock_type_t (starts at 1)

var tccIdentityTypes = []string{"bundle_id", "executable_path", "policy_id", "file_provider_domain_id"} // es_tcc_identity_type_t

var tccUpdateTypes = []string{"unknown", "create", "modify", "delete"} // es_tcc_event_type_t

var tccRights = []string{ // es_tcc_authorization_right_t
	"denied", "unknown", "allowed", "limited", "add_modify_added", "session_pid", "learn_more",
}

var tccReasons = []string{ // es_tcc_authorization_reason_t
	"none", "error", "user_consent", "user_set", "system_set", "service_policy", "mdm_policy",
	"service_override_policy", "missing_usage_string", "prompt_timeout", "preflight_unknown",
	"entitled", "app_type_policy", "prompt_cancel",
}

func enumName(names []string, v int64) string {
	if v >= 0 && v < int64(len(names)) && names[v] != "" {
		return names[v]
	}
	return strconv.FormatInt(v, 10)
}

// Darwin signal numbers (<sys/signal.h>).
var signalNames = []string{
	"", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGEMT", "SIGFPE",
	"SIGKILL", "SIGBUS", "SIGSEGV", "SIGSYS", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGURG",
	"SIGSTOP", "SIGTSTP", "SIGCONT", "SIGCHLD", "SIGTTIN", "SIGTTOU", "SIGIO", "SIGXCPU",
	"SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGINFO", "SIGUSR1", "SIGUSR2",
}

func signalName(n int64) string {
	if n > 0 && n < int64(len(signalNames)) {
		return signalNames[n]
	}
	return ""
}
