# pkg/source/eslogger

Event source on top of `/usr/bin/eslogger` (macOS 13+). eslogger prints one JSON
object per line, modelled on `es_message_t` from the Endpoint Security SDK.
`Decode` turns one line into an `event.Event`; `Source.Run` runs eslogger and
streams decoded events.

Ground truth used: the macOS 26 SDK headers
(`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/ESMessage.h`,
`ESTypes.h`, `Kernel.framework/Headers/kern/cs_blobs.h`), `man eslogger`, and the
JSON key names compiled into `/usr/bin/eslogger` on macOS 26.6.2. The integer
`event_type` values were read by compiling a probe against `EndpointSecurity.h`.
No real eslogger capture was available (it needs root + Full Disk Access), so the
fixtures in `testdata/eslogger/` are built from the header layouts. The first
real capture should be decoded with `go test` style checks before trusting
rules in production (spec §5 risk 5).

## Decoding rules

- Tolerant: unknown fields are ignored; missing fields leave zero values; a field
  of the wrong JSON type (number as string, object where a string was expected,
  …) is skipped, not fatal. Only malformed JSON, a line that is not a JSON object,
  a line over 16 MiB (`MaxLineSize`), or an `event_type` that contradicts the
  event key is an error. Errors are counted (`decode_errors`), never logged with
  the raw line.
- Event identification: integer `event_type` cross-checked with the single key
  under `event`. If the integer is unknown but the key is a mapped name, the key
  wins (SDK renumbering). Valid but unmapped events return `ok=false`.
- `evt.time` is the message `time` field (RFC 3339, nanoseconds). It is never
  replaced with the wall clock; a line without `time` yields a zero time.
- `evt.seq` is `global_seq_num`, else `seq_num`.
- `evt.source` is `eslogger`.

### Process fields (`ps.*`, `target.ps.*`) from `es_process_t`

| Field | From |
|---|---|
| `pid`, `pidversion` | `audit_token.pid`, `audit_token.pidversion` |
| `ppid` | `ppid` (the current parent) |
| `original_ppid` | `original_ppid`, the parent at fork time; nil when 0. It differs from `ppid` after reparenting (a double fork leaves the child under launchd). `pkg/ps` keeps `parent` (and `ancestors`) as the **current** parent, so a reparented process has `ps.parent.exe = /sbin/launchd`; rules catch the double fork with `ps.original_ppid` (also on `ps.parent.original_ppid`). |
| `uid`, `euid` | `audit_token.ruid`, `audit_token.euid` (uid_t, so `nobody` is 4294967294) |
| `exe`, `name` | `executable.path`, its base name |
| `signing_id`, `team_id` | `signing_id`, `team_id` (null becomes empty). `team_id` is taken **only** from the ES `team_id` field, never derived from the signing ID or a path. |
| `cdhash` | `cdhash`, lowercase hex; an all-zero cdhash becomes empty |
| `is_platform` | `is_platform_binary` |
| `is_signed` | `codesigning_flags` has `CS_SIGNED` (0x20000000) **and** `CS_VALID` (0x1) **and not** `CS_ADHOC` (0x2). So unsigned, ad-hoc, linker-signed (`CS_LINKER_SIGNED` 0x20000, which implies ad-hoc) and invalidated signatures are all `false`. **Caveat:** a binary signed with a self-made certificate is still `true`: `is_signed` says "has a valid, non-ad-hoc signature", not "signed by someone trustworthy". |
| `cs_category` | `cs_validation_category` (`es_cs_validation_category_t`, message version >= 10), rendered as `invalid`, `platform`, `testflight`, `development`, `app_store`, `enterprise`, `developer_id`, `local_signing`, `rosetta`, `oopjit`, `none` (values 0 to 10 in `ESTypes.h` of the macOS 26 SDK). Absent, `null`, or a message `version` below 10 gives an empty value, so `ps.cs_category` is nil and any trust condition on it fails closed. An unknown number renders as its decimal value (never a trusted category). |
| `tty` | `tty.path` |
| `uuid` | `pid << 32 \| pidversion` (same formula as `ps.UUID`) |
| (not a rule field) `Proc.ExeDev`, `ExeIno`, `ExeCtimeNs` | `executable.stat.st_dev` (32-bit `dev_t`), `st_ino`, `st_ctimespec` (Unix ns). Zero when ES gave no stat. `pkg/yara` uses them to scan only the file that actually ran. |
| `parent` | **stub** with only `pid`/`pidversion` from `parent_audit_token`. `pkg/ps` replaces it with the full parent, or `nil` when the parent is unknown or the pid was recycled. Without `pkg/ps` enrichment, `ps.parent.exe` is therefore empty. |

**Trust decisions** (exclusions, allow-lists, "is this a legitimate tool")
must use `ps.is_platform` (an Apple platform binary) or the pair
`(ps.team_id, ps.signing_id)` (team IDs are issued by Apple) **together with**
`ps.cs_category in ('developer_id', 'app_store')`: a self-signed certificate can
carry another vendor's Team ID, and only the validation category says Apple's
CA chain authorised the signature. Never use
`ps.signing_id` alone or `ps.is_signed` alone: any signer can choose any
signing ID, including `com.apple.*`.

`cmdline`, `args`, `cwd` and `env` exist only on exec events; `pkg/ps` copies
them onto later events of the same process.

Added by `pkg/ps`, not by the decoder (so never in the golden files):
`Proc.UniqueID`, the kernel's per-boot unique id (`p_uniqueid`, proc_info
flavor 17), read in live mode only when the table first sees a process
(exec, fork, bootstrap), only when the kernel's pidversion for that pid is the
event's, 0 on a failed read; and `ps.ancestors_untrusted` (also
`ps.parent.ancestors_untrusted`): true when the chain up to launchd is
incomplete or holds a process that is neither `is_platform` nor a Team ID
with `cs_category` `developer_id`/`app_store`. `username`, `ancestors` and the
full `parent` come from `pkg/ps`.

### File identity (`event.File.Dev`, `Ino`, `CtimeNs`)

From `es_file_t.stat` when ES gives one: `st_dev` (32-bit `dev_t`), `st_ino`,
`st_ctimespec` (Unix ns). Not rule fields; `pkg/yara` uses them to scan only
the file the event was about. A `create` to a `new_path` has no stat (zero).

## ES event to canonical name

| eslogger name | `event_type` | `evt.name` | `ps` (Proc) is | Other objects |
|---|---|---|---|---|
| `exec` | 9 | CreateProcess | the **new image** (`event.exec.target`) with args/env/cwd | |
| `fork` | 11 | Fork | the **child** (`event.fork.child`); its parent is the forking process | |
| `exit` | 15 | TerminateProcess | the exiting process | |
| `open` | 10 | OpenFile | opener | `file` = `event.open.file` |
| `create` | 13 | CreateFile | creator | `file.path` = `existing_file.path` (destination_type 0) or `new_path.dir.path + "/" + new_path.filename` (destination_type 1); `file.mode` = `new_path.mode` when given |
| `write` | 33 | WriteFile | writer | `file` = target (only subscribed with `Config.SubscribeWrite`) |
| `close` | 12 | WriteFile | closer | `file` = target; **only when `modified` is true**, otherwise ignored |
| `rename` | 25 | RenameFile | renamer | `file.path` = source, `file.dest` = existing_file or new_path dir + filename |
| `unlink` | 32 | DeleteFile | deleter | `file` = target |
| `setextattr` | 27 | SetXattr | caller | `file` = target |
| `deleteextattr` | 70 | DeleteXattr | caller | `file` = target |
| `setmode` | 29 | SetMode | caller | `file` = target; `file.mode` = the **new** mode (permission bits) |
| `setowner` | 30 | SetOwner | caller | `file` = target |
| `get_task` | 16 | OpenProcess | caller | `target.ps` = target |
| `signal` | 31 | Signal | sender | `target.ps` = target |
| `trace` | 96 | Ptrace | tracer | `target.ps` = target |
| `remote_thread_create` | 97 | CreateRemoteThread | creator | `target.ps` = target |
| `btm_launch_item_add` | 124 | AddLaunchItem | the **instigator** when present, else the reporting daemon | `file.path` = launch item path |
| `mount` | 22 | Mount | caller | `file.path` = mount point |
| `kextload` | 17 | LoadKext | caller | |
| `authentication` | 111 | Authenticate | the **instigator** when present (od, touchid, token), else the reporting daemon | |
| `sudo` | 131 | Sudo | the sudo process | |
| `tcc_modify` | 147 | ModifyTCC | the **instigator** when present, else tccd | |
| `xp_malware_detected` | 112 | XProtectDetect | the XProtect process | `file.path` = detected path |

## `evt.arg[...]` reference

All values are strings. A key is absent when the source had no value (rules
then see "absent field" semantics: every comparison false).

| Key | Events | Value |
|---|---|---|
| `args_truncated` | CreateProcess | `true` when argv exceeded 64 KiB (`MaxArgsBytes`) or 4096 entries and was cut |
| `signing_id_truncated`, `team_id_truncated` | any | `true` when `ps.signing_id` / `ps.team_id` exceeded 256 bytes (`MaxIdentityBytes`) and was cut; `target_signing_id_truncated` / `target_team_id_truncated` for `target.ps` |
| `env_truncated` | CreateProcess | `true` when the environment exceeded 16 KiB (`MaxEnvBytes`, keys + values) or 512 entries and was cut |
| `prev_exe` | CreateProcess | executable of the process **before** exec (`process.executable.path`) |
| `env.<NAME>` | CreateProcess | every `DYLD_*` environment variable, e.g. `evt.arg[env.DYLD_INSERT_LIBRARIES]` (the full environment is in `ps.env[NAME]`) |
| `script` | CreateProcess | script path when the image is a `#!` script (`event.exec.script.path`) |
| `dyld_exec_path` | CreateProcess | `dyld_exec_path`, only when it differs from `ps.exe` |
| `parent_pid` | Fork | pid of the forking process |
| `exit_status` | TerminateProcess | raw wait status (`stat`), decimal |
| `open_flags` | OpenFile | kernel `fflag`, decimal |
| `open_flag_names` | OpenFile | symbolic fflag bits joined by `|`, e.g. `FWRITE|O_CREAT|O_TRUNC` |
| `open_access` | OpenFile | `read`, `write`, `readwrite` or `none` (FREAD 0x1 / FWRITE 0x2 bits) |
| `via` | WriteFile | `close` (close with modified=true) or `write` (write event) |
| `xattr` | SetXattr, DeleteXattr | attribute name, e.g. `com.apple.quarantine` |
| `mode` | SetMode | new permission bits, 4-digit octal, e.g. `4755`, `0777` |
| `owner_uid`, `owner_gid` | SetOwner | new owner uid / gid, decimal |
| `task_type` | OpenProcess | `task_for_pid`, `expose_task`, `identity_token` (or the number) |
| `signal` | Signal | signal number, decimal, e.g. `9` |
| `signal_name` | Signal | e.g. `SIGKILL`, `SIGTERM` (Darwin numbering) |
| `instigator_exe`, `instigator_pid` | Signal | the instigator, when it differs from the sender |
| `reporter_exe` | AddLaunchItem, Authenticate, ModifyTCC | executable of the daemon that reported the event (the message `process`) when `ps` was switched to the instigator |
| `instigator_pid` | AddLaunchItem, Authenticate, ModifyTCC | pid from `instigator_token` when the instigator process itself is absent |
| `launch_item_type` | AddLaunchItem | `user_item`, `app`, `login_item`, `agent`, `daemon` |
| `launch_item_url` | AddLaunchItem | raw `item.item_url` |
| `launch_item_path` | AddLaunchItem | `item_url` converted from `file://` URL to a path (also in `file.path`) |
| `launch_item_app` | AddLaunchItem | `item.app_url` as a path |
| `launch_item_exe` | AddLaunchItem | `executable_path` (the program the item runs) |
| `launch_item_legacy`, `launch_item_managed` | AddLaunchItem | `true` / `false` |
| `launch_item_uid` | AddLaunchItem | `item.uid`, decimal |
| `app_exe` | AddLaunchItem | executable of the `app` process, when present |
| `mount_path` | Mount | `statfs.f_mntonname` |
| `mount_from` | Mount | `statfs.f_mntfromname` (e.g. `/dev/disk4s2`, `//server/share`) |
| `mount_fstype` | Mount | `statfs.f_fstypename` (e.g. `apfs`, `hfs`, `smbfs`) |
| `mount_disposition` | Mount | `external`, `internal`, `network`, `virtual`, `nullfs`, `unknown` |
| `kext_id` | LoadKext | kext bundle identifier |
| `auth_type` | Authenticate | `od`, `touchid`, `token`, `auto_unlock` |
| `auth_success` | Authenticate | `true` / `false` |
| `auth_record_type`, `auth_record_name`, `auth_node_name`, `auth_db_path` | Authenticate (od) | OpenDirectory record details |
| `auth_touchid_mode` | Authenticate (touchid) | `verification` / `identification` |
| `auth_uid` | Authenticate (touchid) | uid, when `has_uid` |
| `auth_pubkey_hash`, `auth_token_id`, `auth_kerberos_principal` | Authenticate (token) | token details |
| `auth_username`, `auth_auto_unlock_type` | Authenticate (auto_unlock) | username; `machine_unlock` / `auth_prompt` |
| `sudo_success` | Sudo | `true` / `false` |
| `sudo_command` | Sudo | the command line sudo was asked to run |
| `sudo_from_uid`, `sudo_from_user` | Sudo | invoking user |
| `sudo_to_uid`, `sudo_to_user` | Sudo | target user |
| `sudo_reject_plugin`, `sudo_reject_message` | Sudo | on rejection: plugin name, failure message |
| `tcc_service` | ModifyTCC | e.g. `kTCCServiceSystemPolicyAllFiles`, `kTCCServiceAccessibility`, `kTCCServiceScreenCapture` |
| `tcc_identity` | ModifyTCC | bundle id or path that gained/lost the right |
| `tcc_identity_type` | ModifyTCC | `bundle_id`, `executable_path`, `policy_id`, `file_provider_domain_id` |
| `tcc_update_type` | ModifyTCC | `unknown`, `create`, `modify`, `delete` |
| `tcc_right` | ModifyTCC | `denied`, `unknown`, `allowed`, `limited`, `add_modify_added`, `session_pid`, `learn_more` |
| `tcc_reason` | ModifyTCC | `none`, `error`, `user_consent`, `user_set`, `system_set`, `service_policy`, `mdm_policy`, `service_override_policy`, `missing_usage_string`, `prompt_timeout`, `preflight_unknown`, `entitled`, `app_type_policy`, `prompt_cancel` |
| `tcc_responsible_exe` | ModifyTCC | executable of the responsible process, when present |
| `xp_malware_identifier` | XProtectDetect | e.g. `OSX.AtomicStealer.A` |
| `xp_signature_version`, `xp_incident_identifier` | XProtectDetect | |
| `xp_detected_path`, `xp_detected_executable` | XProtectDetect | (`file.path` = detected path) |

Enum values that are not in the table render as their decimal number.

`pkg/yara` adds one more key on `YaraMatch` events: `trigger` = the `evt.name`
that caused the scan (`CreateProcess`, `CreateFile`, `WriteFile`).

`pkg/ps` adds identity markers (see pkg/ps): `identity`, `parent_identity`,
`target_identity` = `unverified` when that process (or the event's parent /
target process) was seeded at start from `kern.procargs2` and no exec event
from ES has replaced its image since. procargs2 can be rewritten by the
process itself, so its args, env and cwd are claims, not facts. The same
mark is on the process itself as `Proc.Seeded` (on `e.Proc`, `e.Target` and
the `Parent` copy), so response code can check it without reading
`evt.arg`. When the parent is not in the table, `pkg/ps` sets `Parent` to nil
and every `ps.parent.*` field is nil. A rule or
response action must not trust such a process's command line, and the kill
action refuses it (WS A).

## Subscription (`ESEventTypes`)

- Maps canonical names to eslogger names from a fixed table; an empty input means
  everything supported. `WriteFile` subscribes to `close` only (one event per
  modified file instead of one per `write(2)`); `ESEventTypesWithWrite` /
  `Config.SubscribeWrite` adds `write`.
- `pkg/ps` needs `CreateProcess`, `Fork` and `TerminateProcess` even when no rule
  uses them (`ps.RequiredEvents()`); the caller must add them to the subscription.

## `Source.Run`

- Refuses to start unless euid is 0 (`ErrNotRoot`). As root, `Config.Binary`
  must be exactly `DefaultBinary` (`/usr/bin/eslogger`, SIP-protected); any
  other value is refused. It must be an absolute path to a regular file.
- `Source.PID()` returns the running eslogger child pid (0 when none). The
  optional `Config.OnStart(pid)` is called on every (re)start, so the caller can
  protect that pid.
- Launches eslogger with a fixed argv (`Source.Args`), no shell, a minimal
  environment (`PATH`, `LANG` only), cwd `/`. eslogger stays in ZAAFVesper's process
  group on purpose: it suppresses events from its own process group, which keeps
  ZAAFVesper's own file writes out of the stream.
- Reads stdout line by line; lines over 16 MiB are skipped and counted.
- Early drops:
  - `ExcludeSigning` matches `ps.signing_id` **only when `ps.is_platform` is
    true**, because a signing ID alone is forgeable.
  - `ExcludePaths` holds directory prefixes, matched per path component: `/dev`
    matches `/dev` and `/dev/...` but not `/devil`. Trailing slashes are ignored
    and relative entries are dropped. It applies to file events only, and a
    rename is kept if its destination is not excluded.
  - Process lifecycle events are never dropped.
- Blocking send to `out` (back-pressure), cancelled by ctx.
- eslogger exiting unexpectedly is restarted with backoff 1 s doubling to 30 s,
  at most 5 restarts per minute, then `Run` returns the error with eslogger's
  stderr. `ErrNoFullDiskAccess`, `ErrNotRoot` and `ErrTooManyClients` (recognised
  from eslogger's `ES_NEW_CLIENT_RESULT_ERR_*` messages) are returned at once.
- `Stats()`: `lines`, `decoded`, `ignored`, `decode_errors`, `oversize_lines`,
  `excluded`, `sent`, `restarts`, `seq_gaps`, `events_missed`.
- Dropped events: `global_seq_num` is numbered per ES client, i.e. per
  eslogger run, and every delivered message uses one number, including lines
  ZAAFVesper ignores. A jump means Endpoint Security or eslogger dropped
  events: `seq_gaps` and `events_missed` count it and
  `OnDegraded(fn)` reports `es_events_dropped` with detail
  `missed N events (global_seq_num A to B); T missed in total`. A number that
  does not increase starts a new sequence (restart), and the tracker is reset
  on every eslogger start. Reports are rate-limited to one a minute; the next
  one ends with `(N more suppressed since last report)`. Lines that fail to
  decode carry no usable number and are counted under `decode_errors` only;
  an oversize line (skipped) shows up as a gap.

## Fixtures and tests

`testdata/eslogger/seqgap/gaps.jsonl` holds lines whose `global_seq_num` skips
numbers (`TestSeqGapReported`).

`testdata/eslogger/<eslogger-name>.jsonl` holds hand-built lines for every mapped
type; `<name>.golden.json` is the decoded output (`null` = line ignored by
design). Regenerate goldens with `go test ./pkg/source/eslogger -run TestGolden
-update` and review the diff. `TestRuleFields` checks the fields rules rely on
through `event.Get` / `event.GetIndexed`.
