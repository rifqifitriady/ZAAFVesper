# ZAAFVesper built-in rules (macOS)

46 hand-written behaviour rules, 12 rules converted from SigmaHQ (see
[Sigma import](#sigma-import)), 5 YARA signatures and two shared macro files (`macros.yml`, `network.yml`). Every
hand-written rule maps to one MITRE ATT&CK technique, has a fixture file with at least one `match` and two `nomatch`
scenarios (one of them a realistic benign lookalike), and, where Atomic Red Team ships a
macOS test for the behaviour, lists that test's GUID in `tests.atomic`.

ATT&CK IDs follow the data bundled with the Atomic Red Team checkout used for this work
(`atomic_red_team/enterprise-attack.json`). That release renamed TA0005 to **Stealth**,
added **TA0112 Defense Impairment**, and revoked several older IDs. Old to new:
T1562 and T1562.001 to **T1685**, T1562.004 to **T1686**, T1070.002 to **T1685.006**,
T1562.003 to T1690. Every `technique.id`/`tactic.id` pair below was checked against that
file: not revoked, name identical, tactic is one of the technique's tactics.

## Rule layout and platforms

- **Where rules live.** Rules are loaded from `rules/*.yml` and, recursively, from rule subdirectories such as `rules/windows/` or `rules/sigma/macos/`. The directories `macros/`, `testdata/` and `yara/`, and dot directories, are never read as rules. Symbolic links are not followed, and as root the whole tree must pass the ownership and ACL checks. Macros are shared: they come only from `rules/macros/`.
- **Fixtures.** Each rule's fixture file sits next to it, in `<rule dir>/testdata/<rule file name>.yml`. For example, `rules/windows/x.yml` is tested by `rules/windows/testdata/x.yml`. A fixture file without a rule of the same name is reported, per directory.
- **`platforms:`** is optional and takes a list of `macos`, `windows` and `linux`; any other value is a load error. When the key is left out, the rule applies to every platform. The built-in macOS rules declare `platforms: [macos]`, and the two sensor-health rules declare none.
  - `run` loads only the rules for the platform it runs on.
  - `replay` defaults to the host platform; `--platform windows|linux|macos|all` overrides it.
  - `rules validate` and `rules test` check every rule on every platform, so a Windows rule's fixtures run on a Mac.
- **Events and fields.** The canonical event names and fields shared by all platforms are defined in `pkg/event`. The mapping from Sigma log sources and field names is in `pkg/sigmamap`. A field the source did not report resolves to nil, so a comparison on it is false.

## Sigma import

`zaafvesper sigma convert <sigma dir|file> -o <rules dir> [--report report.json] [--force]`
converts Sigma rules (Sigma 2.1 rule format) into ZAAFVesper rules. A rule is converted only
when ZAAFVesper can express it exactly; anything else is skipped with a reason. The one
deliberate narrowing is keyword searches, which look in the category's mapped string
fields rather than in every value of the raw event (see below).

**What it reads.** Every `*.yml` and `*.yaml` under the input directory, recursively. Dot
directories are skipped. Symbolic links are never followed; each one is reported as an
error. Files over 1 MiB are refused.

**What it writes.** One rule per converted Sigma file, named after the Sigma file (lower
case, only `a-z 0-9 _ -`). An existing file is never replaced unless `--force` is given,
and `--force` replaces only files the converter wrote itself (they start with its header
comment): a hand-written rule or a symbolic link with the same name is refused as an
error. An output directory that is a symbolic link is refused; the directory is then
opened once and every file is created through that handle, so a directory swapped for a
link while the command runs cannot redirect the writes. A converted rule whose id is
already used by a rule file under the output directory is not written, and neither is a
rule that would exceed the loader's 1 MiB file limit. Convert into a directory of its own,
for example `rules/sigma/imported/`, and run `zaafvesper rules validate` on the whole
rules tree before deploying: one bad or duplicate rule stops `run` from loading any rule. The summary goes to the terminal; `--report` also writes it as JSON
(`converted`, `skipped` with `kind` and `reason`, `errors`). The exit code is 1 when a file
could not be read or written, and 0 otherwise, even when rules were skipped.

**How a Sigma rule maps.**

| Sigma | ZAAFVesper |
|---|---|
| `logsource.product` macos, windows, linux | `platforms: [macos]`, `[windows]` or `[linux]` (always set) |
| `logsource.category` | `evt.name in (...)` from `pkg/sigmamap` |
| field names | `pkg/sigmamap` field map; special values such as `Initiated: 'true'` through its value map |
| `id` | rule `id` when it is a UUID v4; otherwise a stable id derived from it. The original is kept in `labels.sigma.id` |
| `title`, `description` | `name`, `description` |
| `level` | `severity` (informational becomes info; a missing level becomes low and is reported) |
| `tags` `attack.tNNNN` | `labels.technique.id`. T1562, T1562.001, T1562.003, T1562.004 and T1070.002 are rewritten to their current IDs (table at the top of this file) and get tactic TA0112 |
| `tags` `attack.<tactic>` | `labels.tactic.id` and `labels.tactic.name` (defense-evasion is TA0005 Stealth) |
| `author`, `references` | `labels.sigma.author`, `references`, and the author in the alert text (DRL 1.1) |
| `falsepositives` | `notes` |
| `status` deprecated or unsupported | skipped |

**Bounds.** A Sigma file may be at most 1 MiB, nested at most 32 levels and hold at most
20 000 YAML nodes; anchors, aliases, merge keys and duplicate keys are refused. A value or
regular expression may be at most 4 KiB, and a condition at most 4 KiB, 1 000 tokens and
64 levels deep. The generated condition may be at most 256 KiB; expansions (`windash`,
`cidr`, keywords, a search used many times) are measured before they are built, so a
small file that would expand past the limit is skipped at once.

**Supported detection features.** Field maps (AND), lists of maps (OR), value lists (OR),
keyword lists, `null` (field not reported), the empty string. Modifiers `contains`,
`startswith`, `endswith`, `all`, `re` with `i`, `m`, `s` (RE2 syntax only), `cidr` (IPv4),
`windash`, `exists`, `cased`, `neq` (single value). Sigma 2.1 wildcards `*` and `?` and
escapes `\*`, `\?`, `\\`. Conditions `and`, `or`, `not`, parentheses, `1 of`, `any of`,
`all of`, `them` (identifiers starting with `_` excluded), name patterns such as
`selection_*`, and a list of conditions (OR).

**Semantics, where they could differ.**

- Strings compare case-insensitively unless `cased` is given; `re` is case-sensitive unless
  `|i`. Regular expressions are unanchored.
- A field the event does not report is nil in ZAAFVesper, so `Field: null` is true and any
  comparison on it is false; `not` over it is true. ZAAFVesper has no JSON null, so a
  field that is present but null cannot occur.
- Some ZAAFVesper fields are always present when the process is known, as an empty string
  if the source gave nothing (for example `ps.cmdline`). `null` and `exists: false` are
  then false for them.
- Keyword searches look, case-insensitively, in every string field the category maps
  (for `process_creation`: image, command line, parent image and so on).
- `cidr` is compiled to an anchored regular expression over the dotted-quad text of the
  address, also accepted as `::ffff:a.b.c.d`. IPv6 ranges are skipped: ZAAFVesper has no
  address-range operator yet.
- A number compared with a numeric ZAAFVesper field (`ps.pid`, `net.dport`) is an integer
  comparison; with a string field it is compared as text.

**Skipped, with a reason.** Aggregations (`| count()` and others), `timeframe`,
correlation and filter rules, rule collections (several YAML documents), `service`
log sources, products and categories not in `pkg/sigmamap`, fields without a mapping,
the modifiers `base64`, `base64offset`, `utf16*`, `wide`, `fieldref`, `expand`, `lt`,
`lte`, `gt`, `gte` and the time modifiers, `2 of` and higher counts, regular expressions
that are not RE2, and invalid Sigma (for example two of `contains`, `startswith`,
`endswith`; a regex flag without `re`; `all` on a single value; `null` inside a list).

**Conformance.** The converter is tested against ZAAFElegia's language-neutral Sigma
conformance cases (vendored in `pkg/sigma/testdata/conformance/` with attribution): 20
cases, 73 events, every supported feature. Rules the converter refuses on purpose are
listed in the test with the reason. Events with JSON null, arrays or nested objects are
not representable as ZAAFVesper events and are not checked.

**Converted rules and `rules test`.** A converted rule is treated exactly like a
hand-written one: `rules validate` warns that it has no fixture, and `rules test` fails
for it ("missing fixture file") until you add `<rules dir>/testdata/<rule file name>.yml`
with at least one `match` and two `nomatch` scenarios. The converter does not generate
fixtures, because fixtures written from the rule itself would prove nothing. The fixture
requirement is unchanged.

**Shipped converted rules (`rules/sigma/macos/`).** 12 SigmaHQ macOS rules, chosen because
they use only fields ZAAFVesper's eslogger source reports (image, command line, parent
image) and their logic holds on real macOS argument shapes. Each has hand-written
fixtures. Their originals are in `pkg/sigma/testdata/sigmahq/` and a test checks the
shipped files are exactly the converter's output. License: DRL 1.1, see
[`rules/sigma/NOTICE.md`](../rules/sigma/NOTICE.md). SigmaHQ macOS rules left out: ones
the built-in rules already cover (emond, StartupItems, quarantine removal, security tool
tampering), noisy discovery rules (`sw_vers`, `sysctl`, `ioreg`, and similar), the hidden
account rule (its regex matches any digit), the firmware password rule (it also fires on
the read-only `-check`), and the `sysadminctl -addUser ... -admin` rule (it misses
`-admin` as the last argument). One known weakness is kept from SigmaHQ: "Root Account
Enable Via Dsenableroot" excludes ` -d ` with surrounding spaces, so a bare
`dsenableroot -d` (which disables root) still fires; its fixture shows this.

**Shipped converted rules for Windows and Linux (`rules/sigma/windows/`, `rules/sigma/linux/`).**
14 Windows and 11 Linux SigmaHQ rules for the Sysmon sources, chosen because they use
only fields the Sysmon decoder fills on that platform. Hand-written fixtures; originals in
`pkg/sigma/testdata/sigmahq-windows/` and `-linux/`, checked the same way. Selection and
exclusions: [`rules/sigma/NOTICE.md`](../rules/sigma/NOTICE.md).

| Rule (file) | Tactic | Technique | Severity | Sigma author |
|---|---|---|---|---|
| System Integrity Protection (SIP) Disabled<br>`proc_creation_macos_csrutil_disable.yml` | Discovery | T1518.001 | medium | Joseliyo Sanchez, @Joseliyo_Jstnk |
| User Added To Admin Group Via Dscl<br>`proc_creation_macos_dscl_add_user_to_admin_group.yml` | Initial Access, Persistence, Privilege Escalation, Stealth | T1078.003 | medium | Sohan G (D4rkCiph3r) |
| User Added To Admin Group Via DseditGroup<br>`proc_creation_macos_dseditgroup_add_to_admin_group.yml` | Initial Access, Persistence, Privilege Escalation, Stealth | T1078.003 | medium | Sohan G (D4rkCiph3r) |
| Root Account Enable Via Dsenableroot<br>`proc_creation_macos_dsenableroot_enable_root_account.yml` | Initial Access, Persistence, Privilege Escalation, Stealth | T1078, T1078.001, T1078.003 | medium | Sohan G (D4rkCiph3r) |
| JXA In-memory Execution Via OSAScript<br>`proc_creation_macos_jxa_in_memory_execution.yml` | Execution | T1059.002, T1059.007 | high | Sohan G (D4rkCiph3r) |
| Suspicious Microsoft Office Child Process - MacOS<br>`proc_creation_macos_office_susp_child_processes.yml` | Execution, Persistence | T1059.002, T1137.002, T1204.002 | high | Sohan G (D4rkCiph3r) |
| OSACompile Run-Only Execution<br>`proc_creation_macos_osacompile_runonly_execution.yml` | Execution | T1059.002 | high | Sohan G (D4rkCiph3r) |
| Potential Persistence Via PlistBuddy<br>`proc_creation_macos_persistence_via_plistbuddy.yml` | Persistence, Privilege Escalation | T1543.001, T1543.004 | high | Sohan G (D4rkCiph3r) |
| Guest Account Enabled Via Sysadminctl<br>`proc_creation_macos_sysadminctl_enable_guest_account.yml` | Initial Access, Persistence, Privilege Escalation, Stealth | T1078, T1078.001 | low | Sohan G (D4rkCiph3r) |
| Potential Base64 Decoded From Images<br>`proc_creation_macos_tail_base64_decode_from_image.yml` | Stealth | T1140 | high | Joseliyo Sanchez, @Joseliyo_Jstnk |
| Time Machine Backup Deletion Attempt Via Tmutil - MacOS<br>`proc_creation_macos_tmutil_delete_backup.yml` | Impact | T1490 | medium | Pratinav Chandra |
| Time Machine Backup Disabled Via Tmutil - MacOS<br>`proc_creation_macos_tmutil_disable_backup.yml` | Impact | T1490 | medium | Pratinav Chandra |

These rules keep SigmaHQ's ATT&CK tags. Unlike the hand-written rules, their technique
and tactic IDs were not checked against the bundled `enterprise-attack.json` (only the
revoked IDs listed above are rewritten), and no atomic test has been run against them.

## Network rules (42–44)

The network rules match `NetworkConnect` and `NetworkAccept` events from socket polling (`pkg/source/netpoll`, see [operations](operations.md#network-telemetry-socket-polling)). What they can and cannot see:

- **Polling, not a stream.** A socket is found by polling every `--net-interval` (1 s) and right after each exec. A connection that opens and closes between two polls is never seen, so these rules catch long-lived shells and sessions, not short beacons.
- **No DNS.** macOS gives no DNS visibility without a NetworkExtension, so `net.dhost` is never set and rule 44 treats every public destination as a raw IP.
- **Identity.** When the process was seen executing, the event carries its full identity from the process table. Otherwise the identity comes from the kernel and is marked `evt.arg[identity] = unverified` with no signing data. Rule 42 matches either (by path or name); rule 43 requires a verified identity, so it misses a payload that started before ZAAFVesper rather than flag every signed helper whose signing data is unknown.
- **Evasion gaps.** UDP sent with `sendto()` on an unconnected socket shows only as a listening socket, so these rules never see it as a connection. A renamed copy of a shell or interpreter outside the usual paths evades rules 42 and 44 (rule 42 also matches by process name). Flooding Endpoint Security until events are dropped (`es_events_dropped`) can leave a process with an unverified identity, which rule 43 skips. Padding a process with many descriptors only delays polling (`netpoll_fd_capped` is raised).
- **False positives.** Rule 42: a shell that really holds a socket is rare; `ssh`, `nc` or `curl` started from a shell hold their own sockets and do not match. Rule 43: unsigned developer builds run from `/tmp` that talk to the internet. Rule 44: scripts that talk to cloud databases or brokers on their native ports (5432, 6379, 9092, 27017) and game or VoIP traffic from interpreters; add exclusions in the configuration. Common client ports (`net_common_ports` in `rules/macros/network.yml`) and private, loopback, link-local, CGNAT (100.64.0.0/10) and unique-local destinations are not "uncommon public" destinations.

## Rule table

Seq = sequence rule. Action = response taken only when ZAAFVesper runs with `--enable-response`.

| # | Rule (file) | Tactic | Technique | Severity | Seq | Action | Atomic tests |
|---|---|---|---|---|---|---|---|
| 1 | Cron or periodic job installed<br>`rules/persistence_cron_periodic.yml` | TA0003 Persistence | T1053.003 Cron | medium |  |  | `435057fb-74b1-410e-9403-d81baf194f75`<br>`b7d42afa-9086-4c8a-b7b0-8ea3faa6ebb0` |
| 2 | Event Monitor (emond) rule persistence<br>`rules/persistence_emond_rule.yml` | TA0003 Persistence | T1546.014 Emond | high |  |  | `23c9c127-322b-4c75-95ca-eff464906114` |
| 3 | Third-party kernel extension loaded<br>`rules/persistence_kernel_extension_load.yml` | TA0003 Persistence | T1547.006 Kernel Modules and Extensions | medium |  |  | `f4391089-d3a5-4dd1-ab22-0419527f2672` |
| 4 | Launch Agent persistence via plist write<br>`rules/persistence_launch_agent_plist.yml` | TA0003 Persistence | T1543.001 Launch Agent | high |  |  | `a5983dee-bf6c-4eaf-951c-dbc1a7b90900`<br>`66774fa8-c562-4bae-a58d-5264a0dd9dd7` |
| 5 | Launch Daemon persistence via plist write<br>`rules/persistence_launch_daemon_plist.yml` | TA0003 Persistence | T1543.004 Launch Daemon | high |  |  | `03ab8df5-3a6b-4417-b6bd-bb7a5cfd74cf` |
| 6 | Launch item plist written by a Developer ID signed process<br>`rules/persistence_launch_item_plist_by_developer_id.yml` | TA0003 Persistence | T1543 Create or Modify System Process | low |  |  | (none indexed for this technique) |
| 7 | Login Item registered shortly after osascript ran<br>`rules/persistence_login_item_after_osascript.yml` | TA0003 Persistence | T1547.015 Login Items | medium | yes |  | `716e756a-607b-41f3-8204-b214baf37c1d` |
| 8 | Login Item added via inline AppleScript<br>`rules/persistence_login_item_via_osascript.yml` | TA0003 Persistence | T1547.015 Login Items | high |  |  | (none indexed for this technique) |
| 9 | Shell start-up file modified by non-editor process<br>`rules/persistence_shell_profile_modification.yml` | TA0003 Persistence | T1546.004 Unix Shell Configuration Modification | medium |  |  | `94500ae1-7e31-47e3-886b-c328da46872f`<br>`0a898315-4cfa-4007-bafe-33a4646d115f` |
| 10 | StartupItems persistence<br>`rules/persistence_startup_items.yml` | TA0003 Persistence | T1037.005 Startup Items | high |  |  | `134627c3-75db-410e-bff8-7a920075f198`<br>`fc369906-90c7-4a15-86fd-d37da624dde6`<br>`10cf5bec-49dd-4ebf-8077-8f47e420096f` |
| 11 | Setuid or setgid bit set with chmod<br>`rules/privilege_escalation_setuid_bit_set.yml` | TA0004 Privilege Escalation | T1548.001 Setuid and Setgid | medium |  |  | `759055b3-3885-4582-a8ec-c00c9d64dd79`<br>`db55f666-7cba-46c6-9fe6-205a05c3242c`<br>`896dfe97-ae43-4101-8e96-9a7996555d80` |
| 12 | Sudoers modified outside visudo<br>`rules/privilege_escalation_sudoers_modification.yml` | TA0004 Privilege Escalation | T1548.003 Sudo and Sudo Caching | high |  |  | `91a60b03-fb75-4d24-a42e-2eb8956e8de1`<br>`a7b17659-dd5e-46f7-b7d1-e6792c91d0bc` |
| 13 | TCC database modified outside tccd<br>`rules/privilege_escalation_tcc_database_modification.yml` | TA0004 Privilege Escalation | T1548.006 TCC Manipulation | high |  |  | (none indexed for this technique) |
| 14 | Process started with DYLD_INSERT_LIBRARIES<br>`rules/stealth_dyld_insert_libraries.yml` | TA0005 Stealth | T1574.006 Dynamic Linker Hijacking | high |  |  | `4d66029d-7355-43fd-93a4-b63ba92ea1be` |
| 15 | File hidden with chflags or SetFile<br>`rules/stealth_hidden_file_flag.yml` | TA0005 Stealth | T1564.001 Hidden Files and Directories | low |  |  | `b115ecaf-3b24-4ed2-aefe-2fcb9db913d3`<br>`3b7015f2-3144-4205-b799-b05580621379` |
| 16 | Shell history file deleted<br>`rules/stealth_shell_history_deleted.yml` | TA0005 Stealth | T1070.003 Clear Command History | medium |  |  | `a934276e-2be5-4a36-93fd-98adbb5bd4fc`<br>`23d348f3-cc5c-4ba9-bd0a-ae09069f0914` |
| 17 | Task port, ptrace or remote thread from untrusted binary<br>`rules/stealth_task_port_access_by_untrusted_binary.yml` | TA0005 Stealth | T1055 Process Injection | high |  |  | (none indexed for this technique) |
| 18 | macOS firewall disabled<br>`rules/defense_impairment_firewall_disabled.yml` | TA0112 Defense Impairment | T1686 Disable or Modify System Firewall | medium |  |  | (none indexed for this technique) |
| 19 | Gatekeeper or quarantine disabled system-wide<br>`rules/defense_impairment_gatekeeper_disabled.yml` | TA0112 Defense Impairment | T1685 Disable or Modify Tools | high |  |  | `2a821573-fb3f-4e71-92c3-daac7432f053` |
| 20 | Quarantine attribute removed from file<br>`rules/defense_impairment_quarantine_attribute_removed.yml` | TA0112 Defense Impairment | T1553.001 Gatekeeper Bypass | medium |  |  | `fb3d46c6-9480-4803-8d7d-ce676e1f1a9b` |
| 21 | Security tool or sensor stopped<br>`rules/defense_impairment_security_tool_tampering.yml` | TA0112 Defense Impairment | T1685 Disable or Modify Tools | high |  |  | `8fba7766-2d11-4b4a-979a-1e3d9cc9a88c`<br>`62155dd8-bb3d-4f32-b31c-6532ff3ac6a3`<br>`07f43b33-1e15-4e99-be70-bc094157c849`<br>`b3e7510c-2d4c-4249-a33f-591a2bc83eef`<br>`40074085-dbc8-492b-90a3-11bcfc52fda8` |
| 22 | System or audit logs cleared<br>`rules/defense_impairment_system_log_clearing.yml` | TA0112 Defense Impairment | T1685.006 Clear Linux or Mac System Logs | high |  |  | `989cc1b1-3642-4260-a809-54f9dd559683`<br>`653d39cd-bae7-499a-898c-9fb96b8b5cd1`<br>`6290f8a8-8ee9-4661-b9cf-390031bf6973`<br>`c23bdb88-928d-493e-b46d-df2906a50941`<br>`bc8eeb4a-cc3e-45ec-aa6e-41e973da2558`<br>`0208ea60-98f1-4e8c-8052-930dce8f742c`<br>`848e43b3-4c0a-4e4c-b4c9-d1e8cea9651c`<br>`03013b4b-01db-437d-909b-1fdaa5010ee8`<br>`86f0e4d5-3ca7-45fb-829d-4eda32b232bb`<br>`b0768a5e-0f32-4e75-ae5b-d036edcf96b6`<br>`810a465f-cd4f-47bc-b43e-d2de3b033ecc`<br>`e62f8694-cbc7-468f-862c-b10cd07e1757` |
| 23 | System logging or audit disabled<br>`rules/defense_impairment_system_logging_disabled.yml` | TA0112 Defense Impairment | T1685 Disable or Modify Tools | high |  |  | (none indexed for this technique) |
| 24 | Browser credential or cookie store read by another process<br>`rules/credential_access_browser_credential_store_read.yml` | TA0006 Credential Access | T1555.003 Credentials from Web Browsers | high |  |  | `c1402f7b-67ca-43a8-b5f3-3143abedc01b`<br>`124e13e5-d8a1-4378-a6ee-a53cd0c7e369`<br>`29d0c390-3cbc-4e4e-a52b-a1350ed836b7` |
| 25 | Keychain secrets dumped with security CLI<br>`rules/credential_access_keychain_dump_via_security.yml` | TA0006 Credential Access | T1555.001 Keychain | high |  |  | `88e1fa00-bf63-4e5b-a3e1-e2ea51c8cca6` |
| 26 | Keychain database read by file tool or untrusted binary<br>`rules/credential_access_keychain_file_read.yml` | TA0006 Credential Access | T1555.001 Keychain | high |  |  | `5c32102a-c508-49d3-978f-288f8a9f6617` |
| 27 | Fake password prompt via osascript<br>`rules/credential_access_osascript_password_prompt.yml` | TA0006 Credential Access | T1056.002 GUI Input Capture | high |  |  | `76628574-0bc1-4646-8fe2-8f4427b47d15`<br>`b7037b89-947a-427a-ba29-e7e9f09bc045` |
| 28 | Fake password prompt via osascript from untrusted origin<br>`rules/credential_access_osascript_password_prompt_untrusted_origin.yml` | TA0006 Credential Access | T1056.002 GUI Input Capture | critical |  | suspend, kill (parent) | (none indexed for this technique) |
| 29 | SSH or GnuPG private key read by unusual process<br>`rules/credential_access_ssh_private_key_read.yml` | TA0006 Credential Access | T1552.004 Private Keys | high |  |  | `46959285-906d-40fa-9437-5a439accd878`<br>`864bb0b2-6bb5-489a-b43b-a77b3a16d68a`<br>`2a5a0601-f5fb-4e2e-aa09-73282ae6afca` |
| 30 | Non-interactive screen capture from script or untrusted parent<br>`rules/collection_noninteractive_screencapture.yml` | TA0009 Collection | T1113 Screen Capture | medium |  |  | `0f47ceb1-720f-4275-96b8-21f0562217ac`<br>`deb7d358-5fbd-4dc4-aecc-ee0054d2d9a4` |
| 31 | Security software enumeration<br>`rules/discovery_security_software_enumeration.yml` | TA0007 Discovery | T1518.001 Security Software Discovery | low |  |  | `ba62ce11-e820-485f-9c17-6f3c857cd840` |
| 32 | System profiling burst from a script<br>`rules/discovery_system_profiling_burst.yml` | TA0007 Discovery | T1082 System Information Discovery | low | yes |  | `edff98ec-0f73-4f63-9890-6b117092aff6` |
| 33 | launchctl submits a job or loads a plist from a temp folder<br>`rules/execution_launchctl_submit_or_load_from_temp.yml` | TA0002 Execution | T1569.001 Launchctl | medium |  |  | `6fb61988-724e-4755-a595-07743749d4e2` |
| 34 | Downloaded or decoded script piped into a shell<br>`rules/execution_remote_script_piped_to_shell.yml` | TA0002 Execution | T1059.004 Unix Shell | high |  |  | `d0c88567-803d-4dca-99b4-7ce65e7b257c` |
| 35 | Suspicious AppleScript or JXA execution<br>`rules/execution_suspicious_osascript.yml` | TA0002 Execution | T1059.002 AppleScript | medium |  |  | `3600d97d-81b9-4171-ab96-e4386506e2c2` |
| 36 | Binary dropped in a temp or shared folder and executed without developer identity<br>`rules/execution_untrusted_binary_dropped_and_run_from_temp.yml` | TA0002 Execution | T1204.002 Malicious File | high | yes | quarantine_file (process) | (none indexed for this technique) |
| 37 | XProtect malware detection<br>`rules/threat_xprotect_malware_detection.yml` | TA0002 Execution | T1204.002 Malicious File | critical |  |  | (none indexed for this technique) |
| 38 | YARA signature match<br>`rules/threat_yara_signature_match.yml` | TA0002 Execution | T1204.002 Malicious File | high |  |  | (none indexed for this technique) |
| 39 | Download followed by stdin-fed shell<br>`rules/command_and_control_download_then_stdin_shell.yml` | TA0011 Command and Control | T1105 Ingress Tool Transfer | high | yes |  | (none indexed for this technique) |
| 40 | ZAAFVesper sensor degraded<br>`rules/defense_impairment_sensor_degraded.yml` | TA0112 Defense Impairment | T1685 Disable or Modify Tools | medium |  |  | (none; synthetic event) |
| 41 | Executable replaced right after exec (YARA scan evasion)<br>`rules/defense_impairment_sensor_exec_replaced.yml` | TA0112 Defense Impairment | T1685 Disable or Modify Tools | high |  |  | (none; synthetic event) |
| 42 | Shell holding a network connection to another host (reverse or bind shell)<br>`rules/network_shell_remote_socket.yml` | TA0002 Execution | T1059.004 Unix Shell | high |  |  | (none indexed for this technique) |
| 43 | Binary without developer identity in a temp folder connects out<br>`rules/network_unsigned_temp_binary_outbound.yml` | TA0011 Command and Control | T1071 Application Layer Protocol | high |  |  | (none indexed for this technique) |
| 44 | Script interpreter connects to a public IP on an uncommon port<br>`rules/network_interpreter_raw_ip_uncommon_port.yml` | TA0011 Command and Control | T1571 Non-Standard Port | medium |  |  | (none indexed for this technique) |
| 45 | Quarantine attribute removed by an untrusted process<br>`rules/defense_impairment_quarantine_attribute_removed_by_untrusted_process.yml` | TA0112 Defense Impairment | T1553.001 Gatekeeper Bypass | high |  | requarantine | (none indexed for this technique) |
| 46 | Launch Agent or Daemon written by an untrusted process<br>`rules/persistence_launch_item_plist_by_untrusted_process.yml` | TA0003 Persistence | T1543.001 Launch Agent, T1543.004 Launch Daemon | high |  | remove_persistence | (none indexed for this technique) |

Totals: 46 rules, 4 sequence rules, 28 rules with at least one macOS atomic indexed under the rule's own technique (59 GUIDs), 4 rules with response actions (see [operations.md](operations.md#response)). Every action needs `--enable-response` and happens after the event: none of them prevents anything.

`tests.atomic` lists only GUIDs that `atomics/Indexes/Indexes-CSV/macos-index.csv` files
under the rule's own technique (or its parent). Atomics filed under another technique that
also exercise a rule are cited in that rule's `references` instead, as
"atomic <guid> (indexed <technique>) also exercises this behaviour":
`d0c88567` (T1059.004) on the T1105 download-then-shell sequence; `3a15c372` (T1140) on the
pipe-to-shell rule; `b16ef901`/`4d46e16b` (T1027.002, UPX) on the dropped-binary rule;
`11979f23` (T1543.001) on the emond rule; `10cf5bec`/`fc369906` (T1037.005) on the
launchctl rule.

**"Mapped" is not "validated".** No atomic has been executed against a live sensor yet.
Spec section 5 step 4 (run `sudo zaafvesper run --capture`, execute the listed atomics with
Rifqi's approval, keep the capture as a regression fixture) is still to do.

## YARA signatures (`rules/yara/`)

Written for ZAAFVesper; no strings or conditions copied from public rule sets. All compile with
libyara 4.6 (`yarac`) and pass `yr check` (YARA-X).

| File | Rule | Tags | ATT&CK | What it needs to fire |
|---|---|---|---|---|
| `macos_infostealer.yar` | `MAL_Mac_Infostealer_HarvestTargets_Nov26` | stealer, macos | T1555.003 | Mach-O or shebang script under 30 MB with a keychain reference AND 3 browser store paths AND 2 crypto-wallet locations/extension IDs |
| `macos_password_phish.yar` | `SUSP_Mac_OsascriptPasswordDialog_Nov26` | stealer, phishing, macos | T1056.002 | Mach-O, shebang script or compiled AppleScript that builds a dialog with a hidden/default answer asking for a password, plus osascript/NSAppleScript |
| `macos_reverse_shell.yar` | `SUSP_Mac_ReverseShell_OneLiner_Nov26` | backdoor, macos | T1059.004 | bash `/dev/tcp` redirect, mkfifo+nc loop, `nc -e /bin/sh`, Python socket+dup2/pty, or Perl Socket+exec shell |
| `macos_dropper_quarantine_strip.yar` | `SUSP_Mac_Dropper_QuarantineStripExec_Nov26` | dropper, macos | T1553.001 | download (`curl -o` / NSURLSession) AND quarantine removal AND `chmod +x/755/777` |
| `macos_hunting_launchagent_writer.yar` | `SUSP_Mac_EmbeddedLaunchAgentTemplate_Nov26` | **hunting**, persistence, macos | T1543.001 | small Mach-O embedding a LaunchAgents path and a RunAtLoad/ProgramArguments plist template |

Each rule carries `meta: author = "ZAAFVesper", description, reference, attack, date`. The
built-in rule "YARA signature match" alerts on every match except rules tagged `hunting`;
that tag is the switch for research signatures that should feed custom rules or hunts but
not page anyone.

Goodware check (7 Nov 2026, this Mac): all five rules scanned `/bin`, `/usr/bin`,
`/usr/sbin`, `/usr/libexec`, `/System/Applications`, `/Applications` (about 858 000 files),
`/opt/homebrew/bin` and `~/Downloads` with **0 matches**. The password-dialog rule
initially matched Sublime Text's AppleScript snippet package; a file-type gate (Mach-O,
`#!` script or compiled AppleScript) removed it. Each rule fires on a hand-made inert test
sample; none has been run against real malware samples yet.

## Macros and lists (`rules/macros/macros.yml`)

Event macros, one per canonical `evt.name`: `spawn_process fork_process exit_process
open_file create_file write_file rename_file delete_file set_xattr delete_xattr set_mode
set_owner open_process send_signal ptrace remote_thread add_launch_item load_kext mount
authenticate sudo modify_tcc xprotect_detect yara_match sensor_degraded`.

Composite macros: `file_written` (CreateFile or WriteFile), `apple_trusted_process`,
`apple_package_installer`, `verified_team_id`, `parent_verified_team_id`,
`no_developer_identity`, `parent_no_developer_identity`, `apple_developer_tool`, `parent_apple_developer_tool`,
`parent_from_user_writable`, `ancestor_from_user_writable`, `ancestor_chain_incomplete`, `reparented`, `launchd_parent`, `generic_reader_process`,
`spawn_osascript`, `developer_id_signed`,
`osascript_credential_prompt`, `untrusted_prompt_origin`, `trusted_editor`.

Lists: `shells`, `shell_names`, `script_interpreters`, `script_interpreter_name_globs`,
`apple_signed_trusted`, `temp_drop_globs`, `user_writable_exe_globs`,
`file_access_tool_names`, `browser_team_ids`, `vendor_cs_categories`, `apple_browser_signing_prefixes`,
`security_tool_identifiers`, `security_tool_process_names`, `sensor_self_names`,
`logging_service_identifiers`, `logging_config_globs`, `shell_profile_globs`, `shell_history_names`,
`system_log_globs`, `cron_globs`, `sudoers_globs`, `tcc_db_globs`, `browser_secret_globs`.

Path lists carry both `/private/...` (what Endpoint Security reports) and the `/etc`,
`/tmp`, `/var` spellings. Globs use the engine's semantics: `*` crosses `/`.

## Trust and allow-list policy

An exclusion may only rest on identity the attacker cannot choose:

- **Apple platform binary**: `ps.is_platform = true`, together with a `signing_id` or a path
  under a SIP-protected directory (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`,
  `/usr/libexec`, `/System`). Macro `apple_trusted_process`. Platform trust does not use
  the signing category.
- **A specific vendor**: that vendor's Team ID **with a verified signing category**
  (`ps.cs_category in ('developer_id', 'app_store')`, list `vendor_cs_categories`, macro
  `verified_team_id`), paired with its signing IDs, e.g. VS Code = `UBF8T346G9` +
  `com.microsoft.VSCode`, Sublime Text = `Z6D26JE4Y4` + `com.sublimetext.4`
  (`trusted_editor`), browsers by verified Team ID (`browser_team_ids`: Google, Mozilla,
  Microsoft, Brave).
- **Apple's non-platform tools** (Xcode, Command Line Tools, `debugserver`, `clang`):
  these are *not* platform binaries; codesign on this Mac shows them signed with Apple's
  Team ID `59GAB85EFG`. Macro `apple_developer_tool` binds to that Team ID and, like every
  Team ID trust, also requires the verified signing category.

### Signing category (open finding M4)

A self-signed certificate can embed any Team ID, so a Team ID on its own is forgeable.
Since round 2 every place where a Team ID grants trust or lowers severity also requires
`cs_category` (Endpoint Security's `cs_validation_category`, macOS 15+) to be
`developer_id` or `app_store`. Affected: `no_developer_identity`,
`parent_no_developer_identity`, `apple_developer_tool`, `parent_apple_developer_tool`,
`developer_id_signed`, `trusted_editor` and the browser rule's Team ID exclusion. A forged
Team ID reports `local_signing` (or another category) and is treated like unsigned code.

**Fails closed.** On macOS releases where Endpoint Security does not report the category,
`ps.cs_category` is nil and every Team ID trust above is false: Developer ID apps then
alert like unsigned code (keychain/task-port/dropped-binary rules, osascript parents),
launch-item writers stay on the high-severity rules instead of the low companion, and a
Developer ID parent of an osascript password prompt makes the prompt critical, so with
`--enable-response` that parent is killed. Expect more alerts there, never fewer. Each
affected rule has a match fixture for both a `local_signing` forgery and an absent
category.

### Unknown parent = untrusted (open finding M2)

When a process's parent is not in the process table (evicted under pressure, or never
seen), every `ps.parent.*` field is nil. Any comparison on a nil field is false, infix
negations included; only a prefix `not` turns it true. Parent trust is therefore always
tested positively and negated with a prefix `not`:

- `parent_no_developer_identity` = `not (ps.parent.is_platform = true) and not
  (parent_verified_team_id)`: TRUE for an absent parent. (The old form
  `ps.parent.is_platform = false and ...` was false for an absent parent, i.e. it treated
  the unknown parent as trusted.)
- `ancestor_chain_incomplete` = `not (ps.ancestors = '/sbin/launchd')`: the chain stops at
  the first unknown ancestor and pkg/ps never evicts launchd, so an unknown ancestor
  anywhere removes `/sbin/launchd`. Used by `untrusted_prompt_origin`, so flooding the
  table to evict the payload behind `sh -c osascript ...` cannot downgrade the critical
  rule either.
- Parent-based exclusions written as `not (ps.parent.<trusted test>)` (screen capture,
  DYLD) already alert on an absent parent; fixtures now prove it.

Effect: an absent parent makes the osascript password prompt critical, makes JXA from
osascript "suspicious", and satisfies the first step of the profiling burst.

What is **not** trust:

- `signing_id` or `ps.name` on their own: an ad-hoc or self-signed signer picks any
  identifier.
- `ps.is_signed = true`: the decoder sets it for any valid non-ad-hoc signature, a
  self-signed certificate included.
- `ps.team_id` without a verified category: see M4 above.
- `ps.team_id != ''` with a verified category (any Developer ID): Developer IDs are cheap
  and notarized malware exists. `developer_id_signed` is only used to route such writers to
  the low-severity rule "Launch item plist written by a Developer ID signed process", never
  to drop an event.
- PackageKit / `installd`: it installs any `.pkg`, malicious ones included. It is not an
  exclusion anywhere except for SIP-protected `/System` paths (StartupItems rule).
  `system_installd` (Apple-signed packages only) stays on the trusted list.

"No developer identity" (`no_developer_identity`) = not a platform binary and no verified
Team ID: unsigned, ad-hoc, linker-signed, self-signed, forged Team ID, and (fail closed)
any Team ID when the category is not reported.

### Trusted editors (open finding M7, security review F4)

Since round 3 `trusted_editor` (shell start-up file rule) trusts only vendor GUI editors:
VS Code and Sublime Text by Team ID + signing ID + verified signing category. The Apple
platform terminal-editor branch is gone, and with it the lists `editor_names` and
`vim_script_arg_regexes`. Round 2 required a TTY and clean arguments, but the round 3
review showed that a background payload can run `vim` under a pseudo-terminal
(`script(1)`) with `VIMINIT` or piped keystrokes: there is a TTY and argv is clean, yet
nobody is typing. Interactivity cannot be proven from the event, so vi, vim, nano, pico,
ed and TextEdit are never trusted.

**Known false positive:** editing `~/.zshrc`, `~/.zprofile` etc. by hand in vim or nano
raises "Shell start-up file modified by non-editor process" (medium). That is by design;
triage the edit (the alert names the editor, the parent and the file).

Residual: VS Code's Electron binary can run as Node (`ELECTRON_RUN_AS_NODE=1`) under its
genuine signature; that is not covered.

## `evt.arg` keys used

The sensor workstream fills these; names and formats were checked against
`pkg/source/eslogger/README.md` (7 Nov 2026). A branch that tests a missing key never fires,
except `kext_id`, whose absence makes the kext rule alert:

| Key | Rules | Expected value |
|---|---|---|
| `xattr` | Quarantine attribute removed | attribute name, e.g. `com.apple.quarantine` |
| `launch_item_type` | Login Item registered shortly after osascript | lower-case ES enum name without prefix: `user_item`, `app`, `login_item`, `agent`, `daemon` |
| `launch_item_path` | same (output only) | item URL/path |
| `kext_id` | Third-party kernel extension loaded | bundle identifier, e.g. `com.softraid.driver.SoftRAID` |
| `open_flag_names` | System or audit logs cleared (truncate branch) | symbolic flags joined by `\|`, containing `O_TRUNC` when set, e.g. `FWRITE\|O_CREAT\|O_TRUNC` |
| `xp_malware_identifier` | XProtect malware detection (output only) | XProtect signature name |
| `condition` | ZAAFVesper sensor degraded; Executable replaced right after exec | one of `proctable_pressure`, `alerts_capped`, `capture_capped`, `yara_queue_full`, `yara_exec_replaced`, `yara_skipped_nonlocal` (synthetic `SensorDegraded` event). A missing `condition` still alerts on the medium rule. |
| `detail` | same (output only) | free text from the sensor; may contain an attacker-chosen path |

Keys set by the Linux eBPF source (`evt.source = ebpf`; agreed for v0.4, no rule uses
them yet except the `SetUID` ones, which are part of the event contract):

| Key | Events | Value |
|---|---|---|
| `old_uid`, `old_euid`, `new_uid`, `new_euid` | `SetUID` | decimal uids before and after the change; `ps.uid`/`ps.euid` are the values before |
| `exit_status` | `TerminateProcess` | the kernel's wait status, decimal (exit code × 256, or the signal number), as for eslogger |
| `args_truncated` | `CreateProcess` | `true` when the command line was longer than the limit or unreadable (eBPF source: 64 KiB; other sources: see their notes) |
| `path_incomplete` | any event with a path | `true` when a path (executable, file, rename destination, working directory) was deeper than 512 components (eBPF source) or longer than 4 KiB; the value is then the trailing part |
| `name_from_comm` | any eBPF event whose process image is unknown | the kernel's `comm` of the process, which the process sets itself; `ps.name` is then empty and `comm` is never used as the name |
| `truncated` | `CreateFile` | `true` when an existing file was opened for writing with `O_TRUNC` (its content replaced) rather than newly created |
| `syscall` | `Ptrace`, `OpenProcess` | `ptrace_attach`, `ptrace_seize`, `process_vm_readv` or `process_vm_writev` |
| `module_name` | `DriverLoad` | the kernel module's name, e.g. `dummy` |
| `module_source` | `DriverLoad` | `file` (from a file, path in `image.path`), `memory` (init_module from a buffer; `image.path` empty) or `unknown` |

Signing category: `ps.cs_category`, `ps.parent.cs_category` (values are the `event.CS*`
constants: `developer_id`, `app_store`, `local_signing`, `platform`, ...; nil when not
reported). Ancestry trust: `ps.ancestors_untrusted` (bool, computed by pkg/ps). Fork-time parent: `ps.original_ppid` (password-prompt double-fork check; nil
when not reported).

Other indexed fields used: `ps.env[DYLD_INSERT_LIBRARIES]` and
`ps.parent.env[DYLD_INSERT_LIBRARIES]` (needs exec env in the decoder and env kept in the
process snapshot), `yara.meta[attack]` and `yara.meta[description]` (output only).

## Known limits and false-positive notes

- **Package installs alert.** With PackageKit no longer excluded, installing a `.pkg` that
  ships a launch daemon/agent, cron/periodic script, emond rule or sudoers fragment raises
  the corresponding alert, and vendor EDR upgrades that `launchctl unload` their own job
  raise "Security tool or sensor stopped". This is accepted noise; review the package.
- **Developer ID writers of launch items** go to a separate low-severity rule instead of
  being dropped. Allow-list known vendors locally as Team ID + signing ID pairs.
- **Kernel extension load**: the decoder gives only `kext_id` and the caller (no kext path),
  so the exclusion is "com.apple.* identifier AND platform caller". If kernelmanagerd is
  always the caller, a third-party kext that names itself com.apple.* is missed.
- **System logs cleared** is scoped to logs Apple's daemons write (system.log, install.log,
  asl, launchd, powermanagement, /var/audit, unified log store). Third-party logs in
  /var/log are out of scope rather than allow-listed.
- **SSH / GnuPG keys**: GUI SSH clients that read keys themselves (Termius, Transmit,
  JetBrains) now alert; Developer ID alone is not an allow-list.

- **Shell start-up file modified**: following an installer's instruction such as Homebrew's
  `echo 'eval "$(brew shellenv)"' >> ~/.zprofile` looks the same as the atomic. Medium
  severity; triage the written content.
- **Launch Agent**: `brew services start` (Homebrew's Ruby, no Team ID) alerts once per
  new service.
- **Download followed by stdin-fed shell**: legitimate `curl | sh` installers (rustup, nvm,
  oh-my-zsh) alert; only the exact official Homebrew command is excluded. If bash execs
  before curl in a pipeline the sequence is missed; the single-event pipe rule covers
  pipelines passed as one `-c` argument.
- **Shell history deleted**: in-place truncation (`cat /dev/null > ~/.bash_history`, atomic
  `b1251c35`) is not covered, because bash truncates its own history on exit.
- **Dropped binary run from temp**: shebang scripts execute as their interpreter, so only
  Mach-O payloads match. Exposing the ES exec `script` path as an `evt.arg` would close this.
- **Keychain file read**: script interpreters are deliberately out of scope (keyring
  libraries open the file through Security.framework); Python stealers copying with
  `shutil` are a gap.
- **SSH / GnuPG keys**: Homebrew OpenSSH, Ansible/paramiko and Homebrew `gpg` have no
  identity an attacker cannot choose, so they are not allow-listed (the GnuPG branch only
  fires on generic file tools).
- **Login Item after osascript**: there is no join key between osascript and the BTM event,
  so the window is 30 s. A user adding a login item right after unrelated automation alerts.
- **Quarantine removed**: `xattr -dr` on an app bundle raises one alert per file.
- **Security software enumeration**: MDM/compliance scripts alert (low severity); tune with a
  local exclusion.
- **Browser Team IDs**: only Google (checked with codesign here), Mozilla, Microsoft and
  Brave are listed. Opera, Vivaldi and Arc reading their own stores alert until their IDs
  are read from a real install; a wrong ID would allow-list another developer.
- **Response actions** (only with `--enable-response`; reactive, after the event):
  "Fake password prompt via osascript from untrusted origin" suspends and then kills the
  untrusted parent that launched the prompt (osascript is an Apple platform binary and is
  always refused); "Binary dropped in a temp or shared folder and executed without
  developer identity" quarantines the executable (the running process keeps running);
  "Quarantine attribute removed by an untrusted process" re-adds the attribute; "Launch
  Agent or Daemon written by an untrusted process" boots the job out (only when launchd
  loaded that label from this plist) and quarantines the plist; since 9 Nov 2026 (owner
  decision) it also covers an Apple tool such as `/bin/cp` or `sh -c` whose parent is
  untrusted or unknown, or with an untrusted ancestor, which adds false positives for
  installer scripts of unsigned installers and for plists copied by hand from a terminal
  app that was running before the sensor started. Limits: when the payload
  ran the prompt through `system()`/`popen()`, the parent is a platform `/bin/sh` and is
  refused, so nothing is suspended or killed; when the parent is unknown there is nothing
  to act on. Acting on the first untrusted *ancestor* would need a new target kind. On
  macOS without a reported signing category a Developer ID parent counts as untrusted
  and can be killed (see "Fails closed" above). A plist named `homebrew.mxcl.*` is never
  acted on (it stays on the alert-only plist rules), so malware using that name still
  alerts but keeps its plist.
- **Password prompt, incomplete ancestor chain**: the chain is bounded at 16 entries, so a
  prompt from a chain deeper than 16 processes, or from a process whose ancestor exited
  and was dropped from the table, is treated as untrusted (critical). Replaying a capture
  without launchd in the table would make every password prompt critical.
- **Password prompt, double fork (security review F3)**: a payload can fork a child, exit,
  and let the child (now reparented to launchd: ppid 1, parent `/sbin/launchd`, ancestors
  `[/sbin/launchd]`) exec the prompt, so the chain looks complete and trusted. Macro
  `reparented` (`ps.ppid = 1 and ps.original_ppid != 1`, from `es_process_t.original_ppid`)
  makes that an untrusted origin, so the critical rule fires and the high rule does not.
  The kill target is then the parent, launchd, which is protected: **a double-forked
  prompt is alert-only.** When the source does not report `original_ppid` the field is nil
  and `reparented` is false, but such a prompt is still critical through `launchd_parent`
  (below).
- **Password prompt, parent is launchd (F3 residual, owner decision 8 Nov 2026)**: macro
  `launchd_parent` (`ps.ppid = 1 and ps.parent.exe = '/sbin/launchd'`) is part of
  `untrusted_prompt_origin`. A credential prompt that launchd starts directly (a
  LaunchAgent or LaunchDaemon, `original_ppid` 1) is therefore critical, and the high rule
  does not fire (the two rules stay exact complements). Writing a user LaunchAgent plist is
  how a payload gets this parent, and no legitimate launch job collects the login password
  through osascript. The kill target is launchd (pid 1), which the response layer always
  refuses, so this case is **alert-only**. A prompt from Terminal -> login -> zsh, every
  ancestor trusted, stays high. Expected false positives: a vendor launch job that runs an
  osascript password dialog now raises a critical alert instead of a high one.
- **Password prompt, untrusted ancestor (security review New-2)**: path globs miss payloads
  in user- or admin-writable places outside `user_writable_exe_globs` (`~/Documents`,
  `/Applications/X.app`, `/opt/homebrew/bin`) that run the prompt through a platform shell
  (`sh -c "osascript ..."`). `untrusted_prompt_origin` now also fires on
  `ps.ancestors_untrusted = true`. That field is computed by pkg/ps, not by the rules: true
  when any ancestor up to launchd is neither a platform binary nor a verified vendor
  identity (Team ID + Developer ID / App Store category), or the chain is incomplete. The
  rule is only as good as that computation. Replayed raw eslogger captures get it from the
  process table built during replay (so a replay must see the ancestors' exec events or
  bootstrap data); fixtures set it by hand as pkg/ps would. The path and parent conditions
  stay as additional signals. A Developer ID ancestor without a reported category makes
  this true (fails closed). The launchd-parented prompt residual (F3) was decided by the owner on 8 Nov 2026: see the next item.
- **Sensor degraded** (medium) and **Executable replaced right after exec** (high) alert
  on ZAAFVesper's own synthetic `SensorDegraded` events. Components limit their reports
  per (condition, pid or path); the pipeline allows each condition 20 events a minute
  (120 in total), never limits `es_events_dropped`, and summarises anything it held back
  in one `degraded_suppressed` event a minute. Large builds (process-table pressure), a burst of genuine
  alerts (alerts capped) and executables on network shares (`yara_skipped_nonlocal`) are
  common benign causes; an updater replacing a running binary is the benign cause of
  `yara_exec_replaced`. ATT&CK T1685 (Disable or Modify Tools, which includes degrading
  sensors and blocking telemetry) is the adversarial hypothesis, not a verdict.

## How the fixtures were checked

- `zaafvesper rules validate --rules rules`: 43 rules, 4 sequences, 70 macros/lists, 0 warnings
  (v0.2 active response, 9 Nov 2026).
- `zaafvesper rules test --rules rules`: 287 scenarios, 287 passed, 0 failed (194 before
  round 2, 250 after round 2, 253 after round 3, 261 after round 4, 263 after round 5,
  281 with the v0.2 response companions). Includes the security reviewer's SEC-R3
  (double fork, script(1)+vim) and three SEC-R4 (untrusted ancestor) fixtures.
- Every `technique.id`/`tactic.id` re-checked against `enterprise-attack.json`; every
  `tests.atomic` GUID is indexed under the rule's technique (or its parent).
- Each identity-based exclusion has a "forged" match scenario: a signing ID claimed under a
  different Team ID (VS Code, Chrome) or by a self-signed binary with no Team ID
  (debugserver, Sublime, the password-prompt parent) still fires.
- Before the engine built, a throwaway reference evaluator (scratch only) was used;
  mutation tests confirmed the nomatch scenarios exercise the exclusions.
- Round 2 mutation tests (scratch copy): dropping the signing-category requirement (on the
  process, on the parent, in the browser rule, on Xcode's parent), restoring the old
  `ps.parent.is_platform = false` form, dropping the ancestor-chain check, the TTY check,
  the arguments-known check or the vim script-argument check each made the matching new
  fixtures fail. Round 3: dropping `reparented` from `untrusted_prompt_origin` makes the
  SEC-R3 double-fork match and its high-rule nomatch fail. Round 4: dropping
  `ps.ancestors_untrusted = true` makes the three SEC-R4 matches and their high-rule
  nomatches fail. Round 5: dropping `launchd_parent` from `untrusted_prompt_origin` makes
  all six launchd-parented scenarios fail (three critical matches and their three
  high-rule nomatches).

Fixtures are synthetic events written to mirror what each cited atomic does (as eslogger
would report it). They prove the rule logic, not the decoder: a real capture is still needed
to confirm field population (`ps.env`, `evt.arg[...]`, `/private` path forms).

## Windows and Linux starter rules (v0.2, Sysmon)

Hand-written starters for the Sysmon sources, each with `platforms:`, one or more
`match` scenarios and at least one benign lookalike `nomatch`. Technique IDs and
tactics were checked against the same `enterprise-attack.json` as the macOS rules;
the Atomic Red Team GUIDs were checked in that checkout (test name and platform).
The fixtures are hand-written from Sysmon's documented fields, not captured from a
live host. Converted SigmaHQ rules for Windows (14) and Linux (11) are in `rules/sigma/windows/`
and `rules/sigma/linux/`; how they were chosen and what was left out is in
[`rules/sigma/NOTICE.md`](../rules/sigma/NOTICE.md).

| Rule (file) | Tactic | Technique | Severity | Atomic tests |
|---|---|---|---|---|
| PowerShell started with an encoded command<br>`rules/windows/execution_powershell_encoded_command.yml` | TA0002 Execution | T1059.001 PowerShell | high | `86a43bad-12e3-4e85-b97c-4d5cf25b95c3`<br>`0d181431-ddf3-4826-8055-2dbf63ae848b` |
| LSASS process memory opened for reading<br>`rules/windows/credential_access_lsass_memory_access.yml` | TA0006 Credential Access | T1003.001 LSASS Memory | critical | `0be2230c-9ab3-4ac2-8826-3199b9a0ebf8`<br>`7cede33f-0acd-44ef-9774-15511300b24b`<br>`2536dee2-12fb-459a-8c37-971844fa73be` |
| Registry Run key value set<br>`rules/windows/persistence_registry_run_key.yml` | TA0003 Persistence | T1547.001 Registry Run Keys / Startup Folder | medium | `e55be3fd-3521-4610-9d1a-e210e42dcf05`<br>`554cbd88-cde1-4b56-8168-0be552eed9eb` |
| Volume shadow copies deleted or recovery disabled<br>`rules/windows/impact_shadow_copy_deletion.yml` | TA0040 Impact | T1490 Inhibit System Recovery | critical | `43819286-91a9-4369-90ed-d31fb4da2c01`<br>`6a3ff8dd-f49c-4272-a658-11c2fe58bd88`<br>`263ba6cb-ea2b-41c9-9d4e-b652dadd002c` |
| WMI event subscription persistence<br>`rules/windows/persistence_wmi_event_subscription.yml` | TA0003 Persistence | T1546.003 WMI Event Subscription | high | `3c64f177-28e2-49eb-a799-d767b24dd1e0` |
| Remote thread created in another process from a user-writable location<br>`rules/windows/stealth_remote_thread_into_other_process.yml` | TA0005 Stealth | T1055 Process Injection | high | (Atomic runs from C:\AtomicRedTeam, outside the rule's paths) |
| Cron job file created<br>`rules/linux/persistence_cron_file_write.yml` | TA0003 Persistence | T1053.003 Cron | medium | `078e69eb-d9fb-450e-b9d0-2e118217c846`<br>`2d943c18-e74a-44bf-936f-25ade6cccab4` |
| Systemd unit file created outside the package manager<br>`rules/linux/persistence_systemd_unit_file_write.yml` | TA0003 Persistence | T1543.002 Systemd Service | high | `d9e4f24f-aa67-4c6e-bcbf-85622b697a7c` |
| Sudoers file created outside visudo<br>`rules/linux/privilege_escalation_sudoers_file_write.yml` | TA0004 Privilege Escalation | T1548.003 Sudo and Sudo Caching | high | (the Atomic tests edit with sed -i: a rename, which Sysmon for Linux does not report as FileCreate of sudoers) |
| Shell history file deleted<br>`rules/linux/stealth_shell_history_deleted.yml` | TA0005 Stealth | T1070.003 Clear Command History | medium | `a934276e-2be5-4a36-93fd-98adbb5bd4fc` |
| Interactive shell redirected to a network socket<br>`rules/linux/execution_reverse_shell_dev_tcp.yml` | TA0002 Execution | T1059.004 Unix Shell | critical | (none for this pattern) |

Field notes for Sysmon events: `ps.uid` is -1 (Sysmon reports a user name, in
`ps.username`); `ps.original_name` is the PE original file name, which survives a
rename of the executable; `ps.ancestors_untrusted` is a macOS notion and always
true on Windows and Linux, so do not use it in these rules.

## Round 2 changes (8 Nov 2026)

Rules whose behaviour changed were bumped to 1.1.0:
`credential_access_osascript_password_prompt_untrusted_origin` (kill target parent,
unknown parent and incomplete ancestor chain = untrusted, verified category),
`credential_access_osascript_password_prompt` (complement of the above),
`credential_access_browser_credential_store_read`, `credential_access_keychain_file_read`,
`stealth_task_port_access_by_untrusted_binary`,
`execution_untrusted_binary_dropped_and_run_from_temp`, `stealth_dyld_insert_libraries`,
`persistence_launch_agent_plist`, `persistence_launch_daemon_plist`,
`persistence_launch_item_plist_by_developer_id` (verified signing category),
`execution_suspicious_osascript`, `discovery_system_profiling_burst` (unknown parent and
verified category on the parent), `persistence_shell_profile_modification` (verified
category, interactive non-scripted editors only). New: rules 40 and 41 (sensor health).
`collection_noninteractive_screencapture` is unchanged; it gained an unknown-parent match
fixture.

## Round 3 changes (8 Nov 2026)

Bumped to 1.2.0: `credential_access_osascript_password_prompt_untrusted_origin` and
`credential_access_osascript_password_prompt` (macro `reparented`: a prompt reparented to
launchd by a double fork is an untrusted origin; alert-only, because the kill target is
launchd), `persistence_shell_profile_modification` (no platform terminal-editor
exemption; vim/nano/ed/TextEdit writes alert). Removed lists `editor_names` and
`vim_script_arg_regexes`; the four round-2 vim argument/TTY fixtures were dropped and the
former vim/nano benign lookalikes are now match scenarios.

## Round 4 changes (8 Nov 2026)

Bumped to 1.3.0: `credential_access_osascript_password_prompt_untrusted_origin` and its
exact complement `credential_access_osascript_password_prompt`: `untrusted_prompt_origin`
also includes `ps.ancestors_untrusted = true`. Fixtures: the reviewer's three SEC-R4
scenarios (critical match / high nomatch) and a Terminal -> login -> zsh -> osascript
prompt with every ancestor trusted (high match / critical nomatch).

## Round 5 changes (8 Nov 2026, owner decisions)

Bumped to 1.4.0: `credential_access_osascript_password_prompt_untrusted_origin` and its
exact complement `credential_access_osascript_password_prompt`: new macro
`launchd_parent` in `untrusted_prompt_origin`, so a credential prompt whose parent is
launchd (a LaunchAgent or LaunchDaemon start, `original_ppid` 1, or no `original_ppid`
reported) is critical and alert-only (the kill target, launchd, is always refused).
Fixtures: the two launchd-parented prompts that were high matches / critical nomatches
moved to critical match / high nomatch, plus a new JXA LaunchAgent pair. The Terminal ->
login -> zsh -> osascript prompt stays high (match there, nomatch on the critical rule).

## v0.2 active response (9 Nov 2026)

Bumped: `execution_untrusted_binary_dropped_and_run_from_temp` 1.2.0 (`quarantine_file`,
target process); `credential_access_osascript_password_prompt_untrusted_origin` 1.5.0
(`suspend` then `kill`, both on the parent); `defense_impairment_quarantine_attribute_removed`
1.1.0 and `persistence_launch_agent_plist` / `persistence_launch_daemon_plist` 1.2.0
(they now exclude the untrusted cases, which moved to the new companion rules). New rules 45
and 46 with macros `untrusted_quarantine_remover` (the remover has no verified identity, or
is an Apple tool whose direct parent has none; seeded terminal apps make
`ps.ancestors_untrusted` unsuitable here) and `untrusted_launch_item_writer` (no verified
identity, Homebrew service plists excepted). Fixtures moved with the cases: the ad-hoc
loader and the unknown-parent `xattr` are companion matches; a user's `xattr -d` under a
platform zsh stays on the medium rule; forged and unreported Team IDs and unsigned writers
of launch plists are companion matches; `cp`, Developer ID vendors and
`homebrew.mxcl.redis.plist` are companion nomatches.

Owner decision of 9 Nov 2026 (R1-4): macro `untrusted_launch_item_writer` also covers an Apple
tool (`ps.is_platform = true`) with an untrusted or unknown parent or `ps.ancestors_untrusted`.
The ART `sudo cp` fixtures now carry their trusted parent (sudo) and the `installd` fixture
its parent launchd, so they stay on the alert-only rules; new companion matches: a dropper
writing with `/bin/cp`, and `sh -c cp` under a dropper ancestor; new companion nomatch: `cp`
under Terminal -> zsh with a trusted chain.
