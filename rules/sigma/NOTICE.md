# Converted SigmaHQ rules: notice

The rules in `rules/sigma/macos/` (and, below, `rules/sigma/windows/` and
`rules/sigma/linux/`) are converted from Sigma rules published by the
SigmaHQ project, https://github.com/SigmaHQ/sigma, at commit
`53b90df66c5b6d1b9be6ba9289c56fe49dd74a73` (7 Nov 2026). They were converted with
`zaafvesper sigma convert` and are not edited by hand.

**License.** These rules are licensed under the Detection Rule License (DRL) 1.1,
https://github.com/SigmaHQ/Detection-Rule-License. The full text is in
[`LICENSE.Detection.Rules.md`](LICENSE.Detection.Rules.md). The rest of ZAAFVesper is
Apache-2.0; the DRL applies to these rule files only.

**Attribution, as DRL 1.1 requires.**

- Every converted rule keeps the Sigma author in `labels.sigma.author`, the Sigma id in
  `labels.sigma.id`, the original path in `labels.sigma.source` (relative to the
  SigmaHQ repository) and the Sigma references in `references`.
- Every alert from these rules carries the author twice: in the alert text
  ("Sigma rule by ...") and in the `sigma.author` label of the alert.

**Changes made.** The detection logic is unchanged. The rule format is translated:
Sigma fields become ZAAFVesper fields through `pkg/sigmamap`, the log source becomes an
`evt.name` constraint and `platforms: [macos]`, the level becomes the severity, and the
ATT&CK tags become `technique.id` and `tactic.id` labels.

**The originals** are kept unchanged in `pkg/sigma/testdata/sigmahq/rules/macos/`. A test
converts them again and fails if the files here differ. To regenerate:

    zaafvesper sigma convert pkg/sigma/testdata/sigmahq -o rules/sigma/macos --force

| Rule | Original file (SigmaHQ) | Author |
|---|---|---|
| System Integrity Protection (SIP) Disabled | `rules/macos/process_creation/proc_creation_macos_csrutil_disable.yml` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| User Added To Admin Group Via Dscl | `rules/macos/process_creation/proc_creation_macos_dscl_add_user_to_admin_group.yml` | Sohan G (D4rkCiph3r) |
| User Added To Admin Group Via DseditGroup | `rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml` | Sohan G (D4rkCiph3r) |
| Root Account Enable Via Dsenableroot | `rules/macos/process_creation/proc_creation_macos_dsenableroot_enable_root_account.yml` | Sohan G (D4rkCiph3r) |
| JXA In-memory Execution Via OSAScript | `rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml` | Sohan G (D4rkCiph3r) |
| Suspicious Microsoft Office Child Process - MacOS | `rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml` | Sohan G (D4rkCiph3r) |
| OSACompile Run-Only Execution | `rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.yml` | Sohan G (D4rkCiph3r) |
| Potential Persistence Via PlistBuddy | `rules/macos/process_creation/proc_creation_macos_persistence_via_plistbuddy.yml` | Sohan G (D4rkCiph3r) |
| Guest Account Enabled Via Sysadminctl | `rules/macos/process_creation/proc_creation_macos_sysadminctl_enable_guest_account.yml` | Sohan G (D4rkCiph3r) |
| Potential Base64 Decoded From Images | `rules/macos/process_creation/proc_creation_macos_tail_base64_decode_from_image.yml` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| Time Machine Backup Deletion Attempt Via Tmutil - MacOS | `rules/macos/process_creation/proc_creation_macos_tmutil_delete_backup.yml` | Pratinav Chandra |
| Time Machine Backup Disabled Via Tmutil - MacOS | `rules/macos/process_creation/proc_creation_macos_tmutil_disable_backup.yml` | Pratinav Chandra |

## Windows and Linux (`rules/sigma/windows/`, `rules/sigma/linux/`)

A small curated set, converted the same way from the same SigmaHQ commit
(`53b90df66c5b6d1b9be6ba9289c56fe49dd74a73`), for the Sysmon sources
(`pkg/source/sysmon`). Same license (DRL 1.1), same attribution in every rule and
alert, same "not edited by hand" rule. The originals are kept unchanged, with their
SigmaHQ paths, in `pkg/sigma/testdata/sigmahq-windows/` and
`pkg/sigma/testdata/sigmahq-linux/`; `TestShippedSigmaWindowsLinuxRegenerate`
converts them again and fails if the files here differ. To regenerate:

    zaafvesper sigma convert pkg/sigma/testdata/sigmahq-windows -o rules/sigma/windows --force
    zaafvesper sigma convert pkg/sigma/testdata/sigmahq-linux -o rules/sigma/linux --force

The fixtures in `<platform>/testdata/` are hand-written (the converter does not
generate them): at least one match and two benign lookalikes per rule.

**How they were chosen.** Status stable or test, level high or critical, only
Sigma fields that the Sysmon decoder fills on that platform, and a spread over
event types (process creation, process access, remote thread, named pipe,
registry, driver load, file creation, network connection). About 1,800 Windows and
130 Linux rules convert; 14 and 11 are shipped.

**Left out, and why.**
- Log sources the sensor does not read: PowerShell script block and module logs,
  the Security, System and Application event logs, Windows Defender, CodeIntegrity,
  auditd, syslog, sshd, cron, ClamAV. The converter skips these.
- Fields Sysmon does not fill on the platform: on Linux `OriginalFileName`, `Hashes`,
  `Company` and similar PE version fields, and `LogonId`.
- Linux rules on `DestinationHostname` (crypto-mining pools, ngrok tunnels): Sysmon
  for Linux does not resolve destination names, so they would not fire.
- Rules that are mostly long hash or name lists (vulnerable or malicious driver
  lists) or depend on one tool's file names; they belong in a later, larger import
  with live testing.
- Low and medium rules, to keep false positives low until the adapters are
  validated on real hosts.

**Known weaknesses kept from SigmaHQ.** The converted rules keep SigmaHQ's logic
exactly (they must equal the converter's output), including two exclusions that test
text the attacker controls:
- "Suspicious File Downloaded From Direct IP Via Certutil.EXE" excludes any command
  line containing `://7-`, so adding a dummy argument such as `"://7-"` silences it.
- "Linux Webshell Indicators" excludes children of `node` whose command line contains
  `ip neigh show`, so a webshell behind a Node.js server that appends that text to its
  command (for example `cat /etc/shadow "ip neigh show"`) is not reported.

The hand-written rules in `rules/windows/` and `rules/linux/` are not affected by these
exclusions. A local fix needs a documented deviation from SigmaHQ (a later change).

**ps.parent fields.** Sigma's `ParentImage` and `ParentCommandLine` map to
`ps.parent.*`, which comes from the process table. "Suspicious Java Children Processes"
and "Linux Webshell Indicators" therefore stay silent for a process whose parent the
table does not know (for example a parent that started before the sensor and was not
seeded). Sysmon's own view of the parent is kept in `evt.arg[parent_image]` for
hand-written rules.

**Known gap.** Three Linux reverse-shell rules (Perl, PHP, Python) carry only the
ATT&CK tactic tag in Sigma, so `rules validate` warns that they have no
`technique.id`.

### Windows

| Rule | Original file (SigmaHQ) | Author |
|---|---|---|
| Password Dumper Remote Thread in LSASS | `rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml` | Thomas Patzke |
| Driver Load From A Temporary Directory | `rules/windows/driver_load/driver_load_win_susp_temp_use.yml` | Florian Roth (Nextron Systems) |
| LSASS Process Memory Dump Files | `rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml` | Florian Roth (Nextron Systems) |
| CobaltStrike Named Pipe | `rules/windows/pipe_created/pipe_created_hktl_cobaltstrike.yml` | Florian Roth (Nextron Systems), Wojciech Lesicki |
| Lsass Memory Dump via Comsvcs DLL | `rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml` | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| Boot Configuration Tampering Via Bcdedit.EXE | `rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml` | E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.yml` | Nasreddine Bencherchali (Nextron Systems) |
| HackTool - Mimikatz Execution | `rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml` | Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton |
| Remotely Hosted HTA File Executed Via Mshta.EXE | `rules/windows/process_creation/proc_creation_win_mshta_http.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| Suspicious Eventlog Clearing or Configuration Change Activity | `rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml` | Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan Poudel (Nextron Systems) |
| Shadow Copies Deletion Using Operating Systems Utilities | `rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml` | Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades) |
| Potential Credential Dumping Via LSASS SilentProcessExit Technique | `rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.yml` | Florian Roth (Nextron Systems) |
| Bypass UAC Using Event Viewer | `rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.yml` | frack113 |

### Linux

| Rule | Original file (SigmaHQ) | Author |
|---|---|---|
| Linux Reverse Shell Indicator | `rules/linux/network_connection/net_connection_lnx_back_connect_shell_dev.yml` | Florian Roth (Nextron Systems) |
| Syslog Clearing or Removal Via System Utilities | `rules/linux/process_creation/proc_creation_lnx_clear_syslog.yml` | Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| Copy Passwd Or Shadow From TMP Path | `rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| Potential Netcat Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml` | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| Potential PHP Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml` | @d4ns4n_ |
| Python Reverse Shell Execution Via PTY And Socket Modules | `rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml` | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| History File Deletion | `rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml` | Florian Roth (Nextron Systems) |
| Linux HackTool Execution | `rules/linux/process_creation/proc_creation_lnx_susp_hktl_execution.yml` | Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure]) |
| Suspicious Java Children Processes | `rules/linux/process_creation/proc_creation_lnx_susp_java_children.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Linux Webshell Indicators | `rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml` | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |

THE RULES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND (see the license).
