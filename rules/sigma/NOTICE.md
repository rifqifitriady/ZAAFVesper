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

**Changes made.** The detection logic is unchanged. Where an Atomic Red Team test exercises a rule, its GUID is added to `tests.atomic` from a curated map (`pkg/sigma/testdata/atomics-<platform>.yml`, `--atomics`). The rule format is translated:
Sigma fields become ZAAFVesper fields through `pkg/sigmamap`, the log source becomes an
`evt.name` constraint and `platforms: [macos]`, the level becomes the severity, and the
ATT&CK tags become `technique.id` and `tactic.id` labels.

**The originals** are kept unchanged in `pkg/sigma/testdata/sigmahq/rules/macos/`. A test
converts them again and fails if the files here differ. To regenerate:

    zaafvesper sigma convert pkg/sigma/testdata/sigmahq -o rules/sigma/macos --force \
      --atomics pkg/sigma/testdata/atomics-macos.yml

| Rule | Original file (SigmaHQ) | Author |
|---|---|---|
| Creation Of A Local User Account | `rules/macos/process_creation/proc_creation_macos_create_account.yml` | Alejandro Ortuno, oscd.community |
| System Integrity Protection (SIP) Disabled | `rules/macos/process_creation/proc_creation_macos_csrutil_disable.yml` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| User Added To Admin Group Via Dscl | `rules/macos/process_creation/proc_creation_macos_dscl_add_user_to_admin_group.yml` | Sohan G (D4rkCiph3r) |
| User Added To Admin Group Via DseditGroup | `rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml` | Sohan G (D4rkCiph3r) |
| Root Account Enable Via Dsenableroot | `rules/macos/process_creation/proc_creation_macos_dsenableroot_enable_root_account.yml` | Sohan G (D4rkCiph3r) |
| JXA In-memory Execution Via OSAScript | `rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml` | Sohan G (D4rkCiph3r) |
| MacOS Network Service Scanning | `rules/macos/process_creation/proc_creation_macos_network_service_scanning.yml` | Alejandro Ortuno, oscd.community |
| Suspicious Microsoft Office Child Process - MacOS | `rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml` | Sohan G (D4rkCiph3r) |
| OSACompile Run-Only Execution | `rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.yml` | Sohan G (D4rkCiph3r) |
| Potential Persistence Via PlistBuddy | `rules/macos/process_creation/proc_creation_macos_persistence_via_plistbuddy.yml` | Sohan G (D4rkCiph3r) |
| Split A File Into Pieces | `rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml` | Igor Fits, Mikhail Larin, oscd.community |
| Potential Discovery Activity Using Find - MacOS | `rules/macos/process_creation/proc_creation_macos_susp_find_execution.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Suspicious History File Operations | `rules/macos/process_creation/proc_creation_macos_susp_histfile_operations.yml` | Mikhail Larin, oscd.community |
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

    zaafvesper sigma convert pkg/sigma/testdata/sigmahq-windows -o rules/sigma/windows --force \
      --atomics pkg/sigma/testdata/atomics-windows.yml
    zaafvesper sigma convert pkg/sigma/testdata/sigmahq-linux -o rules/sigma/linux --force \
      --atomics pkg/sigma/testdata/atomics-linux.yml

The fixtures in `<platform>/testdata/` are hand-written (the converter does not
generate them): at least one match and two benign lookalikes per rule.

**How they were chosen.** Status stable or test (5 stable, 39 test among the shipped
44), only Sigma fields that the Sysmon decoder fills on that platform, and a spread over
event types (process creation, process access, remote thread, named pipe,
registry, driver load, file creation, network connection). The first selection (v0.3,
14 Windows and 11 Linux rules) took level high or critical only. The v0.4 additions
(14 Windows and 5 Linux rules) also took medium rules for techniques the set did not
cover. Shipped today: 28 Windows rules (3 critical, 16 high, 9 medium) and 16 Linux rules
(1 critical, 10 high, 5 medium); there are no low rules. The count of rules that convert
at all (about 1,800 Windows and 130 Linux) is from the v0.3 selection run and was not
repeated for v0.4.

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
- Low rules, and medium rules other than the 14 shipped ones (nine Windows, five Linux,
  taken for techniques the high and critical rules did not cover), to keep false
  positives low until the adapters are validated on real hosts.

**Known weaknesses kept from SigmaHQ.** The converted rules keep SigmaHQ's logic
exactly (they must equal the converter's output), including seven exclusions that test
text the attacker controls. Each one is a way to make the rule stay silent for an attack
it is meant to catch. What an operator can do about all of them is in the paragraph after
the list.
- "Suspicious File Downloaded From Direct IP Via Certutil.EXE" excludes any command
  line containing `://7-`, so adding a dummy argument such as `"://7-"` silences it.
- "Linux Webshell Indicators" excludes children of `node` whose command line contains
  `ip neigh show`, so a webshell behind a Node.js server that appends that text to its
  command (for example `cat /etc/shadow "ip neigh show"`) is not reported.
- "WMIC Remote Command Execution" (`wmic /node:` against another host) excludes any
  command line that contains `localhost` or `127.0.0.1` anywhere, not only as the node.
  `wmic /node:10.0.0.5 process call create "cmd /c payload.exe & rem localhost"` is
  silent.
- "Disable Or Stop Services" (`systemctl`, `service`, `chkconfig`) excludes command lines
  that contain `--no-reload disable snap-snapd-` or ` stop snap-snapd-`, and command lines
  that end in `snap.amazon-ssm-agent.amazon-ssm-agent.service`. `systemctl` takes several
  units, so `systemctl stop snap-snapd-x.service auditd.service` stops the audit daemon
  and is silent. It also excludes any `systemctl` whose parent command line contains
  `/dpkg/info/ubuntu-pro-client.prerm upgrade`, or `tmp.ci/preinst upgrade` when the
  command also has ` stop ` and `ssh.`: a script saved as
  `/tmp/dpkg/info/ubuntu-pro-client.prerm` and started with the argument `upgrade` runs
  any `systemctl stop` or `disable` without an alert.
- "MacOS Network Service Scanning" (`nc`, `netcat`) excludes any command line with an
  `-l` flag or `--listen`, to leave out listeners. The test is on the text, not on `nc`'s
  mode. Checked on macOS 26: `nc -vz -w1 127.0.0.1 18080 -- --listen` still connects
  (the extra argument after `--` is ignored) and is silent. `nmap` and `telnet` are not
  affected.
- "Potential Tampering With RDP Related Registry Keys Via Reg.EXE" excludes any `reg add`
  line that contains both `SecurityLayer` and `02` anywhere, meant for the hardening value
  `SecurityLayer = 2`. The data is not tested: `reg add \\srv02\HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp /v SecurityLayer /t REG_DWORD /d 0 /f`
  lowers the RDP security layer to its weakest setting on a remote host whose name
  contains `02`, and is silent.
- "Potentially Suspicious Rundll32 Activity" excludes any command line that contains
  `shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver` (the rule tests the text
  on the whole command line, not the image), so appending that string to a payload
  command line silences the rule for that line. It also excludes any
  `Shell32.dll,Control_RunDLL ... .cpl` child of `C:\Windows\System32\control.exe` whose
  parent command line contains `.cpl`, so a malicious `.cpl` started through
  `control.exe` is not reported; the rule does not check that the `.cpl` is a system one.

**What an operator can do.** These files are regenerated by the converter, so editing
them fails `TestShippedSigmaWindowsLinuxRegenerate`. Options, none of them a change to the
shipped rule: (1) add a hand-written companion rule in the rules directory (for example
`rules/windows/`, with its own fixtures, which `rules test` requires) that matches the
same binary and tests the specific field the attack needs rather than a substring of the
whole line: for WMIC, the value after `/node:`; for `nc`, whether `-l` is an option
before the host; for `systemctl`, the unit names rather than the line; for `reg add`,
the data after `/d`. The companion fires where the shipped rule is silenced, and both
fire on a plain attack. (2) For the two package-script parent exclusions, write the
companion on `ps.parent.exe` (the script's interpreter and its path) instead of the
parent command line.
(3) Treat a silent result from these seven rules as "not detected by this rule", not as
"clean". The hand-written rules in `rules/windows/` and `rules/linux/` do not have these
exclusions. A fix inside the converted rules needs a documented deviation from SigmaHQ
(a later change; the converter would need an option to drop an exclusion).

**ps.parent fields.** Sigma's `ParentImage` and `ParentCommandLine` map to
`ps.parent.*`, which comes from the process table. "Suspicious Java Children Processes"
and "Linux Webshell Indicators" therefore stay silent for a process whose parent the
table does not know (for example a parent that started before the sensor and was not
seeded). Sysmon's own view of the parent is kept in `evt.arg[parent_image]` for
hand-written rules.

**Known gap.** Three Linux reverse-shell rules (Perl, PHP, Python) carry only the
ATT&CK tactic tag in Sigma, so `rules validate` warns that they have no
`technique.id`.

**Left out in v0.4.** Two SigmaHQ Windows rules that convert cleanly are not shipped because their Sigma tags add the Execution tactic (TA0002) to a technique ATT&CK files under another tactic only, which `zaafvesper coverage --attack` reports: `proc_creation_win_cmstp_execution_by_creation` (T1218.003, Stealth) and `proc_creation_win_mmc_mmc20_lateral_movement` (T1021.003, Lateral Movement). Converted rules are not edited by hand, so they wait for a converter option that drops tactics their techniques do not have.

### Windows

| Rule | Original file (SigmaHQ) | Author |
|---|---|---|
| Password Dumper Remote Thread in LSASS | `rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml` | Thomas Patzke |
| Driver Load From A Temporary Directory | `rules/windows/driver_load/driver_load_win_susp_temp_use.yml` | Florian Roth (Nextron Systems) |
| Prefetch File Deleted | `rules/windows/file/file_delete/file_delete_win_delete_prefetch.yml` | Cedric MAURUGEON |
| LSASS Process Memory Dump Files | `rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml` | Florian Roth (Nextron Systems) |
| CobaltStrike Named Pipe | `rules/windows/pipe_created/pipe_created_hktl_cobaltstrike.yml` | Florian Roth (Nextron Systems), Wojciech Lesicki |
| Lsass Memory Dump via Comsvcs DLL | `rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml` | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| Boot Configuration Tampering Via Bcdedit.EXE | `rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml` | E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community |
| File Download Via Bitsadmin | `rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml` | Michael Haag, FPT.EagleEye |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Findstr GPP Passwords | `rules/windows/process_creation/proc_creation_win_findstr_gpp_passwords.yml` | frack113 |
| HackTool - WinRM Access Via Evil-WinRM | `rules/windows/process_creation/proc_creation_win_hktl_evil_winrm.yml` | frack113 |
| HackTool - Mimikatz Execution | `rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml` | Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton |
| HackTool - Rubeus Execution | `rules/windows/process_creation/proc_creation_win_hktl_rubeus.yml` | Florian Roth (Nextron Systems) |
| Remotely Hosted HTA File Executed Via Mshta.EXE | `rules/windows/process_creation/proc_creation_win_mshta_http.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Msxsl.EXE Execution | `rules/windows/process_creation/proc_creation_win_msxsl_execution.yml` | Timur Zinniatullin, oscd.community |
| Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) | `rules/windows/process_creation/proc_creation_win_ntdsutil_usage.yml` | Thomas Patzke |
| Enumeration for Credentials in Registry | `rules/windows/process_creation/proc_creation_win_reg_enumeration_for_credentials_in_registry.yml` | frack113 |
| Potential Tampering With RDP Related Registry Keys Via Reg.EXE | `rules/windows/process_creation/proc_creation_win_reg_rdp_keys_tamper.yml` | pH-T (Nextron Systems), @Kostastsale, TheDFIRReport |
| Suspicious Regsvr32 Execution From Remote Share | `rules/windows/process_creation/proc_creation_win_regsvr32_remote_share.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| Potentially Suspicious Rundll32 Activity | `rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml` | juju4, Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems) |
| Suspicious Eventlog Clearing or Configuration Change Activity | `rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml` | Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan Poudel (Nextron Systems) |
| Shadow Copies Deletion Using Operating Systems Utilities | `rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml` | Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades) |
| Psexec Execution | `rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution.yml` | omkar72 |
| Windows Credential Manager Access via VaultCmd | `rules/windows/process_creation/proc_creation_win_vaultcmd_list_creds.yml` | frack113 |
| WMIC Remote Command Execution | `rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml` | frack113, Nasreddine Bencherchali (Nextron Systems) |
| Potential Credential Dumping Via LSASS SilentProcessExit Technique | `rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.yml` | Florian Roth (Nextron Systems) |
| Bypass UAC Using Event Viewer | `rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.yml` | frack113 |

### Linux

| Rule | Original file (SigmaHQ) | Author |
|---|---|---|
| Linux Reverse Shell Indicator | `rules/linux/network_connection/net_connection_lnx_back_connect_shell_dev.yml` | Florian Roth (Nextron Systems) |
| Remove Immutable File Attribute | `rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Syslog Clearing or Removal Via System Utilities | `rules/linux/process_creation/proc_creation_lnx_clear_syslog.yml` | Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| Copy Passwd Or Shadow From TMP Path | `rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| Potential Linux Process Code Injection Via DD Utility | `rules/linux/process_creation/proc_creation_lnx_dd_process_injection.yml` | Joseph Kamau |
| Potential Netcat Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml` | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| Potential PHP Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml` | @d4ns4n_ |
| Python Reverse Shell Execution Via PTY And Socket Modules | `rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml` | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| Disable Or Stop Services | `rules/linux/process_creation/proc_creation_lnx_services_stop_and_disable.yml` | Nasreddine Bencherchali (Nextron Systems) |
| History File Deletion | `rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml` | Florian Roth (Nextron Systems) |
| Linux HackTool Execution | `rules/linux/process_creation/proc_creation_lnx_susp_hktl_execution.yml` | Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure]) |
| Suspicious Java Children Processes | `rules/linux/process_creation/proc_creation_lnx_susp_java_children.yml` | Nasreddine Bencherchali (Nextron Systems) |
| Touch Suspicious Service File | `rules/linux/process_creation/proc_creation_lnx_touch_susp.yml` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| User Has Been Deleted Via Userdel | `rules/linux/process_creation/proc_creation_lnx_userdel.yml` | Tuan Le (NCSGroup) |
| Linux Webshell Indicators | `rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml` | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |

THE RULES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND (see the license).
