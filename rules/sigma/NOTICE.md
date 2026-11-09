# Converted SigmaHQ rules: notice

The rules in `rules/sigma/macos/` are converted from Sigma rules published by the
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

THE RULES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND (see the license).
