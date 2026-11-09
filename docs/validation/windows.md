# Live validation: Windows

**In plain words:** on a fresh Windows machine run by GitHub, Sysmon and ZAAFVesper were installed exactly as our install
notes say. ZAAFVesper then watched a set of harmless attack simulations. **All 16 rules that were tested raised their
alert.** 4 rules were deliberately not tested, because testing them would mean touching the machine's real password store
(LSASS) or loading a kernel driver.

> **Validated on a GitHub runner, not on your PC.** The runner is a throw-away `windows-latest` machine (image
> `win25-vs2026`, version 20261103.298.1). Your Windows build, Sysmon configuration and software will differ.

**Words used here.**
- **Sysmon**: Microsoft's free system monitor. It records process starts, network connections, file and registry changes; ZAAFVesper reads its events.
- **Atomic Red Team**: a public library of small, documented attack simulations, one per ATT&CK technique.
- **Rule fired**: ZAAFVesper raised that rule's alert while the test that should trigger it was running.

**Run:** <https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42602354087> (commit `f1f86c5`, workflow `.github/workflows/live-windows-linux.yml`). The same results came from the earlier runs
[4](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42576321836), [5](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42576955604), [6](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42600746381) and [7](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42601419858).

## Setup on the runner

| Part | Version and pin |
|---|---|
| Sysmon | Sysmon64.exe 15.22 from `download.sysinternals.com/files/Sysmon.zip`, SHA-256 `00ecf1b4…11aa54`, Authenticode signer Microsoft Windows Publisher |
| Sysmon configuration | sysmon-modular (MIT) at commit `a45dedb1…`, `sysmonconfig-excludes-only.xml` from the release built from that commit; the tag is checked to point to that commit, and the file's SHA-256 is `4c7d27bc…cd28a4` |
| ZAAFVesper | built from this commit, installed in `C:\Program Files\ZAAFVesper`, run as the `ZAAFVesper` Windows service (LocalSystem) with `--output-dir C:\ProgramData\ZAAFVesper\logs`, exactly as `packaging/windows/README.md` says. The ownership and ACL checks, the Sysmon provenance check and the service start all passed. |
| Tests | Atomic Red Team at commit `a0e3f9bc…`, each YAML file hash-checked (`scripts/ci/b/atomics.sha256`), run by `scripts/ci/b/artrun` from `scripts/ci/b/windows-plan.json` |

**How tests are counted.**
- "atomic" tests run the Atomic Red Team test's own command with its default inputs. No prerequisites are fetched.
- "inline" tests are documented local equivalents, used where the Atomic test would download a tool, delete real data, or touch LSASS. Each one's note says what it does instead; for example, shadow copies are deleted on drive `Q:`, which does not exist.
- A rule counts as fired for a test only when its alert's event time falls inside that test's time window. The table shows both.
- The plan starts and ends with a **canary** test. If either raises no alert, the sensor was not receiving events, and the run is marked incomplete (the job is red).
- Every test acts only on the runner itself or on `127.0.0.1`.

## Results

20 rules for windows: **16 fired**, **0 fired for some tests only**, **0 did not fire**, **4 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Boot Configuration Tampering Via Bcdedit.EXE<br>`rules/sigma/windows/proc_creation_win_bcdedit_boot_conf_tamper.yml` | fired | inline-bcdedit: fired (alert 10:42:12.248, test 10:42:12.031–10:42:12.322) | C:\Windows\System32\bcdedit.exe (pid 1380, parent C:\Windows\system32\cmd.exe) ran: bcdedit.exe  /set {00000000-0000-0000-0000-000000000000} recoveryenabled No (Sigma rule by E.M. Anhaus (originally from Atomic Blue Dete… |
| Bypass UAC Using Event Viewer<br>`rules/sigma/windows/registry_set_bypass_uac_using_eventviewer.yml` | fired | inline-eventviewer-uac: fired (alert 10:42:42.413, test 10:42:42.378–10:42:42.419) | C:\Windows\system32\reg.exe (pid 2488) matched on RegistrySetValue (Sigma rule by frack113) |
| CobaltStrike Named Pipe<br>`rules/sigma/windows/pipe_created_hktl_cobaltstrike.yml` | fired | inline-named-pipe: fired (alert 10:42:36.271, test 10:42:35.962–10:42:38.296) | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (pid 6384) matched on PipeCreate (Sigma rule by Florian Roth (Nextron Systems), Wojciech Lesicki) |
| HackTool - Mimikatz Execution<br>`rules/sigma/windows/proc_creation_win_hktl_mimikatz_command_line.yml` | fired | inline-mimikatz-cmdline: fired (alert 10:42:23.011, test 10:42:22.981–10:42:23.024) | C:\Windows\System32\cmd.exe (pid 2824, parent C:\Windows\system32\cmd.exe) ran: cmd.exe  /c "echo privilege::debug sekurlsa::logonpasswords" (Sigma rule by Teymur Kheirkhabarov, oscd.community, David ANDRE (additional ke… |
| LSASS Process Memory Dump Files<br>`rules/sigma/windows/file_event_win_lsass_default_dump_file_names.yml` | fired | inline-lsass-dump-name: fired (alert 10:42:44.496, test 10:42:44.460–10:42:44.503) | C:\Windows\system32\cmd.exe (pid 2292) wrote C:\Windows\Temp\lsass.dmp (Sigma rule by Florian Roth (Nextron Systems)) |
| Potential Credential Dumping Via LSASS SilentProcessExit Technique<br>`rules/sigma/windows/registry_event_silentprocessexit_lsass.yml` | fired | inline-silentprocessexit: fired (alert 10:42:40.330, test 10:42:40.296–10:42:40.336) | C:\Windows\system32\reg.exe (pid 624) matched on RegistrySetValue (Sigma rule by Florian Roth (Nextron Systems)) |
| PowerShell started with an encoded command<br>`rules/windows/execution_powershell_encoded_command.yml` | fired | inline-encoded-powershell: fired (alert 10:42:09.744, test 10:42:09.713–10:42:10.030) | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (pid 6552, parent C:\Windows\system32\cmd.exe) ran an encoded command: powershell.exe  -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB6AGEAYQBmAHYA… |
| Process Memory Dump Via Comsvcs.DLL<br>`rules/sigma/windows/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | fired | inline-comsvcs-minidump: fired (alert 10:42:31.854, test 10:42:30.489–10:42:33.961) | C:\Windows\System32\rundll32.exe (pid 8424, parent C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe) ran: "C:\Windows\system32\rundll32.exe" C:\Windows\System32\comsvcs.dll MiniDump 4884 C:\Users\RUNNER~1\AppDat… |
| Registry Run key value set<br>`rules/windows/persistence_registry_run_key.yml` | fired | art-T1547.001-e55be3fd: fired (alert 10:40:01.306, test 10:40:01.270–10:40:01.313), art-T1547.001-554cbd88: fired (alert 10:40:03.392, test 10:40:03.360–10:40:03.398) | C:\Windows\system32\reg.exe (pid 6196) set HKU\S-1-5-21-3289802278-1561746829-1498425070-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team = C:\Path\AtomicRedTeam.exe |
| Remote thread created in another process from a user-writable location<br>`rules/windows/stealth_remote_thread_into_other_process.yml` | fired | inline-remote-thread: fired (alert 10:42:47.796, test 10:42:46.531–10:42:49.817) | C:\Users\RUNNER~1\AppData\Local\Temp\remotethread.exe (pid 8140) created a thread in C:\Windows\System32\PING.EXE (pid 8596) at 0x00007FFE06D9F300 |
| Remotely Hosted HTA File Executed Via Mshta.EXE<br>`rules/sigma/windows/proc_creation_win_mshta_http.yml` | fired | inline-mshta-http: fired (alert 10:42:25.373, test 10:42:25.025–10:42:28.487) | C:\Windows\System32\mshta.exe (pid 9012, parent C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe) ran: "C:\Windows\system32\mshta.exe" http://127.0.0.1:9/zaafvesper-validation.hta  (Sigma rule by Nasreddine Benc… |
| Shadow Copies Deletion Using Operating Systems Utilities<br>`rules/sigma/windows/proc_creation_win_susp_shadow_copies_deletion.yml` | fired | inline-vssadmin-delete: fired (alert 10:40:05.476, test 10:40:05.440–10:40:05.668), inline-wmic-shadowcopy-delete: not run | inline-wmic-shadowcopy-delete: wmic.exe is not on this runner image; C:\Windows\System32\vssadmin.exe (pid 2712, parent C:\Windows\system32\cmd.exe) ran: vssadmin.exe  delete shadows /for=Q: /quiet (Sigma rule by Florian… |
| Suspicious Eventlog Clearing or Configuration Change Activity<br>`rules/sigma/windows/proc_creation_win_susp_eventlog_clear.yml` | fired | canary-start: fired (alert 10:39:59.235, test 10:39:59.192–10:39:59.267), inline-wevtutil: fired (alert 10:42:14.353, test 10:42:14.324–10:42:14.372), canary-end: fired (alert 10:42:51.848, test 10:42:51.818–10:42:… | C:\Windows\System32\wevtutil.exe (pid 6624, parent C:\Windows\system32\cmd.exe) ran: wevtutil.exe  cl ZAAFVesper-Canary-NoSuchLog (Sigma rule by Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan … |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE<br>`rules/sigma/windows/proc_creation_win_certutil_download_direct_ip.yml` | fired | inline-certutil: fired (alert 10:42:16.423, test 10:42:16.373–10:42:20.951) | C:\Windows\System32\certutil.exe (pid 7804, parent C:\Windows\system32\cmd.exe) ran: certutil.exe  -urlcache -split -f http://127.0.0.1:9/zaafvesper-validation.exe C:\Users\RUNNER~1\AppData\Local\Temp\zaafvesper-validati… |
| Volume shadow copies deleted or recovery disabled<br>`rules/windows/impact_shadow_copy_deletion.yml` | fired | inline-vssadmin-delete: fired (alert 10:40:05.476, test 10:40:05.440–10:40:05.668), inline-wmic-shadowcopy-delete: not run, inline-bcdedit: fired (alert 10:42:12.248, test 10:42:12.031–10:42:12.322) | inline-wmic-shadowcopy-delete: wmic.exe is not on this runner image; C:\Windows\System32\vssadmin.exe (pid 2712, parent C:\Windows\system32\cmd.exe) inhibits recovery: vssadmin.exe  delete shadows /for=Q: /quiet |
| WMI event subscription persistence<br>`rules/windows/persistence_wmi_event_subscription.yml` | fired | art-T1546.003-3c64f177: fired (alert 10:40:10.274, test 10:40:07.684–10:41:07.697) | WMI WmiConsumerEvent by runnervmm7ud1\runneradmin:  "AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example"  "C:\\Windows\\System32\\notepad.exe" <none> |
| Driver Load From A Temporary Directory<br>`rules/sigma/windows/driver_load_win_susp_temp_use.yml` | not tested |  | Needs loading a kernel driver from a Temp folder. Not run. |
| LSASS process memory opened for reading<br>`rules/windows/credential_access_lsass_memory_access.yml` | not tested |  | Would read the runner's real LSASS memory (credentials). Not run. |
| Lsass Memory Dump via Comsvcs DLL<br>`rules/sigma/windows/proc_access_win_lsass_dump_comsvcs_dll.yml` | not tested |  | Would dump the runner's real LSASS memory (credentials). Not run. |
| Password Dumper Remote Thread in LSASS<br>`rules/sigma/windows/create_remote_thread_win_susp_password_dumper_lsass.yml` | not tested |  | Would inject a thread into the runner's LSASS. Not run. |

### Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| canary-start  | inline | 15007 | Canary: proves the sensor receives and evaluates events at this point of the run. Error: exit status 15007 |
| art-T1547.001-e55be3fd Reg Key Run | atomic | 0 |  |
| art-T1547.001-554cbd88 Reg Key RunOnce | atomic | 0 |  |
| inline-vssadmin-delete  | inline | 2 | Safe form of ART T1490 43819286: targets drive Q:, which does not exist, so no shadow copy can be deleted. Error: exit status 2 |
| inline-wmic-shadowcopy-delete  | inline | 0 | Safe form of ART T1490 6a3ff8dd: selects a shadow copy id that does not exist. Needs wmic.exe, which newer Windows images no longer ship. Not run: wmic.exe is not on this runner image |
| art-T1546.003-3c64f177 Persistence via WMI Event Subscription - CommandLineEventConsumer | atomic | 1 | The test's PowerShell creates the filter, consumer and binding (the rule fires) but does not exit; artrun stops it after 60 s and runs the cleanup. Error: timed out after 1m0s |
| inline-encoded-powershell  | inline | 0 | Equivalent of ART T1059.001 86a43bad: that test needs the AtomicTestHarnesses module from the PowerShell Gallery (not pinned). |
| inline-bcdedit  | inline | 1 | Targets a boot entry that does not exist, so the boot configuration is not changed; the command line is what the rules check. Error: exit status 1 |
| inline-wevtutil  | inline | 15007 | Clears a log that does not exist; no real log is cleared. Error: exit status 15007 |
| inline-certutil  | inline | 2147954429 | Points at a closed local port: nothing is downloaded. Error: exit status 0x80072efd |
| inline-mimikatz-cmdline  | inline | 0 | Only the command line is mimicked; no credential tool runs. |
| inline-mshta-http  | inline | 0 | Closed local port: nothing is loaded. |
| inline-comsvcs-minidump  | inline | 0 | Dumps a ping.exe started for the test, never LSASS. |
| inline-named-pipe  | inline | 0 |  |
| inline-silentprocessexit  | inline | 0 | The key is removed right after; LSASS is not touched. |
| inline-eventviewer-uac  | inline | 0 | Event Viewer is not started; the key is removed right after. |
| inline-lsass-dump-name  | inline | 0 | An empty file with a dump's name; no memory is dumped. |
| inline-remote-thread  | inline | 0 | scripts/ci/b/remotethread, copied to the user's Temp folder, starts a ping.exe and creates one thread in it at kernel32!ExitThread; nothing else is injected. |
| canary-end  | inline | 15007 | Canary: proves the sensor receives and evaluates events at this point of the run. Error: exit status 15007 |

## Linked Atomic tests not run as they are

| Atomic test | Why |
|---|---|
| `86a43bad-12e3-4e85-b97c-4d5cf25b95c3` | Needs the AtomicTestHarnesses module from the PowerShell Gallery (not pinned); replaced by inline-encoded-powershell. |
| `0d181431-ddf3-4826-8055-2dbf63ae848b` | Needs the AtomicTestHarnesses module from the PowerShell Gallery (not pinned); replaced by inline-encoded-powershell. |
| `0be2230c-9ab3-4ac2-8826-3199b9a0ebf8` | Dumps the runner's real LSASS with ProcDump (credentials, and a tool download). Not run. |
| `7cede33f-0acd-44ef-9774-15511300b24b` | Dumps the runner's real LSASS with ProcDump (credentials, and a tool download). Not run. |
| `2536dee2-12fb-459a-8c37-971844fa73be` | Dumps the runner's real LSASS with comsvcs.dll (credentials). Its command shape is covered by inline-comsvcs-minidump against a ping.exe. |
| `43819286-91a9-4369-90ed-d31fb4da2c01` | Deletes every shadow copy on the machine; replaced by inline-vssadmin-delete against a drive that does not exist. |
| `6a3ff8dd-f49c-4272-a658-11c2fe58bd88` | Deletes every shadow copy on the machine; replaced by inline-wmic-shadowcopy-delete against an id that does not exist. |
| `263ba6cb-ea2b-41c9-9d4e-b652dadd002c` | Deletes the machine's backup catalog (wbadmin delete catalog), which has no harmless target. Not run; the rule's vssadmin branch is tested. |

## What the live runs found and fixed

1. **The Run key rule missed RunOnceEx** (seen in [run 1](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574233249)). Atomic T1547.001 "Reg Key RunOnce" (`554cbd88`)
   writes `HKLM\...\CurrentVersion\RunOnceEx\0001\Depend`, which "Registry Run key value set" did not cover. The rule now
   includes `RunOnceEx` (version 1.1.0, with a fixture of the live event shape), and both Run key tests fire.
2. **The documented Windows install works as written.** The service starts under LocalSystem. The ACL checks accept
   `C:\Program Files\ZAAFVesper` and the protected `C:\ProgramData\ZAAFVesper`. Every Sysmon event passed the provenance
   check (`untrusted_events=0`, no record gaps).
3. **Kill identity.** Process identities are bound for processes still alive when their create event is read (`identity_bound`
   in the service log). Short-lived test commands have exited by then, and the kill response refuses those, as designed.
   Kills themselves are validated by workstream D (`docs/validation/response.md`).

## Re-run

Actions → `live-windows-linux` → *Run workflow*, or push to a `validate/**` branch. The job summary carries the table above, and
the `validation-windows` artifact holds the alerts, the service log, the raw Sysmon events and per-test results.
