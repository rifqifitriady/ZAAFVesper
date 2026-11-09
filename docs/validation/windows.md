# Live validation: Windows

> **Validated on a GitHub runner, not on your PC.** These results come from a throw-away
> `windows-latest` runner (image `windows-2025-vs2026`, release
> [win25-vs2026/20261103.298](https://github.com/actions/runner-images/releases/tag/win25-vs2026%2F20261103.298))
> with Sysmon and ZAAFVesper installed as `packaging/windows/README.md` describes. Your Windows
> build, Sysmon configuration and software will differ.

**Run:** <https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42576321836> (commit `d1dfe53`, workflow `.github/workflows/live-windows-linux.yml`).

## Setup on the runner

| Part | Version and pin |
|---|---|
| Sysmon | Sysmon64.exe 15.22 from `download.sysinternals.com/files/Sysmon.zip`, SHA-256 `00ecf1b4…11aa54`, Authenticode signer Microsoft Windows Publisher |
| Sysmon configuration | sysmon-modular `sysmonconfig-excludes-only.xml` from release `configs-a45dedb13a43` (MIT), SHA-256 `4c7d27bc…cd28a4` |
| ZAAFVesper | built from this commit, installed in `C:\Program Files\ZAAFVesper`, run as the `ZAAFVesper` Windows service (LocalSystem) with `--output-dir C:\ProgramData\ZAAFVesper\logs`, exactly as the install notes say. The ownership and ACL checks, the Sysmon provenance check and the service start all passed. |
| Tests | Atomic Red Team at commit `a0e3f9bc…`, each YAML file hash-checked (`scripts/ci/b/atomics.sha256`), run by `scripts/ci/b/artrun` from `scripts/ci/b/windows-plan.json` |

**How tests are counted.**
- "atomic" tests run the Atomic Red Team test's own command, with its default inputs. No prerequisites are fetched.
- "inline" tests are documented local equivalents, used where the Atomic test needs a download or would act on something that must not be touched. Each one's note says what it does instead.
- A rule counts as fired for a test only when its alert's event time falls inside that test's time window.
- Everything acts on the runner itself or on `127.0.0.1`.

20 rules for windows: **16 fired**, **0 fired for some tests only**, **0 did not fire**, **4 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Boot Configuration Tampering Via Bcdedit.EXE<br>`rules/sigma/windows/proc_creation_win_bcdedit_boot_conf_tamper.yml` | fired | inline-bcdedit: fired | C:\Windows\System32\bcdedit.exe (pid 4564, parent C:\Windows\system32\cmd.exe) ran: bcdedit.exe  /set {00000000-0000-0000-0000-000000000000} recoveryenabled No (Sigma rule by E.M. Anhaus (originally from Atomic Blue Dete… |
| Bypass UAC Using Event Viewer<br>`rules/sigma/windows/registry_set_bypass_uac_using_eventviewer.yml` | fired | inline-eventviewer-uac: fired | C:\Windows\system32\reg.exe (pid 9588) matched on RegistrySetValue (Sigma rule by frack113) |
| CobaltStrike Named Pipe<br>`rules/sigma/windows/pipe_created_hktl_cobaltstrike.yml` | fired | inline-named-pipe: fired | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (pid 8668) matched on PipeCreate (Sigma rule by Florian Roth (Nextron Systems), Wojciech Lesicki) |
| HackTool - Mimikatz Execution<br>`rules/sigma/windows/proc_creation_win_hktl_mimikatz_command_line.yml` | fired | inline-mimikatz-cmdline: fired | C:\Windows\System32\cmd.exe (pid 8252, parent C:\Windows\system32\cmd.exe) ran: cmd.exe  /c "echo privilege::debug sekurlsa::logonpasswords" (Sigma rule by Teymur Kheirkhabarov, oscd.community, David ANDRE (additional ke… |
| LSASS Process Memory Dump Files<br>`rules/sigma/windows/file_event_win_lsass_default_dump_file_names.yml` | fired | inline-lsass-dump-name: fired | C:\Windows\system32\cmd.exe (pid 4888) wrote C:\Windows\Temp\lsass.dmp (Sigma rule by Florian Roth (Nextron Systems)) |
| Potential Credential Dumping Via LSASS SilentProcessExit Technique<br>`rules/sigma/windows/registry_event_silentprocessexit_lsass.yml` | fired | inline-silentprocessexit: fired | C:\Windows\system32\reg.exe (pid 8880) matched on RegistrySetValue (Sigma rule by Florian Roth (Nextron Systems)) |
| PowerShell started with an encoded command<br>`rules/windows/execution_powershell_encoded_command.yml` | fired | inline-encoded-powershell: fired | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (pid 10080, parent C:\Windows\system32\cmd.exe) ran an encoded command: powershell.exe  -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB6AGEAYQBmAHY… |
| Process Memory Dump Via Comsvcs.DLL<br>`rules/sigma/windows/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | fired | inline-comsvcs-minidump: fired | C:\Windows\System32\rundll32.exe (pid 6768, parent C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe) ran: "C:\Windows\system32\rundll32.exe" C:\Windows\System32\comsvcs.dll MiniDump 7984 C:\Users\RUNNER~1\AppDat… |
| Registry Run key value set<br>`rules/windows/persistence_registry_run_key.yml` | fired | art-T1547.001-e55be3fd: fired, art-T1547.001-554cbd88: fired | C:\Windows\system32\reg.exe (pid 5016) set HKU\S-1-5-21-3289802278-1561746829-1498425070-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team = C:\Path\AtomicRedTeam.exe |
| Remote thread created in another process from a user-writable location<br>`rules/windows/stealth_remote_thread_into_other_process.yml` | fired | inline-remote-thread: fired | C:\Users\RUNNER~1\AppData\Local\Temp\remotethread.exe (pid 1104) created a thread in C:\Windows\System32\PING.EXE (pid 4924) at 0x00007FFCEED3F300 |
| Remotely Hosted HTA File Executed Via Mshta.EXE<br>`rules/sigma/windows/proc_creation_win_mshta_http.yml` | fired | inline-mshta-http: fired | C:\Windows\System32\mshta.exe (pid 1328, parent C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe) ran: "C:\Windows\system32\mshta.exe" http://127.0.0.1:9/zaafvesper-validation.hta  (Sigma rule by Nasreddine Benc… |
| Shadow Copies Deletion Using Operating Systems Utilities<br>`rules/sigma/windows/proc_creation_win_susp_shadow_copies_deletion.yml` | fired | art-T1490-43819286: fired, art-T1490-6a3ff8dd: not run | art-T1490-6a3ff8dd: wmic.exe is not on this runner image; C:\Windows\System32\vssadmin.exe (pid 1896, parent C:\Windows\system32\cmd.exe) ran: vssadmin.exe  delete shadows /all /quiet (Sigma rule by Florian Roth (Nextron… |
| Suspicious Eventlog Clearing or Configuration Change Activity<br>`rules/sigma/windows/proc_creation_win_susp_eventlog_clear.yml` | fired | inline-wevtutil: fired | C:\Windows\System32\wevtutil.exe (pid 3060, parent C:\Windows\system32\cmd.exe) ran: wevtutil.exe  cl ZAAFVesper-Validation-NoSuchLog (Sigma rule by Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shra… |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE<br>`rules/sigma/windows/proc_creation_win_certutil_download_direct_ip.yml` | fired | inline-certutil: fired | C:\Windows\System32\certutil.exe (pid 10008, parent C:\Windows\system32\cmd.exe) ran: certutil.exe  -urlcache -split -f http://127.0.0.1:9/zaafvesper-validation.exe C:\Users\RUNNER~1\AppData\Local\Temp\zaafvesper-validat… |
| Volume shadow copies deleted or recovery disabled<br>`rules/windows/impact_shadow_copy_deletion.yml` | fired | art-T1490-43819286: fired, art-T1490-6a3ff8dd: not run, inline-bcdedit: fired | art-T1490-6a3ff8dd: wmic.exe is not on this runner image; C:\Windows\System32\vssadmin.exe (pid 1896, parent C:\Windows\system32\cmd.exe) inhibits recovery: vssadmin.exe  delete shadows /all /quiet |
| WMI event subscription persistence<br>`rules/windows/persistence_wmi_event_subscription.yml` | fired | art-T1546.003-3c64f177: fired | WMI WmiConsumerEvent by runnervmm7ud1\runneradmin:  "AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example"  "C:\\Windows\\System32\\notepad.exe" <none> |
| Driver Load From A Temporary Directory<br>`rules/sigma/windows/driver_load_win_susp_temp_use.yml` | not tested |  | Needs loading a kernel driver from a Temp folder. Not run. |
| LSASS process memory opened for reading<br>`rules/windows/credential_access_lsass_memory_access.yml` | not tested |  | Would read the runner's real LSASS memory (credentials). Not run. |
| Lsass Memory Dump via Comsvcs DLL<br>`rules/sigma/windows/proc_access_win_lsass_dump_comsvcs_dll.yml` | not tested |  | Would dump the runner's real LSASS memory (credentials). Not run. |
| Password Dumper Remote Thread in LSASS<br>`rules/sigma/windows/create_remote_thread_win_susp_password_dumper_lsass.yml` | not tested |  | Would inject a thread into the runner's LSASS. Not run. |

## Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| art-T1547.001-e55be3fd Reg Key Run | atomic | 0 |  |
| art-T1547.001-554cbd88 Reg Key RunOnce | atomic | 0 |  |
| art-T1490-43819286 Windows - Delete Volume Shadow Copies | atomic | 1 | The runner has no shadow copies, so nothing is deleted. Prerequisites not fetched: Create volume shadow copy of C:\ . This prereq command only works on Windows Server or Windows 8. Error: exit status 1 |
| art-T1490-6a3ff8dd  | atomic | 0 | Needs wmic.exe, which newer Windows images no longer ship. Not run: wmic.exe is not on this runner image |
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

## What the live runs found and fixed

1. **Run key rule missed RunOnceEx.** Atomic T1547.001 "Reg Key RunOnce" (`554cbd88`) writes
   `HKLM\...\CurrentVersion\RunOnceEx\0001\Depend`, which "Registry Run key value set" did not cover.
   The rule now includes `RunOnceEx` (version 1.1.0, with a fixture of the live event shape). Run 4 shows both Run key tests firing.
2. **The documented Windows install works as written.** The service starts under LocalSystem. The ACL checks accept
   `C:\Program Files\ZAAFVesper` and the protected `C:\ProgramData\ZAAFVesper`. Every Sysmon event passed the
   provenance check (`untrusted_events=0`, no record gaps).
3. **Kill identity.** Process identities were bound for processes still alive when their create event was read (`identity_bound` in the service log). Short-lived test commands had exited by then, so their identity could not be bound; the kill response refuses those, which is the designed fail-closed behaviour. Kills themselves are validated by workstream D.

## Not tested, and why

- The two LSASS memory rules and "Password Dumper Remote Thread in LSASS" would read or inject into the runner's real LSASS, so they were not run.
- "Driver Load From A Temporary Directory" needs a kernel driver loaded from a Temp folder, so it was not run.
- The `wmic` variant of T1490 is not run because the runner image has no `wmic.exe`. The rule fired through the `vssadmin` test.

## Re-run

Actions → `live-windows-linux` → *Run workflow*, or push to a `validate/**` branch. The job summary carries the table above, and the `validation-windows` artifact holds the alerts, the service log and per-test results.
