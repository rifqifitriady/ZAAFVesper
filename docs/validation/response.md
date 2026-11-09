# Live validation: response actions

v0.3 workstream D. The response actions ran **for real, as root (an elevated administrator on Windows), on throw-away GitHub Actions runners**: real signals, the real kernel identity checks, the real quarantine vault, `/bin/launchctl`, `/sbin/pfctl`, and the real `zaafvesper quarantine` and `zaafvesper isolation` commands. No stubs.

**Validated on a GitHub runner is not validated on your Mac.** The runners are virtual machines with a fresh image, pf disabled at start, and no Endpoint Security client. Your Mac's pf configuration, MDM profiles, logged-in users and installed software can change what happens.

- Workflow: [`.github/workflows/live-response.yml`](../../.github/workflows/live-response.yml) (manual, or a push to a `validate/**` branch).
- Evidence run: [run 42599275323](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323), commit `764760f`, 9 Nov 2026. All three jobs passed. Each job's summary shows the table, and the artifacts `response-macos`, `response-linux` and `response-windows` hold the JSON results and the full log of every decision. The code since that commit differs only in this document.
- Earlier runs:
  - [Run 42574128112](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574128112): every action behaved the same way. One case was marked failed because of a bug in the harness's own check, not in the product: it read `pfctl`'s stderr notice "No ALTQ support in kernel" as rules left in the anchor. The run also left out the "sensor's own process" case on Windows.
  - [Run 42574446132](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574446132): the same results with the harness check fixed.
  - [Run 42575482840](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840): the same results after the security-review changes to the harness (below) and with a connectivity check.

  The evidence run adds the engineering judge's points: refused targets are checked to be still present, every case records a result, the runner's own addresses are offered to the never-block check, and the vault is cleaned.

## How it works

`zaafvesper validate-response` is a validation harness compiled into the real binary only with the build tag `zaafvesper_validate`. The workflow builds with that tag; release and package builds do not contain the harness at all. It is not in the usage text, and it refuses to run unless all of these hold:
- `ZAAFVESPER_VALIDATE_RESPONSE=throwaway-runner` (set only by the workflow);
- a GitHub-hosted runner (`GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`);
- root, or an elevated administrator;
- no installed ZAAFVesper and no ZAAFVesper state on the machine. It drives the real responder of `pkg/response` and then checks the system state itself:
- the process is gone or stopped (`kern.proc` on macOS, `/proc/<pid>/stat` on Linux, process exit on Windows);
- the file has moved, or the attribute is present;
- `launchctl print` no longer finds the job;
- the pf table holds the address, and a TCP connection to it is blocked.

The responder's log line alone is never taken as proof.

What the harness sets up itself, and what that means for the results:
- **Events are built from the kernel, not from an event source.** No eslogger or Sysmon runs here (workstreams B and C test those). Each test event takes the process identity that the kernel reports for a process the harness started: the kernel unique id or start stamp, the start time, the executable and the code-signing flags. The responder's checks then run exactly as in production.
- **The process-table binding is out of scope here.** On Windows the Sysmon `ProcessGuid` binding is done by the Sysmon source and is not exercised. The creation-time check it feeds is exercised.
- **Acting cases touch only targets the harness created.** Refusal probes also aim at pid 1 (System, pid 4, on Windows), the harness's own process and `/usr/bin/true`. These must be refused before anything changes, and the harness checks afterwards that the process is still present or the file still exists. The created targets are:
  - its own child processes, which are copies of the binary in `sleeper` mode, plus one `/bin/sleep`;
  - files in its own temporary folder;
  - launch items labelled `com.rifqifitriady.zaafvesper-validate.*`;
  - two addresses in pf: the loopback alias `10.254.254.2`, which the script adds and which never leaves the runner, and the documentation address `198.51.100.77`.
  The vault entries the run created are removed at the end; the harness refuses to start unless the vault is empty. The runner's own connectivity is never blocked: after the run, a step checks that api.github.com still answers HTTP 200, and in the evidence run it did.
- **Never-block set.** It is offered as peers of the isolated process: loopback, an Apple 17.0.0.0/8 address, a multicast address, the default gateway, the DNS resolvers, and every address of the runner's own interfaces except the test alias. None entered the pf table. The script's exit trap and a final `if: always()` step flush the anchor and remove the alias even when a step fails. The harness also cleans up after a cancel or a crash.
- **Test-only settings:**
  - The response budgets are raised to 1000 so that no case is refused for budget reasons. The budgets are covered by unit tests.
  - `suspend_for` is 3 s and the isolation time-to-live 20 s, so the resume and the expiry happen within the run.
  - The loopback alias is left out of the Mac's own-address list, so that pf can be shown to block it. That is the only change to the responder's own-address input; every other address of the runner stays in the never-block set and is checked.

## Results (evidence run)

Result values: **acted** (the action happened and the system state shows it), **refused correctly** (a guard rail refused, and nothing changed), **failed**, and **not testable** (with the reason).

### macOS (`macos-latest`: image macos-26-arm64 20261102.0473.1, macOS 26.7.2 build 25G332, Apple silicon)

| Action | Case | Expected | Outcome | Result | Observed (by the harness, in the log) | Run |
|---|---|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted | pid 1908 exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true / decision: kernel unique id now 1909, event 1910 (another process) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true / decision: start time now 2026-11-09T10:14:09.107377Z, event 2026-11-09T10:14:07.107377Z (pid reused) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly | pid 1906 still present after the decision=true / decision: protected pid | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | system process (pid 1) | refuse | `refused-protected` | refused correctly | pid 1 still present after the decision=true / decision: pid <= 1 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | SIGSTOP of the test process | act | `suspended` | acted | stopped=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | automatic resume after suspend_for (3 s) | act | `resumed` | acted | running again=true / decision: no kill followed within 3s | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | suspend then kill (no resume afterwards) | act | `killed` | acted | exited=true pending resumes=0 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | kernel unique id differs | refuse | `refused-identity-mismatch` | refused correctly | stopped=false / decision: kernel unique id now 1925, event 1926 (another process) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | exec into /bin/sleep after detection (eslogger event) | act | `killed` | acted | exited=true / decision: executable now "/bin/sleep", event "$TMP/zv-subject"; process exec'd into an Apple platform binary after detection (not a platform binary at event time; kernel unique id and start time match the event) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | exec into /bin/sleep, platform flag not from eslogger | refuse | `refused-protected` | refused correctly | alive=true / decision: Apple platform binary (current image); whether it was one at detection is not known from Endpoint Security | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | Apple platform binary at detection (/bin/sleep) | refuse | `refused-protected` | refused correctly | alive=true / decision: Apple platform binary | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | file moved into /var/db/zaafvesper/quarantine | act | `quarantined` | acted | / decision: vault id 3a62d1c960ee7eb6d3249b58633670ca43f72af74a4f9c8ea23134727f6b4394 (restore: zaafvesper quarantine restore 3a62d1c960ee) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | zaafvesper quarantine list shows it | act |  | acted | id 3a62d1c960ee7eb6 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | zaafvesper quarantine restore puts it back | act |  | acted | restored 3a62d1c960ee7eb6 to $TMP/q/payload (mode 0755, owner 0:0) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | executable of a running process (target process) | act | `quarantined` | acted | file gone=true process still running=true (expected: quarantine does not stop it) / decision: vault id 7e36c0f087649a8fedf92465944b79cad6905673e5588479e56283c024e88211 (restore: zaafvesper quarantine restore 7e36c0f08764) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | /usr/bin/true (protected path) | refuse | `refused-protected-path` | refused correctly | / decision: protected path /usr/ | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | file replaced since the event | refuse | `refused-file-check` | refused correctly | / decision: file at the path is dev=16777227 ino=3058995, the event's was dev=16777227 ino=3058994 (replaced since the event) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | symbolic link | refuse | `refused-file-check` | refused correctly | / decision: open link: too many levels of symbolic links (gone, or a symbolic link) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| requarantine | quarantine attribute stripped by an untrusted process | act | `requarantined` | acted | attribute now "0001;6af19cfd;ZAAFVesper;" / decision: com.apple.quarantine set; Gatekeeper assesses the file at its next launch | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| requarantine | stripped by Apple's xattr under a trusted parent | refuse | `refused-writer-not-untrusted` | refused correctly | attribute stays absent / decision: the remover is not untrusted (a verified identity, or an Apple tool under a trusted parent) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | LaunchDaemon loaded in the system domain | act | `persistence-removed` | acted | booted out=true plist moved=true / decision: booted out system/com.rifqifitriady.zaafvesper-validate.d8706db39; plist quarantined as 1e9f1fcb5ccff092196ad0bb5e422a6c85d01fa2de93257c74bad744a01cd10a (restore: zaafvesper quarantine restore 1e... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | zaafvesper quarantine list shows it | act |  | acted | id 1e9f1fcb5ccff092 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | zaafvesper quarantine restore puts it back | act |  | acted | restored 1e9f1fcb5ccff092 to /Library/LaunchDaemons/com.rifqifitriady.zaafvesper-validate.d8706db39.plist (mode 0644, owner 0:0) the launch item com.rifqifitriady.zaafvesper-validate.d8706db39 is NOT loaded again; load it yourself if you tr... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | plist borrowing a loaded job's label: no bootout, plist quarantined | refuse | `persistence-removed` | refused correctly | real job still loaded=true / decision: label system/com.rifqifitriady.zaafvesper-validate.a83fc12d5 is loaded from /Library/LaunchDaemons/com.rifqifitriady.zaafvesper-validate.a83fc12d5.plist, not from this plist (borrowed label); not boote... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | written by /bin/cp under a trusted chain | refuse | `refused-writer-not-untrusted` | refused correctly | / decision: written by an Apple platform binary whose parent and ancestors are trusted | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | LaunchAgent loaded in gui/501 | act | `persistence-removed` | acted | booted out=true plist moved=true / decision: booted out gui/501/com.rifqifitriady.zaafvesper-validate.g8d159562; plist quarantined as c27efc71b25871d90b43a36949a5e2dd6d4221f029f6596649f1be4e838eeef0 (restore: zaafvesper quarantine restore c... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | peers blocked in pf (loopback alias, documentation address) | act | `isolated` | acted | table=[10.254.254.2 198.51.100.77] connection to the alias blocked=true / decision: blocked 10.254.254.2, 198.51.100.77 for 20s; pf blocks these addresses for the whole host, not only this process; not blocked: 17.253.144.10 (Apple's networ... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | never-block set (gateway, DNS resolvers, loopback, Apple 17.0.0.0/8, multicast) | refuse |  | refused correctly | checked [127.0.0.1 17.253.144.10 224.0.0.251 fe80::1 fe80::14d3:76fe:1fe:c147 192.168.64.5 fe80::5fee:f442:945c:87b1 fe80::8212:bbc0:5f95:8c06 fe80::a548:a4e9:da38:8bd8 fe80::ce81:b1c:bd2c:69e 192.168.64.1 192.168.64.1], blocked by mistake ... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | zaafvesper isolation list shows the address | act |  | acted | 10.254.254.2 until 2026-11-09T10:14:41Z (rule validate-isolate, pid 2030 $TMP/zv-subject) 198.51.100.77 until 2026-11-09T10:14:41Z (rule validate-isolate, pid 2030 $TMP/zv-subject) pf blocks these addresses for the whole Mac (anchor com.a... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | zaafvesper isolation release lifts the block | act |  | acted | reachable again=true released 1 address(es): [10.254.254.2] | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | time-to-live expiry (20s in this run) | act |  | acted | table now [] | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | clean shutdown flushes the anchor | act |  | acted | rules left: | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | clean shutdown releases the pf enable reference (pfctl -X) | act |  | acted | pf enabled before the run=false, after shutdown=false | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |

### Linux (`ubuntu-latest`: image ubuntu-26.04 20261101.186.1, kernel 7.0.0-1019-azure)

| Action | Case | Expected | Outcome | Result | Observed (by the harness, in the log) | Run |
|---|---|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted | pid 4249 exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true / decision: kernel unique id now 7835, event 7836 (another process) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true / decision: start time now 2026-11-09T10:13:45.35Z, event 2026-11-09T10:13:43.35Z (pid reused) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly | pid 4241 still present after the decision=true / decision: protected pid | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | system process (pid 1) | refuse | `refused-protected` | refused correctly | pid 1 still present after the decision=true / decision: pid <= 1 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | SIGSTOP of the test process | act | `suspended` | acted | stopped=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | automatic resume after suspend_for (3 s) | act | `resumed` | acted | running again=true / decision: no kill followed within 3s | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | suspend then kill (no resume afterwards) | act | `killed` | acted | exited=true pending resumes=0 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | kernel unique id differs | refuse | `refused-identity-mismatch` | refused correctly | stopped=false / decision: kernel unique id now 8385, event 8386 (another process) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| requarantine | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |

### Windows (`windows-latest`: image windows-2025-vs2026 20261103.298.1)

| Action | Case | Expected | Outcome | Result | Observed (by the harness, in the log) | Run |
|---|---|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted | pid 5468 exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true / decision: kernel unique id now 134386928608106116, event 134386928608106117 (another process) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true / decision: start time now 2026-11-09T10:14:21.8139729Z, event 2026-11-09T10:14:19.8139729Z (pid reused) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly | pid 4136 still present after the decision=true / decision: protected pid | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | system process (pid 4) | refuse | `refused-unknown-process` | refused correctly | pid 4 still present after the decision=true / decision: cannot read the process from the kernel: pid 4 is a kernel process | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| suspend | all cases |  |  | not testable: Windows has no SIGSTOP; the suspend action is refused before the responder (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| kill | Sysmon ProcessGuid binding |  |  | not testable: done by the Sysmon source (pkg/source/sysmon Binder), which does not run here; the creation-time check it feeds is exercised above (workstream B validates Sysmon) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| quarantine_file | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| requarantine | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| remove_persistence | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |
| isolate_process | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599275323) |

## Findings

- **No product bug found.** Every action acted where it should, and every guard rail exercised refused where it should, on all three platforms.
- **macOS: pf was disabled at start.**
  - The responder enabled pf with `pfctl -E`.
  - The stock `com.apple/*` anchor point evaluated `com.apple/com.rifqifitriady.zaafvesper`: a TCP connection to the blocked address failed and worked again after `isolation release`.
  - At a clean shutdown the enable reference was released (`pfctl -X`) and pf was disabled again.
- **macOS: GUI session present.** The runner has a console user (`runner`, uid 501) with a GUI session, so the LaunchAgent case ran in `gui/501`.
- **macOS: exec into a platform binary (owner decision 1B).**
  - A process that exec'd into `/bin/sleep` after detection was killed, when the event said it was not a platform binary and came from eslogger.
  - The same process was refused when the platform flag was not from eslogger.
- **macOS: `quarantine_file` with target process.** It removed the executable while the process kept running, as documented: quarantine does not stop a process.
- **Linux:** `pidfd_open` is available (kernel 7.0).

## Not covered here

- **eslogger.** Events from eslogger (workstream C: `docs/validation/macos.md`) and from Sysmon (workstream B).
- **Gatekeeper's reaction to a re-added quarantine attribute.** The attribute is shown to be present.
- **A live race between the identity check and a reused pid.** The mismatch refusals use altered identities.
- **The budgets and the retry of budget-refused actions.** Unit tests cover them, with real time.
- **Your own Mac.**
