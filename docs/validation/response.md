# Live validation: response actions

v0.3 workstream D. The response actions ran **for real, as root (an elevated administrator on Windows), on throw-away GitHub Actions runners**: real signals, the real kernel identity checks, the real quarantine vault, `/bin/launchctl`, `/sbin/pfctl`, and the real `zaafvesper quarantine` and `zaafvesper isolation` commands. No stubs.

**Validated on a GitHub runner is not validated on your Mac.** The runners are virtual machines with a fresh image, pf disabled at start, and no Endpoint Security client. Your Mac's pf configuration, MDM profiles, logged-in users and installed software can change what happens.

- Workflow: [`.github/workflows/live-response.yml`](../../.github/workflows/live-response.yml) (manual, or a push to a `validate/**` branch).
- Evidence run: [run 42575482840](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840), commit `ab570af`, 9 Nov 2026. All three jobs passed. Each job's summary shows the table, and the artifacts `response-macos`, `response-linux` and `response-windows` hold the JSON results and the full log of every decision. The code since that commit differs only in this document.
- Earlier runs:
  - [Run 42574128112](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574128112): every action behaved the same way. One case was marked failed because of a bug in the harness's own check, not in the product: it read `pfctl`'s stderr notice "No ALTQ support in kernel" as rules left in the anchor. The run also left out the "sensor's own process" case on Windows.
  - [Run 42574446132](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574446132): the same results with the harness check fixed.

  The evidence run adds the security-review changes to the harness (below) and a connectivity check.

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
- **Only targets the harness created:**
  - its own child processes, which are copies of the binary in `sleeper` mode, plus one `/bin/sleep`;
  - files in its own temporary folder;
  - launch items labelled `com.rifqifitriady.zaafvesper-validate.*`;
  - two addresses in pf: the loopback alias `10.254.254.2`, which the script adds and which never leaves the runner, and the documentation address `198.51.100.77`.
  The runner's own connectivity is never blocked: after the run, a step checks that api.github.com still answers HTTP 200, and in the evidence run it did. The script's exit trap and a final `if: always()` step flush the anchor and remove the alias even when a step fails. The harness also cleans up after a cancel or a crash.
- **Test-only settings:**
  - The response budgets are raised to 1000 so that no case is refused for budget reasons. The budgets are covered by unit tests.
  - `suspend_for` is 3 s and the isolation time-to-live 20 s, so the resume and the expiry happen within the run.
  - The loopback alias is left out of the Mac's own-address list, so that pf can be shown to block it. Every other address is the real never-block set.

## Results (evidence run)

Result values: **acted** (the action happened and the system state shows it), **refused correctly** (a guard rail refused, and nothing changed), **failed**, and **not testable** (with the reason).

### macOS (`macos-latest`: image macos-26-arm64 20261102.0473.1, macOS 26.7.2 build 25G332, Apple silicon)

| Action | Case | Expected | Outcome | Result | Observed | Run |
|---|---|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted | pid 3523 exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly | the sensor kept running; decision: protected pid | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | system process (pid 1) | refuse | `refused-protected` | refused correctly | launchd / init still running; decision: pid <= 1 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | SIGSTOP of the test process | act | `suspended` | acted | stopped=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | automatic resume after suspend_for (3 s) | act | `resumed` | acted | running again=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | suspend then kill (no resume afterwards) | act | `killed` | acted | exited=true pending resumes=0 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | kernel unique id differs | refuse | `refused-identity-mismatch` | refused correctly | stopped=false | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | exec into /bin/sleep after detection (eslogger event) | act | `killed` | acted | exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | exec into /bin/sleep, platform flag not from eslogger | refuse | `refused-protected` | refused correctly | alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | Apple platform binary at detection (/bin/sleep) | refuse | `refused-protected` | refused correctly | alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | file moved into /var/db/zaafvesper/quarantine | act | `quarantined` | acted | decision: vault id 14e32d50a872fd31ca0626c6b032588940776ffea79fc4cc49e2814b759a5815 (restore: zaafvesper quarantine restore 14e32d50a872) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | zaafvesper quarantine list shows it | act |  | acted | id 14e32d50a872fd31 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | zaafvesper quarantine restore puts it back | act |  | acted | restored 14e32d50a872fd31 to <tmp>/q/payload (mode 0755, owner 0:0) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | executable of a running process (target process) | act | `quarantined` | acted | file gone=true process still running=true (expected: quarantine does not stop it) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | /usr/bin/true (protected path) | refuse | `refused-protected-path` | refused correctly | decision: protected path /usr/ | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | file replaced since the event | refuse | `refused-file-check` | refused correctly | decision: file at the path is dev=16777230 ino=3062087, the event's was dev=16777230 ino=3062086 (replaced since the event) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | symbolic link | refuse | `refused-file-check` | refused correctly | decision: open link: too many levels of symbolic links (gone, or a symbolic link) | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| requarantine | quarantine attribute stripped by an untrusted process | act | `requarantined` | acted | attribute now "0001;6af16d55;ZAAFVesper;" | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| requarantine | stripped by Apple's xattr under a trusted parent | refuse | `refused-writer-not-untrusted` | refused correctly | attribute stays absent | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | LaunchDaemon loaded in the system domain | act | `persistence-removed` | acted | booted out=true plist moved=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | zaafvesper quarantine list shows it | act |  | acted | id 5b21c15215cc006f | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | zaafvesper quarantine restore puts it back | act |  | acted | restored 5b21c15215cc006f to /Library/LaunchDaemons/com.rifqifitriady.zaafvesper-validate.d4943332e.plist (mode 0644, owner 0:0)
the launch item com.rifqifitriady.zaafvesper-validate.d4943332e is NOT loaded again; load i... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | plist borrowing a loaded job's label: no bootout, plist quarantined | refuse | `persistence-removed` | refused correctly | real job still loaded=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | written by /bin/cp under a trusted chain | refuse | `refused-writer-not-untrusted` | refused correctly | decision: written by an Apple platform binary whose parent and ancestors are trusted | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | LaunchAgent loaded in gui/501 | act | `persistence-removed` | acted | booted out=true plist moved=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | peers blocked in pf (loopback alias, documentation address) | act | `isolated` | acted | table=[10.254.254.2 198.51.100.77] connection to the alias blocked=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | never-block set (gateway, DNS resolvers, loopback, Apple 17.0.0.0/8, multicast) | refuse |  | refused correctly | checked [127.0.0.1 17.253.144.10 224.0.0.251 192.168.64.1 192.168.64.1], blocked by mistake [] | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | zaafvesper isolation list shows the address | act |  | acted | 10.254.254.2  until 2026-11-09T06:51:22Z  (rule validate-isolate, pid 3940 <tmp>/zv-subject)
198.51.100.77  until 2026-11-09T06:51:22Z  (rule validate-isolate, pid 3940 <tmp>/zv-subject)
pf blocks these addresses for the... | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | zaafvesper isolation release lifts the block | act |  | acted | reachable again=true released 1 address(es): [10.254.254.2] | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | time-to-live expiry (20s in this run) | act |  | acted | table now [] | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | clean shutdown flushes the anchor | act |  | acted | rules left: | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | clean shutdown releases the pf enable reference (pfctl -X) | act |  | acted | pf enabled before the run=false, after shutdown=false | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |

### Linux (`ubuntu-latest`: image ubuntu-26.04 20261101.186.1, kernel 7.0.0-1019-azure)

| Action | Case | Expected | Outcome | Result | Observed | Run |
|---|---|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted | pid 4037 exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly | the sensor kept running; decision: protected pid | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | system process (pid 1) | refuse | `refused-protected` | refused correctly | launchd / init still running; decision: pid <= 1 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | SIGSTOP of the test process | act | `suspended` | acted | stopped=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | automatic resume after suspend_for (3 s) | act | `resumed` | acted | running again=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | suspend then kill (no resume afterwards) | act | `killed` | acted | exited=true pending resumes=0 | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | kernel unique id differs | refuse | `refused-identity-mismatch` | refused correctly | stopped=false | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| requarantine | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |

### Windows (`windows-latest`: image windows-2025-vs2026 20261103.298.1)

| Action | Case | Expected | Outcome | Result | Observed | Run |
|---|---|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted | pid 5976 exited=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly | process still alive=true | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly | the sensor kept running; decision: protected pid | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | system process (pid 4) | refuse | `refused-unknown-process` | refused correctly | System still running; decision: cannot read the process from the kernel: pid 4 is a kernel process | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| suspend | all cases |  |  | not testable: Windows has no SIGSTOP; the suspend action is refused before the responder (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| kill | Sysmon ProcessGuid binding |  |  | not testable: done by the Sysmon source (pkg/source/sysmon Binder), which does not run here; the creation-time check it feeds is exercised above (workstream B validates Sysmon) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| quarantine_file | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| requarantine | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| remove_persistence | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |
| isolate_process | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |  | [run](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575482840) |

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
