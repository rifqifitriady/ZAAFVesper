# Live validation: response actions

v0.3 workstream D. The response actions ran **for real, as root (an elevated administrator on Windows), on throw-away GitHub Actions runners**: real signals, the real kernel identity checks, the real quarantine vault, `/bin/launchctl`, `/sbin/pfctl`, and the real `zaafvesper quarantine` and `zaafvesper isolation` commands. No stubs.

**Validated on a GitHub runner is not validated on your Mac.** The runners are virtual machines with a fresh image, pf disabled at start, and no Endpoint Security client. Your Mac's pf configuration, MDM profiles, logged-in users and installed software can change what happens.

- Workflow: [`.github/workflows/live-response.yml`](../../.github/workflows/live-response.yml) (manual, or a push to a `validate/**` branch).
- Evidence run: [run 42574446132](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574446132), commit `e024247`, 9 Nov 2026. All three jobs passed. Each job's summary shows the table, and the artifacts `response-macos`, `response-linux` and `response-windows` hold the JSON results and the full log of every decision.
- Earlier run: [run 42574128112](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574128112). Every action behaved the same way. One case was marked failed because of a bug in the harness's own check, not in the product: it read `pfctl`'s stderr notice "No ALTQ support in kernel" as rules left in the anchor. That run also left out the "sensor's own process" case on Windows. Both are fixed in the evidence run.

## How it works

`zaafvesper validate-response` is a validation harness built into the real binary. It is not in the usage text. It refuses to run unless `ZAAFVESPER_VALIDATE_RESPONSE=throwaway-runner` is set (only the workflow sets it), and it needs root or an elevated administrator. It drives the real responder of `pkg/response` and then checks the system state itself:
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
  The runner's own connectivity is never blocked. The script's exit trap and a final `if: always()` step flush the anchor and remove the alias even when a step fails.
- **Test-only settings:**
  - The response budgets are raised to 1000 so that no case is refused for budget reasons. The budgets are covered by unit tests.
  - `suspend_for` is 3 s and the isolation time-to-live 20 s, so the resume and the expiry happen within the run.
  - The loopback alias is left out of the Mac's own-address list, so that pf can be shown to block it. Every other address is the real never-block set.

## Results (evidence run)

Result values: **acted** (the action happened and the system state shows it), **refused correctly** (a guard rail refused, and nothing changed), **failed**, and **not testable** (with the reason).

### macOS (`macos-latest`: image macos-26-arm64 20261102.0473.1, macOS 26.7.2 build 25G332, Apple silicon)

| Action | Case | Expected | Outcome | Result |
|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly |
| kill | system process (pid 1) | refuse | `refused-protected` | refused correctly |
| suspend | SIGSTOP of the test process | act | `suspended` | acted |
| suspend | automatic resume after suspend_for (3 s) | act | `resumed` | acted |
| suspend | suspend then kill (no resume afterwards) | act | `killed` | acted |
| suspend | kernel unique id differs | refuse | `refused-identity-mismatch` | refused correctly |
| kill | exec into /bin/sleep after detection (eslogger event) | act | `killed` | acted |
| kill | exec into /bin/sleep, platform flag not from eslogger | refuse | `refused-protected` | refused correctly |
| kill | Apple platform binary at detection (/bin/sleep) | refuse | `refused-protected` | refused correctly |
| quarantine_file | file moved into /var/db/zaafvesper/quarantine | act | `quarantined` | acted |
| quarantine_file | zaafvesper quarantine list shows it | act |  | acted |
| quarantine_file | zaafvesper quarantine restore puts it back | act |  | acted |
| quarantine_file | executable of a running process (target process) | act | `quarantined` | acted |
| quarantine_file | /usr/bin/true (protected path) | refuse | `refused-protected-path` | refused correctly |
| quarantine_file | file replaced since the event | refuse | `refused-file-check` | refused correctly |
| quarantine_file | symbolic link | refuse | `refused-file-check` | refused correctly |
| requarantine | quarantine attribute stripped by an untrusted process | act | `requarantined` | acted |
| requarantine | stripped by Apple's xattr under a trusted parent | refuse | `refused-writer-not-untrusted` | refused correctly |
| remove_persistence | LaunchDaemon loaded in the system domain | act | `persistence-removed` | acted |
| remove_persistence | zaafvesper quarantine list shows it | act |  | acted |
| remove_persistence | zaafvesper quarantine restore puts it back | act |  | acted |
| remove_persistence | plist borrowing a loaded job's label: no bootout, plist quarantined | refuse | `persistence-removed` | refused correctly |
| remove_persistence | written by /bin/cp under a trusted chain | refuse | `refused-writer-not-untrusted` | refused correctly |
| remove_persistence | LaunchAgent loaded in gui/501 | act | `persistence-removed` | acted |
| isolate_process | peers blocked in pf (loopback alias, documentation address) | act | `isolated` | acted |
| isolate_process | never-block set (gateway, DNS resolvers, loopback, Apple 17.0.0.0/8, multicast) | refuse |  | refused correctly |
| isolate_process | zaafvesper isolation list shows the address | act |  | acted |
| isolate_process | zaafvesper isolation release lifts the block | act |  | acted |
| isolate_process | time-to-live expiry (20s in this run) | act |  | acted |
| isolate_process | clean shutdown flushes the anchor | act |  | acted |
| isolate_process | clean shutdown releases the pf enable reference (pfctl -X) | act |  | acted |

### Linux (`ubuntu-latest`: image ubuntu-26.04 20261101.186.1, kernel 7.0.0-1019-azure)

| Action | Case | Expected | Outcome | Result |
|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly |
| kill | system process (pid 1) | refuse | `refused-protected` | refused correctly |
| suspend | SIGSTOP of the test process | act | `suspended` | acted |
| suspend | automatic resume after suspend_for (3 s) | act | `resumed` | acted |
| suspend | suspend then kill (no resume afterwards) | act | `killed` | acted |
| suspend | kernel unique id differs | refuse | `refused-identity-mismatch` | refused correctly |
| quarantine_file | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |
| requarantine | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |
| remove_persistence | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |
| isolate_process | all cases |  |  | not testable: macOS only: refused-unsupported on Linux (run_linux.go supportedActions) |

### Windows (`windows-latest`: image windows-2025-vs2026 20261103.298.1)

| Action | Case | Expected | Outcome | Result |
|---|---|---|---|---|
| kill | test process, identity verified | act | `killed` | acted |
| kill | kernel unique id differs (pid reused) | refuse | `refused-identity-mismatch` | refused correctly |
| kill | start time differs | refuse | `refused-identity-mismatch` | refused correctly |
| kill | the sensor's own process | refuse | `refused-protected` | refused correctly |
| kill | system process (pid 4) | refuse | `refused-unknown-process` | refused correctly |
| suspend | all cases |  |  | not testable: Windows has no SIGSTOP; the suspend action is refused before the responder (run_windows.go supportedActions) |
| quarantine_file | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |
| requarantine | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |
| remove_persistence | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |
| isolate_process | all cases |  |  | not testable: macOS only: refused-unsupported on Windows (run_windows.go supportedActions) |

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
