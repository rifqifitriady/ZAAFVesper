# Live validation on Windows and Linux runners (v0.3 workstream B)

`.github/workflows/live-windows-linux.yml` installs Sysmon (Windows) and Sysmon for
Linux on fresh GitHub runners. It then installs ZAAFVesper as the packaging notes say,
runs the tests in `windows-plan.json` and `linux-plan.json`, and records which rules
fired. The results are in `docs/validation/`.

- **Sysmon**: Microsoft's free system monitor. It records process starts, network
  connections, file and registry changes. ZAAFVesper reads its events.
- **Atomic Red Team**: a public library of small, documented attack simulations
  (one per ATT&CK technique). Rules name the tests that exercise them.

## Files

| File | What it is |
|---|---|
| `artrun/` | Go tool: `run` executes a plan, `report` turns the sensor's alerts into the per-rule table |
| `remotethread/` | Windows helper for the remote-thread rule (one thread at `kernel32!ExitThread` in a `ping.exe` it starts) |
| `windows-plan.json`, `linux-plan.json` | the tests, the rules each should fire, the canaries, and what is deliberately not run |
| `atomics.sha256` | SHA-256 of each Atomic Red Team YAML file used |
| `windows-setup.ps1`, `linux-setup.sh` | install Sysmon and ZAAFVesper on the runner |
| `sysmon-linux.xml` | Sysmon for Linux configuration |

## Pins, and how to update one

Every download is pinned and checked before use. A changed download stops the job. It never runs silently.

| Pin | Where | Update |
|---|---|---|
| Atomic Red Team commit | workflow `ART_COMMIT` | Pick a new commit and download each listed `atomics/<T>/<T>.yaml` from it. Review the tests in the plans. Write the new hashes into `atomics.sha256`. |
| Sysmon (Windows) | workflow `SYSMON_ZIP_SHA256` | Sysinternals serves one current build at a fixed URL. When the job fails on the hash, download `Sysmon.zip`, check the Microsoft signature of `Sysmon64.exe`, and replace the hash. |
| sysmon-modular configuration | workflow `SYSMON_MODULAR_COMMIT`, `_TAG`, `SYSMON_CONFIG_SHA256` | Take a newer `configs-<commit>` release. Its tag must point to the commit you pin. Use the file's hash from that release's `SHA256SUMS`. |
| Sysmon for Linux | workflow `SYSMONFORLINUX_*`, `SYSINTERNALSEBPF_*` (one hash pair per Ubuntu release) | Use the version and `SHA256:` line from `packages.microsoft.com/ubuntu/<release>/prod/dists/<codename>/main/binary-amd64/Packages.gz`. When `ubuntu-latest` moves to a release without pins, the job stops: add that release's pair and a case in `linux-setup.sh`. |
| GitHub actions | `uses: …@<sha> # vX` | Resolve the new tag to its commit SHA. |

## Rules for the tests

- Only tests that act on the runner itself or on loopback (`127.0.0.1`, `::1`).
- Nothing that deletes data with no harmless target (shadow copies on a drive that does not exist, an event log that does not exist).
- Nothing that touches LSASS.
- Atomic tests run their own YAML command with default inputs. Prerequisites are never fetched. A test that needs a download is replaced by an inline equivalent; the plan's note and `skipped_atomics` say which and why.
- Each plan starts and ends with a canary test. If a canary raises no alert, the run is reported as incomplete and the job is red.
