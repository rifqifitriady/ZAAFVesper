# Live validation on a GitHub macOS runner

Workflow: [`.github/workflows/live-macos.yml`](../../.github/workflows/live-macos.yml), harness in [`scripts/ci/c/`](../../scripts/ci/c/). It runs on `workflow_dispatch` and on pushes to `validate/**`.

> **Validated on a GitHub runner is not validated on your Mac.** The runner is a throw-away macOS virtual machine with **SIP disabled**, Full Disk Access granted to `/bin/bash` in its TCC database, and a GitHub/Anka process tree around the job. A Mac with SIP on, the installer package, the LaunchDaemon and Full Disk Access on the ZAAFVesper binary itself are still not validated here.

## Runs

| Date (UTC) | Run | Commit | Result |
|---|---|---|---|
| 9 Nov 2026 11:14 | [42607447169](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42607447169) | `fe29f95` (final harness) | **50 checks, 0 failed**; 2 rules not testable; sensor ran 213 s as root and stopped cleanly |
| 9 Nov 2026 10:55 | [42604807438](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42604807438) | `867ce48` | 47 checks, 0 failed; sensor ran 215 s |
| 9 Nov 2026 10:35 | [42601933739](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42601933739) | `c682ca4` | 43 checks, 0 failed (sensor ran only about 55 s, so a soak phase was added) |
| 9 Nov 2026 10:22 | [42600448973](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42600448973) | `7aa7844` (before the security-review changes) | 41 checks, 0 failed |

Times are the runs' start times in UTC.

The results below are from run [42607447169](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42607447169) unless stated. Every row corresponds to a row of that run's job summary (rule rows by their trigger id, the others by the check they describe), and the evidence is in its `live-macos-results` artifact: alerts in `outdir/alerts-*.jsonl` (match the rule's `id`), the events in `events.ndjson`, the receivers' logs in `receiver/`, the zaaf findings in `zaaf-findings.ndjson`, run statuses in `status.tsv`, and the full table in `results.md`.

Runs while the harness was being built: [42576991593](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42576991593) (every Endpoint Security rule silent; see "eslogger"), [42599223857](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599223857) (the diagnosis), [42599771481](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42599771481) (54 of 56; it found the shutdown-flush gap fixed below), [42601040109](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42601040109) (40 of 41: the old eslogger probe counted background noise and saw none in 4 s; replaced by the diagnosis counts).

Runner: `macos-latest`, macOS 26.7.2 (25G332), arm64 virtual machine, SIP disabled. Each run's job summary has the full table, and the `live-macos-results` artifact (30 days) holds the alert files, the capture, the event stream, the receivers' logs, the spool listing and the sensor log.

## What the run does

1. **eslogger probe and diagnosis** (`esdiag.sh`): runs `/usr/bin/eslogger` alone under `sudo`, once subscribed to `exec` only and once to the sensor's full set, while it starts marked commands from the job's own shell and the same commands from a launchd job.
2. **Installs as root** like the package: binary in `/usr/local/sbin`, rules and configuration in `/usr/local/etc/zaafvesper`, all `root:wheel` and not group- or world-writable, so every root ownership check of `run` applies.
3. **Starts two receivers on 127.0.0.1** (`receiver/`): syslog over TLS (RFC 5425 framing) and an HTTPS webhook with a bearer token. Both use a throw-away CA, which ZAAFVesper pins with `--syslog-ca` and `--webhook-ca`. The token is random per run, masked in the log, and stored root-owned `0600`.
4. **Runs `zaafvesper run` as root** (213 s in the final run) with the capture, the output directory, socket polling (`--net-interval 500ms --net-loopback`), both SIEM outputs with the spool, `--alerts-ocsf` and `--elegia-out -`, piped through `tee` into `zaaf hunt` (ZAAFElegia built from commit `c2e0212`, pinned).
5. **Socket polling**: an `nc` listener and a process holding a connection to it, as the `runner` user (another uid than the root sensor).
6. **Fires safe local actions** (`triggers.sh`) from a launchd job, as the `runner` user.
7. **Soak**: lets the sensor run until it has been up for over 3 minutes, then fires one late action (a quarantine strip) that must still be detected.
8. **Stops the receivers**, fires two more actions, checks that the spool holds them, restarts the receivers and waits for the spool to drain.
9. **Stops the sensor with SIGINT** (checked: "sensor stopped cleanly on SIGINT" and "sensor | tee | zaaf pipe exited 0") and checks everything (`check.py`). The job fails on any failed check.

## eslogger: works, but not for the job's own processes

- Job summary: "eslogger under sudo" PASS ("reports launchd-started commands (3 events); job-tree commands: 0 events"), and two INFO rows with the diagnosis counts.
- `sudo /usr/bin/eslogger` **runs** on the runner: the runner's TCC database grants Full Disk Access to `/bin/bash` (recorded in each run: `esdiag/tcc-full-disk-access.txt`, job-summary row "runner TCC: Full Disk Access for /bin/bash"), so the job's shell can start it.
- **Endpoint Security reports nothing for the job's own process tree.** In every run, eslogger alone, with either subscription, reported the marked commands started through launchd (3 matching events) and **none** of the two marked commands started from the job's shell (0 matching events; `esdiag/esdiag.tsv` in the artifact). Other processes are reported normally (launchd, xpcproxy, Spotlight, the runner's Anka scripts). The first full run therefore raised no Endpoint Security alert at all (run 42576991593).
- **Workaround:** the triggers run as a launchd job (`outside.sh`: `launchctl submit` as root, then `sudo -u runner`), outside the job's tree. With that, every trigger is seen. The muting happens with eslogger alone, so it comes from the runner environment, not from ZAAFVesper; whether a real Mac ever mutes processes in a similar way is not tested here. Tests driven straight from a job's shell are blind on these runners.
- **Dropped events:** the source reported `global_seq_num` gaps in every run (run 42607447169: `seq_gaps=9837`, `events_missed=118006` against 225,095 decoded events over 213 s), and `es_events_dropped` was raised. No trigger was lost. It is not established whether these are real drops under the `open` event volume or numbers used by the muted job tree; treat the count as an upper bound on loss.

## Rules

Each action is listed with the rule it is meant to fire. All are local to the runner: test files, a test plist that is never loaded, a crontab that is removed, a loopback socket.

Job summary rows: "rules | `<id>`: `<rule>`" (the id is the first word in the Action column below). Each "fired" row had at least one alert of that rule in `outdir/alerts-*.jsonl`.

| Action (ATT&CK) | Rule | Result |
|---|---|---|
| `quarantine`: `xattr -d com.apple.quarantine` on a test file (T1553.001) | `defense_impairment_quarantine_attribute_removed` | fired |
| `c-late-quarantine`: the same, after the sensor had run for over 3 minutes | `defense_impairment_quarantine_attribute_removed` | fired ("late action (after the soak) still detected": 3 alerts across phases a, c and b) |
| `launchagent`: `cp` a test plist into `~/Library/LaunchAgents` (T1543.001) | `persistence_launch_agent_plist` | fired |
| `launchdaemon`: `sudo cp` a test plist into `/Library/LaunchDaemons` (T1543.004) | `persistence_launch_daemon_plist` | fired |
| `osascript`: `osascript -e 'do shell script "… base64 -D"'`, no UI (T1059.002) | `execution_suspicious_osascript` | fired |
| `chflags`: `chflags hidden` (T1564.001) | `stealth_hidden_file_flag` | fired |
| `history`: `rm ~/.zsh_history` (T1070.003) | `stealth_shell_history_deleted` | fired |
| `zshrc`: append to `~/.zshrc` from `sh` (T1546.004) | `persistence_shell_profile_modification` | fired |
| `secsw`: `ps aux \| egrep "Little Snitch\|falcond…"` (T1518.001) | `discovery_security_software_enumeration` | fired |
| `profiling`: `system_profiler` then `sw_vers` from one shell (T1082) | `discovery_system_profiling_burst` (sequence) | fired |
| `launchctl`: `launchctl submit` of a test job (T1569.001) | `execution_launchctl_submit_or_load_from_temp` | fired |
| `setuid`: `chmod u+xs` on a test file (T1548.001) | `privilege_escalation_setuid_bit_set` | fired |
| `screencapture`: `screencapture -x` (T1113; the capture itself fails without permission, the exec is detected) | `collection_noninteractive_screencapture` | fired |
| `pipe`: `echo … \| base64 -d \| sh` (T1059.004) | `execution_remote_script_piped_to_shell` | fired |
| `keychain`: `security dump-keychain`, metadata only (T1555.001) | `credential_access_keychain_dump_via_security` | fired |
| `cron`: `crontab /tmp/…` (T1053.003) | `persistence_cron_periodic` | fired |
| `dropped`: unsigned Go binary copied to `/tmp` and run (T1204.002) | `execution_untrusted_binary_dropped_and_run_from_temp` (sequence) | fired |
| `revshell`: `bash` holds a `/dev/tcp` connection to an `nc` on 127.0.0.1 (T1059.004) | `network_shell_remote_socket` (socket polling) | fired |
| — | `network_unsigned_temp_binary_outbound` | **not testable**: needs a public destination, and the validation stays on 127.0.0.1 |
| — | `network_interpreter_raw_ip_uncommon_port` | **not testable**: same reason |

Also fired: `defense_impairment_sensor_degraded`, for `es_events_dropped` and for `output_down` while the receivers were stopped (as designed).

Not exercised here: the remaining macOS rules. These are the ones that need a real target (browser stores, other vendors' tools, kernel extensions), a GUI prompt, system-wide changes (Gatekeeper, firewall, sudoers, TCC.db, logs), YARA, or XProtect. Their fixtures still pass in CI. Response actions are workstream D.

## Socket polling (as root, against processes of another user)

| Check | Result |
|---|---|
| `nc -l 127.0.0.1 5555` → one `NetworkAccept` `listen` | pass |
| a process connecting to it → one `NetworkConnect` `outbound` | pass |
| the accepted socket in `nc` → one `NetworkAccept` `inbound` | pass |
| every network event has `source: netpoll` | pass |

Evidence: the `network_connection` records in `events.ndjson` (`Image` `/usr/bin/nc` or `…/dropped`, `DestinationPort` 5555, `Initiated` absent / `"true"` / `"false"`). Polling ran at 500 ms over 429 polls, reading about 237,000 processes in all, with no `budget_exhausted`, `fd_caps` or `untracked_sockets` (sensor log `stats: network`).

## SIEM outputs and spool

| Check | Result |
|---|---|
| syslog over TLS, pinned CA, received every alert | pass |
| HTTPS webhook (bearer token) received every alert | pass |
| alerts raised while both receivers were stopped went to the spool | pass (2 spool files; `spool-while-down.txt`) |
| the spool drained after the receivers came back, and those alerts arrived | pass |
| nothing left in the spool at shutdown | pass, after the fix below |
| the token is absent from everything uploaded (every file of the artifact, plus the decompressed capture) | pass |

Evidence: `receiver/syslog.log` and `receiver/webhook.log`, compared per rule id with the alert file by `check.py` ("syslog over TLS (pinned CA) received every alert", "HTTPS webhook received every alert", "alerts raised while down were delivered later: …"). Splunk HEC mode was not run live (it uses the same HTTPS path; unit tests cover its format).

## ZAAFElegia and OCSF

| Check | Result |
|---|---|
| `--alerts-ocsf`: one OCSF 2004 finding per alert | pass |
| `zaafvesper run --elegia-out - \| zaaf hunt -r <rules> -` live: xattr quarantine removal | pass |
| same: shell with an outbound connection | pass |
| same: `chflags hidden` | pass |

The three Sigma rules are in `scripts/ci/c/sigma/`.

## Bugs found and fixed

- **The last alerts before shutdown were spooled, not sent** (run 42599771481). The forwarder put every record still queued at `Close` into the spool, even when the endpoint was up. So an alert raised in the last second before a clean stop reached the SIEM only after the next start. Now it gets one last delivery attempt (bounded to 3 s, or less when `Close` has a shorter timeout; syslog write deadlines follow it) when the endpoint is up; otherwise, or when that attempt fails, the records are spooled as before. Tests: `TestForwarderFinalFlushOnClose` (fails without the fix) and `TestFinalFlushFollowsCloseTimeout`.
- The fix keeps delivery **at least once**: a record whose final send timed out after the receiver had taken it is spooled and sent again at the next start (a possible duplicate), and the final flush does not send older spooled records first, so ordering across a restart is not guaranteed. `TestFinalFlushBoundedByHangingEndpoint` shows that an endpoint which never answers holds `Close` for about 3 s and the record is spooled.
- The harness itself also needed fixes, none of them in ZAAFVesper: eslogger ignores SIGINT (it is stopped with SIGTERM, as the sensor already does), and `launchctl submit` restarts a job when it exits.

## How the workflow is protected

From the independent security review (no critical, high or medium findings), with its low findings fixed:
- **Triggers:** `workflow_dispatch` and push to `validate/**` only, so forks and pull requests cannot run it.
- **Permissions and actions:** `permissions: contents: read`, `persist-credentials: false`, no secrets, and every action pinned to a commit SHA that matches its tag. No `${{ }}` in any `run:` block.
- **Pinned toolchains:** Go is downloaded from go.dev and checked against its published sha256. ZAAFElegia is fetched at a full commit, the commit is re-checked, and it is built with `cargo --locked` (every crate carries a checksum) and a pinned Rust toolchain (`RUSTUP_TOOLCHAIN`).
- **Least privilege:** `zaaf`, the receivers and the triggers run unprivileged; only eslogger, the sensor and the installs use `sudo`.
- **Bounds:** every wait has a deadline, a cleanup trap stops the sensor, receivers and launchd jobs on any failure, and the scripts refuse to run outside a GitHub-hosted runner.
- **Artifact:** it is public for 30 days and holds runner telemetry: command lines, environment variable names (values are redacted) and the runner's own endpoints. No secret was found in it.

## Limits of this validation

- SIP is disabled on the runner, and Full Disk Access comes from `/bin/bash`, not from the ZAAFVesper binary.
- The package install, the LaunchDaemon, `KeepAlive` and the newsyslog rotation are not covered.
- Only loopback networking is used. Rules that need a public destination are not testable here.
- One runner image, and the sensor runs for about 3.5 minutes per run. That is not a long soak test.
