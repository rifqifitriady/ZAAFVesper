# Security findings ledger (as of 8 Nov 2026)

Threat model: malware running as the owner's normal account (uid 501) that controls event content and every user-writable file. Sources:
- security re-review round 2 (H1, H2, M1–M7, Low);
- independent reviews of the fixes (round 3: F1–F10; round 4: New-1 to New-5);
- the engineering judge.

Nothing has been exploited or validated live. Nothing was run as root during review. Plan and decisions: [docs/plans/2026-11-08-security-round2.md](../plans/2026-11-08-security-round2.md).

Status values:
- **Closed (code)**: fixed and covered by the named tests; live validation still pending.
- **Partial**: mitigated; the residual is stated.
- **Open**.

## High

| # | Finding | Status | Mechanism and evidence | Residual |
|---|---|---|---|---|
| H1 | Root ran the Makefile, toolchain, sources and caches (`sudo make install`), all writable by the normal account. | **Partial** | `make install` refuses ([Makefile](../../Makefile) `install`). `make package` builds a script-free flat `.pkg` as the user. Root runs only Apple binaries: `cp` into a root-only dir, `shasum`, `pkgutil --expand` with a no-Scripts check, `installer`, `launchctl` (README "Install and run live"). The judge inspected the package: Bom, PackageInfo and Payload only, every entry root:wheel. | Root still installs a binary built by the same account. That account can tamper with the build or with the printed hash, swap `dist/*.pkg` before the root copy, or shadow `sudo`. Closing H1 needs a CI-built package signed with a Developer ID and notarized, checked with `pkgutil --check-signature` before install. That requires the owner's certificate. |
| H2 | A sensor started with `sudo` in a terminal can be stopped or paused by the normal account. | **Closed (code)** | The LaunchDaemon `com.rifqifitriady.zaafvesper` runs as root with KeepAlive, umask 077 and a 0700 log directory. Job-control signals are ignored (`TestIgnoreJobControlSignals`). Terminal mode prints a warning. | launchd behaviour not validated live. |

## Medium

| # | Finding | Status | Mechanism and evidence | Residual |
|---|---|---|---|---|
| M1 | The pre-kill identity check used process-controlled `kern.procargs2`. | **Closed (code)** | Right before the kill:<br>• **Kernel unique id.** The kernel's `p_uniqueid` (proc_info flavor 17) must equal the value the process table recorded when it first saw the process. A missing, unreadable or different id refuses the kill.<br>• **Start time** must match within 1 ms.<br>• **Protected image.** The current image's protection comes from the kernel (`csops` platform flag, `proc_pidpath` protected paths).<br>• **Rename, delete or replace** of the executable is logged and does not save the process.<br>• **Team ID without a reported signing category:** refused.<br>If a process execs again before its earlier exec event is handled, that earlier incarnation has no recorded id and a kill on it is refused (fail closed; no rule kills the target process today). Tests: `TestGuardRails`, `TestKillEvasionRealProcesses`, `TestIdentifyChild`, `TestIdentifySelf`, `TestKillParent`, `TestUniqueIDRead`. | `KillParent` races a parent that exits first. A detected process that execs into an Apple platform binary is refused as protected (owner decision pending, New-3). On macOS where Endpoint Security does not report the signing category, killing a process that has a Team ID only raises an alert. |
| M2 | A process-table flood evicted a malware's parent, downgrading a CRITICAL rule. | **Closed (code)** | • Args, env and cmdline are shed before eviction, and the identity skeleton is kept (`TestFloodKeepsParentSkeleton`, `TestSkeletonEvictionLastResort`).<br>• `proctable_pressure` reaches the capture end to end (`TestProcTablePressureEndToEnd`).<br>• An unknown parent counts as untrusted (`TestUnknownParentIsNil`, rule fixtures).<br>• A double fork counts as untrusted through `ps.original_ppid` (`TestReparentedKeepsRealParent`).<br>• An untrusted ancestor anywhere in the chain counts as untrusted through `ps.ancestors_untrusted` (`TestAncestorsUntrusted`, SEC-R4 fixtures). | A credential prompt spawned by launchd itself (original_ppid 1) stays HIGH (owner decision pending). A double-forked prompt only raises an alert, because its parent is launchd. `original_ppid` from live eslogger is unconfirmed. |
| M3 | YARA scanned whatever was at the path when the worker ran. | **Partial** | • Exec and file scans are bound to the event's dev, ino and ctime (`TestExecScanBoundToExecStat` with a matching replacement file, `TestFileScanBoundToEventStat`).<br>• A ctime-only change on a written file is scanned (`TestChmodAfterCloseStillScanned`).<br>• An executable deleted while its process still runs is reported (`TestExecGoneWhileRunningReported`).<br>• Reports are limited per (condition, pid or path), so one decoy does not hide another (`TestDecoyThenRealReplacementBothReported`). | A payload that unlinks itself, forks and exits the original pid within the queue latency is counted (`exec_gone`) but neither scanned nor reported. If eslogger's stat shape or precision differs live, exec scans report replacement or go unbound (counted as `exec_unbound`). |
| M4 | A self-signed binary can carry another vendor's Team ID. | **Closed (code)** | `cs_validation_category` is decoded, with a gate on ES message version 10 or later (`TestCSCategoryAndExeStat`). Every Team ID trust also requires `developer_id` or `app_store` (rule fixtures with `local_signing` and with the category absent). An unreported category fails closed. | Not validated live against a forged Team ID. |
| M5 | The `--json` alert file had no cap. | **Partial** | • Per-alert cap in one pass; identity is never cut; signing fields are capped at 256 B (`TestEncodePaddedAlertFastAndKeepsIdentity`, `TestEncodeCapsSigningFields`).<br>• File cap with rotation (`TestJSONLRotates`).<br>• Files younger than 7 days are never pruned (`TestOutputDirPrunePolicy`).<br>• High and critical alerts have their own file series and budget, plus a stderr fallback line while JSONL is stopped (`TestOutputDirBudgetFullOfYoungFiles`).<br>• eslogger `global_seq_num` gaps raise `es_events_dropped` (`TestSeqGapReported`). | A low-severity flood can stop the main JSONL series for up to 7 days (New-1). The high series can itself be filled by a flood of HIGH alerts (e.g. a no-dialog osascript command whose text only *looks* like a password prompt; R5-1); after that, high and critical alerts survive only as stderr fallback lines, which put rule id, pid and exe before the output so only the output is cut. Per-source aggregation and off-host shipping are the complete fix. |
| M6 | README advised Full Disk Access for Terminal. | **Closed** | FDA is granted to `/usr/local/sbin/zaafvesper` and re-granted after each upgrade ([README](../../README.md) "Install and run live"). | — |
| M7 | Scriptable editors were allow-listed for writes to shell start-up files. | **Closed (code)** | The platform terminal-editor exemption is removed. The SEC-R3 `script(1)` + vim fixture now matches. Only vendor GUI editors with a verified identity are exempt. | Editing `~/.zshrc` by hand in vim or nano now raises a medium alert (accepted false positive). |

## Low and later items

| Item | Status | Evidence / note |
|---|---|---|
| Kill rule targeted osascript, a platform binary that was never killed | **Closed (code)** | `action: [{name: kill, target: parent}]`; `TestKillTargetParent`, `TestKillParent` |
| Dedup key lacked pidversion; dedup also suppressed the response | **Closed (code)** | `TestDeduperPIDReuse`, `TestKillTargetParent` |
| `import "magic"` refusal could be bypassed | **Closed (code)** | Lexer allow-list plus libyara's own import callback; includes are disabled (`TestCheckRuleSource`, `TestLibyaraImportCheck`, `TestImportAndIncludeBypassesRefused`). libmagic is still linked into the static build. |
| Extended ACLs were not checked | **Closed (code)** | `TestACLs`, using real `chmod +a` |
| Network file system scans could stall workers | **Partial** | `TestKnownNetworkMountSkippedBeforeOpen`, `TestMountEventInvalidatesMountCache`, `TestMountReachesScanner`. A hung mount was not tested live. |
| `coverage` output was not bidi-sanitised | **Closed** | `TestCoverageSanitized` |
| `pkg/ps` race tests took ~400 s | **Closed** | `go test -race ./pkg/ps` now takes about 9 s (race-scaled sizes in `pkg/ps/race_on_test.go`) |
| F8 decoys could spend the global kill budget | **Closed (code)** | 10 kills/min per rule, 30 globally, and `response_rate_limited` (`TestRateLimit`, `TestResponseBudgetRaisesDegraded`) |
| New-4 decoys could spend the degraded-event ceiling | **Partial** | 20 per minute per condition; 120 in total; `es_events_dropped` is never limited. While anything is suppressed, one `degraded_suppressed` summary per minute; stats print every 10 minutes (`TestDegradedDecoyDoesNotHideReal`). Reports past the 20th of one condition in a minute appear only as a count in the summary. |
| F10 daemon log | **Partial** | newsyslog config without compression, so rotated lines stay readable. Repeated refusals are logged once a minute (`TestRepeatedRefusalsLoggedOnce`). launchd keeps writing to the renamed file, so rotation effectively happens once per daemon lifetime and `zaafvesper.log.0` can keep growing (R5-2); the daemon writing its own capped log is the fix. |
| New-5 attacker-chosen signing identifier length | **Closed (code)** | Capped at 256 B in the decoder and the encoder (`TestIdentityCapped`, `TestEncodeCapsSigningFields`) |
| AppleDouble `._*` entries in the package payload | Accepted | `com.apple.provenance` cannot be removed by the user. Every loader skips dotfiles (`TestDotfilesSkipped`). |

## Decisions pending with the owner

- **New-3:** kill a detected process after it execs into an Apple platform binary? Today it is refused as protected.
- **F3 residual:** treat a credential prompt whose parent is launchd as an untrusted origin?
- **R5-1:** aggregate high/critical alerts per source so one process tree cannot fill the reserve?
- **New-1 / M5:** the default budgets: main alert files 8 × 256 MiB, high alerts 4 × 256 MiB, 7-day floor.
- **H1:** a CI build with a Developer ID signature.

## Not yet validated live

- Install, ownership of the package, LaunchDaemon and KeepAlive.
- Full Disk Access on the binary.
- Ownership and ACL checks as root.
- Real eslogger capture on macOS 26: `cs_validation_category`, `original_ppid`, `executable.stat`, `global_seq_num`.
- `p_uniqueid` and `csops` on other users' processes as root.
- Atomic test runs (28 rules carry GUIDs).
- Real kills, including the parent-exit race.
- YARA on a hung network mount.
- newsyslog with launchd's open descriptors.
