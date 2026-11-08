# Security fix round 2 (8 Nov 2026)

Closes the findings in [docs/security/open-findings.md](../security/open-findings.md) (H1, H2, M1–M7 and the Low list). Threat model is unchanged: malware running as the owner's normal account (uid 501) that controls event content and every user-writable file. The owner approved "fix all" on 8 Nov 2026.

## Owner decisions taken for this round

- **Kill target.** The critical osascript-prompt rule kills the **untrusted parent** that launched the prompt (`action: [{name: kill, target: parent}]`), not osascript (a platform binary that is always protected). Platform, protected-path, seeded and unverified processes are still never killed.
- **Install.** Root never runs the Makefile, the Go toolchain or any other user-writable code. The user builds a flat `.pkg` with `make package` (no install scripts in the package); root only runs Apple's `/usr/sbin/installer` on it. `make install` refuses to run.
- **Run mode.** A LaunchDaemon is the supported live mode. Full Disk Access is granted to `/usr/local/sbin/zaafvesper`, not to Terminal. Terminal `sudo` mode stays for development and prints a warning.
- **cs_validation_category.** Wherever a vendor Team ID is used as trust, the process must also have `ps.cs_category in ('developer_id', 'app_store')`. On macOS releases whose Endpoint Security does not report the category the field is nil, so trust fails closed (more alerts, never fewer).
- **Unknown parent = untrusted.**

## Contract changes (pkg/event, done by the integrator)

- `event.SensorDegraded` (synthetic, category `sensor`), with `evt.arg[condition]` and `evt.arg[detail]`. Conditions used this round: `proctable_pressure`, `alerts_capped`, `capture_capped`, `yara_queue_full`, `yara_exec_replaced`, `yara_skipped_nonlocal`.
- `Proc.CSCategory` → rule field `ps.cs_category` / `ps.parent.cs_category` / `target.ps.cs_category` (string; nil when unreported). Values are the `event.CS*` constants.
- `Proc.Seeded` (bool): process learned at start-up, identity unverified.
- `Proc.ExeDev`, `Proc.ExeIno`, `Proc.ExeCtimeNs`: executable identity at exec time.

## Cross-workstream interfaces

- `pkg/ps`: `func (s *Snapshotter) OnDegraded(fn func(condition, detail string))`. Called synchronously; `fn` must not block. ps rate-limits itself to one call per condition per minute.
- `pkg/yara`: the concrete scanner gains the same `OnDegraded(fn func(condition, detail string))` method. The pipeline wires both through a type assertion, so `pkg/source.Scanner` is unchanged.
- The pipeline turns each call into a `SensorDegraded` event fed to the rule engine (and to the capture), plus one stderr line.
- `pkg/rules.Action` gains `Target string` (`yaml:"target"`): `""`/`process` (default) or `parent`. Anything else is a load error.
- When a process's parent is not in the table, `e.Proc.Parent` is nil, so every `ps.parent.*` field is nil.

## Workstreams and file ownership

| WS | Owns | Findings |
|---|---|---|
| A | `cmd/`, `pkg/alert`, `pkg/response`, `pkg/rules` (Go code only), `pkg/config`, `pkg/capture`, `Makefile`, `packaging/`, `README.md` | H1, H2, M1, M5, M6, Low: dedup key, ACLs, coverage sanitising |
| B | `pkg/ps`, `pkg/source/eslogger`, `pkg/yara`, `testdata/eslogger` | M2 (table), M3, M4 (decode), Low: magic, network FS, slow race tests |
| C | `rules/` (YAML, macros, fixtures, yara), `docs/rules.md` | M2 (rules), M4 (rules), M7, Low: kill target |

The integrator owns `pkg/event`, `docs/security/`, `docs/plans/` and the final commit.

## Round 3 (after judge FAIL 2.00 and security review round 3)

Owner decisions taken by the integrator under "fix all" (to confirm with the owner):

- **Kill identity (security F2, judge M1b).** pid + process start time compared within 1 ms binds the process incarnation (pids are allocated sequentially; reuse within 1 ms is impossible). pidversion is not readable without Mach calls/cgo, so it is not used; this deviation is recorded in open-findings.md. A path or file mismatch no longer refuses the kill (malware renaming or deleting itself must not escape). The kill is refused only when the CURRENT image is protected: platform binary (csops CS_PLATFORM_BINARY), protected path, or unknown protection status. A target with a Team ID but no reported cs_category is refused (kills on macOS without the category stay alert-only).
- **M5 overflow (F7).** Preserve evidence over completeness: never prune alert files younger than 7 days; when the budget is full, stop writing JSONL and keep raising `alerts_capped`.
- **M7 (F4).** The platform terminal-editor exemption is dropped: shell start-up file writes by vim/nano alert. Vendor GUI editors keep their (team_id, signing_id, cs_category) exemption.
- **H1 (F1).** Stays PARTIAL until a CI-built, Developer-ID-signed package exists (needs the owner's certificate). Interim: documented root-side copy + hash + no-Scripts check using Apple binaries only; README states the residual.

New contract: `Proc.OriginalPPID` → `ps.original_ppid` (nil when 0). New degraded conditions: `es_events_dropped` (global_seq_num gap), `response_rate_limited`; round 4 adds `degraded_suppressed` (summary of reports held back by the per-condition ceiling).

## Round 4 (final fix pass, after judge FAIL 2.00 and security review round 4)

- **Kill identity:** add the kernel unique id. pkg/ps reads `p_uniqueid` (proc_info flavor 17, PROC_PIDUNIQIDENTIFIERINFO, same syscall 336) when it first sees a process (exec, fork, bootstrap) into `Proc.UniqueID`; the responder reads it again right before the kill and refuses on mismatch, on a failed read, or when the event has none. pid + start time (1 ms) stays as a second check.
- **Ancestry trust (security New-2):** `ps.ancestors_untrusted` (bool) computed by pkg/ps; rules use it in `untrusted_prompt_origin` instead of relying on path globs only.
- **Alert overflow (security New-1, owner trade-off):** high and critical alerts get a reserved budget (own file series) so a low-severity flood cannot silence them; while the main JSONL is stopped, high and critical alerts still go out as one sanitized stderr line each.
- **Degraded ceiling (judge issue 3, security New-4):** per-condition share of the ceiling; `es_events_dropped` is never dropped; one summary SensorDegraded per minute reports what the ceiling suppressed.
- **Small items:** newsyslog without `J` (rotated lines stay readable); signing_id/team_id capped at 256 bytes in decoder and encoder; mount cache invalidated on every Mount event; injected clocks in the new tests.
- **Left for the owner:** killing after an exec into a platform binary (New-3); treating a launchd-parented credential prompt as untrusted (F3-residual); self-deleting daemonizing payloads (F5-residual) documented.
