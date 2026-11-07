# Open security findings (as of 7 Nov 2026, commit aeb967e)

Source: independent security re-review (round 2) and engineering judge round 2. Threat model: malware running as the owner's normal account (uid 501) that controls event content and user-writable files. Nothing below has been exploited live; nothing was run as root during review.

Round 1 fixes verified as holding: root ownership walk and fd-based reads; YARA cache poisoning (ctime/cdhash key) and symlink-safe opens; memory caps (2 147 MB → 301 MB peak under a 1 MiB-argv flood); capture size cap; env redaction; async console; coverage output safety; platform-binary protection.

## High

| # | Finding | Where | Planned fix |
|---|---|---|---|
| H1 | `sudo make install` runs the Makefile, Go toolchain, sources and build cache as root, all writable by the normal account; a staged binary can be swapped before the root copy. Static YARA archives come from user-owned Homebrew. | Makefile install/staticlib | Build as user; root step = small copy-only script into a root-owned staging dir with sha256 check. Long term: CI build with pinned toolchain and libyara (no magic), signed + notarized `.pkg`. |
| H2 | Running via `sudo` in a terminal lets the normal account stop or pause the sensor (`sudo` relays signals; SIGHUP on Terminal quit). | README run mode; `cmd/zaafvesper/run.go` | Ship a LaunchDaemon (root real uid, KeepAlive, Full Disk Access on the binary itself); ignore SIGHUP/SIGTSTP/SIGTTIN/SIGTTOU; terminal mode = development only. |

## Medium

| # | Finding | Planned fix |
|---|---|---|
| M1 | Pre-kill identity check uses `kern.procargs2` exec_path (process-controlled): a symlink with another name or a self-rewrite defeats it. | Use `proc_pidpath` (full path) and audit-token pidversion + start time. |
| M2 | Process-table byte budget can be flooded (~900 big-argv processes) to evict a malware's parent, downgrading the CRITICAL osascript-prompt rule to HIGH. | Shed args/env first and keep identity skeleton; "sensor degraded" alert; rules treat unknown parent as untrusted. |
| M3 | YARA exec scan reads whatever is at the path when the worker runs (swap after exec). | Decode ES executable stat (dev/ino/ctime) and require a match after fstat; alert on replacement. |
| M4 | A self-signed certificate can carry another vendor's Team ID, so (team_id, signing_id) allow-lists may be forgeable. | Decode `cs_validation_category`; require Developer ID / App Store wherever team_id is trust. Confirm live in a VM. |
| M5 | `--json` alert file has no size cap; alert size is attacker-controlled. | `--json-max-bytes` plus per-alert caps. |
| M6 | README advises Full Disk Access for Terminal, which extends FDA to everything launched from it. | LaunchDaemon with FDA on the binary (see H2). |
| M7 | Scriptable platform editors (`ed`, `vim -es`) are allow-listed for shell start-up file writes. | Require a TTY / non-script parent, or drop `ed`. |

## Low

Kill rule targets `osascript` (a platform binary), so response currently never kills; dedup key lacks pidversion and also suppresses response; `import "magic"` regex refusal is bypassable (build libyara without magic); extended ACLs not checked; network-filesystem scans can stall YARA workers; `coverage` JSON not bidi-sanitised; `pkg/ps` race tests take ~400 s.

## Not yet validated live

Real eslogger capture on macOS 26, atomic test runs (28 rules carry GUIDs), real kills, ES `team_id` / `cs_validation_category` for self-signed code.
