# Operating ZAAFVesper

Install, live operation, response, data handling and the sensor's own security. For a short overview see the [README](../README.md); for the security status of each finding see [security/open-findings.md](security/open-findings.md).

## Requirements

- macOS 13+ (developed on macOS 26, Apple Silicon). `/usr/bin/eslogger` ships with the OS.
- Live mode: the LaunchDaemon from the installer package (runs as root), with Full Disk Access granted to `/usr/local/sbin/zaafvesper` itself.
- Build: Go 1.27+. YARA support: `brew install yara pkg-config`. Builds that run as root link libyara **statically** (`make build-yara`, `make package YARA=1`).

## Install and run live (root)

> **Status:** root no longer runs any user-writable code: no `sudo make`, no Go toolchain as root, and a LaunchDaemon instead of a terminal (finding H2 addressed in code). Root still installs a package that your normal account built and stored, so finding H1 is **mitigated, not closed** (see *Residual risk* below and [security/open-findings.md](security/open-findings.md)). The package, the LaunchDaemon, Full Disk Access and real kills have **not yet been validated live as root**; treat the first install as a test on a machine you can recover.

Root never runs `make`, the Go toolchain or anything else your normal account can write. You build an installer package as yourself; root only runs Apple's own binaries on it.

```bash
# 1. As your normal user (never with sudo)
make package                   # pure Go;  or: make package YARA=1  (static YARA build)
# prints dist/ZAAFVesper-<version>.pkg and its SHA-256

# 2. As root, Apple binaries only. Copy the package out of your account
#    into a root-only directory, then verify that copy and install it.
sudo /bin/mkdir -m 0700 /var/root/zaafvesper-install
sudo /bin/cp dist/ZAAFVesper-0.1.0.pkg /var/root/zaafvesper-install/
sudo /usr/bin/shasum -a 256 /var/root/zaafvesper-install/ZAAFVesper-0.1.0.pkg
#    -> must equal the SHA-256 that make package printed; stop if not
sudo /usr/sbin/pkgutil --expand /var/root/zaafvesper-install/ZAAFVesper-0.1.0.pkg /var/root/zaafvesper-install/x
sudo /bin/ls /var/root/zaafvesper-install/x
#    -> must list only Bom, PackageInfo and Payload; stop if a Scripts entry exists
sudo /usr/sbin/installer -pkg /var/root/zaafvesper-install/ZAAFVesper-0.1.0.pkg -target /
sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/com.rifqifitriady.zaafvesper.plist
```

`make package` prints these commands with the right version and path. Installing from the root-owned copy closes the window in which the package in `dist/` could be swapped between your check and the install.

The package (no install scripts; every path recorded as `root:wheel`) contains:

| Path | Mode |
|---|---|
| `/usr/local/sbin/zaafvesper` | 0755 |
| `/usr/local/etc/zaafvesper/zaafvesper.yml`, `config.d/`, `rules/` | dirs 0755, files 0644 |
| `/Library/LaunchDaemons/com.rifqifitriady.zaafvesper.plist` | 0644 |
| `/etc/newsyslog.d/zaafvesper.conf` | 0644 (rotates `/var/log/zaafvesper/*.log` at 10 MB, 5 uncompressed generations, 0600) |
| `/var/log/zaafvesper/` | 0700 (also created by the sensor if missing) |
| `/var/db/zaafvesper/` and `/var/db/zaafvesper/quarantine/` | 0700 (response state and quarantine vault; see *Response*) |

The package also resets `/usr/local`, `/usr/local/sbin` and `/usr/local/etc` to `root:wheel 0755`, which is the macOS default on Apple Silicon. On an Intel Mac with Homebrew in `/usr/local` that changes Homebrew's ownership; do not install there without planning for it.

**Full Disk Access** goes to the binary, never to Terminal: System Settings > Privacy & Security > Full Disk Access > `+`, press Cmd-Shift-G and add `/usr/local/sbin/zaafvesper`. Then restart the daemon (`sudo /bin/launchctl kickstart -k system/com.rifqifitriady.zaafvesper`). Every upgrade installs a new binary with a new code-directory hash, so remove and re-add the entry after each upgrade; without it eslogger cannot start and the daemon keeps restarting (see `/var/log/zaafvesper/zaafvesper.log`).

The daemon runs `zaafvesper run --config /usr/local/etc/zaafvesper/zaafvesper.yml --rules /usr/local/etc/zaafvesper/rules --output-dir /var/log/zaafvesper --no-console --no-color` as root with `RunAtLoad` and `KeepAlive`, outside any terminal session, so the normal account has no terminal or `sudo` session through which to stop or pause it (not yet validated live). Alerts go to `/var/log/zaafvesper/alerts-<UTC time>.jsonl`, sensor messages to `/var/log/zaafvesper/zaafvesper.log`. The response actions are off; to enable them, add `--enable-response` (or first `--dry-run-response`) to `ProgramArguments` in the plist, then `bootout` and `bootstrap` again.

Upgrade: build the new package, copy and verify it as above, `sudo /usr/sbin/installer -pkg ... -target /`, `sudo /bin/launchctl kickstart -k system/com.rifqifitriady.zaafvesper`, and re-grant Full Disk Access.

Uninstall (alerts in `/var/log/zaafvesper` are kept until you delete them):

```bash
sudo /bin/launchctl bootout system/com.rifqifitriady.zaafvesper
sudo /bin/rm /Library/LaunchDaemons/com.rifqifitriady.zaafvesper.plist /usr/local/sbin/zaafvesper /etc/newsyslog.d/zaafvesper.conf
sudo /bin/rm -r /usr/local/etc/zaafvesper
sudo /usr/sbin/pkgutil --forget com.rifqifitriady.zaafvesper
```

Before removing `/var/db/zaafvesper`, check `sudo /usr/local/sbin/zaafvesper quarantine list`: it holds every file the response moved away. A clean shutdown already removes every pf block (`zaafvesper isolation list` shows none).

`make install` is disabled and prints these steps.

**Terminal mode is for development only.** `sudo /usr/local/sbin/zaafvesper run` still works and ignores SIGHUP, SIGTSTP, SIGTTIN and SIGTTOU, but your normal account can still end it through `sudo` and the terminal; it prints a warning when started from a terminal.

**ZAAFVesper refuses to start as root** unless its binary, configuration, rules, YARA rules and output directory, and every directory above them up to `/`, are root-owned, not group/world-writable and carry no ACL entry that permits anyone to write (`chmod +a "... allow write"` and similar; deny entries are fine). Running `sudo` from a user-owned checkout is refused by design. For the same reason a YARA build that loads a Homebrew `libyara.dylib` is refused as root (fail closed): use the static `YARA=1` package, or `--no-yara`.

**Residual risk (H1 is mitigated, not closed).** The package is only as trustworthy as the account that built it:

- *Same-account build.* Malware running as that user before or during `make package` can alter the sources, the Go toolchain, the Homebrew static libraries (`YARA=1`) or the staged files, and also the SHA-256 that `make package` prints. The hash check only proves that root installs the file you built, not that the build was clean. The package is unsigned.
- *`dist/` is user-writable.* Between `make package` and the root-side copy the package can be replaced. Comparing root's hash of the copy with the printed hash detects a swap after printing, not one made by malware that also controls the build output.
- *A compromised account controls `sudo`.* A `sudo` shell function or alias, or a changed `PATH`, in that account can run something else as root. Type `sudo` commands in a fresh login shell of another admin account (or use `command sudo` after checking `type sudo`) when you suspect the account.

The fix is a CI build with a pinned toolchain and libyara, signed with a Developer ID Installer certificate and notarized, installed only after the signature is checked.

## Response

Response is **off by default**. `--enable-response` lets rules that declare an action carry it out; `--dry-run-response` runs every guard rail and logs what each action would do, and does nothing (it wins over `--enable-response`). `replay` never acts.

**The honest limit.** Endpoint Security through eslogger is notify-only, and ZAAFVesper has no Endpoint Security entitlement, so nothing here blocks anything *before* it happens. Every action runs after the event that triggered it, typically milliseconds to a second later. A payload can already have run, read a file, phoned home or copied itself elsewhere. The actions contain and clean up; they do not prevent. Real blocking (Endpoint Security AUTH events) needs Apple's entitlement and is out of scope for v0.2.

The actions, which a rule lists in order under `action:`:

| Action | Targets | What it does |
|---|---|---|
| `kill` | `process` (default), `parent` | SIGKILL. |
| `suspend` | `process` (default), `parent` | SIGSTOP right away, so the next action (normally a `kill`) does not race the payload. The process is resumed (SIGCONT, after re-checking it is the same process) after `response.suspend_for` (default 30 s, at most 10 min) unless it was killed, and at a clean shutdown. |
| `quarantine_file` | `file` (default: the event's file, the destination of a rename), `process` (the executable of the event's process) | Moves the file into the vault `/var/db/zaafvesper/quarantine/<sha256>` (mode 0400, so no exec bit) with a sidecar `<sha256>.json` (original path, owner, mode, extended attributes, rule, process, time), then removes the original. A running process keeps running. |
| `requarantine` | `file` | Re-adds `com.apple.quarantine` (`0001;<time>;ZAAFVesper;`) to a file or bundle whose attribute was just removed, so Gatekeeper assesses it at the next launch. It acts only on a `DeleteXattr` of that attribute by an untrusted remover; an attribute that is present again is left alone. |
| `remove_persistence` | `file` | For a plist directly in `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/Users/<name>/Library/LaunchAgents` or `/var/root/Library/LaunchAgents`: reads its `Label` (XML or binary plist), runs `/bin/launchctl bootout` on it in `system`, `gui/<console user>` or `gui/<home owner>`, then quarantines the plist like `quarantine_file`. |
| `isolate_process` | `process` (default), `parent` | Adds the process's remote peers to a pf table and blocks them for `response.isolation_ttl` (default 1 h). Peers are the event's own (`NetworkConnect`, `NetworkAccept`) and those seen for the same process in the last 10 minutes. |

Built-in rules with actions: *Binary dropped in a temp or shared folder and executed without developer identity* (`quarantine_file`, target process), *Quarantine attribute removed by an untrusted process* (`requarantine`), *Launch Agent or Daemon written by an untrusted process* (`remove_persistence`) and *Fake password prompt via osascript from untrusted origin* (`suspend` then `kill`, both on the parent). The two "untrusted" rules are companions of the alert-only rules for the same behaviour: a remover or writer with no verified identity goes to the companion, the rest stays alert-only (Apple tools run by a user, PackageKit, Homebrew's `homebrew.mxcl.*` service plists, Developer ID vendors).

### Guard rails shared by every action

- **Budgets.** All actions together: 10 per rule and 30 in total per minute; a kill that follows the sensor's own suspend of the same process counts with it as one. A refusal because a budget is spent raises `SensorDegraded` (`response_rate_limited`). The same refusal for the same rule, target and pid (or path) is logged once a minute. Because the budget is shared, malware that triggers many cheap actions (for example requarantine of its own decoy files) can spend it before the action that matters; that residual is in the findings ledger.
- **Off the event loop.** kill and suspend run inline (a few system calls). The slow actions (file copies, `codesign`, `launchctl`, `pfctl`) run one at a time on a background worker with a copy of the event and their own lock; the event loop never waits for that lock (the isolation expiry skips a tick while an action runs), so they do not hold up detection, a kill or a resume. When 64 actions are already waiting, a new one is skipped and reported as `response_rate_limited`. At a clean shutdown suspended processes are resumed first, the running action finishes, queued actions that have not started are dropped (counted), and the pf anchor is flushed; the LaunchDaemon allows 40 s for this (`ExitTimeOut`).
- **Identity and platform flag.** One preflight, shared by every non-signal action, applies the identity rules of kill: an action is refused when the process it judges (the event's process, or its parent for `target: parent`) was only seeded at start-up or is marked unverified, when the parent is not in the process table or its pid does not match, and when whether it is an Apple platform binary is not known (the event is not from eslogger and the process carries no process-table identity). Which process's platform flag counts:

  | Action | Process judged | Apple platform binary |
  |---|---|---|
  | `isolate_process` | the process or its parent | refused, with every other kill protection (pids, names, paths, unreported signing category) |
  | `quarantine_file`, target `process` | the process that ran the file | refused (and the file must belong to its uid or euid) |
  | `quarantine_file`, target `file` | the process that wrote the file | allowed: the file is the target, not the writer (curl downloads are the usual case); the file's own protection is its path and bundle signature |
  | `requarantine` | the remover | allowed only when its parent is unknown or untrusted (`xattr` run by a dropper), refused under a trusted parent |
  | `remove_persistence` | the writer of the plist | refused |
- **Outcomes.** A step that fails is never logged as success: `partial` means some steps were done and one failed (for example the plist was quarantined but `launchctl` could not confirm the job is out), `error` that the action failed.
- **Log.** Every decision is one sanitized line in the daemon's log: `response <outcome> action=<name> target=... pid=... path=... reason=... detail=...` (kill lines keep their v0.1 format without `action=`).

### Process actions: kill and suspend

Before a kill or a suspend ZAAFVesper re-reads the process from the kernel:

- **Same process.** The kernel's unique process id (`p_uniqueid`, read with `proc_pidinfo` right before the signal) must equal the one the process table recorded for the event's process. It is not reused before a reboot, so a different value means another process now holds the pid. The signal is refused when the ids differ, when the event has none recorded, or when it cannot be read now. As a second check the kernel's start time must equal the event's within 1 ms. Tests cover each refusal with stub kernels and a real child process.
- **Protected at detection.** Refused when the process was an Apple platform binary in the event that matched (`is_platform`, from Endpoint Security).
- **Protected now.** Refused when the image running *now* lies under `/System`, `/usr/libexec`, `/sbin` or `/usr/sbin` or is `/usr/bin/eslogger` (`proc_pidpath`), when it is an Apple platform binary with a protected name (`launchd`, `WindowServer`, `loginwindow`, `kernel_task`, `eslogger`), and when its code-signing status (`csops`) or its path cannot be read (protection unknown). pid 1, ZAAFVesper's own pids and the eslogger child are always refused.
- **Renaming does not save it.** In the tests, a process that renamed, deleted or replaced its own executable after exec was still killed (stubbed signal); the changed path or file is written into the decision's `detail`. **Exec into an Apple binary does not save it either** (owner decision 8 Nov 2026): a process that was not a platform binary when it matched and has since exec'd into one, for example `/bin/zsh` or `osascript`, is killed when the kernel unique id and start time still match the event, and only when the event came from eslogger. If it exec'd again before the sensor recorded its unique id, the kill is refused (no recorded id).
- **Suspend** uses exactly these checks. Its resume checks the unique id and start time again, so a pid reused meanwhile never receives SIGCONT. A parent target can exit before the signal; that race has not been tested live.

### File actions: quarantine_file, requarantine, remove_persistence

- **Bound to the event's file.** The event must carry the file's device and inode (from Endpoint Security's stat). The file is opened by walking its path from `/` one component at a time with `O_NOFOLLOW` (a symbolic link anywhere refuses), opened `O_NOFOLLOW|O_NONBLOCK`, and its device and inode must equal the event's. A file replaced, renamed over or swapped for a link since the event is left alone. The kernel's own path of the opened file (`F_GETPATH`) is checked against the protected list again.
- **Regular files only** (requarantine also accepts a bundle directory), on a local file system (a network mount could stall the copy), and at most `response.quarantine_max_bytes` (default 128 MiB) for `quarantine_file`, 1 MiB for a plist. A file that changes size while it is copied is not quarantined.
- **Hard links.** A file with several names is acted on only when it belongs to the uid or euid of the process the event is about (that process could have made the extra names, so refusing would let a payload escape with one `link()` call); only the event's name is removed, and the decision says how many other names remain. A hard link to somebody else's file is refused.
- **Ownership for `target: process`.** The executable must belong to the uid or euid of the process that ran it, so root never clears another user's file from a shared sticky directory (`/private/tmp`, `/Users/Shared`) just because the offender ran it.
- **Never touched** (compared with Unicode case folding, because APFS is case-insensitive): `/System`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, `/Library/Apple`, `/private/var/db`, `/private/etc`, `/dev`, the TCC database, `com.apple.*` launch plists, any file inside a bundle (`.app`, `.framework`, `.kext`, ...) that carries Apple's own signature (`codesign -R "anchor apple"`, 5 s per bundle; a timeout, a crash or any answer other than "not signed" or "requirement not met" refuses), and any file nested in more than three bundles, an Apple platform binary as `target: process`, and ZAAFVesper's own files: its binary, configuration, rules, output directory, LaunchDaemon plist, `/var/db/zaafvesper` and the vault.
- **The original is removed only after** the copy is in the vault, synced, and its sidecar written, and only if the name still points to the same inode. The vault must be a directory owned by root with mode 0700 or nothing is written there.
- **remove_persistence** in addition: the plist's writer must not be an Apple platform binary (a dropper that writes its plist with `/bin/cp` is therefore alert-only; see the findings ledger). `launchctl bootout` runs only for a plain label (`[A-Za-z0-9._-]`, at most 255 characters, a single `Label` key) that is not `com.apple.*` or ZAAFVesper's own, and only when `launchctl print` reports that label loaded **from this very plist**, so a plist that borrows another program's label cannot make the sensor stop that program. If `launchctl` cannot answer (anything but "not found") or the bootout fails, the plist is still quarantined and the outcome is `partial`. A label that fails these checks, an unreadable label, or `/Library/LaunchAgents` with nobody logged in still quarantines the plist but boots nothing out. Jobs loaded in another domain (`user/<uid>`, another GUI user) are not booted out; they stop at logout because the plist is gone. A restored plist is not loaded again.

```bash
sudo /usr/local/sbin/zaafvesper quarantine list
sudo /usr/local/sbin/zaafvesper quarantine restore <first 8+ characters of the id>
```

`restore` creates the file at its original path (never over an existing file, no link followed), with its owner, mode and extended attributes (the quarantine attribute included). setuid, setgid and sticky bits are never restored. It refuses a destination on the protected list.

### Network action: isolate_process

- **pf filters addresses, not processes.** macOS has no per-process firewall without a NetworkExtension, so isolating a process blocks its remote peers **for the whole Mac**: every program loses those addresses until the isolation expires or is released. New peers the process contacts afterwards are not blocked.
- **Never blocked:** loopback, link-local, multicast and broadcast addresses, scoped addresses, this Mac's own interface addresses, its DNS resolvers (`nameserver` lines of `/etc/resolv.conf`), and the management allow-list `response.isolation_allow` (put your gateway, proxy, MDM and log collector there; the sensor warns at start when a rule uses `isolate_process` and the list is empty). The default gateway is **not** detected automatically. At most 16 addresses per action and 256 in all. No built-in rule uses `isolate_process` yet; it needs the `NetworkConnect` / `NetworkAccept` events of the socket poller (workstream S2), which eslogger does not produce, so until then every isolation is refused with `refused-no-peers`.
- **The pf ruleset is a constant**: one table `<zaafvesper_isolated>` and two `block drop quick` rules in the anchor `com.apple/com.rifqifitriady.zaafvesper`. Event data never enters a rule; only addresses parsed and re-printed by Go's `net/netip` enter the table. `/sbin/pfctl` is pinned and run with a fixed argument vector and an empty environment. pf states for the blocked addresses are killed so open connections stop.
- **Lifecycle.** The anchor is loaded and pf enabled (`pfctl -E`, a reference that is released with `pfctl -X` at a clean shutdown) on the first isolation. At start the anchor is flushed (an earlier crash may have left blocks); at a clean shutdown it is flushed again. The anchor lives under `com.apple/` because the stock `/etc/pf.conf` evaluates only anchors there; a custom `/etc/pf.conf` without `anchor "com.apple/*"` makes isolation a no-op.
- **Network data** comes from the `NetworkConnect` / `NetworkAccept` events of the socket poller (workstream S2). It polls, so connections shorter than the polling interval are missed.

```bash
sudo /usr/local/sbin/zaafvesper isolation list
sudo /usr/local/sbin/zaafvesper isolation release 203.0.113.5     # or: release all
```

### Settings

```yaml
response:
  isolation_allow: [10.0.0.53, 192.168.1.0/24]   # never blocked
  isolation_ttl: 1h
  suspend_for: 30s
  quarantine_max_bytes: 134217728
```

None of these turns a response on; only the flags do.

## Data handling

Captures and JSONL alerts are created `0600`, never overwrite an existing file, and store environment variable **names** plus `DYLD_*` values only (other values are `<redacted>`; `--keep-env` keeps everything). Command lines are kept: treat captures as secret material.

- `--output-dir DIR` (what the LaunchDaemon uses): DIR is created `0700` if missing and, as root, must be root-owned and not group/world-writable all the way up to `/`. Each start writes a new `alerts-<UTC time>.jsonl` (so `KeepAlive` restarts never collide with an existing file); `--capture-in-dir` adds `capture-<UTC time>.rcap`. Files are created and pruned relative to the open directory, never through a symbolic link.
- An alert file is capped at `--json-max-bytes` (default 256 MiB). In `--output-dir` mode it then rotates to a new file within a budget of `--json-keep` alert files (default 8). To make room only ZAAFVesper's own files are deleted, oldest first, and **never one younger than 7 days** (judged by the time in its name, not by its modification time) unless it is empty, and never the file being written. When the budget is full of younger files, ZAAFVesper stops writing alerts to that file series rather than delete evidence: it keeps running, raises `alerts_capped` and tries again every minute. Captures in the directory follow the same rule with `--capture-keep` (default 2). With an explicit `--json FILE` the sink stops writing at the cap.
- High and critical alerts are also written to a separate series, `alerts-high-<UTC time>.jsonl`, with its own budget (`--json-high-keep`, default 4 files of `--json-max-bytes`, same 7-day rule), so a flood of lower-severity alerts does not use up the space they need. While any alert file is not being written, each high or critical alert is also written to stderr (the daemon's log) as one sanitized line of at most about 1 KiB.
- One alert is capped at 64 KiB of JSON in one pass: free-text strings are cut to 2 KiB and argument, environment and other lists to 64 entries, and the alert carries `"truncated": true`. Process identity (pid, ppid, pidversion, kernel unique id, exe, name, cdhash, signing category, start time, parent pid and exe) is not cut; signing ID and Team ID, which a self-signer chooses freely, are cut to 256 bytes. If an alert is still too large it is reduced to the rule and these identities.
- A capture stops at `--capture-max-bytes` (default 2 GiB of uncompressed JSON) while the sensor keeps running.
- Repeats of the same rule for the same process (pid, pidversion and start time) within `--dedup-window` (10 s) are left out of the console and JSONL and counted.
- **Per-rule aggregation** (owner decision 8 Nov 2026 for the 20-a-minute limit; the new-source rule was added after the independent security review): for each rule, the first 20 alerts in a minute are written in full to the console and to both JSONL series. After that, the first alert from each source not yet seen in that minute is still written in full, so decoys cannot turn the real alert into a count. A source is the parent's executable for a rule that kills the parent (the osascript prompt), and otherwise the executable plus its parent's executable. Only repeats from a source already seen that minute are held back. When the minute ends (checked every 2 seconds), on the rule's next alert after it, and at shutdown, ONE summary alert per rule is written instead: same rule id, name and severity, `"aggregated": true`, `"count": N`, an output such as `rule fired 80 more times in the last minute; top sources: /tmp/x (parent /bin/zsh) ×50, …` (at most five sources), and the pid, ppid, executable and parent executable of the last three held alerts (in the output and as identity-only events). One rule therefore writes at most 20 + 64 full alerts and one summary a minute in each series. Every alert is still evaluated for response, so the kill budgets are unchanged. Memory is bounded: at most 64 distinct sources are tracked per rule and minute (alerts from further new sources are held as one "other" count) and at most 512 rules are tracked (an alert of a rule beyond that is written in full). `SensorDegraded` alerts are not aggregated: they are already limited per condition. `replay` aggregates by event time. The stats show `aggregated` and `aggregate_summaries`, and the held-back counts per rule every 10 minutes.

## Sensor health

When ZAAFVesper's own telemetry is degraded it raises a synthetic `SensorDegraded` event (`evt.category = sensor`) with `evt.arg[condition]` and `evt.arg[detail]`, writes one line to stderr and runs it through the rules like any other event. Conditions: `alerts_capped`, `capture_capped`, `response_rate_limited` (raised by the pipeline, at most once a minute each), and `proctable_pressure`, `yara_queue_full`, `yara_exec_replaced`, `yara_skipped_nonlocal`, `es_events_dropped` (raised by the process table, YARA and the eslogger source, which limit themselves per condition and object), and `aggregate_sources_exhausted` (a rule saw 64 alert sources in one minute, so alerts from further new sources are only summarised and decoys may be hiding a real one; once per rule and window). Limits in the pipeline: each component condition gets its own share of 20 events a minute, so a flood of one condition does not use up another's (tested: 100 `yara_exec_replaced` reports leave `proctable_pressure` through); all limited conditions together are capped at 120 a minute; `es_events_dropped` is never limited by the pipeline. When anything was dropped by these limits, one `degraded_suppressed` event a minute lists the dropped counts per condition. A flood of more than 20 reports of one condition in a minute therefore hides individual reports beyond the 20th, but not the fact that they happened. Every 10 minutes the daemon writes the degraded, alert-file and response counters to its log.

## Not yet validated live

These need root, Full Disk Access or a real attack and have only been tested with unit tests or by reading the code: every response action as root (real SIGSTOP/SIGCONT, quarantine of a root-owned or other user's file into the root-owned vault, `launchctl print` output and `bootout` in the system and gui domains, `pfctl` loading the anchor, `-E`/`-X` tokens, state kills, and whether the stock `/etc/pf.conf` evaluates `com.apple/com.rifqifitriady.zaafvesper`); `codesign -R "anchor apple"` on real bundles; Gatekeeper's reaction to a re-added quarantine attribute; the package install and its on-disk ownership (including `/var/db/zaafvesper`); launchd `KeepAlive` and the daemon's immunity to the normal account; Full Disk Access on the binary; the ownership and ACL checks against the installed root-owned tree; real kills, including the parent-kill race (the parent may exit first); Endpoint Security's `cs_validation_category` for self-signed code; the JSON shape of eslogger's `executable.stat` (`st_dev`, `st_ino`, `st_ctimespec`); YARA on a hung NFS or SMB mount; and newsyslog's behaviour with launchd's open log descriptors (after a rotation the daemon may keep writing to the rotated file until it restarts; rotated files are left uncompressed so those lines stay readable).

## Telemetry notes

`WriteFile` comes from eslogger's close-with-modification event (one event per modified file). `source.subscribe_write: true` also takes every `write(2)`, which can flood the sensor. Command lines are capped at 64 KiB and environments at 16 KiB per event (`evt.arg[args_truncated]`), and the process table at 128 MiB.

## Security of the sensor itself

ZAAFVesper runs as root, so:

- Binary, rules, macros, YARA rules, config and the output directory are checked (file and every ancestor directory: owner, mode bits and write-granting ACL entries) before anything is parsed, then each file is opened once with `O_NOFOLLOW` and parsed from that same descriptor (its ACL is checked on that descriptor too).
- Installed through a script-free package and run by launchd as root; root never executes the build.
- The only child process is `/usr/bin/eslogger` (pinned as root), with a fixed argv, minimal environment and `cwd /`.
- Event strings are sanitised (C0/C1, ESC, bidi controls) before reaching the terminal; regexes are RE2; globs are linear.
- Memory is bounded: per-event argv/env caps, a byte budget for the process table and for partial sequences, bounded YARA queue with exec scans prioritised.
- YARA opens scan targets by walking the path with `openat(O_NOFOLLOW)`, scans regular files only, and keys its cache on ctime and cdhash (mtime is attacker-settable).
- Allow-lists in the built-in rules trust only Apple platform identity or a vendor's specific Team ID + signing ID pair; `is_signed` alone (true for self-signed code) is never trust.

Known residual risk: Endpoint Security does not report whether a signing certificate chains to Apple, so a self-signed binary that embeds another vendor's Team ID would need live validation (see [rules.md](rules.md)).
