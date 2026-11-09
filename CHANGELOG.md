# Changelog

All releases are pre-release: nothing has yet been validated live as root on a real host. Open risks are in [docs/security/open-findings.md](docs/security/open-findings.md).

## v0.2 · 9 Nov 2026

Four workstreams, each with its own engineering-judge pass and independent security review, merged in pull requests #1 to #4.

**Sigma import ([#1](https://github.com/rifqifitriady/ZAAFVesper/pull/1)).**
- `zaafvesper sigma convert` turns Sigma rules for macOS, Windows and Linux into ZAAFVesper rules. Rules that cannot be expressed exactly are skipped with a reason.
- Semantics are tested against ZAAFElegia's Sigma conformance cases.
- 37 SigmaHQ rules ship converted (12 macOS, 14 Windows, 11 Linux), under DRL 1.1.

**Network telemetry and outputs ([#2](https://github.com/rifqifitriady/ZAAFVesper/pull/2)).**
- Socket polling reports outbound and listening connections without an Apple entitlement. It can miss short connections, and DNS is not visible.
- Three network rules: reverse shell, unsigned binary from a temp folder connecting out, interpreter to a public IP on an uncommon port.
- Outputs to syslog over TLS, an HTTPS webhook and Splunk HEC, with a capped spool.
- ZAAFElegia stream (`--elegia-out`, Sigma field names) and OCSF Detection Finding alerts (`--alerts-ocsf`).

**Active response ([#3](https://github.com/rifqifitriady/ZAAFVesper/pull/3)).**
- Opt-in actions: `suspend`, `quarantine_file` (root-only vault, restorable), `requarantine`, `remove_persistence` (launchctl bootout plus quarantine of the plist) and `isolate_process` (pf table, one hour).
- Every action acts after the event and re-checks its target. Kill/suspend and file/network actions have separate budgets.
- Owner decisions: a plist copied by an Apple tool under an untrusted process chain is rolled back. Isolation never blocks the gateway, DNS, link-local, loopback or Apple's 17.0.0.0/8.

**Windows and Linux adapters, preview ([#4](https://github.com/rifqifitriady/ZAAFVesper/pull/4)).**
- One Sysmon decoder serves two sources: the Windows event log (Windows service) and Sysmon for Linux through journald (systemd unit).
- Process tables and kill identity per platform (creation time and ProcessGuid on Windows, pidfd on Linux).
- 11 hand-written rules and 25 converted SigmaHQ rules.
- Cross-compiled and tested against fixtures only; not yet run on a real Windows or Linux host.

**Engine and contract.**
- Event model extended with network, DNS, registry, image and driver load, pipe, WMI and tampering events, plus `evt.platform`. Unreported fields resolve to nil.
- Rules may declare `platforms:` and live in subdirectories. `run` loads only the host's rules.

**Owner decisions on the kill path and alerts.**
- A detected process is still killed after it execs into an Apple binary.
- A credential prompt whose parent is launchd is CRITICAL.
- Alerts are aggregated per rule (20 a minute, plus the first alert of every new source), and `aggregate_sources_exhausted` warns when decoys may be hiding one.

Totals: 94 rules, 467 rule fixtures, 63 MITRE ATT&CK techniques.

## v0.1 · 7–8 Nov 2026

First release, for macOS:
- Endpoint Security through `eslogger`, a Fibratus-style rule language with sequences, and 41 rules mapped to ATT&CK.
- YARA bound to file identity, capture and replay.
- Opt-in kill with kernel identity checks.
- A script-free installer package with a LaunchDaemon.
- Three rounds of security hardening.
