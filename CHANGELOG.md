# Changelog

All releases are pre-release. Since v0.3 the sensor is validated live as root on throw-away GitHub runners, not on your own machine. Open risks are in [docs/security/open-findings.md](docs/security/open-findings.md).

## v0.3 · 9 Nov 2026 · Prove it live

Four workstreams (#5, #6, #7, #8) used throw-away GitHub Actions runners as a root test lab. These are GitHub runners, not your own Mac.

- **CI and releases ([#5](https://github.com/rifqifitriady/ZAAFVesper/pull/5)).**
  - Every push and pull request runs vet, race tests, the rule fixtures, cross builds for 3 OS and the static YARA build.
  - Tagged releases are built on GitHub with an SBOM and signed build provenance (`gh attestation verify`).
- **Windows and Linux live ([#6](https://github.com/rifqifitriady/ZAAFVesper/pull/6)).** Sysmon and Sysmon for Linux were installed from pinned sources, then Atomic Red Team was run against them:
  - Windows: 16 of 16 tested rules fired;
  - Ubuntu 24.04: 16 of 16 fired;
  - Ubuntu 26.04: 13 of 16 fired. The 3 SigmaHQ rules that did not fire expect `rm`/`cp`, which Ubuntu 26.04 runs as `gnurm`/`gnucp`; ZAAFVesper's own rule for the same behaviour still fires.
- **Response actions live ([#7](https://github.com/rifqifitriady/ZAAFVesper/pull/7)).** kill, suspend, quarantine, requarantine, remove_persistence and pf isolation ran as root on macOS, and kill ran on Windows and Linux, all with the identity checks. No product bug was found.
- **macOS live ([#8](https://github.com/rifqifitriady/ZAAFVesper/pull/8)).**
  - `eslogger` ran as root, and 17 rules fired from safe local actions.
  - Socket polling, syslog over TLS, the webhook and spool, and the live ZAAFElegia pipe were all verified (50 of 50 checks).
  - One bug was found and fixed: the last alerts before a clean stop were spooled instead of delivered.
- **Flaky tests fixed** after CI exposed them on other machines: syslog and forwarder spool timing, pid collisions, a test that read the host's DNS, and a YARA queue race.

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
