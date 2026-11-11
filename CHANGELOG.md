# Changelog

All releases are pre-release. Since v0.3 the sensor is validated live as root on throw-away GitHub runners, not on your own machine. Open risks are in [docs/security/open-findings.md](docs/security/open-findings.md).

## v0.4 · 10 Nov 2026 · Reach

Four workstreams (#9 to #12), each with an independent security review and an engineering-judge pass, merged in the order E, F, H, G. The live validation of the merged tree on throw-away GitHub runners (macOS, Windows, Linux with eBPF, response, ZAAFElegia) all passed.

- **Containment on Windows and Linux ([#12](https://github.com/rifqifitriady/ZAAFVesper/pull/12)).**
  - `isolate_process` (Windows Firewall rules; an nftables table on Linux), `quarantine_file` into a locked vault, `remove_persistence` (Run values, services, scheduled tasks; systemd units, cron, shell rc files) and `suspend`, with the same guard rails as macOS.
  - Limit: under the shipped systemd unit the Linux file actions are refused (private mount namespace); see `packaging/linux/README.md`.
- **Linux eBPF source ([#11](https://github.com/rifqifitriady/ZAAFVesper/pull/11)).**
  - `--source ebpf` (default on Linux) reads exec, file, network, DNS, ptrace and module events from the kernel without Sysmon. Ubuntu 24.04 fired 16 of 16 rules, Ubuntu 26.04 fired 13 of 16, the same as Sysmon.
  - Known limits: a single ring buffer (F11, v0.5), validated on arm64 6.8 and GitHub's 7.0 kernels only. `bpf/vmlinux_min.h` is hand-written, an owner-accepted deviation.
- **Detection expansion ([#10](https://github.com/rifqifitriady/ZAAFVesper/pull/10)).** From 63 to 107 ATT&CK techniques: 136 rules, 705 test scenarios. New `coverage --report --attack` and `sigma convert --atomics`. Seven SigmaHQ exclusions that test attacker-controlled text are documented as known weaknesses.
- **ZAAFElegia integration ([#9](https://github.com/rifqifitriady/ZAAFVesper/pull/9)).**
  - A versioned record format (`zaafvesper.elegia/1`) with a published JSON schema; `--elegia-dir` writes rotating segment files (up to 8 GiB, never deleting a segment younger than 7 days; a full directory stops capture and raises `elegia_dir_full`).
  - Four correlation rules for ZAAFElegia's M2, and an end-to-end CI job that builds ZAAFElegia at a pinned commit. No ZAAFElegia M2 owner has confirmed the format yet.
- **Fixed on the way:** tests that read the host's DNS resolver or depended on fixed pids; `rules/defense_impairment_sensor_degraded.yml` 1.2.1 now describes the eBPF, Sysmon and ZAAFElegia conditions.
- **Not run live:** 21 rules and 25 Atomic tests that cannot run on a runner, the eBPF object on x86, kernels below 6.8, ZAAFElegia under a LaunchDaemon as root.

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
