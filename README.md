<div align="center">

<img src="docs/assets/banner.svg" width="100%" alt="ZAAFVesper: behaviour-driven security sensor for macOS">

<br>

[![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-0A0D26?style=for-the-badge&logo=apple&logoColor=white)](#requirements) [![Go](https://img.shields.io/badge/Go-1.27-1FE5C3?style=for-the-badge&logo=go&logoColor=0A0D26)](go.mod) [![License](https://img.shields.io/badge/license-Apache--2.0-9D6BFF?style=for-the-badge)](LICENSE) [![Status](https://img.shields.io/badge/status-pre--release-FF3EC8?style=for-the-badge)](#project-status)

[![Rules](https://img.shields.io/badge/detection%20rules-56-3B8EFF?style=flat-square)](docs/rules.md) [![Fixtures](https://img.shields.io/badge/rule%20fixtures-319%20passing-1FE5C3?style=flat-square)](rules/testdata) [![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-41%20techniques-FF3EC8?style=flat-square)](#detection-coverage) [![Atomic](https://img.shields.io/badge/Atomic%20Red%20Team-28%20rules%20linked-9D6BFF?style=flat-square)](https://github.com/redcanaryco/atomic-red-team)

**[Quick start](#quick-start)** · **[How it works](#how-it-works)** · **[Coverage](#detection-coverage)** · **[Writing rules](#writing-rules)** · **[Security](#security-model)** · **[Operations guide](docs/operations.md)**

</div>

---

ZAAFVesper watches what processes on a Mac actually **do**: what they spawn, which files they touch, which secrets they read, how they try to persist. It matches that behaviour against readable rules mapped to MITRE ATT&CK. Events come from Apple's Endpoint Security framework through the built-in `eslogger`. The rule language is modelled on [Fibratus](https://github.com/rabbitstack/fibratus), and every built-in rule ships with test fixtures. Most rules also name the Atomic Red Team test that exercises them.

> *Vesper* is the evening star: a watch that stays awake after dark.

## Project status

> [!WARNING]
> **Pre-release.** Every rule passes its fixtures and the code has been through several independent security review rounds. However, the installer package, the LaunchDaemon, Full Disk Access and real kills have **not yet been validated live as root**. Treat a first install as a test on a machine you can recover. Open items and residual risks are tracked in [docs/security/open-findings.md](docs/security/open-findings.md).

## What it does

<table>
<tr>
<td width="50%" valign="top">

**Behaviour rules, not signatures**<br>
44 rules over process, file, network, persistence, credential and defence-impairment activity. Single-event rules and `sequence` rules correlate steps such as *download → write → execute* by path or process. Twelve more come from SigmaHQ, converted with `zaafvesper sigma convert`.

</td>
<td width="50%" valign="top">

**Trust that cannot be borrowed**<br>
Allow-lists trust only Apple platform binaries, or a vendor's Team ID plus signing ID **with** a verified Developer ID or App Store signing category. A self-signed binary that copies a Team ID is still untrusted.

</td>
</tr>
<tr>
<td valign="top">

**Process-tree context**<br>
Every event carries its parent and ancestry, signing identity and a kernel-unique process id. An unknown, double-forked or untrusted ancestor is treated as suspicious, never as safe.

</td>
<td valign="top">

**YARA, bound to what ran**<br>
Executed and written files are scanned with YARA. Each scan is tied to the inode in the event, so swapping or deleting the binary right after exec is reported instead of silently skipped.

</td>
</tr>
<tr>
<td valign="top">

**Capture and replay**<br>
Record events to a compressed `.rcap` file. Later, replay that capture or raw `eslogger` JSON through the same pipeline, as your normal user, to test rules or investigate.

</td>
<td valign="top">

**Careful, opt-in response**<br>
Off by default. A rule may kill the offending process or its untrusted parent. The pid is first re-checked against the kernel. The kill is refused for a process that was an Apple platform binary when it was detected, and for protected system paths. Kills are rate-limited per rule.

</td>
</tr>
</table>

## How it works

<p align="center"><img src="docs/assets/pipeline.svg" width="100%" alt="Pipeline: Endpoint Security, Decode, Process tree, Rule engine with YARA, then Alerts, Response and Capture; Replay feeds the same pipeline"></p>

1. **Collect.** `/usr/bin/eslogger` streams Endpoint Security notifications as JSON, and ZAAFVesper decodes 24 event types into one platform-neutral event model.
2. **Enrich.** The process tree adds parent, ancestry, signing category and a kernel-unique id to each event. Its memory is bounded, and under pressure it sheds detail before it drops identity.
3. **Detect.** Rules are indexed by event name and evaluated in order; sequences keep bounded partial state. YARA matches come back into the engine as events.
4. **Act.** Every match is written as an alert to the console and to JSONL files with size caps. With `--enable-response`, a match can also trigger a kill. The sensor raises a `SensorDegraded` event whenever its own telemetry suffers.

## See it run

<p align="center"><img src="docs/assets/demo.svg" width="100%" alt="Terminal: zaafvesper replay prints one alert per line with timestamp, severity, rule name and ATT&CK technique"></p>

<sub>Real output of <code>zaafvesper replay</code> over the bundled eslogger test fixtures (synthetic events). Only the first line of each alert is shown, and only a subset of the alerts.</sub>

## Quick start

No root needed: build, check the rules, replay events.

```bash
git clone https://github.com/rifqifitriady/ZAAFVesper.git && cd ZAAFVesper
make build                                   # pure Go, YARA disabled
./bin/zaafvesper rules validate rules        # parse and type-check every rule
./bin/zaafvesper rules test rules            # run every rule against its fixtures
cat testdata/eslogger/*.jsonl > demo.jsonl
./bin/zaafvesper replay --rules rules demo.jsonl
./bin/zaafvesper coverage --rules rules --navigator -   # ATT&CK Navigator layer
./bin/zaafvesper sigma convert ~/sigma/rules/macos -o my-rules --report report.json
```

### Requirements

- macOS 13 or later (developed on macOS 26, Apple Silicon). `eslogger` ships with the OS.
- Go 1.27+. For YARA: `brew install yara pkg-config`, then `make build-yara`. Builds meant to run as root link libyara statically.

### Run it live

Live mode runs as a root LaunchDaemon installed from a script-free package. You build the package as yourself; root only runs Apple's own tools on it.

```bash
make package                 # as your normal user; prints the .pkg path and its SHA-256
# then follow the root-side copy, verify and install steps it prints
```

The [operations guide](docs/operations.md) covers the rest: the verify-then-install sequence, Full Disk Access for the sensor binary, enabling response, upgrade and uninstall, alert files and rotation, sensor health, and everything still to be validated live.

## Network telemetry and outputs

- **Network events without an entitlement.** ZAAFVesper polls the kernel's socket tables every second and right after each exec, and reports each connection or listener once (`NetworkConnect`, `NetworkAccept`). This is polling: a connection that opens and closes between two polls is missed, and macOS shows no DNS without a NetworkExtension.
- **SIEM outputs.** Alerts (and optionally every event) go to syslog over TLS (RFC 5424, pinned CA), an HTTPS webhook or Splunk HEC, with a capped, root-owned disk spool while the endpoint is down.
- **ZAAFElegia.** `--elegia-out -` streams every event with Sigma field names, so `zaafvesper run --elegia-out - | zaaf hunt -r <sigma rules> -` runs Sigma rules over live telemetry; `--alerts-ocsf` writes alerts as OCSF Detection Findings. See [integrations/zaafelegia](integrations/zaafelegia/README.md).

Details and limits: [docs/operations.md](docs/operations.md#network-telemetry-socket-polling). The live sensor paths (polling other users' processes as root, real SIEM receivers, the live pipe into ZAAFElegia) have not been run as root yet.

## Detection coverage

| Tactic | Rules | Examples |
|---|:-:|---|
| Persistence | 10 | Launch Agents and Daemons, Login Items, cron, emond, kernel extensions, shell start-up files |
| Defense Impairment | 8 | Gatekeeper or firewall disabled, quarantine stripped, logs cleared, security tool or sensor stopped |
| Execution | 7 | Script piped into a shell, suspicious AppleScript/JXA, launchctl jobs from temp folders, unsigned binary dropped and run, XProtect and YARA hits, a shell holding a network connection (reverse shell) |
| Credential Access | 6 | Fake password prompts, Keychain dumps, browser credential stores, SSH and GnuPG keys |
| Stealth | 4 | `DYLD_INSERT_LIBRARIES`, task port and ptrace injection, hidden files, shell history deleted |
| Privilege Escalation | 3 | Setuid bits, sudoers changes, TCC database tampering |
| Discovery | 2 | Security software enumeration, scripted system profiling |
| Command and Control | 3 | Download followed by a stdin-fed shell, unsigned binary in a temp folder connecting out, script interpreter to a public IP on an uncommon port |
| Collection | 1 | Non-interactive screen capture |

The table counts the 41 hand-written rules. The 12 converted SigmaHQ macOS rules in `rules/sigma/macos/` add account changes (admin group, root and guest accounts), SIP and Time Machine tampering, Office child processes and JXA or run-only AppleScript. The full list, with false-positive notes and trust policy, is in [docs/rules.md](docs/rules.md). `zaafvesper coverage --navigator` exports an ATT&CK Navigator layer.

## Writing rules

Rules are YAML, and each one ships with fixtures in `rules/testdata/`. This is a built-in rule, shortened:

```yaml
name: Quarantine attribute removed from file
labels:
  tactic.id: TA0112
  technique.id: T1553.001
  technique.name: Gatekeeper Bypass
condition: >
  delete_xattr
  and evt.arg[xattr] = 'com.apple.quarantine'
  and not (apple_trusted_process)
output: "%ps.exe (pid %ps.pid, parent %ps.parent.exe) removed the quarantine attribute from %file.path"
severity: medium
tests:
  atomic: [fb3d46c6-9480-4803-8d7d-ce676e1f1a9b]
```

Sequences correlate steps across events:

```yaml
condition: >
  sequence maxspan 10m
    |create_file and file.path imatches temp_drop_globs| by file.path
    |spawn_process and no_developer_identity and ps.exe imatches temp_drop_globs| by ps.exe
```

- **Operators:** `= != in iin contains icontains startswith endswith matches imatches regex`.
- **Reuse:** shared macros and lists live in `rules/macros/macros.yml`.
- **Missing fields:** a comparison on an absent field is always false, so write trust as a positive check and untrust with `not`.
- **Workflow:** `rules validate`, then `rules test`, before shipping.
- **Sigma:** `zaafvesper sigma convert <dir> -o <rules dir>` converts Sigma rules for macOS, Windows and Linux. Rules it cannot convert exactly (aggregations, unmapped fields, IPv6 `cidr`, `base64` and others) are skipped with a reason. Converted rules need fixtures like any other rule before `rules test` passes. Details in [docs/rules.md](docs/rules.md#sigma-import).
- **Reference:** the language is specified in [docs/plans/2026-11-07-zaafvesper-mvp.md](docs/plans/2026-11-07-zaafvesper-mvp.md).

## Security model

ZAAFVesper runs as root, so the sensor itself is treated as an attack surface. It assumes malware can run as your normal account.

- **Install:** root never builds anything. The package contains no scripts and everything in it is root-owned. The LaunchDaemon cannot be stopped from your normal account.
- **Before start:** the binary, rules and configuration are checked up to `/` for root ownership, mode bits and ACLs that grant write. Each file is then read through one `O_NOFOLLOW` descriptor.
- **Bounded memory:** argv, env, the process table, sequences, the YARA queue and the alert files all have caps. Event text is sanitised before it reaches a terminal.
- **Network and outputs:** socket polling only reads the process table; its events never update it, and identities it reads from the kernel are marked unverified, so they never drive a kill. SIEM tokens are read from a root-owned `0600` file and never logged or spooled; syslog trusts only the CA you name; webhooks follow no redirects.
- **Kills:** a kill is checked against the kernel's unique process id and start time. A process that was an Apple platform binary when it was detected is never killed, and neither is one whose current image lies on a protected system path. A detected process that later execs into an Apple binary such as `/bin/zsh` is still killed once its identity was recorded (only when Endpoint Security reported that it was not an Apple binary when it was detected); an exec that happens before the sensor recorded the process escapes the kill, not the alert.

The status of every finding, with the tests that back it, is in **[docs/security/open-findings.md](docs/security/open-findings.md)**. The largest open item is the build chain: the package is built on the same account it protects, and it is unsigned. Closing that needs a signed and notarized CI build.

## Project layout

```
cmd/zaafvesper/        CLI: run, replay, rules, coverage, sigma
pkg/event/             platform-neutral event model and field registry
pkg/source/eslogger/   eslogger decoder and supervisor
pkg/source/netpoll/    socket polling (network events without an entitlement)
pkg/output/            syslog/TLS, webhook, Splunk HEC, spool, ZAAFElegia and OCSF
pkg/ps/                process tree, ancestry and identity
pkg/filter/ql/         rule language: lexer, parser, compiler
pkg/rules/             rule loading, engine, sequences, fixtures
pkg/sigma/             Sigma parser and converter
pkg/yara/              YARA scanner bound to file identity
pkg/alert/, response/  alert sinks and caps, kill guard rails
rules/                 44 rules, macros, fixtures, YARA signatures
rules/sigma/macos/     12 converted SigmaHQ rules (DRL 1.1)
integrations/          ZAAFElegia example and notes
packaging/             LaunchDaemon plist, newsyslog config
```

## Roadmap

- Windows adapter (Sysmon with sysmon-modular configs), then Linux.
- Complete network telemetry (DNS, short connections) through a NetworkExtension.
- Native Endpoint Security client with AUTH events (blocking, not just notify).
- Signed and notarized package built in CI.

## Acknowledgements

- [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus): the rule language and the overall model.
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team): the tests that rules are linked to.
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma): the converted rules in `rules/sigma/macos/`, under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) (see [rules/sigma/NOTICE.md](rules/sigma/NOTICE.md)).
- [ZAAFElegia](https://github.com/rifqifitriady/ZAAFElegia): the Sigma conformance cases the converter is tested against.
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular): the modular approach to telemetry noise.
- [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) and [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills): attacker tradecraft and detection practice.

## License

[Apache-2.0](LICENSE). The converted SigmaHQ rules in `rules/sigma/` are under the Detection Rule License 1.1.
