# ZAAFVesper

**Behaviour-driven security sensor for macOS** — realtime detection of attacker tradecraft from Endpoint Security events, with a Fibratus-style rule language, sequence correlation, MITRE ATT&CK mapping, YARA scanning, forensic capture/replay and optional response.

> *Vesper*: the evening watch. A sensor that stays awake after dark and raises the alarm when something is off.

```
eslogger ─▶ decode ─▶ process tree ─▶ exclusions ─▶ rule engine ─▶ alerts (console, JSONL)
                                                       │   ├─▶ response (kill, opt-in)
                       YARA scanner ◀── exec / file ───┘   └─▶ capture (.rcap)
                            └── YaraMatch events ──▶ rule engine
replay (.rcap or raw eslogger JSON) ───────────────────▶ same pipeline, no root needed
```

## Why

Inspired by [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) (Windows/ETW) and validated against [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team): every built-in rule names the atomic test that proves it. Telemetry noise control borrows the modular include/exclude idea of [sysmon-modular](https://github.com/olafhartong/sysmon-modular).

## Requirements

- macOS 13+ (developed on macOS 26, Apple Silicon). `/usr/bin/eslogger` ships with the OS.
- Live mode: root **and** Full Disk Access for the terminal (or the launching process).
- Build: Go 1.27+. YARA support: `brew install yara pkg-config`. Root builds link libyara **statically** (`make build-yara`).

## Quick start (development, no root)

```bash
make build                     # pure Go, YARA disabled
./bin/zaafvesper rules validate rules
./bin/zaafvesper rules test rules   # every rule against its fixtures
./bin/zaafvesper replay session.rcap --rules rules        # replay a capture or raw eslogger JSON
./bin/zaafvesper coverage --rules rules --navigator -     # ATT&CK Navigator layer on stdout
```

## Install and run live (root)

```bash
sudo make install              # or: sudo make install YARA=1  (static YARA build)
sudo /usr/local/sbin/zaafvesper run --capture /var/log/zaafvesper/session.rcap --json /var/log/zaafvesper/alerts.jsonl
```

`make install` puts the binary in `/usr/local/sbin/zaafvesper` and rules and configuration in `/usr/local/etc/zaafvesper`, all owned by root. Give Full Disk Access to the process that launches ZAAFVesper (Terminal for now; a LaunchDaemon is on the roadmap).

**ZAAFVesper refuses to start as root** unless its binary, configuration, rules and YARA rules, and every directory above them up to `/`, are root-owned and not group/world-writable. Running `sudo` from a user-owned checkout is refused by design: anything your normal account can modify must never be executed or trusted by root. For the same reason a YARA build that loads a Homebrew `libyara.dylib` is refused as root (fail closed). Use the static `YARA=1` install, or `--no-yara`.

### Response (kill)

Response is **off by default**. `--enable-response` lets rules that declare `action: [{name: kill}]` terminate the offending process; `--dry-run-response` only logs what would be killed. Before a kill ZAAFVesper re-reads the process from the kernel and refuses when the start time or executable no longer matches the event (pid reuse), when the target is an Apple platform binary or lives under `/System`, `/usr/libexec`, `/sbin` or `/usr/sbin`, or when its identity was only seeded at start-up (unverified). Kills are limited to 10 per minute. `replay` can never kill. Endpoint Security via eslogger is notify-only: ZAAFVesper reacts *after* the behaviour, it cannot block it beforehand.

### Data handling

Captures (`--capture`) and JSONL alerts (`--json`) are created `0600`, never overwrite an existing file, and store environment variable **names** plus `DYLD_*` values only (other values are `<redacted>`; `--keep-env` keeps everything). Command lines are kept: treat captures as secret material. A capture stops at `--capture-max-bytes` (default 2 GiB of uncompressed JSON) while the sensor keeps running. Repeats of the same rule for the same process within `--dedup-window` (10 s) are suppressed and counted.

### Telemetry notes

`WriteFile` comes from eslogger's close-with-modification event (one event per modified file). `source.subscribe_write: true` also takes every `write(2)`, which can flood the sensor. Command lines are capped at 64 KiB and environments at 16 KiB per event (`evt.arg[args_truncated]`), and the process table at 128 MiB.

## Writing rules

```yaml
name: Gatekeeper quarantine attribute removed
id: <uuid>
version: 1.0.0
labels: {tactic.id: TA0005, technique.id: T1553.001, technique.name: Gatekeeper Bypass}
condition: >
  delete_xattr and evt.arg[xattr] = 'com.apple.quarantine' and not ps.is_platform
output: "%ps.exe removed quarantine from %file.path"
severity: medium
tests:
  atomic: [fb3d46c6-9480-4803-8d7d-ce676e1f1a9b]
```

Sequences correlate several events:

```
sequence maxspan 2m
  |create_file and file.path imatches ('/tmp/*', '/Users/Shared/*')| by file.path
  |spawn_process and not ps.is_signed| by ps.exe
```

See [docs/plans/2026-11-07-zaafvesper-mvp.md](docs/plans/2026-11-07-zaafvesper-mvp.md) for the full language and [docs/rules.md](docs/rules.md) for the built-in rules.

## Security of the sensor itself

ZAAFVesper runs as root, so:

- Binary, rules, macros, YARA rules and config are checked (file and every ancestor directory) before anything is parsed, then each file is opened once with `O_NOFOLLOW` and parsed from that same descriptor.
- The only child process is `/usr/bin/eslogger` (pinned as root), with a fixed argv, minimal environment and `cwd /`.
- Event strings are sanitised (C0/C1, ESC, bidi controls) before reaching the terminal; regexes are RE2; globs are linear.
- Memory is bounded: per-event argv/env caps, a byte budget for the process table and for partial sequences, bounded YARA queue with exec scans prioritised.
- YARA opens scan targets by walking the path with `openat(O_NOFOLLOW)`, scans regular files only, and keys its cache on ctime and cdhash (mtime is attacker-settable).
- Allow-lists in the built-in rules trust only Apple platform identity or a vendor's specific Team ID + signing ID pair; `is_signed` alone (true for self-signed code) is never trust.

Known residual risk: Endpoint Security does not report whether a signing certificate chains to Apple, so a self-signed binary that embeds another vendor's Team ID would need live validation (see docs/rules.md).

## Roadmap

Windows adapter (Sysmon with sysmon-modular configs) · Linux · network telemetry (NetworkExtension) · native ES client with AUTH (blocking) · LaunchDaemon installer · SIEM/webhook outputs · Sigma import.

## License

Apache-2.0.
