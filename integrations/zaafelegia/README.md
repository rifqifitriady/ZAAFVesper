# ZAAFVesper → ZAAFElegia

[ZAAFElegia](https://github.com/rifqifitriady/ZAAFElegia) runs Sigma rules directly over NDJSON and writes OCSF Detection Findings. ZAAFVesper can feed it in two ways:

| Flag | What it writes |
|---|---|
| `--elegia-dir DIR` | The same records in rotating segment files for scheduled hunts: `events-<UTC>.ndjson`, closed at `--elegia-segment-bytes` (64 MiB) or `--elegia-segment-age` (15 min), oldest deleted beyond `--elegia-keep-bytes` (1 GiB). The open segment is `events-<UTC>.ndjson.part`, so `zaaf hunt DIR/*.ndjson` never reads a half-written file. |
| `--elegia-out PATH` or `--elegia-out -` | Every event (after exclusions), one JSON object per line, with **Sigma field names** (`Image`, `CommandLine`, `ParentImage`, `DestinationIp`, `DestinationPort`, `Initiated`, …) plus `logsource.product`, `logsource.category`, a Sysmon-compatible `EventID` and `UtcTime`. |
| `--alerts-ocsf PATH` | ZAAFVesper's own alerts as OCSF 1.5.0 Detection Findings (class 2004), in the same shape as `zaaf hunt -o ndjson`. |

## What is in this directory

| Path | What it is |
|---|---|
| [`schema/zaafvesper-elegia-v1.schema.json`](schema/zaafvesper-elegia-v1.schema.json) | JSON Schema of every record (`zaafvesper.schema = "zaafvesper.elegia/1"`). |
| [`pipeline/zaafvesper.yml`](pipeline/zaafvesper.yml) | ZAAFElegia pipeline preset (`zaaf hunt -p`), generated from `pkg/sigmamap`. |
| [`rules/base/`](rules/base/) | Six Sigma rules for ZAAFVesper's macOS events, each with a `name:` for correlations. |
| [`rules/correlation/`](rules/correlation/) | Four Sigma correlation rules (for ZAAFElegia milestone M2). |
| [`samples/`](samples/) | Sample scenarios (`macos-scenarios.ndjson`), their generator and the expected findings. |
| [`example/`](example/) | The small verified example below. |

## Record schema (zaafvesper.elegia/1)

Each line is one JSON object:
- **Sigma fields** of the event's logsource category, flat and named as in Sigma's taxonomy (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `DestinationIp`, `Initiated`, `QueryName`, ...), from `pkg/sigmamap`;
- `logsource.product` and `logsource.category`, a Sysmon-compatible `EventID`, `UtcTime` (Sysmon's format, UTC) and `Computer` (the host; `run` uses the machine's name, `replay` only with `--elegia-host`);
- everything ZAAFVesper adds under `zaafvesper`: `schema`, the canonical event `name`, `seq`, `source`, `platform`, `identity: unverified` when the process identity came from the kernel rather than an exec event, and `proc` / `parent` with the macOS code-signing identity (`signing_id`, `team_id`, `cs_category`, `is_platform`, `is_signed`) and the kernel unique id (`unique_id`).

**Versioning.** Adding a field or a category keeps `zaafvesper.elegia/1`. Renaming, removing or retyping a field makes `zaafvesper.elegia/2`, and the old schema file stays. `TestElegiaRecordsMatchSchema` (pkg/output) validates the encoder's output for every event type against the schema file, so the two cannot drift.

## The `zaafvesper` pipeline preset

ZAAFVesper already writes Sigma names, so standard Sigma rules need no mapping. The preset adds:
- the identity mapping of every Sigma field ZAAFVesper emits, so `zaaf` does not warn that they are "not mapped by any pipeline";
- on macOS, `ProcessGuid` and `ParentProcessGuid` fall back to the kernel unique ids (macOS has no ProcessGuid), so correlations can group by process;
- on macOS, names for the code-signing identity that Sigma has no fields for: `SigningId`, `TeamId`, `SigningCategory`, `PlatformBinary`, `Signed`, `ParentSigningId`, `ParentPlatformBinary`, `IdentityUnverified`, `ZaafEventName`.

```bash
zaaf hunt -p integrations/zaafelegia/pipeline/zaafvesper.yml -r integrations/zaafelegia/rules /var/db/zaafvesper/elegia/*.ndjson
```

The same preset is proposed to ZAAFElegia as `pipelines/zaafvesper.yml`; the copy here is the one the CI test uses.

## Scheduled hunts

Run the sensor with `--elegia-dir /var/db/zaafvesper/elegia` and hunt the closed segments on a schedule, for example from a root LaunchDaemon with `StartInterval` 900. ZAAFElegia has no daemon or network ingest (its v0.1 scope); segments are the file-based hand-over.

The segments are `0600` in a `0700` directory, root-owned, because they hold command lines, so the hunt runs as root. **Everything that root hunt executes or reads as instructions must be root-owned too**, or malware running as your account could change the rules (blinding the hunt) or swap the binary (running code as root):
- `zaaf` installed as `/usr/local/bin/zaaf`;
- the rules in `/usr/local/share/zaafelegia/rules`;
- the preset as `/usr/local/share/zaafelegia/zaafvesper.yml`;
- findings written into a root-owned `0700` directory.

All of these must be `root:wheel` and not group- or world-writable, never in a user's checkout:

```bash
sudo /usr/local/bin/zaaf hunt -p /usr/local/share/zaafelegia/zaafvesper.yml -r /usr/local/share/zaafelegia/rules \
  -o ndjson /var/db/zaafvesper/elegia/*.ndjson >> /var/db/zaafvesper/hunts/findings.ndjson
```

Records are bounded before they reach `zaaf`: every string is capped at 2 KiB, every list at 64 items, and every record at 64 KiB. `zaaf` is memory-safe Rust and bounds its own input lines (8 MiB).

## Correlation rules (ready for ZAAFElegia M2)

| Rule | Type | Groups by | Fires on |
|---|---|---|---|
| `zv_corr_macos_download_chmod_execute` | temporal_ordered, 10m | Computer, User | curl/wget over HTTP, then chmod +x in a temp folder, then a process running from a temp folder |
| `zv_corr_macos_discovery_burst` | value_count of Image ≥ 3, 1m | Computer, ParentProcessGuid | three or more different discovery commands from one parent |
| `zv_corr_macos_shell_many_ports` | value_count of DestinationPort ≥ 3, 10m | Computer, ProcessGuid | one shell connecting out to three or more ports |
| `zv_corr_macos_quarantine_strip_burst` | event_count ≥ 5, 5m | Computer, User | five or more quarantine removals by one user |

ZAAFElegia 0.0.1 (and `main` at `16ba447`) parses these and skips them with "correlation support arrives in milestone M2". Their base rules run today.

The correlations set `generate: false` (the Sigma default). Under ZAAFElegia's M2 decision M2-D8, a base rule referenced only by such correlations stops alerting on its own once correlations run, so the correlation becomes the alert. The base rules match on `EventID` as well as their own fields, so that each one only counts records of its own category.

## Tested in CI

[`elegia-e2e`](../../.github/workflows/elegia-e2e.yml) runs on every push and pull request:
- it builds `zaaf` at a pinned ZAAFElegia commit;
- it turns the sample scenarios into a capture and runs `zaafvesper replay` into `--elegia-dir` segments (small, so several rotate) and into a live `--elegia-out -` pipe;
- it checks that `zaaf check` reports no rule error;
- it checks that `zaaf hunt` finds exactly what [`samples/expected.json`](samples/expected.json) lists, through both paths.

The correlation expectations are reported as PENDING until the pinned ZAAFElegia evaluates correlations. Raise the pin when M2 ships and they become required.

## Live: pipe the sensor into `zaaf hunt`

```bash
sudo /usr/local/sbin/zaafvesper run --elegia-out - | zaaf hunt -r path/to/sigma/rules -o ndjson -
```

With `--elegia-out -` the events own stdout, so ZAAFVesper prints its console alerts on stderr. If `zaaf` reads too slowly, ZAAFVesper drops lines (counted, and reported as `SensorDegraded` `elegia_out_dropped`) rather than stall the sensor.

**Not verified:** this live pipe needs root (`run` uses eslogger) and has not been run here. What has been verified is the format: the example below was produced by the same encoder `--elegia-out` uses (`pkg/output.EncodeSigma`; a golden-file test keeps it in sync) and was hunted with a real ZAAFElegia build.

## Verified example

[`example/events.ndjson`](example/events.ndjson) holds four events as `--elegia-out` writes them: a `curl` download over plain HTTP, a `bash` with an outbound connection to `203.0.113.9:4444` (a reverse shell), `python3` talking HTTPS, and a `Fork` (no Sigma category, so it carries only `Image`, `ProcessId` and `User`). The second line looks like this:

```json
{"Computer":"mac-01","DestinationIp":"203.0.113.9","DestinationPort":4444,"EventID":3,"Image":"/bin/bash","Initiated":"true","ProcessId":702,"Protocol":"tcp","SourceIp":"192.168.1.20","SourcePort":50111,"User":"rifqi","UtcTime":"2026-11-09 08:30:02.000","logsource":{"category":"network_connection","product":"macos"},"zaafvesper":{"name":"NetworkConnect","platform":"macos","proc":{"cs_category":"platform","is_platform":true,"is_signed":true,"pid":702,"pidversion":7702,"signing_id":"com.apple.bash","unique_id":41702},"schema":"zaafvesper.elegia/1","seq":102,"source":"netpoll"}}
```

[`example/sigma/`](example/sigma/) holds two small Sigma rules written for this example. Run on 9 Nov 2026 (UTC+7) with ZAAFElegia 0.0.1, a release build of commit `c2e0212` (`cargo build --release --locked -p zaaf-cli`, binary `target/release/zaaf`): Re-run on 9 Nov 2026 with the schema `zaafvesper.elegia/1` records and ZAAFElegia `main` at `16ba447`: the same two matches.

```bash
zaaf check integrations/zaafelegia/example/sigma
# checked 2 files: 2 rules, 0 filters, 0 correlations skipped, 0 errors, 0 warnings

zaaf hunt -r integrations/zaafelegia/example/sigma -o table integrations/zaafelegia/example/events.ndjson
```

```
| Time                      | Level  | Rule                                 | Title                                                  |
| 2026-11-09T08:30:00+00:00 | medium | 7d2e9b14-3c5a-4f8e-a1b6-0e4d2c9f7a31 | curl downloads over plain HTTP (macOS)                 |
| 2026-11-09T08:30:02+00:00 | high   | 0c1f5e3a-4f6b-4e0f-9d8a-2b7c6a1e9f40 | Unix shell with an outbound network connection (macOS) |
4 events, 0 malformed records, 0 unreadable inputs, 2 rules, 2 matches
```

(Author and Source columns trimmed.) Both expected events match; the HTTPS `python3` connection and the `Fork` do not. ZAAFElegia read the finding time from `UtcTime`.

## Field mapping

The field names come from `pkg/sigmamap` (the categories `process_creation`, `process_termination`, `file_event`, `file_delete`, `file_rename`, `network_connection`, `dns_query`, `image_load`, `driver_load`, `registry_*`, `create_remote_thread`, `process_access`, `pipe_created`, `wmi_event`, `process_tampering`, `create_stream_hash`). `Initiated` is `"true"` for outbound and `"false"` for inbound connections; a listening socket has no `Initiated`. Booleans are written as the strings `"true"`/`"false"`, as Sysmon does; pids and ports are numbers. Empty values are left out.

## Limits

- **ZAAFElegia 0.0.1 does not filter events by a rule's `logsource`.** A Sigma rule written for `process_creation` is evaluated against every event, so a rule that only tests `Image` can also match that process's network or file events. Write rules with fields specific to their category (as the examples do with `Initiated` and `CommandLine`), or split the stream by `logsource.category` before hunting.
- macOS network events come from socket polling: connections shorter than `--net-interval` are missed, and there is no DNS (`dns_query`) on macOS. See [docs/operations.md](../../docs/operations.md#network-telemetry-socket-polling).
- ZAAFElegia has no network ingest yet; ZAAFVesper writes to a file, a pipe or segment files.
- **Logsource filtering is an engine feature ZAAFElegia does not have yet.** A pipeline cannot restrict a rule to events of its own category (pySigma's `add_condition` does this for Sysmon by adding `EventID`). Every record carries `logsource.category` and `EventID`, ready for it; until then, write rules with category-specific fields.
