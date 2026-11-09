# ZAAFVesper → ZAAFElegia

[ZAAFElegia](https://github.com/rifqifitriady/ZAAFElegia) runs Sigma rules directly over NDJSON and writes OCSF Detection Findings. ZAAFVesper can feed it in two ways:

| Flag | What it writes |
|---|---|
| `--elegia-out PATH` or `--elegia-out -` | Every event (after exclusions), one JSON object per line, with **Sigma field names** (`Image`, `CommandLine`, `ParentImage`, `DestinationIp`, `DestinationPort`, `Initiated`, …) plus `logsource.product`, `logsource.category`, a Sysmon-compatible `EventID` and `UtcTime`. |
| `--alerts-ocsf PATH` | ZAAFVesper's own alerts as OCSF 1.5.0 Detection Findings (class 2004), in the same shape as `zaaf hunt -o ndjson`. |

## Live: pipe the sensor into `zaaf hunt`

```bash
sudo /usr/local/sbin/zaafvesper run --elegia-out - | zaaf hunt -r path/to/sigma/rules -o ndjson -
```

With `--elegia-out -` the events own stdout, so ZAAFVesper prints its console alerts on stderr. If `zaaf` reads too slowly, ZAAFVesper drops lines (counted, and reported as `SensorDegraded` `elegia_out_dropped`) rather than stall the sensor.

**Not verified:** this live pipe needs root (`run` uses eslogger) and has not been run here. What has been verified is the format: the example below was produced by the same encoder `--elegia-out` uses (`pkg/output.EncodeSigma`; a golden-file test keeps it in sync) and was hunted with a real ZAAFElegia build.

## Verified example

[`example/events.ndjson`](example/events.ndjson) holds four events as `--elegia-out` writes them: a `curl` download over plain HTTP, a `bash` with an outbound connection to `203.0.113.9:4444` (a reverse shell), `python3` talking HTTPS, and a `Fork` (no Sigma category, so it carries only `Image`, `ProcessId` and `User`). The second line looks like this:

```json
{"DestinationIp":"203.0.113.9","DestinationPort":4444,"EventID":3,"Image":"/bin/bash","Initiated":"true","ProcessId":702,"Protocol":"tcp","SourceIp":"192.168.1.20","SourcePort":50111,"User":"rifqi","UtcTime":"2026-11-09 08:30:02.000","logsource":{"category":"network_connection","product":"macos"},"zaafvesper":{"name":"NetworkConnect","seq":102,"source":"netpoll"}}
```

[`example/sigma/`](example/sigma/) holds two small Sigma rules written for this example. Run on 9 Nov 2026 (UTC+7) with ZAAFElegia 0.0.1, a release build of commit `c2e0212` (`cargo build --release --locked -p zaaf-cli`, binary `target/release/zaaf`):

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
- ZAAFElegia has no network ingest yet; ZAAFVesper writes to a file or a pipe.
