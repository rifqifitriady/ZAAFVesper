# Sysmon decoder (Windows and Linux)

`pkg/source/sysmon` turns one Sysmon event, rendered as XML, into a canonical
`event.Event`. Windows Sysmon (through the event log, `pkg/source/winevt`) and
Sysmon for Linux (through journald, `pkg/source/sysmonlinux`) share the schema
and the rendering, so one decoder serves both. `evt.platform` comes from the
provider name (`Microsoft-Windows-Sysmon` → windows, `Linux-Sysmon` → linux);
any other provider is refused.

## Sources

- Event IDs and field names: Microsoft Learn, *Sysmon* (Sysinternals),
  <https://learn.microsoft.com/sysinternals/downloads/sysmon#events>, and the
  schema Sysmon prints with `sysmon -s` (schema 4.90, Sysmon 15).
- Sysmon for Linux event format (the same XML in syslog, provider `Linux-Sysmon`):
  <https://github.com/microsoft/SysmonForLinux>.
- Sigma field names per log source: `pkg/sigmamap` (the shared contract);
  `TestSigmaFieldsResolve` checks every Sigma field a fixture carries resolves
  on the decoded event.

The fixtures in `testdata/` were written by hand from those field lists (the
values are invented, the field names and formats are Sysmon's). They are not
captures from a live host. Each has a reviewed `.golden.json`.

## Event mapping

| Sysmon ID | Sysmon event | Canonical event | Main fields |
|---|---|---|---|
| 1 | Process creation | CreateProcess | `ps.*` (exe, cmdline, args, cwd, guid, hashes, integrity, company, product, description, original_name), parent stub (`ps.parent.*`, `ps.ppid`) |
| 3 | Network connection | NetworkConnect (Initiated=true) / NetworkAccept | `net.proto`, `net.direction` (outbound/inbound), `net.sip`, `net.sport`, `net.dip`, `net.dport`, `net.dhost` |
| 5 | Process terminated | TerminateProcess | `ps.*` |
| 6 | Driver loaded | DriverLoad | `image.path`, `image.signed`, `image.signature`, `image.signature_status`, `image.hashes` (no process) |
| 7 | Image loaded | ImageLoad | `ps.*`, `image.*`; the module's version info in `evt.arg[file_version|description|product|company|original_file_name]` |
| 8 | CreateRemoteThread | CreateRemoteThread | source `ps.*`, `target.ps.*`, `evt.arg[start_address|start_module|start_function|new_thread_id]` (`start_module` and `start_function` are always set, empty when Sysmon reports `-`) |
| 10 | ProcessAccess | OpenProcess | source `ps.*`, `target.ps.*`, `evt.arg[granted_access|call_trace|source_thread_id]` |
| 11 | FileCreate | CreateFile | `file.path`, `evt.arg[creation_utc_time]` |
| 12 | Registry object create/delete | RegistryCreateKey / RegistryDeleteKey (EventType Create*/Delete*) | `registry.key`, `registry.value` (DeleteValue), `evt.arg[event_type]` |
| 13 | Registry value set | RegistrySetValue | `registry.key`, `registry.value` (last key component), `registry.data` |
| 14 | Registry key/value rename | RegistryRename | `registry.key`, `registry.new_key` |
| 15 | FileCreateStreamHash | FileStreamCreate | `file.path`, `evt.arg[hash|contents]` |
| 17 / 18 | Pipe created / connected | PipeCreate / PipeConnect | `evt.arg[pipe_name|event_type]` |
| 19 / 20 / 21 | WMI filter / consumer / binding | WMIEvent | `ps.username`, `evt.arg[event_type|operation|event_namespace|name|query|type|destination|consumer|filter]` |
| 22 | DNS query | DNSQuery | `dns.query`, `dns.status`, `dns.answers` (QueryResults split at `;`) |
| 23 / 26 | File delete (archived) / delete detected | DeleteFile | `file.path`, `evt.arg[hashes|is_executable|archived]` |
| 25 | Process tampering | ProcessTamper | `evt.arg[type]` |

Every event also carries `evt.arg[sysmon_event_id]` and, when set,
`evt.arg[rule_name]`. Event 1 also keeps Sysmon's view of the parent in
`evt.arg[parent_image|parent_command_line|parent_user]`, because `ps.parent.*`
comes from the process table and is nil when the table does not know the parent.

Not mapped (counted as `unsupported`): 2 (file creation time changed),
4 (Sysmon service state), 9 (raw access read), 16 (Sysmon configuration change),
24 (clipboard), 27–29 (file block), 255 (error).

## Conventions

- Sysmon writes `-` for an unknown value; it is treated as absent (the field
  resolves to nil).
- Times: `UtcTime` (`2006-01-02 15:04:05.000`, UTC), else `System/TimeCreated`.
  `evt.seq` is the EventRecordID.
- Users: Sysmon gives an account name (`DOMAIN\user` on Windows), not a uid:
  `ps.username` is set and `ps.uid`/`ps.euid` are -1.
- `ps.args` is split from the command line: Microsoft C runtime rules on
  Windows, white space on Linux (Sysmon for Linux joins argv with spaces).
  `ps.cmdline` is exact.
- `Proc.PIDVersion` is a 32-bit hash of the ProcessGuid, so the process table
  tells a recycled pid from the process that had it before.

## Parser bounds

At most 1 MiB per event, 128 `<Data>` items, 128 KiB per decoded value,
nesting depth 8 and 4096 XML tokens. A DTD or other directive, an encoding
other than UTF-8, an element inside `<Data>`, a second root element, a
duplicate `<Data Name>`, or a repeated `System`, `EventData` or System header
element (Provider, EventID, EventRecordID, TimeCreated, Execution, Security,
...) is refused. `encoding/xml` never resolves external entities.

Characters XML forbids (control characters other than tab, CR and LF,
U+FFFE/U+FFFF, invalid UTF-8, and `&#..;` references to them) are replaced by
U+FFFD before parsing (`Sanitize`): a command line holding one cannot make the
event disappear. Events that still cannot be read, or that exceed the bounds,
raise a `sysmon_events_unreadable` sensor-degraded alert (at most one a
minute), as gaps in EventRecordID raise `sysmon_events_dropped`.
`FuzzDecode` exercises the parser (`make fuzz`).

## Provenance

The decoder also returns who wrote the event (`System/Execution/@ProcessID`,
`System/Security/@UserID`). On Windows any program can write events under
Sysmon's provider name, so the Windows source accepts an event only from the
process of a running Sysmon service (Service Control Manager) as LocalSystem;
anything else is dropped and raises `sysmon_events_untrusted`. On Linux the
journald source accepts only records whose journald-set fields say root in
`sysmon.service`.

## Process identity (Binder)

`Binder` ties a ProcessGuid to the kernel's start stamp of the process
(Windows: creation FILETIME; Linux: start ticks in `/proc/<pid>/stat`) when the
create event is read, provided the process now holding the pid was created no
later than the event. The kill response compares that stamp again right
before killing. See `binder.go` and the platform READMEs in `packaging/`.
