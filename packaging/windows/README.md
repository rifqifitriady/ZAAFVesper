# ZAAFVesper on Windows (Sysmon via the event log)

> **Status: untested on a real host.** Everything here is cross-compiled from
> macOS (`CGO_ENABLED=0 GOOS=windows`) and the Sysmon decoder is tested against
> fixtures built from Microsoft's documented event schema. The event log
> subscription, the service and the kill path have not been run on Windows yet.
> Treat this as a preview.

## How it works

Sysmon (Microsoft Sysinternals) writes events to the
`Microsoft-Windows-Sysmon/Operational` event log channel. ZAAFVesper subscribes
to that channel with `EvtSubscribe` (wevtapi.dll, loaded from System32, no cgo),
renders each event as XML and decodes it with the same decoder as on Linux
(`pkg/source/sysmon`). Rules use the canonical fields, and the Sigma field names
map onto them (`pkg/sigmamap`).

## Install

Run in an **elevated** PowerShell. Paths below are the recommended layout:
binary, configuration and rules in `C:\Program Files\ZAAFVesper` (only
Administrators, SYSTEM and TrustedInstaller can write there by default),
output in `C:\ProgramData\ZAAFVesper\logs`.

1. **Install Sysmon** from <https://learn.microsoft.com/sysinternals/downloads/sysmon>
   (check the download's Microsoft signature) with a configuration. Recommended
   starting point: **sysmon-modular** by Olaf Hartong,
   <https://github.com/olafhartong/sysmon-modular> (use its generated
   `sysmonconfig.xml`; it is linked here, not copied into this repository).
   ZAAFVesper decodes event IDs 1, 3, 5, 6, 7, 8, 10, 11, 12–14, 15, 17, 18,
   19–21, 22, 23, 25 and 26; a config that excludes an ID (sysmon-modular keeps
   7, image load, narrow because of its volume) means rules on that event never fire.
   ```
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
2. **Build** on any machine as your normal user: `make build-windows`
   (gives `bin\zaafvesper-windows-amd64.exe` and `-arm64.exe`).
3. **Copy** the binary, configuration and rules:
   ```
   New-Item -ItemType Directory 'C:\Program Files\ZAAFVesper' | Out-Null
   Copy-Item bin\zaafvesper-windows-amd64.exe 'C:\Program Files\ZAAFVesper\zaafvesper.exe'
   Copy-Item configs\zaafvesper.yml 'C:\Program Files\ZAAFVesper\zaafvesper.yml'
   Copy-Item -Recurse rules 'C:\Program Files\ZAAFVesper\rules'
   icacls 'C:\Program Files\ZAAFVesper'
   ```
   `icacls` must show write rights (`F`, `M`, `W`) only for SYSTEM,
   Administrators and TrustedInstaller. Running elevated, ZAAFVesper refuses to
   start otherwise: it checks the owner and the DACL of the binary, the
   configuration, the rules and every folder above them, and refuses symbolic
   links and junctions inside them.

   What this check does **not** cover: administrators are trusted (as root is
   on macOS and Linux), so their privileges such as SeBackupPrivilege,
   SeRestorePrivilege or taking ownership are not a refusal; mandatory
   integrity labels are not looked at; only a file's main data stream is read
   (alternate data streams are ignored); and allow entries that only apply to
   files created later (inherit-only) are skipped, because each file is checked
   again when it is read.
4. **Create the output folder** with an access list that only SYSTEM and
   Administrators can use (any user can create folders in `C:\ProgramData`, so
   create it before anyone else can, and check it):
   ```
   New-Item -ItemType Directory 'C:\ProgramData\ZAAFVesper' | Out-Null
   icacls 'C:\ProgramData\ZAAFVesper' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'
   icacls 'C:\ProgramData\ZAAFVesper'
   ```
   If the folder already existed, delete it first unless you know who made it.
   ZAAFVesper refuses to start when the folder, or any folder above it, is a
   junction or symbolic link, or when anyone but SYSTEM, Administrators or
   TrustedInstaller owns it or can change it.
5. **Create the service** (LocalSystem, automatic start, restart on failure):
   ```
   sc.exe create ZAAFVesper start= auto obj= LocalSystem binPath= "\"C:\Program Files\ZAAFVesper\zaafvesper.exe\" run --config \"C:\Program Files\ZAAFVesper\zaafvesper.yml\" --rules \"C:\Program Files\ZAAFVesper\rules\" --output-dir C:\ProgramData\ZAAFVesper\logs --no-console"
   sc.exe failure ZAAFVesper reset= 86400 actions= restart/5000/restart/30000//
   sc.exe sidtype ZAAFVesper unrestricted
   sc.exe start ZAAFVesper
   ```
   A service has no console: start-up messages and errors go to
   `C:\ProgramData\ZAAFVesper\logs\service.log`, alerts to `alerts-*.jsonl` in
   the same folder. ZAAFVesper creates `logs` with a DACL that only SYSTEM and
   Administrators can use.
6. **Check**: `Get-Content C:\ProgramData\ZAAFVesper\logs\service.log` shows the
   rules enabled and the events subscribed.

Uninstall: `sc.exe stop ZAAFVesper; sc.exe delete ZAAFVesper`, then remove the
two folders.

For a quick test without the service, run `zaafvesper.exe run` from an elevated
console (alerts print there; Ctrl+C stops it).

## Why LocalSystem

Reading the Sysmon channel needs an administrator or SYSTEM, and the kill
response must open other users' processes. A less privileged virtual service
account could read the channel after its access list is changed (`wevtutil sl`),
but could not kill; that option is not built yet.

## Kill response on Windows

With `--enable-response`, a rule's `kill` action is carried out only when the
process's Sysmon create event (event 1) was seen and, right then, the process
holding that pid had a creation time no later than the event (so the pid had not
been reused); the event carries the same ProcessGuid; and at kill time the
creation time read on the very handle that is then terminated is still the same.
Critical processes (`IsProcessCritical`: terminating one stops Windows) and
the images of smss, csrss, wininit, winlogon, services, lsass, LsaIso,
fontdrvhost and dwm in `%SystemRoot%\System32`, Sysmon in `%SystemRoot%`,
Defender and ZAAFVesper itself are never killed. Protection is by full path,
compared without regard to case, not by name: malware called `lsass.exe` in a
temporary folder stays killable. Processes that were running before ZAAFVesper
started are never killed.

## Forged events

Any program can write events under Sysmon's provider name. ZAAFVesper accepts
an event only when the event log recorded it as written by LocalSystem from
the process of a running Sysmon service (`Sysmon64`, `Sysmon` or `Sysmon64a`,
asked from the Service Control Manager). Other events are dropped and raise a
`sysmon_events_untrusted` sensor-degraded alert. A Sysmon installed under
another service name is not recognised (all its events are then reported as
untrusted): rename it back or open an issue.

## Response actions on Windows

Of the response actions, Windows supports `kill` only. `quarantine_file`,
`requarantine`, `remove_persistence` and `isolate_process` use the macOS quarantine
attribute, launchctl and pf: on Windows they are refused (`refused-unsupported`,
nothing is changed), `zaafvesper run` warns at start which enabled rules ask for
them, and the alert is still raised.

## Known limits

- Sysmon gives a user name (`DOMAIN\user`), not a uid: `ps.uid` is -1.
- `ps.ancestors_untrusted` is a macOS notion; on Windows it is always true.
- Parent links of processes running before the sensor started come from a
  Toolhelp32 snapshot; Windows reuses parent pids, so they are a best effort.
- YARA is not available on Windows (the build is pure Go, without cgo).
- The SIEM and ZAAFElegia outputs (`--syslog`, `--webhook`, `--alerts-ocsf`,
  `--elegia-out FILE`) are not available on Windows yet: they need the on-disk
  spool, which is Unix-only. `zaafvesper run` refuses them at start-up with a
  message saying so. Alerts are written to `--output-dir`.
- Event log overwrites and dropped events show as `sysmon_events_dropped`
  sensor-degraded alerts (gaps in EventRecordID).
