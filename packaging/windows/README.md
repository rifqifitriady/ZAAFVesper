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
4. **Create the service** (LocalSystem, automatic start, restart on failure):
   ```
   sc.exe create ZAAFVesper start= auto obj= LocalSystem binPath= "\"C:\Program Files\ZAAFVesper\zaafvesper.exe\" run --config \"C:\Program Files\ZAAFVesper\zaafvesper.yml\" --rules \"C:\Program Files\ZAAFVesper\rules\" --output-dir C:\ProgramData\ZAAFVesper\logs --no-console"
   sc.exe failure ZAAFVesper reset= 86400 actions= restart/5000/restart/30000//
   sc.exe sidtype ZAAFVesper unrestricted
   sc.exe start ZAAFVesper
   ```
   A service has no console: start-up messages and errors go to
   `C:\ProgramData\ZAAFVesper\logs\service.log`, alerts to `alerts-*.jsonl` in
   the same folder. ZAAFVesper creates the folder with a DACL that only SYSTEM and
   Administrators can use. If `ProgramData\ZAAFVesper` already exists with other
   rights (for example created by another user beforehand), it refuses to start.
5. **Check**: `Get-Content C:\ProgramData\ZAAFVesper\logs\service.log` shows the
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
Critical processes (`IsProcessCritical`: terminating one stops Windows), System,
smss, csrss, wininit, winlogon, services, lsass, Sysmon, Defender and ZAAFVesper
itself are never killed. Processes that were running before ZAAFVesper started
are never killed.

## Known limits

- Sysmon gives a user name (`DOMAIN\user`), not a uid: `ps.uid` is -1.
- `ps.ancestors_untrusted` is a macOS notion; on Windows it is always true.
- Parent links of processes running before the sensor started come from a
  Toolhelp32 snapshot; Windows reuses parent pids, so they are a best effort.
- YARA is not available on Windows (the build is pure Go, without cgo).
- Event log overwrites and dropped events show as `sysmon_events_dropped`
  sensor-degraded alerts (gaps in EventRecordID).
