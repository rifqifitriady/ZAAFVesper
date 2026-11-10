# ZAAFVesper on Linux (Sysmon for Linux via journald)

> **Status: untested on a real host.** Everything here is cross-compiled and
> tested on macOS and in a Linux container (unit tests, the `/proc` process
> table, the pidfd kill). Sysmon for Linux itself, journald and this unit have
> not been run together yet. Treat this as a preview.

## How it works

Sysmon for Linux (eBPF based, from Microsoft) writes each event as the same XML
Windows Sysmon uses into syslog, which journald stores. ZAAFVesper runs
`/usr/bin/journalctl` with a fixed command line and a fixed minimal environment
(PATH, LANG, colours and pager off; nothing inherited), and
accepts only journal records whose **trusted** fields say they came from root in
`sysmon.service` (`_UID=0`, `_SYSTEMD_UNIT=sysmon.service`; journald sets these
from the sender's credentials). A user who runs `logger -t sysmon '<Event>…'`
cannot inject events. The XML goes through the same decoder as on Windows
(`pkg/source/sysmon`), so the same rule fields and Sigma field names apply.

## Install

Run as root. Paths match the macOS layout.

1. **Install Sysmon for Linux** from Microsoft's package repository
   (<https://github.com/microsoft/SysmonForLinux/blob/main/INSTALL.md>) and start it
   with a configuration. Starting points: Microsoft's MSTIC Linux configs
   (<https://github.com/microsoft/MSTIC-Sysmon/tree/main/linux>). ZAAFVesper uses
   event IDs 1, 3, 5, 11 and 23 on Linux; enable at least those.
   Check it runs as `sysmon.service`: `systemctl status sysmon`.
2. **Turn off journald's rate limit for Sysmon** (otherwise bursts are dropped):
   ```
   install -D -m 0644 packaging/linux/sysmon-log-ratelimit.conf /etc/systemd/system/sysmon.service.d/zaafvesper.conf
   systemctl daemon-reload && systemctl restart sysmon
   ```
3. **Build** on any machine as your normal user: `make build-linux`
   (gives `bin/zaafvesper-linux-amd64` and `-arm64`).
4. **Copy** (all root-owned, not group/world writable; ZAAFVesper refuses to start
   otherwise):
   ```
   install -m 0755 bin/zaafvesper-linux-amd64 /usr/local/sbin/zaafvesper
   install -d -m 0755 /usr/local/etc/zaafvesper
   install -m 0644 configs/zaafvesper.yml /usr/local/etc/zaafvesper/zaafvesper.yml
   cp -R rules /usr/local/etc/zaafvesper/rules && chown -R root:root /usr/local/etc/zaafvesper && chmod -R go-w /usr/local/etc/zaafvesper
   install -m 0644 packaging/linux/zaafvesper.service /etc/systemd/system/zaafvesper.service
   systemctl daemon-reload && systemctl enable --now zaafvesper
   ```
5. **Check**: `journalctl -u zaafvesper` shows the start-up lines (rules enabled,
   events subscribed); alerts are in `/var/lib/zaafvesper/logs/alerts-*.jsonl`. (Not under `/var/log`: on
   Debian and Ubuntu `/var/log` is group-writable by `syslog`, and ZAAFVesper refuses an output
   folder whose parents another account can change. The v0.3 live run on an Ubuntu runner found this.)

Upgrading from v0.2: the alert files moved from `/var/log/zaafvesper/` to
`/var/lib/zaafvesper/logs/`. Point any log shipper at the new folder; old files stay
where they were until you remove them.

Uninstall: `systemctl disable --now zaafvesper`, then remove the files above.

## The unit's hardening

| Setting | Why |
|---|---|
| `CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` | kill other users' processes; read `/proc/<pid>/exe` and `cwd` of other users; read the journal. Nothing else (no `CAP_SYS_ADMIN`, no `CAP_NET_*`). |
| `NoNewPrivileges`, `RestrictSUIDSGID` | journalctl (the only child) cannot gain privileges. |
| `ProtectSystem=strict`, `StateDirectory=zaafvesper` | the only writable place is `/var/lib/zaafvesper` (created root-only by systemd). |
| `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices` | no writes to homes, a private `/tmp`, no device nodes. |
| `SystemCallFilter=@system-service` | includes `pidfd_open` and `pidfd_send_signal` (systemd 245+). |
| `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any` | no network at all (alerts go to files). |
| no `ProtectProc=invisible` | the sensor must see every process. |

## Network outputs

The unit allows no network at all, so `--syslog` and `--webhook` (SIEM and
ZAAFElegia forwarding) do not work under it as shipped. To use them, add a
drop-in (`systemctl edit zaafvesper`) that changes three things:

```
[Service]
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressAllow=192.0.2.10
ReadWritePaths=/var/db/zaafvesper
```

`IPAddressAllow` names only your receiver(s) (keep `IPAddressDeny=any`), and
`/var/db/zaafvesper` holds the outputs' spool (create it with
`install -d -m 0700 /var/db/zaafvesper`). Name resolution also needs the DNS
server's address in `IPAddressAllow`, or use an IP address for the receiver.

## Kill response on Linux

With `--enable-response`, a rule's `kill` action is carried out only when:
the process's Sysmon create event was seen and, right then, the start time in
`/proc/<pid>/stat` was not later than the event (so the pid had not been reused);
the event carries the same ProcessGuid; and at kill time the start time is
still the same. The kill goes through a pidfd opened before that last check, so
a pid reused in between is never signalled (kernels before 5.3 have no pidfd;
then the check and `kill(2)` are separate calls). Processes that were running
before ZAAFVesper started are never killed. Images under `/usr/lib/systemd/`,
`/lib/systemd/` and `/opt/sysmon/`, journalctl, init, pid 1, ZAAFVesper and its
running journalctl child are protected. Protection is by full path, not by
name: a program called `sysmon` in `/tmp` stays killable.

## Response actions on Linux

Linux supports all of the response actions except `requarantine` (macOS only; refused as `refused-unsupported`):

- `kill` and `suspend` (SIGSTOP, resumed after `response.suspend_for` unless a kill follows; the resume re-checks the start time).
- `quarantine_file`: moves the file into the vault `/var/lib/zaafvesper/quarantine`, bound to the event by creation time (or hash) and the writer's user.
- `remove_persistence`: systemd units (disabled, stopped, moved, `daemon-reload`), cron files, shell rc files and `/etc/profile.d` scripts.
- `isolate_process`: nftables table `inet zaafvesper`. It blocks the process's remote peers for the whole host, not only that process.

Details and limits: [docs/operations.md](../../docs/operations.md), "Response on Linux and Windows".

**Packaging limit: the shipped unit does not allow the file actions.** `zaafvesper.service` has `PrivateTmp=yes` and `ProtectSystem=strict` with `ReadWritePaths=/var/log/zaafvesper` only. The service therefore runs in a private mount namespace and has no write access to the vault or to the files the actions must move. The vault cannot be written, and a writer in the host namespace is expected to be refused too (the mount-namespace check compares it with the service's). So under the unit as shipped, `quarantine_file` and `remove_persistence` are refused (or end in `error`), and `isolate_process` is limited to what its state directory allows. `kill` and `suspend` are not affected. To use the creation-time file actions, run response from a drop-in or a separate unit.

Example drop-in. **It is not enabled by default and is untested on a real host**; the live validation ran the responder as plain root from a shell, not under this unit:

```
# /etc/systemd/system/zaafvesper.service.d/response.conf   (systemctl edit zaafvesper)
[Service]
PrivateTmp=no
ReadWritePaths=/var/log/zaafvesper /var/lib/zaafvesper
# systemctl needs to reach the manager for remove_persistence of systemd units;
# the files being removed (/etc/systemd/system, /etc/cron.d, homes) must also
# be writable: either list them in ReadWritePaths or drop ProtectSystem=strict.
```

Create the state directory first (`install -d -m 0700 /var/lib/zaafvesper`). Removing `ProtectSystem=strict` or widening `ReadWritePaths` weakens the sensor's own hardening; decide that per host.

## Known limits

- As root, ZAAFVesper refuses configuration, rules and binaries that are not
  root-owned or are group/world writable. POSIX ACLs are not read separately:
  a named-user or named-group entry can only grant write when the ACL mask
  allows write, and the mask is what the group permission bits show, so such a
  grant is refused by the mode check. (macOS extended ACLs are read separately.)
- Sysmon for Linux reports command lines as argv joined by spaces, so `ps.args`
  cannot tell an argument that contained a space from two arguments; `ps.cmdline`
  is exact.
- Sysmon gives a user name, not a uid: `ps.uid` is -1 for Sysmon events.
- `ps.ancestors_untrusted` is a macOS notion (Apple platform binaries); on Linux
  it is always true.
- The start time in `/proc` has 10 ms resolution; the boot time used to turn it
  into a wall-clock time can move when the clock is stepped, which makes a kill
  refuse (fail closed) rather than hit the wrong process.
