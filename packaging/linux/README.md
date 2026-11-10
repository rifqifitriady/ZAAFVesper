# ZAAFVesper on Linux

**In plain words:** ZAAFVesper watches a Linux machine with its own small kernel
programs (eBPF). Nothing else needs to be installed. If you already run
Sysmon for Linux, ZAAFVesper can read that instead (`--source sysmon`). The
same rules work with either.

> **Status: preview, validated on GitHub runners** (Ubuntu 24.04 and
> ubuntu-latest; see [docs/validation/linux-ebpf.md](../../docs/validation/linux-ebpf.md)
> and [docs/validation/linux.md](../../docs/validation/linux.md)). Not yet run on a
> user's own machine.

## What the machine needs

For the default eBPF source (`--source ebpf`):

- **Linux 5.17 or newer** on x86-64, **6.0 or newer** on arm64 (Ubuntu 22.04
  with the HWE kernel, 24.04 and later; Debian 12 and later; RHEL 9.2 and later).
- **BTF**: the file `/sys/kernel/btf/vmlinux` (a description of the kernel's own
  data structures, present on all the distributions above). Without it ZAAFVesper
  stops and says so, rather than guess.
- `CONFIG_SECURITY_PATH` (file delete and rename events; standard on Ubuntu,
  Debian, RHEL and Fedora). Without it those two events are missing and the start-up
  log says `file-delete events unavailable`; everything else still works.
- ZAAFVesper must run in the host's process namespace (not inside a
  container's): the kernel reports host process ids. It refuses to start
  otherwise.

There is **no automatic fallback** to Sysmon: if the eBPF programs cannot run,
`zaafvesper run` stops with the reason and the hint `use --source sysmon`. A sensor
that silently switched to other telemetry would hide that its coverage changed.

## How it works

At start ZAAFVesper loads its kernel programs (compiled into the binary; see
[pkg/source/ebpf/README.md](../../pkg/source/ebpf/README.md)) and attaches only the
ones its rules need. They report program starts and exits, file creation,
deletion and renaming, uid changes, debugging or memory access to another
process, kernel module loads, TCP connections and DNS queries through one
fixed-size buffer. When ZAAFVesper falls behind and the buffer is full, the
kernel counts what it could not add, and ZAAFVesper raises a `SensorDegraded`
alert (`ebpf_events_dropped`) at most once a minute. Nothing is pinned or left
in the kernel: when ZAAFVesper stops, its programs are gone.

## Install

Run as root. Paths match the macOS layout.

1. **Build** on any machine as your normal user: `make build-linux`
   (gives `bin/zaafvesper-linux-amd64` and `-arm64`; no compiler for the kernel
   programs is needed).
2. **Copy** (all root-owned, not group/world writable; ZAAFVesper refuses to start
   otherwise):
   ```
   install -m 0755 bin/zaafvesper-linux-amd64 /usr/local/sbin/zaafvesper
   install -d -m 0755 /usr/local/etc/zaafvesper
   install -m 0644 configs/zaafvesper.yml /usr/local/etc/zaafvesper/zaafvesper.yml
   cp -R rules /usr/local/etc/zaafvesper/rules && chown -R root:root /usr/local/etc/zaafvesper && chmod -R go-w /usr/local/etc/zaafvesper
   install -m 0644 packaging/linux/zaafvesper.service /etc/systemd/system/zaafvesper.service
   systemctl daemon-reload && systemctl enable --now zaafvesper
   ```
3. **Check**: `journalctl -u zaafvesper` shows the start-up lines (rules enabled,
   events subscribed, and any `events unavailable on this kernel` warning);
   alerts are in `/var/lib/zaafvesper/logs/alerts-*.jsonl`. (Not under `/var/log`:
   on Debian and Ubuntu `/var/log` is group-writable by `syslog`, and ZAAFVesper
   refuses an output folder whose parents another account can change.)

Upgrading from v0.3: the unit now passes `--source ebpf`, so Sysmon for Linux is
no longer read. To keep Sysmon, use the drop-in below. Upgrading from v0.2: the
alert files moved from `/var/log/zaafvesper/` to `/var/lib/zaafvesper/logs/`.

Uninstall: `systemctl disable --now zaafvesper`, then remove the files above.

## Using Sysmon for Linux instead

1. **Install Sysmon for Linux** from Microsoft's package repository
   (<https://github.com/microsoft/SysmonForLinux/blob/main/INSTALL.md>) and start it
   with a configuration that enables at least event IDs 1, 3, 5, 11 and 23
   (starting points: <https://github.com/microsoft/MSTIC-Sysmon/tree/main/linux>).
2. **Turn off journald's rate limit for Sysmon** (otherwise bursts are dropped):
   ```
   install -D -m 0644 packaging/linux/sysmon-log-ratelimit.conf /etc/systemd/system/sysmon.service.d/zaafvesper.conf
   systemctl daemon-reload && systemctl restart sysmon
   ```
3. **Switch ZAAFVesper** with the drop-in shipped here
   ([zaafvesper-source-sysmon.conf](zaafvesper-source-sysmon.conf); the v0.3 Sysmon
   live run installs exactly this file):
   ```
   install -D -m 0644 packaging/linux/zaafvesper-source-sysmon.conf /etc/systemd/system/zaafvesper.service.d/source-sysmon.conf
   systemctl daemon-reload && systemctl restart zaafvesper
   ```

With `--source sysmon`, ZAAFVesper runs `/usr/bin/journalctl` with a fixed command
line and environment and accepts only journal records whose **trusted** fields
say they came from root in `sysmon.service` (`_UID=0`,
`_SYSTEMD_UNIT=sysmon.service`), so `logger -t sysmon '<Event>…'` cannot inject
events. The XML goes through the same decoder as on Windows.

## The unit's hardening

| Setting | Why |
|---|---|
| `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` | load and attach the kernel programs (`CAP_BPF`, `CAP_PERFMON`; no `CAP_SYS_ADMIN`); kill; read `/proc/<pid>/exe` and `cwd` of other users (and the journal with `--source sysmon`). Nothing else (no `CAP_SYS_MODULE`, no `CAP_NET_*`). |
| `SystemCallFilter=@system-service` plus `bpf perf_event_open` | the usual service set (it includes `pidfd_open` and `pidfd_send_signal`), plus the two calls that load and attach the programs. |
| `NoNewPrivileges`, `RestrictSUIDSGID` | no child can gain privileges. |
| `ProtectSystem=strict`, `StateDirectory=zaafvesper` | the only writable place is `/var/lib/zaafvesper` (created root-only by systemd). |
| `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices` | no writes to homes, a private `/tmp`, no device nodes. |
| `ProtectKernelModules`, `ProtectKernelTunables`, `ProtectKernelLogs` | the sensor cannot load modules or change kernel settings; it only reads. |
| `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any` | no network at all (alerts go to files). |
| no `ProtectProc=invisible`, no `PrivatePIDs` | the sensor must see every process, in the host's process namespace. |

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

With `--enable-response`, a rule's `kill` action is carried out only when the
process at that pid is still the one that matched: its start time in
`/proc/<pid>/stat` (clock ticks since boot) equals the one the event recorded,
before and at kill time. The kill goes through a pidfd opened before that last
check, so a pid reused in between is never signalled. The eBPF source records
the start time in the kernel at the moment of each event, so even a process that
exits a few milliseconds later is identified correctly; with `--source sysmon`
the start time is read from `/proc` when the create event arrives, and processes
that were running before ZAAFVesper started are never killed. Images under
`/usr/lib/systemd/`, `/lib/systemd/` and `/opt/sysmon/`, journalctl, init, pid 1
and ZAAFVesper itself are protected. Protection is by full path, not by name: a
program called `sysmon` in `/tmp` stays killable.

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
  grant is refused by the mode check.
- eBPF source: file paths and the executable path are rebuilt from the kernel's
  directory entries, at most 512 components and 4 KiB deep; a longer path is reported
  by its last part with `evt.arg[path_incomplete] = "true"`. Command lines are
  reported up to 64 KiB (`evt.arg[args_truncated]` when longer). Delete and rename are reported
  when the kernel's permission check runs, just before the change; a change that
  then fails is still reported. Process access (`Ptrace`, `OpenProcess`) is
  reported once the kernel's own permission checks have passed; security modules
  such as Yama may still refuse it.
- eBPF source: DNS covers queries sent over UDP port 53 (the name and type, not
  the answers). DNS over TCP, DNS over TLS or HTTPS, and queries a program sends
  through another API (for example in-kernel) are not seen. On Ubuntu each
  program's query goes to the local resolver (`127.0.0.53`), which then asks the
  real server: both queries are reported, the first with the program that asked.
- Sysmon source: Sysmon for Linux reports command lines as argv joined by spaces,
  so `ps.args` cannot tell an argument that contained a space from two arguments;
  it gives a user name, not a uid (`ps.uid` is -1).
- `ps.ancestors_untrusted` is a macOS notion (Apple platform binaries); on Linux
  it is always true.
- Start times in `/proc` have 10 ms resolution. ZAAFVesper reads the boot time
  once at start, so every part of it converts start times the same way; when the
  clock is stepped by a large amount later, start times shown in alerts can be
  off by that amount (identity checks compare clock ticks, which do not move).
