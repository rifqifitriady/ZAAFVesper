# Linux eBPF source

**In plain words:** small programs that ZAAFVesper loads into the Linux kernel
to see what happens on the machine (programs starting, files changing,
connections, …) without Sysmon. The kernel checks every such program before
it runs it, and the programs only observe: they cannot change, block or slow
down anything beyond their own few microseconds of work.

*eBPF* is the kernel's built-in way to run such checked programs. *BTF* is the
kernel's description of its own data structures; the programs use it to read
the right fields on every kernel version (*CO-RE*: compile once, run
everywhere).

## What it reports

| Kernel activity | Event | Main fields |
|---|---|---|
| a program starts (exec) | `CreateProcess` | `ps.exe` (full path), `ps.cmdline`, `ps.args`, `ps.cwd`, `ps.uid`, `ps.euid`, parent |
| a process exits | `TerminateProcess` | `evt.arg[exit_status]` |
| a new process (fork) | `Fork` | the child, with its parent |
| a file is opened | `OpenFile` | `file.path`; only when a rule asks for `OpenFile` (very frequent) |
| a file is created, or an existing one replaced (`O_TRUNC`) | `CreateFile` | `file.path`, `evt.arg[truncated]` |
| a file is deleted / renamed | `DeleteFile` / `RenameFile` | `file.path`, `file.dest` |
| a uid changes (setuid, sudo, …) | `SetUID` | `evt.arg[old_uid]` … `[new_euid]` |
| ptrace attach or seize | `Ptrace` | `target.ps.*`, `evt.arg[syscall]` |
| `process_vm_readv` / `writev` | `OpenProcess` | `target.ps.*`, `evt.arg[syscall]` |
| a kernel module is loaded | `DriverLoad` | `image.path`, `evt.arg[module_name]`, `evt.arg[module_source]` (`file` for `finit_module`, including compressed `.ko.zst` files the kernel decompresses; `memory` for `init_module`) |
| a TCP connection is made / accepted | `NetworkConnect` / `NetworkAccept` | `net.*` (for accepted ones the source is the remote peer, as with Sysmon) |
| a DNS query is sent over UDP port 53 | `DNSQuery` | `dns.query`, `dns.type`, `net.dip` |

Every event has `evt.source = ebpf` and `evt.platform = linux`. The full list of
`evt.arg` keys is in [docs/rules.md](../../../docs/rules.md).

**Process identity.** Each event carries the process's start time as the kernel
records it (the same clock ticks as field 22 of `/proc/<pid>/stat`), read at the
moment of the event. The process table and the kill check therefore identify a
process exactly, even one that exits a few milliseconds later. The parent is
the parent *process* (not the thread that started the child), so `ps.parent.*`
works for multi-threaded parents such as Java and Go servers.

**Which `ps.exe` each event gets.** Only the exec record carries the
executable. The source remembers each live process's executable (copied to a
child at fork, forgotten at exit) and puts it on the process's later events;
a process that started before ZAAFVesper is looked up once in `/proc`, checked
against its start time.

## Lost and bad records

The kernel side writes into one ring buffer (8 MiB). When ZAAFVesper reads too
slowly and the buffer is full, the kernel counts each record it could not add,
per kind; every second ZAAFVesper reads the counters, and any increase raises a
`SensorDegraded` event `ebpf_events_dropped` (at most once a minute, with the
counts). A record that cannot be decoded raises `ebpf_events_unreadable`.
`zaafvesper run` prints the counters in its statistics: `events_missed` (records
lost in the kernel), `seq_gaps` (seconds in which some were lost) and
`decode_errors`, the same names the other sources use.

## What it needs, and what happens without it

Linux 5.17+ on x86-64 or 6.0+ on arm64, with `/sys/kernel/btf/vmlinux`; root
(`CAP_BPF`, `CAP_PERFMON`); the host's process namespace. Without BTF, on an
older kernel or in a container's process namespace, `zaafvesper run` stops with
the reason and `use --source sysmon`. When a kernel lacks one optional hook
(for example delete and rename need `CONFIG_SECURITY_PATH`), only that group of
events is left out, and the start-up log says so.

Only the programs some rule needs are loaded. ZAAFVesper's own file activity
is filtered out in the kernel (by its process id, never by name). Nothing is
pinned in the kernel: when ZAAFVesper exits, the programs are gone.

## Files

| File | What |
|---|---|
| `bpf/zaaf.bpf.c` | the kernel programs (C) |
| `bpf/vmlinux_min.h` | the few kernel types they read, by name |
| `bpf/libbpf/` | five unchanged libbpf headers, pinned by hash ([README](bpf/libbpf/README.md)) |
| `zaaf_x86_bpfel.o`, `zaaf_arm64_bpfel.o` + `.go` | the compiled programs, committed so a normal build needs no compiler for them |
| `wire.go`, `decode.go`, `dns.go` | turn kernel records into events (tested on any OS, fuzzed) |
| `groups.go` | which programs produce which events |
| `source_linux.go` | load, attach, read, count drops |

## Regenerating the kernel programs

Only needed after changing `bpf/`. Needs Docker:

```
pkg/source/ebpf/bpf/regen.sh
```

It builds the pinned toolchain in `bpf/toolchain/Dockerfile` (Go image by
digest, clang 19.1.7 from a dated Debian snapshot, bpf2go v0.22.0) and runs it
with an empty environment, so the same source always gives the same bytes. The
`ebpf-objects` workflow regenerates them on every change and fails if the
committed objects differ by a single byte; it also checks the libbpf header
hashes and runs govulncheck.

## Tests

- `go test ./pkg/source/ebpf/` (any OS): every record kind, malformed records,
  the DNS parser, drop accounting, the event-group plan; `FuzzRecord` fuzzes the
  decoder.
- As root on Linux with BTF, the same command also loads the real programs and
  triggers each kind of activity (`source_linux_test.go`). Elsewhere these
  tests skip; `ZAAF_EBPF_REQUIRE=1` turns a skip into a failure. Locally on a Mac:
  ```
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/ebpf.test ./pkg/source/ebpf
  docker run --rm --privileged --pid=host -v /tmp:/t golang:1.27.3-trixie \
    sh -c 'mount -t tracefs tracefs /sys/kernel/tracing; ZAAF_EBPF_REQUIRE=1 /t/ebpf.test -test.v'
  ```
- The `live-linux-ebpf` workflow runs them as root on GitHub's Ubuntu runners,
  then the Atomic Red Team plan against the installed unit
  ([docs/validation/linux-ebpf.md](../../../docs/validation/linux-ebpf.md)).

## Licence

The BPF C sources are `GPL-2.0-only OR BSD-2-Clause` (the kernel accepts
programs that use its tracing helpers only under a GPL-compatible licence); the
rest of ZAAFVesper stays Apache-2.0. The compiled objects are embedded in the Go
binary as data and loaded through the `bpf()` system call; they are distributed
under the BSD-2-Clause option.
