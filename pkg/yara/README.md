# pkg/yara

YARA scanner (`source.Scanner`) on libyara through `github.com/hillu/go-yara/v4`
(cgo). It is compiled only with `-tags yara`; without the tag `New` returns
`ErrDisabled` and `CheckLoadedImages` returns nil (the binary is then pure Go).

## Behaviour

- Rules: every `*.yar` / `*.yara` in `Config.RulesDir`, one namespace per file
  (file name without extension). `include` is disabled. Each file is read with
  `config.SecureRead` (one `O_NOFOLLOW` open; `fstat` on that descriptor for
  regular file, 4 MiB cap and, under the owner policy, owner and no
  group/world write). The bytes are compiled with `AddString`, so the checked
  descriptor and the compiled content are the same. Imports are allow-listed
  (see below) and any `include` is refused.
- Triggers: `CreateProcess` scans `ps.exe` (Apple platform binaries skipped
  unless `ScanPlatform`). `CreateFile` and `WriteFile` scan `file.path` when it
  lies under a `WatchDirs` glob (default `/tmp /private/tmp /Users/*/Downloads
  /Users/Shared`; ES reports resolved paths).
- Opening a file: the path is walked from `/` one component at a time with
  `openat(2)` and `O_NOFOLLOW`. A symlink anywhere in the path is refused and
  counted under `symlinks`, so a swapped middle directory cannot redirect root's
  open. The final open adds `O_NONBLOCK`, then the descriptor is `fstat`ed:
  regular files only, at most `MaxFileSize`.
- Local file systems only, in two steps. First, before any syscall on the
  path, it is compared with the mount points that `getfsstat(MNT_NOWAIT)`
  lists without `MNT_LOCAL` (cached, re-read at most every 5 s and right
  after any `Mount` event passed to `Submit`, at most 1024 mounts;
  `MNT_NOWAIT` never waits on a server). Then every directory on the
  walk and the file itself are checked with `fstatfs`. Without `MNT_LOCAL`
  (SMB, NFS, AFP, WebDAV, …) the walk stops, nothing is read, `non_local` is counted and
  `yara_skipped_nonlocal` is reported. A slow or hostile server therefore
  cannot stall the workers. Each scan is also bounded by libyara's timeout
  (`TimeoutSec`, default 10 s, counted under `timeouts`).
- Exec binding: `CreateProcess` carries Endpoint Security's stat of the
  executable at exec (`Proc.ExeDev`, `ExeIno`, `ExeCtimeNs`). The opened
  descriptor must have the same device and inode, and the same ctime when ES
  gave one, and the path must not contain a symlink. Otherwise the path no
  longer leads to the file that ran (swapped or rewritten in place): the file
  is **not** scanned, `exec_replaced` is counted and `yara_exec_replaced` is
  reported with the pid, path and reason. When the path is gone (`ENOENT`,
  `ESTALE`, `ENOTDIR`), the scanner checks whether the process is still the
  same live incarnation (`kern.proc.pid`, start time equal to the event's
  within 1 ms): a binary deleted while its process runs is reported the same
  way; one deleted after the process exited (`go run`, test binaries,
  installers) is only counted under `exec_gone`. An exec event without a
  stat is scanned as before and counted under `exec_unbound` (no report).
- File binding: `CreateFile`/`WriteFile` scans are bound to the event's
  `file.dev`/`ino` (ES's stat of the target). Another device or inode means
  the path now holds another file: it is skipped and counted under
  `file_changed`, without a degraded report, because that file's own
  create/close event scans it. A ctime-only difference (chmod, xattr, rewrite
  in place of the same file) is scanned as it is now, so a chmod after close
  cannot hide the content.
- Cache: results are keyed by path, dev, inode, size, mtime **and ctime**.
  ctime cannot be set by user code, so rewriting a file and restoring its mtime
  still forces a rescan. Exec scans also key on the cdhash ES reported.
- Queue: bounded (`QueueSize`), two classes. Exec jobs are popped first. An exec
  job submitted to a full queue displaces the oldest file job; it is dropped only
  when the queue holds nothing but exec jobs. `Submit` never blocks. Counters:
  `dropped`, `dropped_exec`, `dropped_file`. A drop (or displacement) while
  running reports `yara_queue_full`; drops before `Start` or after `Close`
  only count.
- Output: one `YaraMatch` event per matching rule with `Proc` copied from the
  trigger, `file.path` = scanned path, `yara.*` filled, `evt.arg[trigger]`, and
  `evt.time` = trigger time.

## Degraded reports: `OnDegraded`

`(*Scanner).OnDegraded(fn func(condition, detail string))` registers the hook
the pipeline turns into `SensorDegraded` events. Conditions:
`yara_queue_full`, `yara_exec_replaced`, `yara_skipped_nonlocal`. Reports
are rate-limited per (condition, key): the key is the pid for
`yara_exec_replaced`, the path for `yara_skipped_nonlocal`, and empty for
`yara_queue_full`; each key reports at most once a minute, and keys are kept
in a 256-entry LRU. So a decoy replacement for one process cannot hide the
real one for another. Suppressed reports are counted per condition and the
next report of that condition ends with `(N more suppressed since last
report)`. `fn` is called synchronously from the
goroutine that hit the condition: `Submit`'s caller for `yara_queue_full`, a
scan worker for the others. It must be safe for concurrent use and must not
block. Builds without the `yara` tag have an inert `Scanner` stub with the same
methods (`New` still returns `ErrDisabled`).

## Rule imports: allow-list

Every rule file is lexed the way libyara's lexer splits it (`//` and `/* */`
comments, also inside hex strings; `"…"` strings with backslash escapes; any
other `/` starts a regular expression, since YARA divides with `\`). Outside
comments, strings and regexps:

- every `import` must be followed by a literal whose raw bytes are exactly one
  of `pe`, `elf`, `macho`, `math`, `hash`, `dotnet`, `time`, `string`,
  `console`. No escape processing: `import "m\x61gic"`, which libyara decodes
  to `magic`, is refused;
- any `include` is refused (and the compiler's `DisableIncludes` stays on);
- an unterminated comment, string or regexp is refused.

Second layer, independent of the lexer: after compiling, `New` scans an
empty buffer with the rules and a callback implementing go-yara's
`ScanCallbackModuleImport`. libyara calls `ImportModule(name)` for every
module the rules import, with the name as libyara itself resolved it
(escapes decoded). A name outside the allow-list returns an error, which
aborts the scan before the module is loaded, and the rule set is refused.

So `magic` (libmagic would load its database from a user-owned Homebrew path
at scan time) and `cuckoo` are unreachable whether or not libyara was built
with them. Tests: `TestCheckRuleSource`, `TestImportAndIncludeBypassesRefused`,
`TestLibyaraImportCheck`. Residual: libmagic stays linked in the static
build until libyara is built without the module.

## Running as root: `CheckLoadedImages`

`CheckLoadedImages()` (yara build, macOS) lists every image dyld has loaded:
the executable and each dylib (`_dyld_image_count` / `_dyld_get_image_name`).
It returns an error naming the first one outside `/usr/lib/` and `/System/`
(dyld shared cache) that fails either check:

- its file, or any ancestor directory, is not owned by root;
- it, or any ancestor directory, is group- or world-writable.

For a symlink, the target is resolved and checked as well. The caller must fail
closed on this error when euid is 0.

On this Mac, `/opt/homebrew` and everything under it is owned by uid 501. A
dynamically linked libyara (`libyara.10.dylib`, plus libcrypto, libmagic and
jansson) therefore fails the check. Running such a build as root would let that
user replace a library that root then loads. Verified by
`TestHomebrewLibyaraFlagged`.

## Static linking (recommended for any root build)

All four static archives exist from Homebrew: `libyara.a`, `libmagic.a`,
`libjansson.a`, `libcrypto.a` (`pkg-config --static --libs yara` gives `-lyara
-lm -lmagic -ljansson -lcrypto`).

go-yara's `yara_static` tag alone is not enough on macOS. It uses the same
`-l` flags, and ld64 prefers the `.dylib` sitting next to each `.a`. What works,
tested on macOS 26.6.2 with Go 1.27.3:

1. Point `-L` at a directory that contains only `libyara.a` (a symlink is enough).
2. Pass the other archives by full path, using the `yara_no_pkg_config` tag.

```sh
mkdir -p build/staticlib && ln -sf /opt/homebrew/opt/yara/lib/libyara.a build/staticlib/libyara.a
H=/opt/homebrew/opt
CGO_ENABLED=1 \
CGO_CFLAGS="-I$H/yara/include" \
CGO_LDFLAGS="-L$PWD/build/staticlib $H/libmagic/lib/libmagic.a $H/jansson/lib/libjansson.a $H/openssl@4/lib/libcrypto.a -lz -lbz2" \
go build -tags 'yara yara_no_pkg_config' -o zaafvesper ./cmd/zaafvesper
otool -L zaafvesper   # expect only /usr/lib/libresolv, libz, libbz2, libSystem
```

With that link, the package tests pass and `CheckLoadedImages` sees nothing
outside `/usr/lib`. Install the binary root-owned (`root:wheel 0755`) in a
root-owned directory, for example `/usr/local/bin`.

Remaining caveat: libyara's `magic` module is compiled in. `import "magic"`
would make libmagic load its database at scan time from
`/opt/homebrew/Cellar/libmagic/5.48/share/misc/magic(.mgc)`, which is
user-owned. `New` refuses it through the import allow-list above
(`TestMagicImportRefused`); building libyara without `magic` remains the
long-term fix.
