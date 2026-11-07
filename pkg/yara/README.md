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
  descriptor and the compiled content are the same. Files with
  `import "magic"` are refused.
- Triggers: `CreateProcess` scans `ps.exe` (Apple platform binaries skipped
  unless `ScanPlatform`). `CreateFile` and `WriteFile` scan `file.path` when it
  lies under a `WatchDirs` glob (default `/tmp /private/tmp /Users/*/Downloads
  /Users/Shared`; ES reports resolved paths).
- Opening a file: the path is walked from `/` one component at a time with
  `openat(2)` and `O_NOFOLLOW`. A symlink anywhere in the path is refused and
  counted under `symlinks`, so a swapped middle directory cannot redirect root's
  open. The final open adds `O_NONBLOCK`, then the descriptor is `fstat`ed:
  regular files only, at most `MaxFileSize`.
- Cache: results are keyed by path, dev, inode, size, mtime **and ctime**.
  ctime cannot be set by user code, so rewriting a file and restoring its mtime
  still forces a rescan. Exec scans also key on the cdhash ES reported.
- Queue: bounded (`QueueSize`), two classes. Exec jobs are popped first. An exec
  job submitted to a full queue displaces the oldest file job; it is dropped only
  when the queue holds nothing but exec jobs. `Submit` never blocks. Counters:
  `dropped`, `dropped_exec`, `dropped_file`.
- Output: one `YaraMatch` event per matching rule with `Proc` copied from the
  trigger, `file.path` = scanned path, `yara.*` filled, `evt.arg[trigger]`, and
  `evt.time` = trigger time.

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
user-owned. `New` therefore refuses any rule file containing `import "magic"`
(`TestMagicImportRefused`). Other modules (`math`, `hash`, `macho`, …) are
allowed.
