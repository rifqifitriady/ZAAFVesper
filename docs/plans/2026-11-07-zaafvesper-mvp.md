# ZAAFVesper MVP: implementation plan

**Goal:** a working macOS behaviour-detection sensor as specified in `docs/specs/2026-11-07-zaafvesper-design.md` (read it first; it wins over this file on any conflict about *what*; this file wins on *interfaces*).
**Architecture:** eslogger → `source/eslogger` → `ps.Snapshotter` (enrich) → global exclusions → `rules.Engine` (single + sequence rules) → alert sinks / response / capture. YARA scanner runs async and re-injects `YaraMatch` events.
**Tech stack:** Go 1.27 (module `github.com/rifqifitriady/ZAAFVesper`), `gopkg.in/yaml.v3`, `github.com/hillu/go-yara/v4` (build tag `yara` only; libyara 4.6.0 from Homebrew at `/opt/homebrew`). No other third-party dependencies without a written reason in the report.
**Global constraints:**
- The shared contract `pkg/event`, `pkg/source/source.go` is FROZEN. Do not change it; request changes in your report.
- Stubs in `pkg/source/eslogger/eslogger.go`, `pkg/ps/ps.go`, `pkg/yara/*.go` define exported signatures that other workstreams compile against. Keep every exported signature in those stubs; you may add more.
- No shell, no `os/exec` with event-derived strings (eslogger itself is launched with a fixed argv of event type names). Regex via Go `regexp` (RE2) only.
- Everything printed to a terminal passes through `alert.Sanitize` (strips C0/C1 control characters and ESC).
- No commits, no pushes. `go vet ./...` and `go test ./...` must pass for your packages.

## Workstreams and ownership (paths do not overlap)

| WS | Owner agent | Owns |
|---|---|---|
| A Engine | backend-devops-engineer | `pkg/filter/**`, `pkg/rules/**`, `pkg/alert/**`, `pkg/response/**`, `pkg/capture/**`, `pkg/config/**`, `cmd/zaafvesper/**`, `configs/**`, `Makefile`, `go.mod`/`go.sum` (A is the only one that runs `go mod tidy`; B lists its module needs) |
| B Sensor | backend-devops-engineer | `pkg/source/eslogger/**`, `pkg/ps/**`, `pkg/yara/**`, `testdata/eslogger/**` |
| C Detection content | dfir-responder | `rules/**` (rules, macros, fixtures, `rules/yara/*.yar`), `docs/rules.md` |

The tech lead (main thread) owns `pkg/event`, `pkg/source/source.go`, `docs/specs`, `docs/plans`, `README.md`, and integration.

## Shared formats (all three workstreams rely on these)

### Rule file (`rules/<tactic>_<short_name>.yml`, one rule per file)
```yaml
name: Launch Agent persistence via plist write
id: 3c3b0c55-1a7e-4c43-9b8a-6c2b2f3c8d11        # UUID v4, unique
version: 1.0.0
description: |
  …
labels:
  tactic.id: TA0003
  tactic.name: Persistence
  technique.id: T1543.001
  technique.name: Launch Agent
references: [https://attack.mitre.org/techniques/T1543/001/]
condition: >
  create_file and file.path imatches ('/Users/*/Library/LaunchAgents/*.plist', '/Library/LaunchAgents/*.plist')
output: "%ps.exe created launch agent %file.path"
severity: high                 # info|low|medium|high|critical
action: []                     # or [{name: kill}]
tests:
  atomic: [a5983dee-bf6c-4eaf-951c-dbc1a7b90900]
min-engine-version: 0.1.0
enabled: true                  # optional, default true
```

### Macros (`rules/macros/*.yml`)
```yaml
- macro: spawn_process
  expr: evt.name = 'CreateProcess'
- list: shells
  items: ['/bin/sh', '/bin/bash', '/bin/zsh', '/bin/dash', '/bin/ksh', '/bin/tcsh', '/bin/csh']
```
A list macro is usable wherever a list literal is: `ps.exe in shells`.

### Condition language (WS A implements, WS C writes)
- Literals: `'single-quoted strings'` (backslash escapes `\'` and `\\`), integers, `true`/`false`, lists `('a', 'b')`.
- Fields: every name in `event.FieldNames()`, plus indexed `evt.arg[key]`, `ps.env[KEY]`, `ps.parent.env[KEY]`, `yara.meta[key]`. Unknown field → compile error naming the rule.
- Operators: `= != < <= > >=`, `in`, `iin`, `contains`, `icontains`, `startswith`, `istartswith`, `endswith`, `iendswith`, `matches`, `imatches` (glob: `*` any run incl. `/`, `?` one char), `regex`. String operators accept a list on the right (true if any element matches). When the left side is `[]string` (ps.args, ps.ancestors, yara.tags) the operator is true if ANY element satisfies it. `not` prefix: `not ps.exe in shells` and the infix forms `not in`, `not imatches`, etc. are both accepted.
- Boolean: `and`, `or`, `not`, parentheses. Precedence: not > and > or.
- Absent field (nil) makes every comparison false, including `!=`, and `not` of it true (Fibratus semantics).
- Functions: `base(f)`, `dir(f)`, `ext(f)`, `lower(f)`, `length(f)` on fields.
- Sequences:
```
sequence maxspan 2m [by <field>]
  |<expr>| [by <field>]
  |<expr>| [by <field>]
```
  2..5 steps. `maxspan` units `ms s m h`. Global `by` joins every step on the same field; per-step `by` joins step N's field value to step N+1's field value (EQL-style; all per-step `by` values must be equal). Output may reference step fields as `%1.file.path`, `%2.ps.exe`; plain `%ps.exe` refers to the last event.

### Fixture file (`rules/testdata/<rule-file-stem>.yml`, required for every rule)
```yaml
match:
  - desc: curl drops a launch agent
    events:
      - name: CreateFile
        proc: {pid: 100, ppid: 1, exe: /usr/bin/curl, name: curl, is_platform: true, is_signed: true}
        file: {path: /Users/a/Library/LaunchAgents/com.evil.plist}
nomatch:
  - desc: launchd itself
    events:
      - name: CreateFile
        proc: {pid: 1, exe: /sbin/launchd, name: launchd, signing_id: com.apple.xpc.launchd, is_platform: true}
        file: {path: /Library/LaunchAgents/com.apple.x.plist}
```
Event fields are the YAML tags of `event.Event`. Scenario events with zero `time` get `2026-01-01T00:00:00Z + i·1s`; `seq` auto-increments. A `match` scenario passes if this rule fires ≥1 time; `nomatch` passes if it never fires. Every rule needs ≥1 match and ≥2 nomatch scenarios (one realistic benign lookalike).

### Global exclusions (`configs/zaafvesper.yml` and `configs/config.d/*.yml`, sysmon-modular style)
```yaml
exclude:
  - name: Spotlight indexers
    events: [OpenFile, WriteFile, CreateFile]
    condition: ps.signing_id istartswith 'com.apple.mdworker'
```

## WS A — Engine tasks
1. `pkg/filter/ql`: lexer → parser (AST) → `Compile(expr string, m *Macros) (*Filter, error)`; `(*Filter).Match(e *event.Event) bool`; `(*Filter).EventNames() []string` (names constrained by `evt.name`/macros on every true path; nil = any). `LoadMacros(paths ...string) (*Macros, error)`. Glob matcher compiled once per literal. Table tests for every operator incl. nil semantics, list LHS, case-insensitive variants, precedence, errors with column numbers. Fuzz test for the parser (`FuzzParse`).
2. Sequence parsing/evaluation (in `pkg/rules`, using ql for steps): state per rule keyed by join value; partials expire after maxspan; cap 10 000 partials per rule (evict oldest); a matched sequence resets its partial. Tests with a fake clock.
3. `pkg/rules`: `LoadDir(dir string) (*Ruleset, error)` (rules from `dir/*.yml`, macros from `dir/macros/*.yml`, ignores `testdata/`, `yara/`); validates schema (unique id, severity enum, ATT&CK id format `^T\d{4}(\.\d{3})?$`, min-engine-version). `NewEngine(rs *Ruleset, opts Options) *Engine`; `(*Engine).Process(e *event.Event) []*Alert` (indexed by evt.name); `(*Engine).RequiredEvents() []string`. `type Alert struct{ RuleID, RuleName, Severity, Output string; Labels map[string]string; Time time.Time; Events []*event.Event; Actions []string }`. `RunFixtures(rulesDir string) ([]FixtureResult, error)`.
4. `pkg/alert`: `Sanitize(string) string`; `Sink` interface `Send(*rules.Alert) error`; console sink (coloured severity, one line + indented detail) and JSONL sink. Exclusions: `pkg/config` compiles `exclude` entries to filters; pipeline drops matching events before rules.
5. `pkg/response`: `Responder` with `Kill(pid int32, reason string) error`; protected list (pid ≤ 1, own pid, eslogger pid, names `kernel_task launchd WindowServer loginwindow`, exe prefixes `/System/`, `/usr/libexec/`, `/sbin/`), rate limit 10/min, `DryRun` mode, every decision logged. Unit tests with an injected kill func.
6. `pkg/capture`: `Writer` (gzip JSONL of `event.Event`) and `Reader` that also accepts raw eslogger JSONL (detect by first line having `event_type`; decode via `eslogger.Decode`) and plain JSONL.
7. `pkg/config`: `Load(path string) (*Config, error)` for `zaafvesper.yml` + `config.d/*.yml` merge; root-ownership check `CheckOwnership(paths ...string) error` (owner uid 0, not group/world writable) enforced when `os.Geteuid()==0`.
8. `cmd/zaafvesper`: `run`, `replay`, `rules list|validate|test`, `coverage --navigator out.json` (ATT&CK Navigator v4.5 layer, techniques scored by rule count), `version`. `run` wires: eslogger source (`eslogger.New`) with `RequiredEvents()`, `ps.NewSnapshotter(true)`, YARA (`yara.New`; on `ErrDisabled` warn and continue), exclusions, engine, sinks, `--capture`, `--enable-response`, `--dry-run-response`. `replay` uses `ps.NewSnapshotter(false)` only for raw eslogger input (normalized captures are already enriched). Clean shutdown on SIGINT/SIGTERM, stats on exit.
9. Benchmark `BenchmarkEngine` (≥ 20 000 events/s with 30 rules) and `Makefile` targets `build`, `build-yara` (`CGO_ENABLED=1 go build -tags yara`), `test`, `rules-test`, `bench`.

## WS B — Sensor tasks
1. `pkg/source/eslogger`: `Decode(line)` for the eslogger JSON schema of macOS 26. Ground truth for field names is the SDK headers at `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/ESMessage.h` and `ESTypes.h` (eslogger JSON mirrors those struct members in snake_case) plus `man eslogger`. Map ES events to canonical names per the spec §4.1. For exec, `Proc` is the **new image** (`event.exec.target`) with `Args`, `Env` (if present), `Cwd`; the pre-exec image becomes `Args["prev_exe"]`. For get_task/signal/trace/remote_thread_create, `Target` is the target process. Fill `Args` with event-specific detail (`signal`, `xattr`, `mode`, `owner_uid`, `kext_id`, `mount_path`, `tcc_service`, `tcc_right`, `auth_type`, `auth_success`, `sudo_command`, `launch_item_type`, `launch_item_path`, `xp_malware_identifier`, `open_flags` …). Tolerant decoding: unknown fields ignored; missing fields leave zero values; line limit 16 MiB. `ESEventTypes(canonical)` maps back to eslogger names. `Run`: exec `/usr/bin/eslogger <types…>` (fixed argv), read stdout with a 16 MiB bufio scanner, early drop by `ExcludePaths` prefix and `ExcludeSigning`, counters, restart-with-backoff if eslogger exits unexpectedly (max 5/min), clear error if not root or Full Disk Access missing (eslogger's stderr mentions it). Hand-written fixture lines in `testdata/eslogger/*.jsonl` for every mapped event type, built from the header layouts; golden tests.
2. `pkg/ps`: process table keyed by pid with pidversion check. Fork → copy parent; exec → replace image; exit → keep 30 s then drop. `Enrich` sets `Proc.Parent` (shallow copy), `Proc.Ancestors` (exe paths up to launchd, max 16), `Proc.UUID = uint64(pid)<<32 | uint64(pidversion)`, `Username` (cached `os/user` lookup). Bootstrap via `sysctl kern.proc.all` (`golang.org/x/sys/unix` is acceptable, name it) for already-running processes. Bounded: max 65 536 entries. Tests with synthetic fork/exec/exit sequences.
3. `pkg/yara` (build tag `yara`, file `scanner.go`): implements `source.Scanner` with go-yara v4 per spec §4.6b: compile `RulesDir` at start, worker pool, max size, timeout, `O_NOFOLLOW` + regular-file check, cache by (path,size,mtime), scan `ps.exe` on CreateProcess and `file.path` on CreateFile/WriteFile under `WatchDirs`; each match → `event.YaraMatch` with `Proc` copied from the triggering event, `Yara` filled, `Source: "yara"`. Non-blocking `Submit` (drop + count when queue full). Tests under the tag using a tiny rule and a temp file. Must build with `CGO_ENABLED=1 go test -tags yara ./pkg/yara/`.

## WS C — Detection content tasks
1. `rules/macros/macros.yml`: event macros (`spawn_process`, `fork_process`, `exit_process`, `open_file`, `create_file`, `write_file`, `rename_file`, `delete_file`, `set_xattr`, `delete_xattr`, `set_mode`, `open_process`, `send_signal`, `ptrace`, `remote_thread`, `add_launch_item`, `load_kext`, `mount`, `authenticate`, `sudo`, `modify_tcc`, `xprotect_detect`, `yara_match`) and lists (`shells`, `script_interpreters`, `apple_signed_trusted` … ). `rules/macros/` may contain more files.
2. ~25 rules per spec §4.4 plus "YARA signature match" and "XProtect malware detection". Each: ATT&CK labels (use current IDs), `tests.atomic` GUIDs from `atomic-red-team` macOS tests where one exists (local clone at `<atomic-red-team clone>/atomics/` — read the atomic's commands so the condition matches what the test really does), a fixture file, low-noise exclusions for Apple platform binaries. At least 3 sequence rules.
3. `rules/yara/*.yar`: 3–5 original rules for macOS threats (e.g. AMOS-style stealer strings, osascript credential prompt, reverse-shell one-liners embedded in Mach-O/scripts). Original wording, tagged, with `meta: author/description/reference/attack`.
4. `docs/rules.md`: table of rules (name, ATT&CK, severity, atomic GUID, sequence?).
