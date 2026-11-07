## Final Evaluation Specification

```yaml
rrd_cycle_applied: true
self_verification_completed: true
evaluation_specification:
  metadata:
    user_prompt: >
      Evaluate the ZAAFVesper MVP (Go 1.27 module github.com/rifqifitriady/ZAAFVesper): a macOS behaviour-detection
      sensor modelled on rabbitstack/fibratus that wraps /usr/bin/eslogger, with a Fibratus-style rule
      language (imatches, sequence/maxspan/by), YAML rules mapped to MITRE ATT&CK, optional kill (off by
      default), capture + replay, YARA behind build tag `yara`. Built by three workstreams: A engine,
      B sensor, C detection content, against the frozen contract pkg/event + pkg/source/source.go.
    artifact_type: "code (Go) + detection content (YAML rules, macros, fixtures, YARA) + docs/rules.md"
    authoritative_sources:
      what: docs/specs/2026-11-07-zaafvesper-design.md
      interfaces: docs/plans/2026-11-07-zaafvesper-mvp.md
      contract: [pkg/event/event.go, pkg/source/source.go]
      es_ground_truth: /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/{ESMessage.h,ESMessageCore.h,ESTypes.h}
      codesign_flags: /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/kern/cs_blobs.h
      attack_data: <atomic-red-team clone>/atomic_red_team/enterprise-attack.json
      atomic_index: <atomic-red-team clone>/atomics/Indexes/Indexes-CSV/macos-index.csv
    baseline_hashes_sha256:
      pkg/event/event.go: 237e0f8266236d961ea4e730703bb4f45f9f19f82c0e3826b2cb7ae272c77ea0
      pkg/source/source.go: 0167f317849d927dee76a78639cf86e877137f5c282df2bc18aebd14c673cb38
      pkg/event/event_test.go: e1696e983ef7c2cf0ea28a1883775741c233af0f61201f8ad83faeabf9a3f672
    reference_facts:
      es_notify_enum: {exec: 9, open: 10, fork: 11, close: 12, create: 13, exit: 15, get_task: 16, kextload: 17, mount: 22, rename: 25, setextattr: 27, setmode: 29, setowner: 30, signal: 31, unlink: 32, write: 33, deleteextattr: 70, trace: 96, remote_thread_create: 97, authentication: 111, xp_malware_detected: 112, btm_launch_item_add: 124, sudo: 131, tcc_modify: 147}
      es_destination_type: {EXISTING_FILE: 0, NEW_PATH: 1}
      codesigning_flags: {CS_VALID: 0x1, CS_ADHOC: 0x2, CS_LINKER_SIGNED: 0x20000, CS_SIGNED: 0x20000000}
      attack_current: "TA0005 = Stealth; TA0112 = Defense Impairment; revoked: T1562 -> T1685, T1562.001 -> T1685, T1562.004 -> T1686, T1070.002 -> T1685.006"
      contract_nil_rule: "Get returns nil only when Proc/Target/Proc.Parent/File/Yara is nil or an indexed key is missing; a present Proc with Exe \"\" yields \"\" (not nil). evt.time is not a registered field."
    commands:
      vet: "go vet ./..."
      test: "go test ./..."
      race: "go test -race ./..."
      yara: "CGO_ENABLED=1 go test -tags yara ./pkg/yara/"
      pure_go_build: "CGO_ENABLED=0 go build ./..."
      rules_test: "go run ./cmd/zaafvesper rules test rules"
      rules_validate: "go run ./cmd/zaafvesper rules validate rules"
      bench: "go test -run '^$' -bench BenchmarkEngine -benchtime 3s ./..."
      fuzz_seed_only: "go test -run FuzzParse ./pkg/filter/ql/   # seed corpus only; do not pass -fuzz (it can write testdata/fuzz into the repo)"
      hashes: "shasum -a 256 pkg/event/event.go pkg/source/source.go"
      yara_compile: "for f in rules/yara/*.yar; do yara -w \"$f\" /dev/null || echo FAIL $f; done"
      navigator: "go run ./cmd/zaafvesper coverage --navigator /dev/stdout"

  scoring:
    aggregation: weighted_sum
    total_weight: 1.0
    procedure:
      - "1. Answer every checklist item YES/NO with evidence (command output, file:line, or quote) and proof tag run|read|likely."
      - "2. Score each rubric dimension 1-5 by placing the artifact against its score_2/score_4 anchors."
      - "3. base = sum(score_i * weight_i)."
      - "4. deductions = 0.10 per important item answered NO + 0.20 per pitfall answered YES; total deductions capped at 1.50."
      - "5. final = max(1.0, base - deductions)."
      - "6. If any essential item is NO: final = min(final, 2.0)."
      - "7. Optional items never change the score; report them."
    pass_threshold:
      rule: "PASS if and only if (a) no essential item is NO, (b) final >= 3.50, and (c) none of D1, D4, D5, D12, D13 scored below 3."
      fail_otherwise: true
    not_verifiable_here:
      - "Live alert latency < 1 s and live eslogger behaviour (need root + Full Disk Access): judge by reading (CK-60) and report as NOT VERIFIED live."
      - "Live atomic validation of >= 20 rules (spec §5.4 requires Rifqi's per-batch approval): the verdict checks GUID traceability only (CK-19, CK-27, D9)."
      - "If the atomic-red-team clone path is missing at verdict time, CK-19/CK-20/CK-26/CK-27 fall back to reading and are tagged proof: likely, not failed."
    judge_output_fields: [criterion_name, score, reason, evidence, proof, overall_label]

  checklist:
    # ---------------- ESSENTIAL (any NO caps final at 2.0) ----------------
    - id: CK-01
      question: "Does `go vet ./...` exit 0?"
      category: hard_rule
      importance: essential
      rationale: "Plan global constraint."
    - id: CK-02
      question: "Does `go test ./...` exit 0?"
      category: hard_rule
      importance: essential
      rationale: "Plan global constraint; every other test-based item depends on it."
    - id: CK-04
      question: "Does `CGO_ENABLED=1 go test -tags yara ./pkg/yara/` exit 0 and run at least one test that compiles a tiny rule, scans a temp file and asserts a YaraMatch event with Source \"yara\"?"
      category: hard_rule
      importance: essential
      rationale: "YARA is in the MVP by owner decision; plan WS B3 names this exact command."
    - id: CK-05
      question: "Does `CGO_ENABLED=0 go build ./...` succeed (the build without the yara tag is pure Go)?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.6b: build without the tag stays pure-Go."
    - id: CK-06
      question: "Does `go run ./cmd/zaafvesper rules test rules` exit 0 with every scenario passing and with the number of rules tested equal to the number of rule files in rules/*.yml?"
      category: hard_rule
      importance: essential
      rationale: "Spec success criterion 2; equal counts prevent a runner that silently skips rules."
    - id: CK-07
      question: "Does `go run ./cmd/zaafvesper rules validate rules` exit 0?"
      category: hard_rule
      importance: essential
      rationale: "Every shipped rule must compile against the field registry and pass schema checks."
    - id: CK-08
      question: "Do the sha256 hashes of pkg/event/event.go and pkg/source/source.go equal the baseline hashes in metadata?"
      category: hard_rule
      importance: essential
      rationale: "Plan: the shared contract is FROZEN."
    - id: CK-09
      question: "Are all stub exported identifiers still present with unchanged signatures: eslogger.Config{Binary, ExcludePaths, ExcludeSigning}, eslogger.New(Config) *Source, (*Source).Name/Run/Stats, eslogger.Decode([]byte) (*event.Event, bool, error), eslogger.ESEventTypes([]string) []string, ps.NewSnapshotter(bool) *Snapshotter, (*Snapshotter).Enrich/Len, yara.Config{RulesDir, Workers, MaxFileSize, TimeoutSec, WatchDirs}, yara.ErrDisabled, yara.New(Config) (source.Scanner, error)?"
      category: hard_rule
      importance: essential
      rationale: "Plan: other workstreams compile against these."
    - id: CK-10
      question: "Does BenchmarkEngine exist, load >= 30 compiled rules including >= 1 sequence rule, feed a mix whose evt.names are indexed by those rules, and report a throughput >= 20 000 events/s (custom events/s metric, or 1e9 / ns_per_op x events_per_op read from the code)?"
      category: hard_rule
      importance: essential
      rationale: "Spec success criterion 4 / plan A9; the mix requirement blocks a benchmark that only feeds events no rule looks at."
    - id: CK-11
      question: "Is os/exec (or syscall.Exec/ForkExec) used only to launch the eslogger binary with an argv built from the static ESEventTypes table, and nowhere else (grep -rn 'os/exec\\|exec.Command\\|syscall.Exec\\|ForkExec\\|/bin/sh' --include=*.go pkg cmd)?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.6: no shell, no exec with event-derived strings (kill must be a syscall, bootstrap must be sysctl)."
    - id: CK-12
      question: "Is Go's regexp the only regex engine (no regexp2/pcre/other in go.mod or imports)?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.6: RE2, no ReDoS."
    - id: CK-13
      question: "Does a passing unit test assert that a comparison on an absent field is false for `=` and `!=` (e.g. `target.ps.exe != 'x'` on an event with Target nil) and that `not` of it is true?"
      category: hard_rule
      importance: essential
      rationale: "Plan: Fibratus nil semantics, explicitly listed in the prompt."
    - id: CK-14
      question: "Do unit tests with an injected kill func show that no kill happens when --enable-response is off even if the rule has action kill, and none when the rule has no kill action even if --enable-response is on?"
      category: hard_rule
      importance: essential
      rationale: "Owner decision: kill optional and off by default; spec §4.5 double gate."
    - id: CK-15
      question: "Do unit tests show Kill refuses pid <= 1, ZAAFVesper's own pid, the eslogger pid, names kernel_task/launchd/WindowServer/loginwindow, and exe prefixes /System/, /usr/libexec/, /sbin/?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.5 / plan A5 protected list."
    - id: CK-16
      question: "When euid == 0, does `run` call CheckOwnership on the rule files, macro files, YARA rule files, zaafvesper.yml and config.d files and refuse to start if any is not uid 0 or is group/world writable?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.6: whoever can write rules can force kills."
    - id: CK-17
      question: "Does a unit test assert that alert.Sanitize removes ESC (0x1B), all other C0 (0x00-0x1F), DEL (0x7F) and C1 (U+0080-U+009F, including U+009B CSI), so no such code point remains in the output?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.6 / plan global: terminal injection prevention."
    - id: CK-18
      question: "Does eslogger.Decode return an error (not panic) for truncated JSON, wrong JSON types and unknown event types (unknown types => ok=false, nil error), and does the source increment a decode_errors counter in Stats()?"
      category: hard_rule
      importance: essential
      rationale: "Spec §4.6: failed decodes are counted, never panic."
    - id: CK-19
      question: "Do >= 20 rules carry tests.atomic GUIDs that each appear in macos-index.csv?"
      category: hard_rule
      importance: essential
      rationale: "Spec success criterion 3 (traceability part)."
    - id: CK-20
      question: "Is every rule's labels.technique.id present and neither revoked nor deprecated in the bundled enterprise-attack.json (so no T1562, T1562.001, T1562.004, T1070.002)?"
      category: hard_rule
      importance: essential
      rationale: "Plan C2 'use current IDs'; the design doc's §4.4 cites IDs that are now revoked."
    - id: CK-21
      question: "Does every rule file have rules/testdata/<stem>.yml with >= 1 match scenario and >= 2 nomatch scenarios?"
      category: hard_rule
      importance: essential
      rationale: "Plan fixture format; spec success criterion 2."
    - id: CK-22
      question: "Are there >= 3 sequence rules among the shipped rules?"
      category: hard_rule
      importance: essential
      rationale: "Plan C2."
    - id: CK-23
      question: "For exec, does Decode set Proc from event.exec.target (new image, with args and cwd) and Args[\"prev_exe\"] from the message's process.executable.path, proven by a golden test?"
      category: hard_rule
      importance: essential
      rationale: "Plan B1; using the instigating (old) image would attribute every CreateProcess to the shell that ran it."

    # ---------------- IMPORTANT (each NO deducts 0.10) ----------------
    - id: CK-24
      question: "Do pkg/filter/ql, pkg/rules, pkg/alert, pkg/response, pkg/capture, pkg/config, pkg/source/eslogger and pkg/ps each contain at least one _test.go file (no '[no test files]' for them in go test output)?"
      category: hard_rule
      importance: important
      rationale: "Plan asks for unit tests in every package; go test passing with no tests proves nothing."
    - id: CK-25
      question: "Does `go test -race ./...` exit 0?"
      category: principle
      importance: important
      rationale: "Pipeline goroutine, YARA workers and sinks share *event.Event; a data race in a root sensor is a correctness and safety bug."
    - id: CK-26
      question: "For every rule, is labels.tactic.id one of the tactics of its technique in enterprise-attack.json (e.g. T1553.001 -> TA0112, T1564.001 -> TA0005)?"
      category: principle
      importance: important
      rationale: "ATT&CK accuracy; TA0005 is now Stealth and TA0112 Defense Impairment."
    - id: CK-27
      question: "For every GUID in tests.atomic, does its macos-index.csv technique equal the rule's technique.id or share its parent technique?"
      category: principle
      importance: important
      rationale: "A GUID pointing at an unrelated technique is false traceability."
    - id: CK-28
      question: "Does a rule exist for each behaviour of spec §4.4 (Launch Agent, Launch Daemon, shell profile, StartupItems, Login Item via osascript, cron/periodic, emond, quarantine removal, spctl --master-disable, DYLD_INSERT_LIBRARIES, chflags hidden, firewall/logging disable, log deletion, security dump-keychain, keychain file access by non-Apple process, osascript password prompt, SSH key access, browser credential store, silent screencapture, security software enumeration, system_profiler/sw_vers sequence, curl/wget piped to shell, exec from /tmp or /Users/Shared then unsigned sequence, osascript JXA from unusual parent, get_task by unsigned binary) plus 'YARA signature match' and 'XProtect malware detection'?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.4 + plan C2 scope."
    - id: CK-29
      question: "Does testdata/eslogger contain hand-written lines for all 24 mapped ES types (exec, fork, exit, open, create, write, close, rename, unlink, setextattr, deleteextattr, setmode, setowner, get_task, signal, trace, remote_thread_create, btm_launch_item_add, mount, kextload, authentication, sudo, tcc_modify, xp_malware_detected), each decoded by a golden test?"
      category: hard_rule
      importance: important
      rationale: "Plan B1."
    - id: CK-30
      question: "Are Proc.PID and Proc.PIDVersion taken from process.audit_token (pid, pidversion), and is UUID = uint64(pid)<<32 | uint64(pidversion)?"
      category: hard_rule
      importance: important
      rationale: "Plan B2; es_process_t carries pid only inside audit_token."
    - id: CK-31
      question: "When the snapshotter is enabled, does `run` always subscribe exec, fork and exit even if no loaded rule needs them?"
      category: principle
      importance: important
      rationale: "Without them the process table, ancestors and parent fields are empty and many rules go dead."
    - id: CK-32
      question: "Does ESEventTypes map WriteFile to both 'write' and 'close', and the other canonical names to the eslogger short names of spec §4.1 (OpenProcess->get_task, Ptrace->trace, AddLaunchItem->btm_launch_item_add, LoadKext->kextload, Authenticate->authentication, ModifyTCC->tcc_modify, XProtectDetect->xp_malware_detected)?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.1 mapping; wrong names make eslogger fail or miss events."
    - id: CK-33
      question: "Do fake-clock sequence tests cover: steps arriving out of order do not match, different join values do not join, a step after maxspan does not complete, and a completed sequence resets so the same partial does not fire twice?"
      category: hard_rule
      importance: important
      rationale: "Plan A2."
    - id: CK-34
      question: "Does a test show the partial-state cap of 10 000 per rule evicts the oldest partial first?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.2 bounded memory under attack."
    - id: CK-35
      question: "Does a test assert that `%1.file.path` in output resolves from step 1's event and plain `%ps.exe` from the last event?"
      category: hard_rule
      importance: important
      rationale: "Plan sequence output semantics."
    - id: CK-36
      question: "Do imatches/matches tests show `*` crossing '/', `?` matching exactly one character, whole-string anchoring, and regex metacharacters (., +, (, [) treated literally?"
      category: hard_rule
      importance: important
      rationale: "Plan glob definition; regex-translated globs commonly leak metacharacters or substring-match."
    - id: CK-37
      question: "Does a test assert precedence not > and > or (e.g. `a or b and not c`)?"
      category: hard_rule
      importance: important
      rationale: "Plan boolean precedence."
    - id: CK-38
      question: "Does compiling a rule with an unknown field fail with an error naming the rule, and do parse errors carry a column number (both asserted in tests)?"
      category: hard_rule
      importance: important
      rationale: "Plan A1/condition language."
    - id: CK-39
      question: "Does FuzzParse exist and does `go test -run FuzzParse ./pkg/filter/ql/` pass on its seed corpus?"
      category: hard_rule
      importance: important
      rationale: "Plan A1; parser reads root-owned but human-written input."
    - id: CK-40
      question: "Does a test show the 11th kill within one minute is refused and logged?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.5 rate limit."
    - id: CK-41
      question: "Does a test show DryRun logs the would-be kill and never calls the kill func?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.5 --dry-run-response."
    - id: CK-42
      question: "Is every kill decision (executed, refused-protected, refused-rate-limited, dry-run) logged with pid, exe, rule and reason?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.5 'kill selalu dicatat'."
    - id: CK-43
      question: "Is yara Submit non-blocking (select with default) with a dropped counter when the queue is full?"
      category: hard_rule
      importance: important
      rationale: "Plan B3; a blocking Submit stalls the whole pipeline on slow scans."
    - id: CK-44
      question: "When yara.New returns ErrDisabled, does `run` print a warning and continue?"
      category: hard_rule
      importance: important
      rationale: "Plan A8."
    - id: CK-45
      question: "Are YaraMatch events from Scanner.Start fed back into the engine in `run`, and does the 'YARA signature match' rule fire on a YaraMatch fixture?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.6b re-injection design."
    - id: CK-46
      question: "Run as a non-root user, does `go run ./cmd/zaafvesper replay testdata/eslogger/<an exec fixture>.jsonl` exit 0 without demanding root?"
      category: hard_rule
      importance: important
      rationale: "Spec success criterion 5."
    - id: CK-47
      question: "Do capture tests show Reader accepts gzip .rcap, raw eslogger JSONL (detected by event_type on the first line) and plain JSONL, and that Writer output round-trips?"
      category: hard_rule
      importance: important
      rationale: "Plan A6."
    - id: CK-48
      question: "Does the CLI expose run, replay, rules list, rules validate, rules test, coverage --navigator and version?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.7."
    - id: CK-49
      question: "Does `run` accept --rules, --config, --capture, --enable-response, --dry-run-response and --json?"
      category: hard_rule
      importance: important
      rationale: "Spec §4.7 / plan A8."
    - id: CK-50
      question: "Does `coverage --navigator` emit JSON with versions.layer \"4.5\", domain \"enterprise-attack\" and one techniques[] entry per covered technique scored by rule count?"
      category: hard_rule
      importance: important
      rationale: "Plan A8."
    - id: CK-51
      question: "Are direct dependencies limited to gopkg.in/yaml.v3, github.com/hillu/go-yara/v4 and (if used) golang.org/x/sys, with any other addition named and justified in a report?"
      category: hard_rule
      importance: important
      rationale: "Plan tech-stack constraint."
    - id: CK-52
      question: "Are there 3-5 files in rules/yara/*.yar and does each compile (`yara -w <file> /dev/null` exits 0)?"
      category: hard_rule
      importance: important
      rationale: "Plan C3."
    - id: CK-53
      question: "Does rules/macros define all 23 event macros named in plan C1 and the lists shells and script_interpreters?"
      category: hard_rule
      importance: important
      rationale: "Plan C1."
    - id: CK-54
      question: "Do tests show LoadDir rejects duplicate ids, an invalid severity, a technique.id not matching ^T\\d{4}(\\.\\d{3})?$, and a min-engine-version above the engine's version?"
      category: hard_rule
      importance: important
      rationale: "Plan A3."
    - id: CK-55
      question: "Are config exclusions applied to events before rule evaluation, shown by a test?"
      category: hard_rule
      importance: important
      rationale: "Plan A4 / sysmon-modular style noise control."
    - id: CK-56
      question: "Does pkg/ps cap the table at 65 536 entries, keep exited processes 30 s, and cap Ancestors at 16, each covered by a test?"
      category: hard_rule
      importance: important
      rationale: "Plan B2 bounded memory."
    - id: CK-57
      question: "Does the eslogger source restart eslogger with backoff at most 5 times per minute and surface a clear error when not root or Full Disk Access is missing?"
      category: hard_rule
      importance: important
      rationale: "Plan B1."
    - id: CK-58
      question: "On SIGINT/SIGTERM does `run` stop eslogger, close the capture writer (gzip footer written, file readable by replay) and print stats?"
      category: hard_rule
      importance: important
      rationale: "Plan A8; an unclosed gzip makes the capture unusable for replay."
    - id: CK-59
      question: "Are --capture and --json files created with mode 0600 (or stricter) and without following a pre-existing symlink (O_EXCL or O_NOFOLLOW)?"
      category: principle
      importance: important
      rationale: "Root writing to a path an unprivileged user pre-planted as a symlink is a classic overwrite; captures hold cmdlines and env."
    - id: CK-60
      question: "Is there no batching or timed flush of >= 1 s between eslogger stdout and the console sink (events processed one by one, sink written per alert)?"
      category: principle
      importance: important
      rationale: "Spec success criterion 1 (alert < 1 s), checkable only by reading here."
    - id: CK-61
      question: "Does `zaafvesper rules test` exit non-zero when any scenario fails?"
      category: hard_rule
      importance: important
      rationale: "Spec §5.2: mandatory in CI."

    # ---------------- OPTIONAL (reported, no score effect) ----------------
    - id: CK-62
      question: "Does every YARA rule carry tags and meta author, description, reference and attack?"
      category: hard_rule
      importance: optional
      rationale: "Plan C3."
    - id: CK-63
      question: "Does docs/rules.md list every rule with name, ATT&CK id, severity, atomic GUID and a sequence flag?"
      category: hard_rule
      importance: optional
      rationale: "Plan C4."
    - id: CK-64
      question: "Does the Makefile provide build, build-yara, test, rules-test and bench targets?"
      category: hard_rule
      importance: optional
      rationale: "Plan A9."
    - id: CK-65
      question: "Is at least one real (not hand-written) eslogger line from macOS 26 present in testdata and decoded by a test?"
      category: principle
      importance: optional
      rationale: "Spec §5.5 schema-drift mitigation; depends on Rifqi providing a capture."
    - id: CK-66
      question: "Does Sanitize also neutralise Unicode bidi controls (U+202A-U+202E, U+2066-U+2069)?"
      category: principle
      importance: optional
      rationale: "Trojan-source style display spoofing of paths in alerts."
    - id: CK-67
      question: "Before signalling, does the responder verify the target still has the expected pidversion or start time?"
      category: principle
      importance: optional
      rationale: "NOTIFY is after the fact; pid reuse could redirect a kill."

    # ---------------- PITFALLS (each YES deducts 0.20) ----------------
    - id: PF-01
      question: "Does any code path print a raw eslogger line, path, cmdline or rule text to stdout/stderr without alert.Sanitize (e.g. logging the failing line on a decode error)?"
      category: principle
      importance: pitfall
      rationale: "Bypasses the ANSI defence outside the console sink."
    - id: PF-02
      question: "Can a single event complete two steps of the same sequence (step 1 and step 2 both satisfied by one event produce an alert)?"
      category: principle
      importance: pitfall
      rationale: "Turns a two-behaviour sequence into a single-behaviour rule; false positives."
    - id: PF-03
      question: "Do two events that both lack the `by` field (nil or empty join value) join each other?"
      category: principle
      importance: pitfall
      rationale: "Absent join keys must not correlate unrelated events."
    - id: PF-04
      question: "Is a glob or regexp compiled inside the per-event Match path rather than once per literal at compile time?"
      category: principle
      importance: pitfall
      rationale: "Plan A1 'compiled once per literal'; throughput killer."
    - id: PF-05
      question: "Do sequence or rate-limit tests depend on time.Sleep or the wall clock instead of an injected clock or event times?"
      category: principle
      importance: pitfall
      rationale: "Flaky tests; plan asks for a fake clock."
    - id: PF-06
      question: "Does the ownership check skip the containing directories (rules dir, rules/macros, rules/yara, config dir, config.d), so a user who can write the directory can add a file after the check?"
      category: principle
      importance: pitfall
      rationale: "Checking files only leaves a writable-directory bypass."
    - id: PF-07
      question: "Does RunFixtures evaluate rule filters directly instead of through NewEngine + Process (bypassing the evt.name index and the sequence engine)?"
      category: principle
      importance: pitfall
      rationale: "Green fixtures would not prove the engine that runs in production."
    - id: PF-08
      question: "Does the decoder stamp Event.Time with time.Now() instead of the message's time field?"
      category: principle
      importance: pitfall
      rationale: "Breaks replay ordering and sequence maxspan on captures."

  rubric_dimensions:
    - name: "D1 Absent-field (nil) semantics"
      description: "Across every operator, function and boolean form, does an absent field (nil per the contract rule) make the comparison false - including !=, not in, not imatches, list RHS, functions such as length()/base() applied to nil - and make `not <comparison>` true? Does the evaluator avoid converting nil to \"\" or 0?"
      scale: "1-5"
      weight: 0.08
      instruction: "Read the evaluator's comparison and function code and the ql tests. Trace each operator and each function for a nil LHS, and the infix negated forms. Do not penalise an empty string on a present Proc being compared normally (contract: that is \"\", not nil). Place the artifact against the anchors; each operator or function that treats nil as a value pulls toward score_2."
      anchors:
        contrast: "Absent LHS returns false before the operator runs, rather than true for !=."
        score_2: |
          case nil:
              return op == NE // absent != 'x' is true
        score_4: |
          if lhs == nil { return false } // absent: every comparison false, incl. !=

    - name: "D2 List left-hand-side semantics"
      description: "When the LHS is []string (ps.args, ps.ancestors, ps.parent.ancestors, target.ps.args, yara.tags), is each element tested separately so the operator is true if ANY element satisfies it, for every string operator including anchored ones (=, startswith, imatches, in)? Are list-LHS x list-RHS combinations and the negated forms consistent with that rule?"
      scale: "1-5"
      weight: 0.05
      instruction: "Read the []string branch of the evaluator and its tests; check =, in, startswith, imatches, regex with list LHS, and `not in`. Place the artifact against the anchors."
      anchors:
        contrast: "Tests each list element, rather than one string joined from the list."
        score_2: |
          case []string:
              return cmpString(op, strings.Join(v, " "), rhs)
        score_4: |
          case []string:
              for _, s := range v { if cmpString(op, s, rhs) { return true } }
              return false

    - name: "D3 Event-name approver soundness"
      description: "Does Filter.EventNames() (and Engine.RequiredEvents()) over-approximate: return nil (any) whenever some true path of the condition is not constrained by evt.name (or, not, macros that are not event macros, sequence steps), and the union only when every branch is constrained? Is RequiredEvents the union over rules, with nil from any rule meaning all supported events?"
      scale: "1-5"
      weight: 0.05
      instruction: "Read EventNames for Or, Not, And, macro expansion and sequences, and RequiredEvents. Mentally evaluate `spawn_process or file.path = 'x'`, `not spawn_process`, `spawn_process and not ps.name = 'a'`. Place against the anchors; any construct that can drop an event a rule needs pulls toward score_2."
      anchors:
        contrast: "An unconstrained OR branch widens the set to any, rather than being ignored."
        score_2: |
          func (n *Or) EventNames() []string { return union(n.L.EventNames(), n.R.EventNames()) } // nil treated as empty
        score_4: |
          if l, r := n.L.EventNames(), n.R.EventNames(); l == nil || r == nil { return nil }

    - name: "D4 Sequence time base"
      description: "Is sequence expiry (maxspan) measured between event timestamps (Event.Time of the first step vs the current event), or an injected clock that replay and fixtures drive from event time, so live, replay and `rules test` agree? Is expiry checked when a later step arrives (not only on a background sweep that might run late)?"
      scale: "1-5"
      weight: 0.08
      instruction: "Read the sequence state machine and how fixtures and replay feed it. Find every use of time.Now/time.Since in pkg/rules. Place against the anchors."
      anchors:
        contrast: "Expiry compares event times, rather than wall-clock time since the partial was stored."
        score_2: |
          if time.Since(p.start) > r.maxspan { delete(st, key) }
        score_4: |
          if e.Time.Sub(p.start) > r.maxspan { delete(st, key) }

    - name: "D5 ES decoding fidelity"
      description: "For each of the 24 mapped ES types, does Decode read the struct member the headers define (snake_case) and follow unions: create/rename destination_type EXISTING_FILE vs NEW_PATH (dir.path + filename), close only when modified=true, rename source -> file.path and destination -> file.dest, signal sig -> Args[signal] with Target = target, open fflag -> open_flags, get_task/trace/remote_thread_create Target = target, btm item.item_type/item_url/executable_path, tcc_modify service/right, sudo command/success, xp_malware_detected malware_identifier/detected_path; message time -> Event.Time; codesigning_flags/is_platform_binary/signing_id/team_id/cdhash/tty mapped; unknown fields ignored?"
      scale: "1-5"
      weight: 0.10
      instruction: "Open the decoder and its testdata/eslogger fixtures beside ESMessage.h/ESMessageCore.h. For each type list the mapping errors (wrong member, missing union branch, instigator/target swap, wrong source of time or pid). Also check fixture JSON keys use the header member names. Place against the anchors; each mis-mapped type pulls toward score_2."
      anchors:
        contrast: "Handles the NEW_PATH branch of the create destination union, rather than only existing_file."
        score_2: |
          case "create":
              e.File = &event.File{Path: c.Destination.ExistingFile.Path}
        score_4: |
          case "create":
              if c.DestinationType == 1 { // ES_DESTINATION_TYPE_NEW_PATH
                  e.File = &event.File{Path: filepath.Join(c.Destination.NewPath.Dir.Path, c.Destination.NewPath.Filename)}
              } else { e.File = &event.File{Path: c.Destination.ExistingFile.Path} }

    - name: "D6 Process identity across pid reuse"
      description: "Does the process table use pidversion (from audit_token / parent_audit_token) so that a reused pid or an exec'd image is not confused with a stale entry when filling Parent, Ancestors and UUID? Does exec replace the image under the new pidversion and fork copy the parent?"
      scale: "1-5"
      weight: 0.04
      instruction: "Read pkg/ps lookup, fork, exec and exit handling and its tests with synthetic sequences that reuse a pid. Place against the anchors."
      anchors:
        contrast: "Parent lookup rejects an entry whose pidversion differs, rather than trusting the pid alone."
        score_2: |
          parent := s.table[e.Proc.PPID]
        score_4: |
          parent := s.lookup(e.Proc.PPID, parentPIDVersion) // nil if pidversion differs

    - name: "D7 ATT&CK mapping currency and precision"
      description: "Is each rule's technique.id the most specific current (not revoked/deprecated) technique for the behaviour in the bundled enterprise-attack.json, and does technique.name match the ATT&CK name? Precise sub-technique where one fits (T1543.001 not T1543)?"
      scale: "1-5"
      weight: 0.07
      instruction: "For every rule, look up technique.id in enterprise-attack.json; note revoked/deprecated ids, mismatched names, and parent ids used where a sub-technique fits. For spctl --master-disable accept T1685 (atomic 2a821573) or T1553.001. Place against the anchors."
      anchors:
        contrast: "Uses the current id, rather than one ATT&CK has revoked."
        score_2: |
          labels: {tactic.id: TA0005, technique.id: T1562.004}
        score_4: |
          labels: {tactic.id: TA0112, technique.id: T1686}

    - name: "D8 Benign-lookalike fixtures"
      description: "Does each rule's nomatch set include a realistic benign event that touches the same path, command family or event type the rule watches and differs only in the attribute the rule uses to exclude it (e.g. a signed updater writing its own LaunchAgent, /usr/bin/ssh reading ~/.ssh/id_ed25519, Chrome opening its own Login Data, interactive `screencapture -i` from Terminal)? Are match events shaped like what the decoder really emits for that ES type?"
      scale: "1-5"
      weight: 0.08
      instruction: "Read every rules/testdata/*.yml. For each rule decide whether at least one nomatch is a true lookalike (same watched object, discriminated by the rule's exclusion logic) or only trivially different (other path, other evt.name). Place against the anchors; rules with only trivial nomatches pull toward score_2."
      anchors:
        contrast: "The nomatch lands on the watched LaunchAgents path, rather than on an unrelated file."
        score_2: |
          nomatch:
            - desc: unrelated file
              events: [{name: CreateFile, file: {path: /tmp/a.txt}}]
        score_4: |
          nomatch:
            - desc: Google updater writes its own launch agent
              events: [{name: CreateFile, proc: {exe: /Users/a/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater, team_id: EQHXZ8M8AV, is_signed: true}, file: {path: /Users/a/Library/LaunchAgents/com.google.GoogleUpdater.wake.plist}}]

    - name: "D9 Conditions faithful to the cited atomic"
      description: "For rules that cite tests.atomic GUIDs, would the condition fire on what that atomic's command actually does on macOS (as seen through eslogger events), e.g. fb3d46c6 runs `xattr -d com.apple.quarantine <app>`, deb7d358 runs `screencapture -x`, 88e1fa00 runs `sudo security dump-keychain -d login.keychain`, 4d66029d runs `DYLD_INSERT_LIBRARIES=<dylib> <app>`? Does the match fixture mirror that command?"
      scale: "1-5"
      weight: 0.05
      instruction: "For each cited GUID, read the atomic's executor command in the clone and check the rule condition and match fixture against it. Rules without a GUID are neutral here. Place against the anchors."
      anchors:
        contrast: "Keys on the effect the atomic produces, rather than a command spelling the atomic never uses."
        score_2: |
          condition: spawn_process and ps.cmdline icontains 'xattr -r -d com.apple.quarantine'
          tests: {atomic: [fb3d46c6-9480-4803-8d7d-ce676e1f1a9b]}
        score_4: |
          condition: delete_xattr and evt.arg[xattr] = 'com.apple.quarantine'
          tests: {atomic: [fb3d46c6-9480-4803-8d7d-ce676e1f1a9b]}

    - name: "D10 Allow-list robustness (false-positive control without a bypass)"
      description: "Do rule exclusions for legitimate software use identity an attacker cannot forge - is_platform, team_id, or exe paths under SIP-protected directories (/usr/bin, /bin, /sbin, /usr/sbin, /usr/libexec, /System) - instead of ps.name, a bare signing_id (any ad-hoc signer can choose it), or user-writable paths? Are noisy event types (OpenFile, WriteFile) constrained enough to be quiet on a normal Mac?"
      scale: "1-5"
      weight: 0.08
      instruction: "Read every rule's `not ...` clauses and macro lists used as allow-lists. Count exclusions anchored on forgeable identity and rules on OpenFile/WriteFile with no process constraint. Place against the anchors."
      anchors:
        contrast: "Anchors the signing ID to a platform binary, rather than trusting the signing ID alone."
        score_2: |
          and not ps.signing_id in ('com.apple.ssh', 'com.apple.ssh-agent')
        score_4: |
          and not (ps.is_platform = true and ps.signing_id in ('com.apple.ssh', 'com.apple.ssh-agent'))

    - name: "D11 Trust-signal reach on Apple Silicon"
      description: "Where a rule means 'untrusted or unsigned binary', does the condition still fire for ad-hoc / linker-signed arm64 binaries (every arm64 binary carries at least a linker signature: CS_SIGNED 0x20000000, CS_ADHOC 0x2, CS_LINKER_SIGNED 0x20000)? Does the rule's notion of unsigned agree with how the decoder derives is_signed?"
      scale: "1-5"
      weight: 0.05
      instruction: "First read how the decoder computes is_signed from codesigning_flags. If is_signed is true for ad-hoc/linker signatures, then rules relying only on `ps.is_signed = false` score toward score_2; if the decoder documents is_signed as 'signed with a team identity or platform' then `is_signed = false` is equivalent to score_4. Place against the anchors."
      anchors:
        contrast: "Fires on ad-hoc-signed binaries, rather than relying on a flag that ad-hoc signing sets."
        score_2: |
          condition: spawn_process and ps.exe istartswith '/tmp/' and ps.is_signed = false
        score_4: |
          condition: spawn_process and ps.exe istartswith '/tmp/' and ps.team_id = '' and ps.is_platform = false

    - name: "D12 Root-ownership enforcement"
      description: "Does CheckOwnership reject a path whose owner is not uid 0 OR whose mode has group/world write (mode & 0o022), using the file's real metadata (stat on the target, or lstat that rejects symlinks), and return an error naming the path?"
      scale: "1-5"
      weight: 0.07
      instruction: "Read CheckOwnership and its tests (temp files with chmod 0666 / 0644 and, if run as non-root, a test seam for uid). Place against the anchors."
      anchors:
        contrast: "Rejects group/world-writable files too, rather than checking the owner only."
        score_2: |
          if st.Uid != 0 { return fmt.Errorf("%s not root-owned", p) }
        score_4: |
          if st.Uid != 0 || st.Mode&0o022 != 0 { return fmt.Errorf("%s must be root-owned and not group/world writable", p) }

    - name: "D13 Kill gating"
      description: "Does a kill require BOTH the operator flag (--enable-response) and a rule action [{name: kill}], with dry-run taking precedence, and does every path that can lead to Kill (live run, replay) go through that gate? Can replay ever kill?"
      scale: "1-5"
      weight: 0.07
      instruction: "Trace from alert to Responder.Kill in cmd/zaafvesper and pkg/response for run and replay. Place against the anchors; any path where the rule action alone triggers a kill is score_2 or lower, and replay able to kill is score 1."
      anchors:
        contrast: "Kill requires the operator flag as well as the rule action, rather than the rule action alone."
        score_2: |
          for _, a := range al.Actions { if a == "kill" { responder.Kill(pid, al.RuleName) } }
        score_4: |
          if opts.EnableResponse { for _, a := range al.Actions { if a == "kill" { responder.Kill(pid, al.RuleName) } } }

    - name: "D14 Terminal output sanitising"
      description: "Does every terminal write that can contain event- or rule-derived text go through alert.Sanitize: console sink headline and indented detail lines, expanded output templates (%field), `rules list`, `rules test` failure messages, replay/run stats and error logs, response logs?"
      scale: "1-5"
      weight: 0.05
      instruction: "Enumerate every fmt.Fprint*/log.* call that writes to stdout/stderr with event or rule data and check each. Place against the anchors."
      anchors:
        contrast: "Passes event-derived text through Sanitize before printing, rather than printing it raw."
        score_2: |
          fmt.Fprintf(w, "%s %s\n", sev, a.Output)
        score_4: |
          fmt.Fprintf(w, "%s %s\n", sev, alert.Sanitize(a.Output))

    - name: "D15 YARA file-open safety"
      description: "Does the scanner open files with O_NOFOLLOW (and O_NONBLOCK so a FIFO cannot hang a worker), then fstat the opened descriptor and scan only regular files within MaxFileSize, with the per-scan timeout applied and the cache keyed by (path, size, mtime) or cdhash?"
      scale: "1-5"
      weight: 0.04
      instruction: "Read pkg/yara/scanner.go open/stat/scan path and its tests. Place against the anchors; Lstat-then-Open (TOCTOU) sits between the two."
      anchors:
        contrast: "Opens without following symlinks and checks the opened descriptor is a regular file, rather than a plain open."
        score_2: |
          f, err := os.Open(path)
        score_4: |
          fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) // then Fstat(fd): S_IFREG only, size <= MaxFileSize

    - name: "D16 Per-event rule dispatch cost"
      description: "Does Engine.Process look up candidate rules by evt.name (plus a separate list for rules whose EventNames is nil, evaluated for every event) instead of evaluating every rule on every event, and are sequence steps dispatched the same way?"
      scale: "1-5"
      weight: 0.04
      instruction: "Read Engine construction and Process. Check that rules with nil EventNames are not dropped from dispatch. Place against the anchors."
      anchors:
        contrast: "Evaluates only rules indexed under the event's name, rather than every rule."
        score_2: |
          for _, r := range e.rules { if r.f.Match(ev) { ... } }
        score_4: |
          for _, r := range e.byName[ev.Name] { ... }; for _, r := range e.anyName { ... }
```
