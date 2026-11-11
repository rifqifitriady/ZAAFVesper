# zaafvesper.elegia/1

`zaafvesper-elegia-v1.schema.json` is the published format of the records ZAAFVesper writes for ZAAFElegia (`--elegia-out`, `--elegia-dir`). Every record carries `zaafvesper.schema = "zaafvesper.elegia/1"`.

## Change policy

- **Compatible (stays `/1`):** adding a field, adding an event category, adding an allowed value to an enumeration. Readers must ignore fields they do not know.
- **Breaking (becomes `/2`):** renaming, removing or retyping a field, or changing what a field's value means. The new schema goes in a new file (`zaafvesper-elegia-v2.schema.json`); the v1 file stays, unchanged.
- **Locked by tests:** `TestElegiaRecordsMatchSchema` (pkg/output) validates the encoder's output for every event type and platform against this file in both directions, and a SHA-256 test fails when the file changes. A change to the schema therefore needs a deliberate edit of the expected hash in the same commit, which is the moment to decide whether it is compatible.

## Sources and platforms

Records come from every event source: macOS Endpoint Security (`eslogger`), Windows Sysmon, and on Linux the eBPF source (default) or Sysmon for Linux. All Linux records carry `logsource.product = "linux"` whichever source produced them.

`--elegia-dir` is not available on Windows yet (the command refuses to start); use `--elegia-out -` there.
