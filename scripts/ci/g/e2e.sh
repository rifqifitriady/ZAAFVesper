#!/bin/bash
# ZAAFVesper -> ZAAFElegia end to end (v0.4 G), unprivileged, for CI:
#   1. the committed sample and pipeline preset are up to date;
#   2. the sample scenarios, as a capture, go through `zaafvesper replay`
#      into --elegia-dir segments (small segments, so several rotate);
#   3. `zaaf check` accepts the rules (correlations parsed);
#   4. `zaaf hunt` over the segments and over a live replay pipe finds what
#      samples/expected.json says (correlations once ZAAFElegia supports them).
# Expects: ZV (zaafvesper binary), ZAAF (zaaf binary). Writes to $OUT.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
: "${ZV:?}" "${ZAAF:?}" "${OUT:?}"
mkdir -p "$OUT"
I="$repo/integrations/zaafelegia"

echo "== 1. committed sample and preset are current"
go run "$I/samples/gen" -check "$I/samples/macos-scenarios.ndjson"
go run "$I/samples/gen" -check-pipeline "$I/pipeline/zaafvesper.yml"

echo "== 2. capture -> zaafvesper replay -> --elegia-dir segments"
go run "$I/samples/gen" -capture "$OUT/scenarios.rcap"
"$ZV" replay --rules "$repo/rules" --platform macos --elegia-host mac-01 \
	--elegia-dir "$OUT/segments" --elegia-segment-bytes 4096 --elegia-keep-bytes 1048576 \
	"$OUT/scenarios.rcap" >"$OUT/replay-alerts.txt" 2>"$OUT/replay.log"
ls -l "$OUT/segments" | tee "$OUT/segments.txt"
if ls "$OUT/segments"/*.part >/dev/null 2>&1; then echo "an open .part segment was left behind"; exit 1; fi

echo "== 3. zaaf check"
"$ZAAF" check -p "$I/pipeline/zaafvesper.yml" "$I/rules" 2>&1 | tee "$OUT/check.txt"

echo "== 4. zaaf hunt over the segments, and over a live replay pipe"
"$ZAAF" hunt -p "$I/pipeline/zaafvesper.yml" -r "$I/rules" -o ndjson "$OUT"/segments/*.ndjson \
	>"$OUT/findings-segments.ndjson" 2>"$OUT/hunt-segments.txt"
"$ZV" replay --rules "$repo/rules" --platform macos --elegia-host mac-01 --elegia-out - "$OUT/scenarios.rcap" 2>/dev/null |
	"$ZAAF" hunt -p "$I/pipeline/zaafvesper.yml" -r "$I/rules" -o ndjson - \
		>"$OUT/findings-pipe.ndjson" 2>"$OUT/hunt-pipe.txt"
python3 "$here/check.py" "$I" "$OUT"
