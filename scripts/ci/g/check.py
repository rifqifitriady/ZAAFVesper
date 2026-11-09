#!/usr/bin/env python3
"""Compares zaaf hunt findings with integrations/zaafelegia/samples/expected.json.

Usage: check.py INTEGRATION_DIR OUT_DIR. Exit 1 on any mismatch. Correlation
expectations apply only when zaaf evaluates correlation rules: ZAAFElegia
0.0.1 parses and skips them (milestone M2), which is reported as PENDING.
"""
import glob, json, os, re, sys

idir, out = sys.argv[1], sys.argv[2]
exp = json.load(open(os.path.join(idir, "samples", "expected.json")))
names = {}  # rule id -> name
for f in glob.glob(os.path.join(idir, "rules", "*", "*.yml")):
    txt = open(f).read()
    rid, name = re.search(r"^id:\s*(\S+)", txt, re.M), re.search(r"^name:\s*(\S+)", txt, re.M)
    if rid and name:
        names[rid.group(1)] = name.group(1)
check_txt = open(os.path.join(out, "check.txt")).read()
correlations_live = "correlation support arrives in milestone M2" not in check_txt
fails, rows = [], []


def verdict(ok, what, detail):
    rows.append(("PASS" if ok else "FAIL", what, detail))
    if not ok:
        fails.append(what)


m = re.search(r"checked (\d+) files: (\d+) rules, \d+ filters, (\d+) correlations skipped, (\d+) errors", check_txt)
verdict(m is not None and m.group(4) == "0", "zaaf check: no rule errors", m.group(0) if m else "no summary line")
if not correlations_live:
    want = len(exp["correlations"])
    verdict(m is not None and m.group(2) == str(len(exp["base"])) and m.group(3) == str(want),
            f"zaaf check: {len(exp['base'])} rules compiled, {want} correlations parsed and skipped (pre-M2)",
            m.group(0) if m else "no summary line")
# Under M2 (decision M2-D8), a rule referenced only by correlations with
# generate: false alerts no longer on its own: every base rule here is such a
# rule, so its standalone matches are expected to disappear.
base_expect = {r: (0 if correlations_live else n) for r, n in exp["base"].items()}
for mode in ("segments", "pipe"):
    counts = {}
    for line in open(os.path.join(out, f"findings-{mode}.ndjson")):
        line = line.strip()
        if not line:
            continue
        f = json.loads(line)
        uid = ((f.get("finding_info") or {}).get("analytic") or {}).get("uid")
        n = names.get(uid, uid)
        counts[n] = counts.get(n, 0) + 1
    summary = open(os.path.join(out, f"hunt-{mode}.txt")).read().strip().splitlines()
    tail = summary[-1] if summary else ""
    ev = re.search(r"(\d+) events, (\d+) malformed", tail)
    verdict(ev is not None and int(ev.group(1)) == exp["events"] and ev.group(2) == "0",
            f"{mode}: {exp['events']} events read, none malformed", tail)
    for rule, want in base_expect.items():
        verdict(counts.get(rule, 0) == want, f"{mode}: {rule}", f"{counts.get(rule, 0)} matches, want {want}")
    for rule, want in exp["correlations"].items():
        if correlations_live:
            verdict(counts.get(rule, 0) == want, f"{mode}: {rule}", f"{counts.get(rule, 0)} alerts, want {want}")
        else:
            rows.append(("PENDING", f"{mode}: {rule}", "zaaf skips correlation rules until milestone M2"))
    extra = sorted(set(counts) - set(exp["base"]) - set(exp["correlations"]))
    verdict(not extra, f"{mode}: no unexpected findings", ", ".join(extra) or "none")
segs = [s for s in glob.glob(os.path.join(out, "segments", "*.ndjson"))]
verdict(len(segs) >= 2, "--elegia-dir rotated into several closed segments", f"{len(segs)} segments")
for s in segs:
    for line in open(s):
        rec = json.loads(line)
        if (rec.get("zaafvesper") or {}).get("schema") != "zaafvesper.elegia/1" or rec.get("Computer") != "mac-01":
            verdict(False, "segment records carry schema zaafvesper.elegia/1 and Computer", line[:200])
            break
md = ["| Result | Check | Detail |", "|---|---|---|"] + [f"| {r} | {w} | {d} |" for r, w, d in rows]
md.append(f"\n{len(rows)} checks, {len(fails)} failed.")
open(os.path.join(out, "results.md"), "w").write("\n".join(md) + "\n")
print("\n".join(md))
sys.exit(1 if fails else 0)
