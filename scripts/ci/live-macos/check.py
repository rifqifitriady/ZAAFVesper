#!/usr/bin/env python3
"""Evaluates a live-macos run from its artifacts directory and writes
results.md and results.json there. Exit 1 when any check FAILS (a rule that
did not fire, an output that lost an alert); "not testable" is not a failure.

Usage: check.py ARTIFACTS_DIR REPO_DIR RUN_URL
"""
import glob, json, os, re, sys

art, repo, run_url = sys.argv[1], sys.argv[2], sys.argv[3]
results = []  # (area, item, verdict, detail)


def add(area, item, ok, detail, verdict=None):
    results.append((area, item, verdict or ("PASS" if ok else "FAIL"), detail))


def read_lines(path):
    try:
        with open(path, errors="replace") as f:
            return [l.rstrip("\n") for l in f if l.strip()]
    except FileNotFoundError:
        return []


def jsonl(path):
    out = []
    for l in read_lines(path):
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


rule_ids, rule_names = {}, {}
for f in glob.glob(os.path.join(repo, "rules", "*.yml")):
    txt = open(f).read()
    m, n = re.search(r"^id:\s*(\S+)", txt, re.M), re.search(r"^name:\s*(.+)$", txt, re.M)
    if m:
        base = os.path.basename(f)[:-4]
        rule_ids[base] = m.group(1).strip("'\"")
        rule_names[base] = n.group(1).strip() if n else base

status = dict(l.split("\t", 1) for l in read_lines(os.path.join(art, "status.tsv")))
es = status.get("eslogger", "missing")
add("eslogger", "eslogger under sudo", es.startswith("ok"), es)
add("eslogger", "zaafvesper run as root", status.get("sensor") == "started as root", status.get("sensor", "missing"))

alert_files = [f for f in glob.glob(os.path.join(art, "outdir", "alerts-*.jsonl")) if "alerts-high-" not in f]
alerts = [a for f in sorted(alert_files) for a in jsonl(f)]
fired = {}
for a in alerts:
    if not a.get("aggregated"):
        fired[a.get("rule_id")] = fired.get(a.get("rule_id"), 0) + 1
id_to_file = {v: k for k, v in rule_ids.items()}

# 1. Rules fired by the triggers.
for line in read_lines(os.path.join(art, "triggers.tsv")):
    tid, rule, what, code = (line.split("\t") + ["", "", "", ""])[:4]
    rid = rule_ids.get(rule)
    n = fired.get(rid, 0)
    add("rules", f"{tid}: {rule}", n > 0, f"{what}; exit {code}; alerts {n}")
others = sorted((id_to_file.get(r, r), n) for r, n in fired.items() if id_to_file.get(r) not in
                {l.split("\t")[1] for l in read_lines(os.path.join(art, "triggers.tsv"))})
for name, n in others:
    add("rules", f"also fired: {name}", True, f"{n} alert(s) (not triggered on purpose)", "INFO")
for rule, why in [
    ("network_unsigned_temp_binary_outbound", "needs a connection to a public address; the validation stays on 127.0.0.1"),
    ("network_interpreter_raw_ip_uncommon_port", "needs a connection to a public address; the validation stays on 127.0.0.1"),
]:
    add("rules", rule, False, why, "NOT TESTABLE")

# 2. Socket polling against real processes (other uid than the root sensor).
events = jsonl(os.path.join(art, "events.ndjson"))
net = [e for e in events if (e.get("logsource") or {}).get("category") == "network_connection"]
def has(pred):
    return [e for e in net if pred(e)]
lst = has(lambda e: e.get("Image") == "/usr/bin/nc" and e.get("DestinationPort") == 5555 and "Initiated" not in e)
out = has(lambda e: str(e.get("Image", "")).endswith("/dropped") and e.get("DestinationPort") == 5555 and e.get("Initiated") == "true")
inn = has(lambda e: e.get("Image") == "/usr/bin/nc" and e.get("DestinationPort") == 5555 and e.get("Initiated") == "false")
add("netpoll", "nc listener on 127.0.0.1:5555 -> NetworkAccept listen", len(lst) == 1, f"{len(lst)} event(s)")
add("netpoll", "outbound connection -> NetworkConnect outbound", len(out) == 1, f"{len(out)} event(s)")
add("netpoll", "accepted connection -> NetworkAccept inbound", len(inn) == 1, f"{len(inn)} event(s)")
srcs = sorted({(e.get("zaafvesper") or {}).get("source") for e in net})
add("netpoll", "network events come from netpoll", srcs == ["netpoll"], f"sources {srcs}; {len(net)} network events in all")

# 3. SIEM receivers and spool.
def rule_counts(lines, pat):
    c = {}
    for l in lines:
        for m in re.finditer(pat, l):
            c[m.group(1)] = c.get(m.group(1), 0) + 1
    return c
sys_lines = [l for l in read_lines(os.path.join(art, "receiver", "syslog.log")) if " alert [" in l]
web_lines = read_lines(os.path.join(art, "receiver", "webhook.log"))
sys_c = rule_counts(sys_lines, r'rule_id="([^"]+)"')
web_c = {}
for l in web_lines:
    try:
        for rec in json.loads(l):
            if rec.get("type") == "alert":
                rid = rec["data"].get("rule_id")
                web_c[rid] = web_c.get(rid, 0) + 1
    except (ValueError, KeyError, TypeError):
        pass
all_c = {}
for a in alerts:
    all_c[a.get("rule_id")] = all_c.get(a.get("rule_id"), 0) + 1
miss_s = {r: n - sys_c.get(r, 0) for r, n in all_c.items() if sys_c.get(r, 0) < n}
miss_w = {r: n - web_c.get(r, 0) for r, n in all_c.items() if web_c.get(r, 0) < n}
add("siem", "syslog over TLS (pinned CA) received every alert", not miss_s and sys_lines != [],
    f"{len(alerts)} alerts written, {len(sys_lines)} syslog alert messages; missing {miss_s or 'none'}")
add("siem", "HTTPS webhook received every alert", not miss_w and web_c != {},
    f"{sum(web_c.values())} webhook alert records; missing {miss_w or 'none'}")
add("siem", "spool used while the receivers were down", not status.get("spool_while_down", "0").startswith("0 "),
    status.get("spool_while_down", "missing"))
add("siem", "spool drained after the receivers came back", status.get("spool_after_up", "").startswith("0 "),
    status.get("spool_after_up", "missing"))
for b in ("defense_impairment_quarantine_attribute_removed", "stealth_hidden_file_flag"):
    rid = rule_ids[b]
    add("siem", f"alerts raised while down were delivered later: {b}",
        sys_c.get(rid, 0) >= 2 and web_c.get(rid, 0) >= 2 and all_c.get(rid, 0) >= 2,
        f"alerts {all_c.get(rid, 0)}, syslog {sys_c.get(rid, 0)}, webhook {web_c.get(rid, 0)}")
left = {}
for m in re.finditer(r"stats: output (\w+): .*?spool_files=(\d+)", log_text := (open(os.path.join(art, "sensor.log"), errors="replace").read() if os.path.exists(os.path.join(art, "sensor.log")) else "")):
    left[m.group(1)] = int(m.group(2))
add("siem", "nothing left in the spool at shutdown (last alerts flushed)", left != {} and all(v == 0 for v in left.values()),
    f"spool files at shutdown: {left or 'no stats'}")
tl = status.get("token_in_outputs", "missing")
add("siem", "webhook token absent from the sensor log, events and alert files", tl == "no", tl)

# 4. OCSF and ZAAFElegia.
ocsf = jsonl(os.path.join(art, "outdir", "alerts.ocsf.ndjson"))
add("zaafelegia", "--alerts-ocsf: one OCSF 2004 finding per alert", len(ocsf) == len(alerts) and all(f.get("class_uid") == 2004 for f in ocsf),
    f"{len(ocsf)} findings for {len(alerts)} alerts")
findings = jsonl(os.path.join(art, "zaaf-findings.ndjson"))
titles = {}
for f in findings:
    t = (f.get("finding_info") or {}).get("title")
    titles[t] = titles.get(t, 0) + 1
for t in ("Quarantine attribute removed with xattr (macOS)", "Unix shell with an outbound network connection (macOS)",
          "File hidden with chflags (macOS)"):
    add("zaafelegia", f"zaaf hunt over the live pipe: {t}", titles.get(t, 0) > 0, f"{titles.get(t, 0)} finding(s)")
add("zaafelegia", "events streamed through --elegia-out -", len(events) > 0, f"{len(events)} events")

# Report.
fails = [r for r in results if r[2] == "FAIL"]
md = [f"Run: {run_url}", "", "| Area | Check | Result | Detail |", "|---|---|---|---|"]
for area, item, v, d in results:
    md.append(f"| {area} | {item} | **{v}** | {str(d).replace('|', '/')} |")
md += ["", f"{len(results)} checks, {len(fails)} failed."]
open(os.path.join(art, "results.md"), "w").write("\n".join(md) + "\n")
json.dump([dict(area=a, check=i, result=v, detail=d) for a, i, v, d in results], open(os.path.join(art, "results.json"), "w"), indent=1)
print("\n".join(md))
sys.exit(1 if fails else 0)
