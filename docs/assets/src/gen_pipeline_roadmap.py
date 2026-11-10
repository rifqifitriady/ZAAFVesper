"""Generate docs/assets/pipeline.svg (v0.2, 2D animated) and roadmap.svg (2D animated timeline)."""
import sys, os
OUT = sys.argv[1]
NAVY, VIOLET, MAGENTA, TEAL, BLUE = "#0A0D26", "#9D6BFF", "#FF3EC8", "#1FE5C3", "#3B8EFF"
FONT = 'ui-sans-serif, -apple-system, &quot;Segoe UI&quot;, Helvetica, Arial, sans-serif'


def head(w, h, title, desc, extra_css=""):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-labelledby="t d">
  <title id="t">{title}</title>
  <desc id="d">{desc}</desc>
  <defs>
    <radialGradient id="bg" cx="0.7" cy="0.45" r="0.7"><stop offset="0" stop-color="{MAGENTA}" stop-opacity="0.12"/><stop offset="1" stop-color="{MAGENTA}" stop-opacity="0"/></radialGradient>
    <radialGradient id="bg2" cx="0.05" cy="0.0" r="0.6"><stop offset="0" stop-color="{VIOLET}" stop-opacity="0.22"/><stop offset="1" stop-color="{VIOLET}" stop-opacity="0"/></radialGradient>
    <pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1" fill="#1E2350"/></pattern>
    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3.5"/></filter>
    <clipPath id="card"><rect width="{w}" height="{h}" rx="18"/></clipPath>
    <marker id="aT" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 Z" fill="{TEAL}"/></marker>
    <marker id="aM" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 Z" fill="{MAGENTA}"/></marker>
    <marker id="aV" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 Z" fill="{VIOLET}"/></marker>
    <marker id="aB" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 Z" fill="{BLUE}"/></marker>
  </defs>
  <style>
    text {{ font-family: {FONT}; }}
    .ttl {{ font-size: 15px; font-weight: 700; fill: #FFFFFF; }}
    .sub {{ font-size: 12px; fill: #B7B3D9; }}
    .lbl {{ font-size: 12px; fill: #CFCBEA; }}
    .box {{ fill: #12163A; stroke-width: 2; }}
    .wire {{ fill: none; stroke-width: 2; stroke-linecap: round; }}
    .move {{ stroke-dasharray: 8 7; animation: run 1.2s linear infinite; }}
    .dash {{ stroke-dasharray: 5 6; animation: run 1.8s linear infinite; }}
    @keyframes run {{ to {{ stroke-dashoffset: -30; }} }}
    .pulse {{ animation: pulse 2.4s ease-in-out infinite; }}
    @keyframes pulse {{ 0%, 100% {{ opacity: 0.3; }} 50% {{ opacity: 0.95; }} }}
    {extra_css}
    @media (prefers-reduced-motion: reduce) {{ * {{ animation: none !important; }} .packet {{ display: none; }} }}
  </style>
  <g clip-path="url(#card)">
    <rect width="{w}" height="{h}" fill="{NAVY}"/><rect width="{w}" height="{h}" fill="url(#dots)"/>
    <rect width="{w}" height="{h}" fill="url(#bg2)"/><rect width="{w}" height="{h}" fill="url(#bg)"/>
'''


def tail(w, h):
    return f'''  </g>
  <rect x="0.75" y="0.75" width="{w - 1.5}" height="{h - 1.5}" rx="17.5" fill="none" stroke="#2E3470" stroke-width="1.5"/>
</svg>
'''


def box(x, y, w, h, col, title, sub, dashed=False, rx=12):
    da = ' stroke-dasharray="6 5"' if dashed else ''
    return (f'<rect class="box" x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" stroke="{col}"{da}/>'
            f'<text x="{x + 16}" y="{y + 27}" class="ttl">{title}</text>'
            f'<text x="{x + 16}" y="{y + 47}" class="sub">{sub}</text>')


# ---------------- pipeline ----------------
W, H = 840, 470
p = [head(W, H, "How ZAAFVesper works",
          "Events from macOS Endpoint Security, Windows Sysmon, Linux Sysmon and socket polling are normalised, enriched by the process tree and evaluated by the rule engine with YARA and Sigma rules. Matches become alerts, SIEM and ZAAFElegia output, opt-in containment and a forensic capture.")]
src = [("macOS", "Endpoint Security", 28), ("Windows", "Sysmon · preview", 128),
       ("Linux", "Sysmon for Linux · preview", 228), ("Network", "socket polling", 328)]
outs = [("Alerts", "console · JSONL · high series", 22, BLUE), ("SIEM", "syslog/TLS · webhook · HEC", 108, BLUE),
        ("ZAAFElegia", "Sigma fields · OCSF", 194, TEAL), ("Contain", "kill · quarantine · pf · opt-in", 280, MAGENTA),
        ("Capture", ".rcap for replay", 366, TEAL)]
# columns: sources 20-200, normalise/process 228-404, engine 432-602, outputs 630-830
X1, W1 = 20, 180
X2, W2 = 228, 176
X3, W3 = 432, 170
X4, W4 = 630, 200
MID2 = X2 + W2 // 2
ENG_Y = 215
for _, _, y in src:
    p.append(f'<path class="wire move" d="M{X1 + W1} {y + 32} C{X1 + W1 + 18} {y + 32}, {X2 - 16} 145, {X2} 145" stroke="{VIOLET}" marker-end="url(#aV)"/>')
p.append(f'<path class="wire move" d="M{MID2} 182 V226" stroke="{TEAL}" marker-end="url(#aT)"/>')
p.append(f'<path class="wire move" d="M{X2 + W2} 262 C{X2 + W2 + 14} 262, {X3 - 14} {ENG_Y}, {X3} {ENG_Y}" stroke="{TEAL}" marker-end="url(#aT)"/>')
p.append(f'<path class="wire dash" d="M{X3 + W3 // 2} 104 V166" stroke="{VIOLET}" marker-end="url(#aV)"/>')
p.append(f'<path class="wire dash" d="M{X3 + W3 // 2} 328 V266" stroke="{VIOLET}" marker-end="url(#aV)"/>')
for _, _, y, col in outs:
    mk = {BLUE: "aB", TEAL: "aT", MAGENTA: "aM"}[col]
    p.append(f'<path class="wire move" d="M{X3 + W3} {ENG_Y} C{X3 + W3 + 14} {ENG_Y}, {X4 - 14} {y + 28}, {X4} {y + 28}" stroke="{col}" marker-end="url(#{mk})"/>')
p.append('<g class="packet">')
for i, (_, _, y) in enumerate(src):
    p.append(f'<circle r="4" fill="#5EF0D6" filter="url(#glow)"><animateMotion dur="3.4s" begin="{i * 0.6:.1f}s" repeatCount="indefinite" path="M{X1 + W1} {y + 32} C{X1 + W1 + 18} {y + 32}, {X2 - 16} 145, {X2} 145 H{MID2} V262 H{X2 + W2} C{X2 + W2 + 14} 262, {X3 - 14} {ENG_Y}, {X3 + W3 // 2} {ENG_Y}"/></circle>')
for i, (_, _, y, col) in enumerate(outs):
    p.append(f'<circle r="3.5" fill="{col}"><animateMotion dur="2.2s" begin="{0.4 + i * 0.45:.2f}s" repeatCount="indefinite" path="M{X3 + W3} {ENG_Y} C{X3 + W3 + 14} {ENG_Y}, {X4 - 14} {y + 28}, {X4 + W4} {y + 28}"/></circle>')
p.append('</g>')
for t, s_, y in src:
    p.append(box(X1, y, W1, 64, VIOLET, t, s_, dashed=(t != "macOS")))
p.append(box(X2, 108, W2, 74, TEAL, "Normalise", "one event model · caps"))
p.append(box(X2, 226, W2, 74, TEAL, "Process tree", "ancestry · signing trust"))
p.append(box(X3, 40, W3, 64, VIOLET, "YARA", "bound to the file that ran"))
p.append(box(X3, 328, W3, 64, VIOLET, "Sigma rules", "converted from SigmaHQ"))
p.append(f'<rect class="pulse" x="{X3 - 4}" y="162" width="{W3 + 8}" height="108" rx="16" fill="none" stroke="{MAGENTA}" stroke-width="2" filter="url(#glow)"/>')
p.append(box(X3, 166, W3, 100, MAGENTA, "Rule engine", "94 rules · sequences"))
p.append(f'<text x="{X3 + 16}" y="236" class="sub">63 ATT&amp;CK techniques</text>')
for t, s_, y, col in outs:
    p.append(f'<rect class="box" x="{X4}" y="{y}" width="{W4}" height="56" rx="12" stroke="{col}"/>'
             f'<text x="{X4 + 14}" y="{y + 23}" class="ttl">{t}</text><text x="{X4 + 14}" y="{y + 42}" class="sub">{s_}</text>')
p.append(tail(W, H))
open(os.path.join(OUT, "pipeline.svg"), "w").write("".join(p))

# ---------------- roadmap ----------------
W, H = 840, 360
css = '''.draw { stroke-dasharray: 520; animation: draw 2.6s ease-out forwards; }
    @keyframes draw { from { stroke-dashoffset: 520; } to { stroke-dashoffset: 0; } }
    .ring { transform-box: fill-box; transform-origin: center; animation: ring 2.2s ease-out infinite; }
    @keyframes ring { from { opacity: .9; transform: scale(1); } to { opacity: 0; transform: scale(2.4); } }
    .card { opacity: 0; animation: up .7s ease-out forwards; }
    @keyframes up { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
    .chip { font-size: 11.5px; font-weight: 700; letter-spacing: .6px; }
    .b { font-size: 12.5px; fill: #CFCBEA; }'''
r = [head(W, H, "ZAAFVesper roadmap",
          "Roadmap: v0.1 Foundation, v0.2 Platform and v0.3 Prove it live are done, v0.4 Reach is in progress, v0.5 Trust and v0.6 Prevent are planned and need an Apple developer account and entitlement.", css)]
nodes = [
    ("v0.1", "Foundation", "DONE · 7 NOV", TEAL, "done", ["eslogger + rule engine", "41 macOS rules", "Installer + daemon"]),
    ("v0.2", "Platform", "DONE · 9 NOV", TEAL, "done", ["Windows + Linux", "Sigma · network", "SIEM · contain"]),
    ("v0.3", "Prove it live", "DONE · 9 NOV", TEAL, "done", ["CI + provenance", "Live tests on runners", "Atomic Red Team"]),
    ("v0.4", "Reach", "NOW", MAGENTA, "now", ["Contain on Win/Linux", "Linux via eBPF", "ZAAFElegia · 100+ TTPs"]),
    ("v0.5", "Trust", "PLANNED", VIOLET, "plan", ["Developer ID signing", "Notarized package", "Apple account"]),
    ("v0.6", "Prevent", "PLANNED", VIOLET, "plan", ["AUTH blocking", "DNS via NetExt", "Apple entitlement"]),
]
xs = [82, 217, 352, 487, 622, 757]
LY = 96
r.append(f'<text x="40" y="44" font-size="13" font-weight="700" letter-spacing="2.4" fill="#5EF0D6">ROADMAP</text>')
r.append(f'<path d="M{xs[0]} {LY} H{xs[-1]}" stroke="#262B5E" stroke-width="4" stroke-linecap="round"/>')
r.append(f'<path class="wire dash" d="M{xs[3]} {LY} H{xs[-1]}" stroke="{VIOLET}" stroke-width="3"/>')
r.append(f'<path class="draw" d="M{xs[0]} {LY} H{xs[3]}" stroke="url(#prog)" stroke-width="4" stroke-linecap="round" fill="none"/>')
r.insert(1, '')
r[0] = r[0].replace('</defs>', f'<linearGradient id="prog" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{TEAL}"/><stop offset="1" stop-color="{MAGENTA}"/></linearGradient></defs>')
for i, ((ver, name, chip, col, state, bullets), x) in enumerate(zip(nodes, xs)):
    if state == "now":
        r.append(f'<circle class="ring" cx="{x}" cy="{LY}" r="13" fill="none" stroke="{MAGENTA}" stroke-width="2"/>')
        r.append(f'<circle cx="{x}" cy="{LY}" r="13" fill="{MAGENTA}" filter="url(#glow)" opacity=".7"/>')
    fill = col if state != "plan" else NAVY
    da = ' stroke-dasharray="4 3"' if state == "plan" else ''
    r.append(f'<circle cx="{x}" cy="{LY}" r="11" fill="{fill}" stroke="{col}" stroke-width="2.5"{da}/>')
    if state == "done":
        r.append(f'<path d="M{x - 5} {LY} l3.5 3.5 l6.5 -7" fill="none" stroke="{NAVY}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>')
    r.append(f'<text x="{x}" y="{LY - 24}" text-anchor="middle" font-size="15" font-weight="800" fill="{col}">{ver}</text>')
    cx0, cw = x - 62, 124
    delay = 0.3 + i * 0.25
    r.append(f'<g class="card" style="animation-delay:{delay:.2f}s">')
    r.append(f'<rect x="{cx0}" y="{LY + 34}" width="{cw}" height="208" rx="14" fill="#12163A" stroke="{col}" stroke-width="{2 if state != "plan" else 1.5}"{da}/>')
    r.append(f'<text x="{cx0 + 12}" y="{LY + 64}" class="ttl" font-size="14">{name}</text>')
    chip_bg = {"done": "#0F3B3A", "now": "#3F1240", "plan": "#221F4D"}[state] if ver != "v0.4" else "#13244D"
    r.append(f'<rect x="{cx0 + 12}" y="{LY + 76}" width="{len(chip) * 7.2 + 12:.0f}" height="22" rx="11" fill="{chip_bg}"/>')
    r.append(f'<text x="{cx0 + 18}" y="{LY + 91}" class="chip" fill="{col}">{chip}</text>')
    for j, bt in enumerate(bullets):
        y = LY + 128 + j * 40
        r.append(f'<circle cx="{cx0 + 15}" cy="{y - 4}" r="3" fill="{col}"/>')
        # wrap at ~20 chars into two lines
        words, lines, cur = bt.split(), [], ""
        for w_ in words:
            if len(cur) + len(w_) + 1 > 14 and cur:
                lines.append(cur); cur = w_
            else:
                cur = (cur + " " + w_).strip()
        lines.append(cur)
        for k, ln in enumerate(lines[:2]):
            r.append(f'<text x="{cx0 + 24}" y="{y + k * 15}" class="b" font-size="12">{ln.replace("&", "&amp;")}</text>')
    r.append('</g>')
r.append(tail(W, H))
open(os.path.join(OUT, "roadmap.svg"), "w").write("".join(r))
print("ok")
