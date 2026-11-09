"""Generate docs/assets/banner.svg: a 3D rotating wireframe globe (precomputed
projection frames animated with SMIL) with orbiting telemetry satellites and
endpoints that flash on detection. Pure SVG, works in a GitHub <img>."""
import math, sys

OUT = sys.argv[1]
W, H = 840, 300
CX, CY, R = 655, 150, 104
TILT = math.radians(20)        # viewer above the equator
FRAMES = 72                    # one frame per 5 degrees
DUR = 24                       # seconds per revolution
NAVY, VIOLET, MAGENTA, TEAL, BLUE = "#0A0D26", "#9D6BFF", "#FF3EC8", "#1FE5C3", "#3B8EFF"


def project(lat, lon, phi):
    """Rotate (lat, lon) by phi around the polar axis, tilt towards the
    viewer, return screen x, y and depth z (z > 0 faces the viewer)."""
    x = math.cos(lat) * math.sin(lon + phi)
    y = math.sin(lat)
    z = math.cos(lat) * math.cos(lon + phi)
    # tilt around the x axis
    y2 = y * math.cos(TILT) - z * math.sin(TILT)
    z2 = y * math.sin(TILT) + z * math.cos(TILT)
    return CX + R * x, CY - R * y2, z2


def fmt(v):
    return f"{v:.1f}"


def keytimes(n):
    return ";".join(fmt(i / (n - 1))[:5] if i not in (0, n - 1) else ("0" if i == 0 else "1") for i in range(n))


phis = [2 * math.pi * i / FRAMES for i in range(FRAMES + 1)]
kt = ";".join(f"{i / FRAMES:.4f}" for i in range(FRAMES + 1))

parts = []

# Meridians: polyline per meridian, path animated across frames; opacity
# follows the depth of the meridian's equator point.
meridians = []
for k in range(12):
    lon = 2 * math.pi * k / 12
    ds, ops = [], []
    for phi in phis:
        pts = [project(math.radians(lat), lon, phi) for lat in range(-90, 91, 10)]
        ds.append("M" + " L".join(f"{fmt(x)},{fmt(y)}" for x, y, _ in pts))
        _, _, z = project(0, lon, phi)
        ops.append(f"{0.18 + 0.62 * max(0.0, z):.2f}")
    meridians.append(
        f'<path fill="none" stroke="{VIOLET}" stroke-width="1.2" d="{ds[0]}" opacity="{ops[0]}">'
        f'<animate attributeName="d" dur="{DUR}s" repeatCount="indefinite" keyTimes="{kt}" values="{";".join(ds)}"/>'
        f'<animate attributeName="opacity" dur="{DUR}s" repeatCount="indefinite" keyTimes="{kt}" values="{";".join(ops)}"/>'
        f'</path>')

# Latitude rings: static under rotation; split into back (dim) and front arcs.
lats = []
for latd in (-60, -30, 0, 30, 60):
    lat = math.radians(latd)
    front, back = [], []
    for lond in range(0, 361, 6):
        x, y, z = project(lat, math.radians(lond), 0)
        (front if z >= 0 else back).append((x, y, z, lond))
    def arc(points):
        # points are in longitude order; break where the run is not contiguous
        segs, cur, prev = [], [], None
        for x, y, z, lond in points:
            if prev is not None and lond - prev > 6:
                segs.append(cur); cur = []
            cur.append((x, y)); prev = lond
        if cur: segs.append(cur)
        return " ".join("M" + " L".join(f"{fmt(x)},{fmt(y)}" for x, y in s) for s in segs if len(s) > 1)
    col = TEAL if latd == 0 else VIOLET
    lats.append(f'<path fill="none" stroke="{col}" stroke-width="1" opacity="0.18" d="{arc(back)}"/>')
    lats.append(f'<path fill="none" stroke="{col}" stroke-width="{1.6 if latd == 0 else 1.1}" opacity="{0.85 if latd == 0 else 0.6}" d="{arc(front)}"/>')

# Endpoints on the surface (macOS, Windows, Linux hosts); they rotate with the
# globe; one of them flashes magenta periodically (a detection).
endpoints = []
for i, (latd, lond, col, flash) in enumerate([(35, 20, TEAL, False), (-15, 110, BLUE, False), (10, 200, TEAL, True),
                                              (50, 260, BLUE, False), (-40, 300, TEAL, False), (5, 330, BLUE, True)]):
    xs, ys, ops, rs = [], [], [], []
    for phi in phis:
        x, y, z = project(math.radians(latd), math.radians(lond), phi)
        xs.append(fmt(x)); ys.append(fmt(y))
        ops.append(f"{(0.95 if z > 0 else 0.0):.2f}")
        rs.append(f"{(3.2 + 1.6 * max(0, z)):.1f}")
    anim = (f'<animate attributeName="cx" dur="{DUR}s" repeatCount="indefinite" keyTimes="{kt}" values="{";".join(xs)}"/>'
            f'<animate attributeName="cy" dur="{DUR}s" repeatCount="indefinite" keyTimes="{kt}" values="{";".join(ys)}"/>'
            f'<animate attributeName="opacity" dur="{DUR}s" repeatCount="indefinite" keyTimes="{kt}" values="{";".join(ops)}" calcMode="discrete"/>')
    endpoints.append(f'<circle r="{rs[0]}" cx="{xs[0]}" cy="{ys[0]}" fill="{col}">{anim}'
                     f'<animate attributeName="r" dur="{DUR}s" repeatCount="indefinite" keyTimes="{kt}" values="{";".join(rs)}"/></circle>')
    if flash:
        endpoints.append(f'<circle r="4" cx="{xs[0]}" cy="{ys[0]}" fill="none" stroke="{MAGENTA}" stroke-width="2" class="flash" style="animation-delay:{i * 1.7:.1f}s">{anim}</circle>')

# Orbit ring (inclined) with satellites carrying telemetry: depth gives size,
# brightness, and hides them behind the globe.
ORX, ORY, OROT = R * 1.42, R * 0.38, -16
def orbit_point(t):
    a = 2 * math.pi * t
    x0, y0 = ORX * math.cos(a), ORY * math.sin(a)
    rot = math.radians(OROT)
    x = x0 * math.cos(rot) - y0 * math.sin(rot)
    y = x0 * math.sin(rot) + y0 * math.cos(rot)
    z = math.sin(a)  # front half: lower part of the ellipse
    return CX + x, CY + y, z
sats = []
N = 60
skt = ";".join(f"{i / N:.4f}" for i in range(N + 1))
for j, col in enumerate([MAGENTA, TEAL, BLUE]):
    xs, ys, ops, rs = [], [], [], []
    for i in range(N + 1):
        x, y, z = orbit_point(i / N + j / 3)
        xs.append(fmt(x)); ys.append(fmt(y))
        inside = (x - CX) ** 2 + (y - CY) ** 2 < R * R
        ops.append("0" if (z < 0 and inside) else f"{0.35 + 0.65 * (z + 1) / 2:.2f}")
        rs.append(f"{2.5 + 2.5 * (z + 1) / 2:.1f}")
    sats.append(f'<circle r="{rs[0]}" cx="{xs[0]}" cy="{ys[0]}" fill="{col}" filter="url(#glow)">'
                f'<animate attributeName="cx" dur="9s" repeatCount="indefinite" keyTimes="{skt}" values="{";".join(xs)}"/>'
                f'<animate attributeName="cy" dur="9s" repeatCount="indefinite" keyTimes="{skt}" values="{";".join(ys)}"/>'
                f'<animate attributeName="r" dur="9s" repeatCount="indefinite" keyTimes="{skt}" values="{";".join(rs)}"/>'
                f'<animate attributeName="opacity" dur="9s" repeatCount="indefinite" keyTimes="{skt}" values="{";".join(ops)}"/>'
                f'</circle>')
# split the orbit into back (behind globe, dim) and front arcs
back_pts, front_pts = [], []
for i in range(0, 181):
    x, y, z = orbit_point(i / 180)
    (front_pts if z >= 0 else back_pts).append(f"{fmt(x)},{fmt(y)}")
orbit_back = f'<path d="M{" L".join(back_pts)}" fill="none" stroke="{MAGENTA}" stroke-width="1.2" opacity="0.25"/>'
orbit_front = f'<path d="M{" L".join(front_pts)}" fill="none" stroke="{MAGENTA}" stroke-width="1.6" opacity="0.75"/>'

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d">
  <title id="t">ZAAFVesper</title>
  <desc id="d">ZAAFVesper, a behaviour-driven security sensor for macOS with Windows and Linux in preview. A rotating 3D globe of endpoints, orbited by telemetry, flags a detection.</desc>
  <defs>
    <radialGradient id="glowV" cx="0.08" cy="0.05" r="0.75"><stop offset="0" stop-color="{VIOLET}" stop-opacity="0.35"/><stop offset="1" stop-color="{VIOLET}" stop-opacity="0"/></radialGradient>
    <radialGradient id="glowM" cx="0.78" cy="0.5" r="0.45"><stop offset="0" stop-color="{MAGENTA}" stop-opacity="0.28"/><stop offset="1" stop-color="{MAGENTA}" stop-opacity="0"/></radialGradient>
    <radialGradient id="sphere" cx="0.38" cy="0.32" r="0.75"><stop offset="0" stop-color="#2A2470" stop-opacity="0.95"/><stop offset="0.7" stop-color="#121640" stop-opacity="0.95"/><stop offset="1" stop-color="{NAVY}" stop-opacity="0.95"/></radialGradient>
    <linearGradient id="title" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#C9B4FF"/><stop offset="0.45" stop-color="#FF7ADB"/><stop offset="1" stop-color="#5EF0D6"/>
      <animateTransform attributeName="gradientTransform" type="translate" values="-0.25 0; 0.25 0; -0.25 0" dur="9s" repeatCount="indefinite"/>
    </linearGradient>
    <pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1" fill="#252A57"/></pattern>
    <clipPath id="card"><rect width="{W}" height="{H}" rx="18"/></clipPath>
    <filter id="glow" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="2.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <filter id="halo" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="14"/></filter>
  </defs>
  <style>
    .sans {{ font-family: ui-sans-serif, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .flash {{ animation: flash 5.1s ease-out infinite; transform-box: fill-box; transform-origin: center; }}
    @keyframes flash {{ 0%, 70% {{ stroke-opacity: 0; transform: scale(1); }} 75% {{ stroke-opacity: 1; transform: scale(1); }} 100% {{ stroke-opacity: 0; transform: scale(3.2); }} }}
    .cursor {{ animation: blink 1.1s steps(1) infinite; }}
    @keyframes blink {{ 50% {{ opacity: 0; }} }}
    .rise {{ animation: rise 1.2s ease-out both; }}
    .rise.d2 {{ animation-delay: .25s; }} .rise.d3 {{ animation-delay: .5s; }} .rise.d4 {{ animation-delay: .75s; }}
    @keyframes rise {{ from {{ opacity: 0; transform: translateY(8px); }} to {{ opacity: 1; transform: none; }} }}
    @media (prefers-reduced-motion: reduce) {{ .flash, .cursor, .rise {{ animation: none; }} }}
  </style>
  <g clip-path="url(#card)">
    <rect width="{W}" height="{H}" fill="{NAVY}"/>
    <rect width="{W}" height="{H}" fill="url(#dots)"/>
    <rect width="{W}" height="{H}" fill="url(#glowV)"/>
    <rect width="{W}" height="{H}" fill="url(#glowM)"/>

    <circle cx="{CX}" cy="{CY}" r="{R + 6}" fill="{VIOLET}" opacity="0.22" filter="url(#halo)"/>
    {orbit_back}
    <circle cx="{CX}" cy="{CY}" r="{R}" fill="url(#sphere)" stroke="#3A3F86" stroke-width="1.2"/>
    {"".join(lats)}
    {"".join(meridians)}
    {"".join(endpoints)}
    {orbit_front}
    {"".join(sats)}

    <g class="sans">
      <text x="44" y="70" font-size="13" font-weight="700" letter-spacing="2.4" fill="#5EF0D6" class="rise">MACOS · WINDOWS · LINUX · MITRE ATT&amp;CK</text>
      <text x="42" y="138" font-size="58" font-weight="800" fill="url(#title)" class="rise d2">ZAAFVesper</text>
      <text x="44" y="176" font-size="18" fill="#D6D3F2" class="rise d3">Behaviour-driven threat detection and response.</text>
      <text x="44" y="202" font-size="18" fill="#A9A5D6" class="rise d3">The evening watch that stays awake after dark.</text>
    </g>
    <text x="44" y="252" class="mono rise d4" font-size="14" fill="#8F8BC2">events <tspan fill="#FF7ADB">→</tspan> rules <tspan fill="#FF7ADB">→</tspan> ATT&amp;CK <tspan fill="#FF7ADB">→</tspan> alert · contain<tspan class="cursor" fill="#5EF0D6"> ▍</tspan></text>
  </g>
  <rect x="0.75" y="0.75" width="{W - 1.5}" height="{H - 1.5}" rx="17.5" fill="none" stroke="#2E3470" stroke-width="1.5"/>
</svg>
'''
open(OUT, "w").write(svg)
print(OUT, len(svg))
