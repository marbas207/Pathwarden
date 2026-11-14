"""Crown W: the final Pathwarden mark, drawn on a strict 64-unit grid.

Elements (5): the W path (drawn as two mirrored halves so the gradient runs
from each violet end node up to the jewel), the crown band, two end nodes and
the jewel. Valley tips are trimmed flat on the "floor" line so the W sits
parallel to the band like the points of a crown.

Two optical sizes share the same anatomy:
  REG    for 48 px and up (strokes 7u)
  SMALL  for 16-32 px (every edge on the 4u = 1px-at-16 grid; heavier strokes)
"""
import math

# Palettes ------------------------------------------------------------------
NAVY = "#0B0E14"
WHITE = "#F7F7F7"
DARK = dict(A="#9D5CFF", B="#7CE46B", I=WHITE, bg=NAVY)          # on dark backgrounds
LIGHT = dict(A="#6B00D6", B="#1F8A3A", I=NAVY, bg=WHITE)          # on light backgrounds
GLOW = dict(A="#A46BFF", B="#86F074", I="#FFFFFF", bg=NAVY)       # glowing hero version
ALARM = "#B57BFF"


def f(*v):
    return " ".join(f"{x:.2f}".rstrip("0").rstrip(".") for x in v)


def geo(small=False):
    if small:
        g = dict(L=(8, 20), V=(20, 44), J=(32, 12), sw=9, floor=44, bar=(8, 56, 48, 56),
                 rn=6, rj=8, ring=2.5)
    else:
        g = dict(L=(9, 19), V=(20.5, 44), J=(32, 12), sw=7, floor=44.5, bar=(11, 53, 50, 56),
                 rn=5.25, rj=6.75, ring=2)
    L, V, J = g["L"], g["V"], g["J"]
    g["R"] = (64 - L[0], L[1])
    g["V2"] = (64 - V[0], V[1])
    # Valleys are mitred then trimmed at the floor, so put the vertex below the
    # floor by exactly the depth where the inner edges meet the floor line.
    g["left"] = f"M{f(*L)} L{f(*V)} L{f(*J)}"
    g["right"] = f"M{f(*g['R'])} L{f(*g['V2'])} L{f(*J)}"
    g["full"] = f"M{f(*L)} L{f(*V)} L{f(*J)} L{f(*g['V2'])} L{f(*g['R'])}"
    # length of each half, for timing animations by distance
    g["len1"] = math.dist(L, V)
    g["len2"] = math.dist(V, J)
    return g


def defs_grad(u, c, g):
    """Two mirrored gradients: violet at each end node, green at the jewel."""
    L, J, R = g["L"], g["J"], g["R"]
    out = ""
    for side, P in (("l", L), ("r", R)):
        out += (f'<linearGradient id="{u}{side}" gradientUnits="userSpaceOnUse" x1="{f(P[0])}" y1="{f(P[1] + 6)}" x2="{f(J[0])}" y2="{f(J[1])}">'
                f'<stop offset="0" stop-color="{c["A"]}"/><stop offset="0.22" stop-color="{c["A"]}"/>'
                f'<stop offset="0.9" stop-color="{c["B"]}"/></linearGradient>')
    return out


def clip_floor(u, g):
    return f'<clipPath id="{u}fl"><rect x="0" y="0" width="64" height="{f(g["floor"])}"/></clipPath>'


def mark_parts(mode="dark", u="cw", small=False, grad=True):
    """Return (defs, body) of the mark in its 64x64 box.

    mode: dark | light | glow | mono-dark (white, for dark bg) | mono-light (navy, for light bg)
    """
    g = geo(small)
    mono = mode.startswith("mono")
    if mono:
        ink = WHITE if mode == "mono-dark" else NAVY
        c = dict(A=ink, B=ink, I=ink)
    else:
        c = {"dark": DARK, "light": LIGHT, "glow": GLOW}[mode]
    defs = clip_floor(u, g)
    if mono or not grad:
        pl = pr = c["I"] if mono else c["A"]
    else:
        defs += defs_grad(u, c, g)
        pl, pr = f"url(#{u}l)", f"url(#{u}r)"
    sw = g["sw"]
    x0, x1, y0, y1 = g["bar"]
    L, R, J = g["L"], g["R"], g["J"]
    w = (f'<g clip-path="url(#{u}fl)" fill="none" stroke-width="{f(sw)}" stroke-linejoin="miter" stroke-miterlimit="2.6">'
         f'<path d="{g["left"]}" stroke="{pl}"/><path d="{g["right"]}" stroke="{pr}"/></g>')
    bar = f'<rect x="{f(x0)}" y="{f(y0)}" width="{f(x1 - x0)}" height="{f(y1 - y0)}" fill="{c["I"]}"/>'
    nodes = (f'<circle cx="{f(L[0])}" cy="{f(L[1])}" r="{f(g["rn"])}" fill="{c["A"]}"/>'
             f'<circle cx="{f(R[0])}" cy="{f(R[1])}" r="{f(g["rn"])}" fill="{c["A"]}"/>')
    jewel = f'<circle cx="{f(J[0])}" cy="{f(J[1])}" r="{f(g["rj"])}" fill="{c["B"]}"/>'
    if mono:
        # In one colour the nodes would melt into the line: knock a hairline gap round them.
        k = g["ring"]
        defs += (f'<mask id="{u}m" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64"><rect width="64" height="64" fill="#fff"/>'
                 f'<circle cx="{f(L[0])}" cy="{f(L[1])}" r="{f(g["rn"] + k)}" fill="#000"/>'
                 f'<circle cx="{f(R[0])}" cy="{f(R[1])}" r="{f(g["rn"] + k)}" fill="#000"/>'
                 f'<circle cx="{f(J[0])}" cy="{f(J[1])}" r="{f(g["rj"] + k)}" fill="#000"/></mask>')
        w = f'<g mask="url(#{u}m)">{w}</g>'
    body = w + bar + nodes + jewel
    if mode == "glow":
        defs += glow_filter(u + "f")
        body = f'<g filter="url(#{u}f)">{body}</g>'
    return defs, body


def glow_filter(fid, std=2.2, k=0.9):
    return (f'<filter id="{fid}" x="-40%" y="-40%" width="180%" height="180%">'
            f'<feGaussianBlur in="SourceGraphic" stdDeviation="{std}" result="b"/>'
            f'<feColorMatrix in="b" type="matrix" values="1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 {k} 0" result="bb"/>'
            f'<feMerge><feMergeNode in="bb"/><feMergeNode in="SourceGraphic"/></feMerge></filter>')


def mark_svg(mode="dark", u="cw", small=False, size=None, pad=0, bg=None, rx=0):
    d, b = mark_parts(mode, u, small)
    wh = f' width="{size}" height="{size}"' if size else ""
    vb = f"{-pad} {-pad} {64 + 2 * pad} {64 + 2 * pad}"
    back = f'<rect x="{-pad}" y="{-pad}" width="{64 + 2 * pad}" height="{64 + 2 * pad}" rx="{rx}" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}"{wh} role="img" aria-label="Pathwarden">'
            f'<defs>{d}</defs>{back}{b}</svg>')


def mark_group(mode, u, x, y, size, small=False):
    d, b = mark_parts(mode, u, small)
    return d, f'<g transform="translate({x:.2f} {y:.2f}) scale({size / 64:.5f})">{b}</g>'
