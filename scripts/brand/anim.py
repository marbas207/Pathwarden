"""Animated Crown W: pure CSS inside SVG (no JS), so it plays in a README <img>.

Intro (about 2.5 s):
  left end node pops -> path draws up the left half to the peak, where a pale
  jewel seed appears -> path draws down and up the right half -> right node pops
  -> jewel ignites green with a burst ring -> crown band wipes in.
Idle (4 s loop, forever):
  an energy pulse runs from both end nodes along the path to the jewel; the jewel
  flashes and sends out a soft ring; a halo behind it breathes.

The resting style of every element is its final state, so the
prefers-reduced-motion rule simply switches the animations off.
"""
from mark import DARK, GLOW, LIGHT, NAVY, f, geo, glow_filter
from text import CAP, TAG, TAG_TRACK, WORD, WORD_TRACK, text_el, width

IDLE = 4.0


def timeline(k=1.0, t0=0.0):
    """Intro cue times in seconds; k stretches, t0 delays everything."""
    T = dict(nl=0.10, d1=0.30, d1e=0.98, seed=0.90, d2=0.98, d2e=1.62, nr=1.56,
             ign=1.72, ring=1.80, bar=1.90, bare=2.45, idle=2.75)
    return {key: t0 + v * k for key, v in T.items()}


def css_for(p, T, reduce_scope=""):
    E = "cubic-bezier(.2,.7,.2,1)"
    ein = "cubic-bezier(.55,0,.85,.5)"
    eout = "cubic-bezier(.15,.5,.45,1)"
    jd = T["ign"] + 0.42  # jewel animation runs 0 -> jd
    seed = T["seed"] / jd * 100
    ign = T["ign"] / jd * 100
    css = f"""
.{p} .n{{transform-box:fill-box;transform-origin:center}}
.{p} .dr{{stroke-dasharray:1.002 2}}
.{p} .pl{{stroke-dasharray:.11 3;stroke-dashoffset:.11;opacity:0}}
.{p} .burst,.{p} .ring,.{p} .flash{{opacity:0}}
.{p} .nl{{animation:{p}pop .42s {E} {T['nl']:.2f}s both}}
.{p} .nr{{animation:{p}pop .42s {E} {T['nr']:.2f}s both}}
.{p} .hl{{animation:{p}drawF {T['d1e'] - T['d1']:.2f}s {ein} {T['d1']:.2f}s both}}
.{p} .hr{{animation:{p}drawR {T['d2e'] - T['d2']:.2f}s {eout} {T['d2']:.2f}s both}}
.{p} .jw{{animation:{p}jewel {jd:.2f}s linear both}}
.{p} .burst{{animation:{p}burst .9s cubic-bezier(.1,.6,.3,1) {T['ign']:.2f}s forwards}}
.{p} .bar{{transform-box:fill-box;transform-origin:left center;animation:{p}wipe {T['bare'] - T['bar']:.2f}s cubic-bezier(.7,0,.2,1) {T['bar']:.2f}s both}}
.{p} .pl{{animation:{p}run {IDLE}s cubic-bezier(.45,0,.6,1) {T['idle']:.2f}s infinite}}
.{p} .flash{{animation:{p}flash {IDLE}s ease-out {T['idle']:.2f}s infinite}}
.{p} .ring{{animation:{p}ring {IDLE}s ease-out {T['idle']:.2f}s infinite}}
.{p} .halo{{transform-box:fill-box;transform-origin:center;animation:{p}halo-in .8s ease-out {T['ign']:.2f}s both,{p}breathe {IDLE}s ease-in-out {T['idle']:.2f}s infinite}}
@keyframes {p}pop{{0%{{transform:scale(0);opacity:0}}60%{{transform:scale(1.28);opacity:1}}100%{{transform:scale(1);opacity:1}}}}
@keyframes {p}drawF{{from{{stroke-dashoffset:1.002}}to{{stroke-dashoffset:0}}}}
@keyframes {p}drawR{{from{{stroke-dashoffset:-1.002}}to{{stroke-dashoffset:0}}}}
@keyframes {p}jewel{{0%,{seed - 0.1:.1f}%{{transform:scale(0);opacity:0;fill:var(--seed)}}
 {seed + 6:.1f}%{{transform:scale(.62);opacity:1;fill:var(--seed)}}
 {ign - 1:.1f}%{{transform:scale(.62);opacity:1;fill:var(--seed)}}
 {ign + (100 - ign) * 0.45:.1f}%{{transform:scale(1.3);opacity:1;fill:var(--jewel)}}
 100%{{transform:scale(1);opacity:1;fill:var(--jewel)}}}}
@keyframes {p}burst{{0%{{transform:scale(1);opacity:.95}}100%{{transform:scale(3.4);opacity:0}}}}
@keyframes {p}wipe{{from{{transform:scaleX(0);opacity:.2}}to{{transform:scaleX(1);opacity:1}}}}
@keyframes {p}run{{0%{{stroke-dashoffset:.11;opacity:1}}27%{{stroke-dashoffset:-1;opacity:1}}28%,100%{{stroke-dashoffset:-1;opacity:0}}}}
@keyframes {p}flash{{0%,24%{{opacity:0}}29%{{opacity:.85}}48%,100%{{opacity:0}}}}
@keyframes {p}ring{{0%,26%{{transform:scale(1);opacity:0}}29%{{transform:scale(1);opacity:.8}}62%,100%{{transform:scale(2.7);opacity:0}}}}
@keyframes {p}halo-in{{from{{opacity:0}}to{{opacity:.55}}}}
@keyframes {p}breathe{{0%,100%{{opacity:.55;transform:scale(1)}}30%{{opacity:.9;transform:scale(1.12)}}}}
@media (prefers-reduced-motion: reduce){{.{p} *{{animation:none!important}}.{p} .halo{{opacity:.55}}}}
"""
    return css


def anim_mark_body(p, mode="glow", pulse="#FFFFFF", glow=True):
    """Animated mark in its 64 box. Returns (defs, body). Wrap in an element with class p."""
    g = geo(False)
    c = {"glow": GLOW, "dark": DARK, "light": LIGHT}[mode]
    L, R, J = g["L"], g["R"], g["J"]
    x0, x1, y0, y1 = g["bar"]
    defs = f'<clipPath id="{p}fl"><rect x="0" y="0" width="64" height="{f(g["floor"])}"/></clipPath>'
    for side, P in (("l", L), ("r", R)):
        defs += (f'<linearGradient id="{p}{side}" gradientUnits="userSpaceOnUse" x1="{f(P[0])}" y1="{f(P[1] + 6)}" x2="{f(J[0])}" y2="{f(J[1])}">'
                 f'<stop offset="0" stop-color="{c["A"]}"/><stop offset="0.22" stop-color="{c["A"]}"/>'
                 f'<stop offset="0.9" stop-color="{c["B"]}"/></linearGradient>')
    defs += (f'<radialGradient id="{p}hg"><stop offset="0" stop-color="{c["B"]}" stop-opacity=".75"/>'
             f'<stop offset="1" stop-color="{c["B"]}" stop-opacity="0"/></radialGradient>')
    if glow:
        defs += glow_filter(p + "gf")
    sw = g["sw"]
    rj = g["rj"]
    seed = "#E9E3F7" if mode != "light" else "#B9B2C9"
    body = (
        f'<circle class="halo" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj * 2.6)}" fill="url(#{p}hg)" opacity=".55"/>'
        f'<g clip-path="url(#{p}fl)" fill="none" stroke-width="{f(sw)}" stroke-linejoin="miter" stroke-miterlimit="2.6">'
        f'<path class="dr hl" pathLength="1" d="{g["left"]}" stroke="url(#{p}l)"/>'
        f'<path class="dr hr" pathLength="1" d="{g["right"]}" stroke="url(#{p}r)"/>'
        f'<path class="pl" pathLength="1" d="{g["left"]}" stroke="{pulse}" stroke-width="{f(sw * 0.62)}" stroke-linecap="round"/>'
        f'<path class="pl" pathLength="1" d="{g["right"]}" stroke="{pulse}" stroke-width="{f(sw * 0.62)}" stroke-linecap="round"/>'
        f'</g>'
        f'<rect class="bar" x="{f(x0)}" y="{f(y0)}" width="{f(x1 - x0)}" height="{f(y1 - y0)}" fill="{c["I"]}"/>'
        f'<circle class="n nl" cx="{f(L[0])}" cy="{f(L[1])}" r="{f(g["rn"])}" fill="{c["A"]}"/>'
        f'<circle class="n nr" cx="{f(R[0])}" cy="{f(R[1])}" r="{f(g["rn"])}" fill="{c["A"]}"/>'
        f'<circle class="n burst" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj)}" fill="none" stroke="{c["B"]}" stroke-width="1.6"/>'
        f'<circle class="n ring" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj)}" fill="none" stroke="{c["B"]}" stroke-width="1.2"/>'
        f'<circle class="n jw" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj)}" fill="{c["B"]}" style="--seed:{seed};--jewel:{c["B"]}"/>'
        f'<circle class="n flash" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj * 0.62)}" fill="#FFFFFF"/>')
    if glow:
        body = f'<g filter="url(#{p}gf)">{body}</g>'
    return defs, body


def svg(W, H, inner, defs, css, label):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" '
            f'aria-label="{label}"><defs>{defs}</defs><style>{css}</style>{inner}</svg>')


def mark_animated(p="cwa", mode="dark", size=256, k=1.0):
    """Transparent animated mark (dark or light UI)."""
    pulse = "#FFFFFF" if mode != "light" else "#7CE46B"
    d, b = anim_mark_body(p, mode, pulse, glow=(mode != "light"))
    s = size / 64
    inner = f'<g class="{p}" transform="scale({s:.4f})">{b}</g>'
    return svg(size, size, inner, d, css_for(p, timeline(k)), "Pathwarden")


def square_animated(p="cws", size=512):
    from build_static import glow_bg
    d0, bg = glow_bg(p + "bg", size, size, rx=size * 0.19, strength=1.1)
    d, b = anim_mark_body(p, "glow")
    ms = size * 0.64
    mx = (size - ms) / 2
    my = mx + (32 - 30.6) * ms / 64
    inner = bg + f'<g class="{p}" transform="translate({mx:.2f} {my:.2f}) scale({ms / 64:.4f})">{b}</g>'
    return svg(size, size, inner, d0 + d, css_for(p, timeline()), "Pathwarden")


def banner_animated(p="cwb", light=False, W=1280, H=400):
    """README banner: the mark draws in, then the wordmark and tagline fade up."""
    from build_static import MX0, MX1, MY0, MY1, fit_tag, glow_bg
    mode = "light" if light else "glow"
    d0, bg = glow_bg(p + "bg", W, H, rx=24, border=True, light=light)
    d, b = anim_mark_body(p, mode, "#7CE46B" if light else "#FFFFFF", glow=not light)
    msize, wsize = 230, 92
    ww = width(WORD, wsize, WORD_TRACK)
    ts = fit_tag(ww)
    gap = msize * 0.2
    x0 = (W - ((MX1 - MX0) * msize / 64 + gap + ww)) / 2 - MX0 * msize / 64
    my = H / 2 - (MY0 + MY1) / 2 * msize / 64
    tx = x0 + MX1 * msize / 64 + gap
    tag_base = my + MY1 * msize / 64
    word_base = tag_base - ts * CAP - wsize * 0.42
    wc, tc = ("#0B0E14", "#4A5468") if light else ("#FFFFFF", "#B4BCCB")
    wd, _ = text_el(WORD, tx, word_base, wsize, wc, True, WORD_TRACK, cls="wm")
    td, _ = text_el(TAG, tx + wsize * 0.02, tag_base, ts, tc, True, TAG_TRACK, cls="tg")
    T = timeline()
    css = css_for(p, T) + (
        f".{p} .wm,.{p} .tg{{animation:{p}rise .8s cubic-bezier(.2,.7,.2,1) both}}"
        f".{p} .wm{{animation-delay:{T['ign'] - 0.1:.2f}s}}.{p} .tg{{animation-delay:{T['ign'] + 0.25:.2f}s}}"
        f"@keyframes {p}rise{{from{{opacity:0;transform:translateY(14px)}}to{{opacity:1;transform:none}}}}")
    inner = (bg + f'<g class="{p}"><g transform="translate({x0:.2f} {my:.2f}) scale({msize / 64:.4f})">{b}</g>{wd}{td}</g>')
    return svg(W, H, inner, d0 + d, css, "Pathwarden: Defend every path to privilege.")


def hero_intro(p="cwh", W=1600, H=900):
    """Website hero intro: glows bloom, the mark draws at full size, the headline
    rises, then everything settles into the idle loop with slowly drifting glows."""
    from build_static import glow_bg
    d0, bg = glow_bg(p + "bg", W, H, rx=0, strength=1.15)
    d, b = anim_mark_body(p, "glow")
    msize = 300
    mx = W / 2 - msize / 2
    my = 205
    T = timeline(k=1.0, t0=0.25)
    head = "Defend every path to privilege."
    hs = 64
    hd, _ = text_el(head, W / 2, 668, hs, "#FFFFFF", True, -0.01, center=True, cls="hd")
    sub = "PATHWARDEN"
    sd, _ = text_el(sub, W / 2, 728, 24, "#B4BCCB", True, 0.42, center=True, cls="sb")
    css = css_for(p, T) + f"""
.{p}bgw .gb1,.{p}bgw .gb2,.{p}bgw .gb3{{transform-box:fill-box;transform-origin:center}}
.{p}bgw .gb1{{animation:{p}bloom 1.4s ease-out both,{p}drift1 14s ease-in-out 1.4s infinite}}
.{p}bgw .gb2{{animation:{p}bloom 1.6s ease-out .2s both,{p}drift2 11s ease-in-out 1.8s infinite}}
.{p}bgw .gb3{{animation:{p}bloom 1.8s ease-out .5s both,{p}drift3 16s ease-in-out 2.3s infinite}}
@keyframes {p}bloom{{from{{transform:scale(.4);opacity:0}}}}
@keyframes {p}drift1{{0%,100%{{transform:translate(0,0)}}50%{{transform:translate(60px,30px)}}}}
@keyframes {p}drift2{{0%,100%{{transform:translate(0,0)}}50%{{transform:translate(-40px,-30px)}}}}
@keyframes {p}drift3{{0%,100%{{transform:translate(0,0)}}50%{{transform:translate(-70px,-20px)}}}}
.{p} .hd{{animation:{p}rise .9s cubic-bezier(.2,.7,.2,1) {T['ign'] - 0.05:.2f}s both}}
.{p} .sb{{animation:{p}rise .9s cubic-bezier(.2,.7,.2,1) {T['ign'] + 0.3:.2f}s both}}
@keyframes {p}rise{{from{{opacity:0;transform:translateY(18px)}}to{{opacity:1;transform:none}}}}
@media (prefers-reduced-motion: reduce){{.{p}bgw *{{animation:none!important}}}}
"""
    inner = (f'<g class="{p}bgw">{bg}</g><g class="{p}"><g transform="translate({mx:.2f} {my:.2f}) scale({msize / 64:.4f})">{b}</g>{hd}{sd}</g>')
    return svg(W, H, inner, d0 + d, css, "Pathwarden: Defend every path to privilege.")
