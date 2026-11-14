"""Static Crown W brand assets: marks, lockups, favicons, social card, README banners.

    python scripts/brand/build_static.py [--no-chrome]

Writes into assets/brand/. SVGs are written directly. Flat PNGs come from
cairosvg; anything with a blur (glow mark, social card, banners, glowing app
icons) is rendered by headless Chrome (render.mjs, Node 22+); --no-chrome
leaves those PNGs as they are. Scratch files go to target/brand-work.
"""
import subprocess
import sys
import io
import json
from pathlib import Path

import cairosvg
from PIL import Image

from mark import GLOW, NAVY, WHITE, glow_filter, mark_group, mark_svg
from text import TAG, TAG_TRACK, WORD, WORD_TRACK, CAP, text_el, width

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "assets" / "brand"
WORK = REPO / "target" / "brand-work"
JOBS = []

TEXT = {
    "dark": ("#F7F7F7", "#A3ACBE"),
    "glow": ("#FFFFFF", "#B4BCCB"),
    "light": (NAVY, "#4A5468"),
    "mono-dark": (WHITE, WHITE),
    "mono-light": (NAVY, NAVY),
}
MODES = ("dark", "light", "glow", "mono-dark", "mono-light")
LOCK_MODES = ("dark", "light", "mono-dark", "mono-light")
# Visible bounds of the mark in its 64 box (regular optical size).
MX0, MX1, MY0, MY1 = 3.75, 60.25, 5.25, 56

_n = [0]


def uid(p):
    _n[0] += 1
    return f"{p}{_n[0]}"


def write(rel, s):
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(s, bytes):
        p.write_bytes(s)
    else:
        p.write_text(s, encoding="utf-8", newline="\n")
    return p


def svg_doc(x, y, w, h, inner, defs="", label="Pathwarden", W=None, H=None):
    W = W or w
    H = H or h
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W:.0f}" height="{H:.0f}" viewBox="{x:.2f} {y:.2f} {w:.2f} {h:.2f}" '
            f'role="img" aria-label="{label}"><defs>{defs}</defs>{inner}</svg>')


def png(svg, w, h=None):
    return cairosvg.svg2png(bytestring=svg.encode(), output_width=w, output_height=h or w)


def chrome_png(svg_rel, out_rel, w, h, transparent=True):
    """Queue a Chrome render of an SVG file at exact pixel size."""
    html = WORK / "frame" / (Path(out_rel).stem + ".html")
    html.parent.mkdir(parents=True, exist_ok=True)
    src = (ROOT / svg_rel).as_uri()
    html.write_text(f'<!doctype html><html><body style="margin:0;background:transparent">'
                    f'<img src="{src}" width="{w}" height="{h}" style="display:block"></body></html>', encoding="utf-8")
    JOBS.append(dict(url=html.as_uri(), out=str(ROOT / out_rel), w=w, h=h, transparent=transparent, wait=400))


# ------------------------------------------------------------------ marks
def build_marks():
    for mode in MODES:
        for small in (False, True):
            name = f"mark/mark{'-small' if small else ''}-{mode}.svg"
            s = mark_svg(mode, uid("m"), small=small)
            write(name, s)
            if mode == "glow":
                # glow needs room for its blur; the 64 box already has 3.75u margins
                chrome_png(name, name.replace(".svg", "-512.png"), 512, 512)
            elif not small:
                write(name.replace(".svg", "-512.png"), png(s, 512))


# ------------------------------------------------------------------ lockups
def lockup(kind, mode, outlined, tagline):
    word_c, tag_c = TEXT[mode]
    u = uid("l")
    if kind == "h":
        if tagline:
            ws = 34
            base = 41.5
        else:
            ws = 33
            base = 44.5  # wordmark baseline sits on the W's flat valley floor
        tx = MX1 + 13
        defs, g = mark_group(mode, u, 0, 0, 64)
        wd, ww = text_el(WORD, tx, base, ws, word_c, outlined, WORD_TRACK)
        inner = g + wd
        if tagline:
            ts = fit_tag(ww)
            td, _ = text_el(TAG, tx + ws * 0.02, MY1, ts, tag_c, outlined, TAG_TRACK)
            inner += td
        x0, y0 = MX0, MY0
        w = tx + ww - x0 + 1
        h = MY1 - MY0
        return svg_doc(x0, y0, w, h, inner, defs, W=w * 3, H=h * 3)
    # stacked
    ws = 40
    ww = width(WORD, ws, WORD_TRACK)
    ms = 96
    top = MY0 * ms / 64
    defs, g = mark_group(mode, u, ww / 2 - ms / 2, 0, ms)
    mark_bottom = MY1 * ms / 64
    base = mark_bottom + ws * CAP * 0.62 + ws * CAP
    wd, _ = text_el(WORD, ww / 2, base, ws, word_c, outlined, WORD_TRACK, center=True)
    inner = g + wd
    bottom = base
    if tagline:
        ts = fit_tag(ww * 0.98)
        tb = base + ws * 0.42 + ts * CAP
        td, _ = text_el(TAG, ww / 2, tb, ts, tag_c, outlined, TAG_TRACK, center=True)
        inner += td
        bottom = tb
    pad = 2
    return svg_doc(-pad, top - pad, ww + 2 * pad, bottom - top + 2 * pad, inner, defs,
                   W=(ww + 2 * pad) * 2.5, H=(bottom - top + 2 * pad) * 2.5)


def fit_tag(target):
    """Tagline size that makes it exactly as wide as the wordmark."""
    return target / width(TAG, 10, TAG_TRACK) * 10


def build_lockups():
    for kind, kn in (("h", "horizontal"), ("s", "stacked")):
        for tagline in (False, True):
            for mode in LOCK_MODES:
                for outlined in (True, False):
                    name = f"lockup/lockup-{kn}{'-tagline' if tagline else ''}-{mode}{'' if outlined else '-live'}.svg"
                    write(name, lockup(kind, mode, outlined, tagline))
    # glowing horizontal lockups for dark heroes
    for tagline in (False, True):
        name = f"lockup/lockup-horizontal{'-tagline' if tagline else ''}-glow.svg"
        write(name, lockup("h", "glow", True, tagline))


# ------------------------------------------------------------------ backgrounds
def glow_bg(u, W, H, rx=0, border=False, light=False, strength=1.0, dots=True):
    defs = (f'<filter id="{u}bl" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="{max(W, H) * 0.07:.1f}"/></filter>'
            f'<pattern id="{u}dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="12" cy="12" r="1.1" fill="{NAVY if light else "#FFFFFF"}"/></pattern>'
            f'<clipPath id="{u}clip"><rect width="{W}" height="{H}" rx="{rx}"/></clipPath>'
            f'<radialGradient id="{u}vig" cx="0.5" cy="0.5" r="0.75"><stop offset="0.55" stop-color="#000" stop-opacity="0"/>'
            f'<stop offset="1" stop-color="#000" stop-opacity="{0.06 if light else 0.45}"/></radialGradient>')
    s = strength
    m = min(W, H)
    if light:
        blobs = [("#9D5CFF", 0.30), ("#B48AFF", 0.18), ("#7CE46B", 0.36)]
        base = "#F7F7FA"
    else:
        blobs = [("#7A3DF0", 0.58), ("#9D5CFF", 0.22), ("#5FD15A", 0.38)]
        base = NAVY
    body = (f'<g clip-path="url(#{u}clip)"><rect width="{W}" height="{H}" fill="{base}"/>'
            f'<g filter="url(#{u}bl)">'
            f'<circle class="gb1" cx="{W * 0.18:.0f}" cy="{H * 0.16:.0f}" r="{m * 0.44:.0f}" fill="{blobs[0][0]}" opacity="{blobs[0][1] * s:.2f}"/>'
            f'<circle class="gb2" cx="{W * 0.36:.0f}" cy="{H * 0.66:.0f}" r="{m * 0.22:.0f}" fill="{blobs[1][0]}" opacity="{blobs[1][1] * s:.2f}"/>'
            f'<circle class="gb3" cx="{W * 0.86:.0f}" cy="{H * 0.92:.0f}" r="{m * 0.42:.0f}" fill="{blobs[2][0]}" opacity="{blobs[2][1] * s:.2f}"/>'
            f'</g>')
    if dots:
        body += f'<rect width="{W}" height="{H}" fill="url(#{u}dots)" opacity="{0.05 if light else 0.045}"/>'
    body += f'<rect width="{W}" height="{H}" fill="url(#{u}vig)"/></g>'
    if border:
        body += (f'<rect x="1" y="1" width="{W - 2}" height="{H - 2}" rx="{max(rx - 1, 0)}" fill="none" '
                 f'stroke="{"#E1E4EA" if light else "#232C3D"}" stroke-width="2"/>')
    return defs, body


def card(W, H, msize, wsize, rx=0, border=False, light=False, label="Pathwarden: Defend every path to privilege."):
    """Mark + wordmark + tagline centred on a glowing card."""
    u = uid("c")
    mode = "light" if light else "glow"
    word_c, tag_c = TEXT[mode]
    ww = width(WORD, wsize, WORD_TRACK)
    ts = fit_tag(ww)
    mvis = (MX1 - MX0) * msize / 64
    gap = msize * 0.2
    total = mvis + gap + ww
    x0 = (W - total) / 2 - MX0 * msize / 64
    # vertical: centre the visible mark; the text block's bottom aligns with the band's bottom
    my = H / 2 - (MY0 + MY1) / 2 * msize / 64
    defs, bg = glow_bg(u, W, H, rx, border, light)
    md, mg = mark_group(mode, u, x0, my, msize)
    tx = x0 + MX1 * msize / 64 + gap
    tag_base = my + MY1 * msize / 64
    word_base = tag_base - ts * CAP - wsize * 0.42
    wd, _ = text_el(WORD, tx, word_base, wsize, word_c, True, WORD_TRACK)
    td, _ = text_el(TAG, tx + wsize * 0.02, tag_base, ts, tag_c, True, TAG_TRACK)
    return svg_doc(0, 0, W, H, bg + mg + wd + td, defs + md, label=label)


def build_social():
    write("social/og-card.svg", card(1200, 630, 300, 104))
    chrome_png("social/og-card.svg", "social/og-card.png", 1200, 630, transparent=False)
    for light in (False, True):
        n = f"social/readme-banner-{'light' if light else 'dark'}.svg"
        write(n, card(1280, 400, 230, 92, rx=24, border=True, light=light))
        chrome_png(n, n.replace(".svg", ".png"), 1280, 400)


# ------------------------------------------------------------------ favicons
def tile(size_px, glow=True, rx_frac=0.22, mark_frac=0.74, full_bleed=False, small=False):
    """Mark on a navy tile. full_bleed: square with no corner radius (maskable / apple)."""
    S = 64
    u = uid("t")
    rx = 0 if full_bleed else S * rx_frac
    if glow:
        defs, bg = glow_bg(u, S, S, rx, strength=1.15, dots=False)
        mode = "glow"
    else:
        defs, bg = "", f'<rect width="{S}" height="{S}" rx="{rx}" fill="{NAVY}"/>'
        mode = "dark"
    ms = S * mark_frac
    off = (S - ms) / 2
    # nudge so the visible mark (not its box) is centred
    dy = (32 - (MY0 + MY1) / 2) * ms / 64
    md, mg = mark_group(mode, u, off, off + dy, ms, small=small)
    if glow:
        defs = defs.replace(f'id="{u}f"', f'id="{u}f"')
    return svg_doc(0, 0, S, S, bg + mg, defs + md, W=size_px, H=size_px)


def fav_small(size_px):
    """Pixel-tuned favicon: navy rounded tile, small optical mark nearly full bleed."""
    u = uid("fv")
    from mark import mark_parts
    d, b = mark_parts("dark", u, small=True, grad=size_px > 16)
    # Exact 64u tile: at 16 px every edge of the small mark lands on whole pixels.
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size_px}" height="{size_px}" viewBox="0 0 64 64">'
            f'<defs>{d}</defs><rect width="64" height="64" rx="12" fill="{NAVY}"/>{b}</svg>')


def favicon_svg():
    """Adaptive SVG favicon: dark colours by default, light colours on light UIs."""
    from mark import mark_parts
    dd, db = mark_parts("dark", "fd", small=True)
    ld, lb = mark_parts("light", "fl", small=True)
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            '<style>.l{display:none}@media (prefers-color-scheme: light){.d{display:none}.l{display:inline}}</style>'
            f'<defs>{dd}{ld}</defs><g class="d">{db}</g><g class="l">{lb}</g></svg>')


def build_favicons():
    imgs = {}
    for sz in (16, 32, 48, 64):
        s = fav_small(sz) if sz <= 32 else tile(sz, glow=False, mark_frac=0.86, rx_frac=0.2, small=sz < 64)
        (WORK / f"fav-{sz}.svg").parent.mkdir(parents=True, exist_ok=True)
        (WORK / f"fav-{sz}.svg").write_text(s, encoding="utf-8")
        data = png(s, sz)
        write(f"favicon/favicon-{sz}.png", data)
        imgs[sz] = Image.open(io.BytesIO(data)).convert("RGBA")
    buf = io.BytesIO()
    imgs[48].save(buf, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)], append_images=[imgs[16], imgs[32]])
    write("favicon/favicon.ico", buf.getvalue())
    write("favicon/favicon.svg", favicon_svg())
    # glowing app icons (Chrome for the blur)
    write("favicon/apple-touch-icon.svg", tile(180, glow=True, full_bleed=True, mark_frac=0.66))
    chrome_png("favicon/apple-touch-icon.svg", "favicon/apple-touch-icon.png", 180, 180, transparent=False)
    for sz in (192, 512):
        write(f"favicon/icon-{sz}.svg", tile(sz, glow=True, mark_frac=0.70))
        chrome_png(f"favicon/icon-{sz}.svg", f"favicon/icon-{sz}.png", sz, sz)
    # maskable: full bleed, mark inside the 80% safe circle
    write("favicon/icon-maskable-512.svg", tile(512, glow=True, full_bleed=True, mark_frac=0.56))
    chrome_png("favicon/icon-maskable-512.svg", "favicon/icon-maskable-512.png", 512, 512, transparent=False)
    write("favicon/site.webmanifest", json.dumps({
        "name": "Pathwarden", "short_name": "Pathwarden", "theme_color": NAVY, "background_color": NAVY,
        "display": "standalone", "start_url": "/",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
            {"src": "/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}]}, indent=2))
    write("favicon/head-snippet.html", "\n".join([
        '<link rel="icon" href="/favicon.ico" sizes="48x48">',
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">',
        '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
        '<link rel="manifest" href="/site.webmanifest">',
        '<meta name="theme-color" content="#0B0E14">',
        '<meta property="og:image" content="/og-card.png">', ""]))


def main():
    build_marks()
    build_lockups()
    build_social()
    build_favicons()
    WORK.mkdir(parents=True, exist_ok=True)
    jobs = WORK / "static-jobs.json"
    jobs.write_text(json.dumps(JOBS, indent=1), encoding="utf-8")
    print("static svgs written;", len(JOBS), "chrome jobs")
    if "--no-chrome" not in sys.argv:
        subprocess.run(["node", str(Path(__file__).with_name("render.mjs")), str(jobs)], check=True)


if __name__ == "__main__":
    main()
