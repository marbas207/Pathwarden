"""The Crown W pieces the program itself uses, built from the same geometry as
the brand set (mark.py, text.py):

  crates/pathwarden-cli/assets/pathwarden.ico
      Windows icon (pathwarden.exe, its desktop window and taskbar button):
      16 to 32 px from the small cut on a navy tile, 48 and 64 px from the
      regular cut on a navy tile, 256 px the glowing app tile.
  assets/brand/inline/mark.svg, assets/brand/inline/wordmark.svg
      The mark and the outlined wordmark for inlining in the app and the
      HTML report. Colors and motion come from CSS classes (report.css), so
      one copy serves both themes and needs no inline style; the attributes
      give the dark colors and the resting state when no stylesheet applies.
      The mark glows as the animated brand files do (anim.py: the whole mark
      under a feGaussianBlur glow), the filter retuned for the ~34 px it is
      shown at: pwcw-g on dark, the fainter pwcw-gl that report.css swaps in
      on light. A filter is an SVG attribute, not a style, so it needs no
      inline style either (the app's CSP has style-src 'self').
      Both share the lockup's vertical box (the mark's visible height), so
      set at the same height their baselines line up as in the horizontal
      lockup.

The terminal logo is drawn by the program itself (line art, with ASCII and
color-depth fallbacks): crates/pathwarden-cli/src/logo.rs. Its previews and
the reference copies in assets/brand/cli/ come from
scripts/docs-media/cli_logo.py.

    python scripts/brand/build_static.py   (first: the favicon PNGs come from it)
    python scripts/brand/build_repo.py
"""
import io
from pathlib import Path

import cairosvg
from PIL import Image

from build_static import MX0, MX1, MY0, MY1, fav_small
from mark import DARK, f, geo, glow_filter, mark_svg
from text import WORD, WORD_TRACK, outline, width

REPO = Path(__file__).resolve().parents[2]
BRAND = REPO / "assets" / "brand"
CLI = REPO / "crates" / "pathwarden-cli" / "assets"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8", newline="\n")
    print("wrote", path.relative_to(REPO))


def png(svg, w, h=None):
    return Image.open(io.BytesIO(cairosvg.svg2png(bytestring=svg.encode(), output_width=w, output_height=h or w))).convert("RGBA")


# ------------------------------------------------------------------ icon
def build_icon():
    fav = BRAND / "favicon"
    frames = {
        16: Image.open(fav / "favicon-16.png").convert("RGBA"),
        20: png(fav_small(20), 20),
        24: png(fav_small(24), 24),
        32: Image.open(fav / "favicon-32.png").convert("RGBA"),
        48: Image.open(fav / "favicon-48.png").convert("RGBA"),
        64: Image.open(fav / "favicon-64.png").convert("RGBA"),
        256: Image.open(fav / "icon-512.png").convert("RGBA").resize((256, 256), Image.LANCZOS),
    }
    order = sorted(frames)
    buf = io.BytesIO()
    frames[order[-1]].save(buf, format="ICO", sizes=[(s, s) for s in order],
                           append_images=[frames[s] for s in order[:-1]])
    write(CLI / "pathwarden.ico", buf.getvalue())


# ------------------------------------------------------------------ inline SVGs
# The visible box of the regular mark, shared by both inline files.
BOX_Y, BOX_H = MY0, MY1 - MY0
WORD_SIZE, WORD_BASE = 33, 44.5  # as in the horizontal lockup: baseline on the valley floor
# The glow, in mark units. The brand files blur by 2.2 units at 230 px and up;
# a ~34 px mark needs a wider, slightly fainter blur to read as a glow rather
# than a soft edge, and a light page wants much less of it.
GLOW_DARK = dict(std=3.2, k=0.85)
GLOW_LIGHT = dict(std=2.4, k=0.32)
# The filter region, fixed in user space so the burst ring (up to 3.4 times
# the jewel) and the breathing halo are never clipped as they grow.
GLOW_BOX = dict(x=-14, y=-20, w=92, h=94)


def inline_glow(fid, std, k):
    b = GLOW_BOX
    return glow_filter(fid, std, k).replace(
        'x="-40%" y="-40%" width="180%" height="180%"',
        f'filterUnits="userSpaceOnUse" x="{b["x"]}" y="{b["y"]}" width="{b["w"]}" height="{b["h"]}"')


def inline_mark():
    g = geo(False)
    L, R, J = g["L"], g["R"], g["J"]
    x0, x1, y0, y1 = g["bar"]
    sw, rj, rn = g["sw"], g["rj"], g["rn"]
    a, b, i = DARK["A"], DARK["B"], DARK["I"]
    grads = ""
    for side, P in (("l", L), ("r", R)):
        grads += (f'<linearGradient id="pwcw-{side}" gradientUnits="userSpaceOnUse" x1="{f(P[0])}" y1="{f(P[1] + 6)}" x2="{f(J[0])}" y2="{f(J[1])}">'
                  f'<stop class="cw-a" offset="0" stop-color="{a}"/><stop class="cw-a" offset="0.22" stop-color="{a}"/>'
                  f'<stop class="cw-b" offset="0.9" stop-color="{b}"/></linearGradient>')
    defs = (f'<clipPath id="pwcw-fl"><rect width="64" height="{f(g["floor"])}"/></clipPath>{grads}'
            f'<radialGradient id="pwcw-h"><stop class="cw-b cw-ho" offset="0" stop-color="{b}" stop-opacity=".75"/>'
            f'<stop class="cw-b" offset="1" stop-color="{b}" stop-opacity="0"/></radialGradient>'
            f'{inline_glow("pwcw-g", **GLOW_DARK)}{inline_glow("pwcw-gl", **GLOW_LIGHT)}')
    pw = f(sw * 0.62)
    body = (
        f'<g class="cw-glow" filter="url(#pwcw-g)">'
        f'<circle class="cw-halo" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj * 2.6)}" fill="url(#pwcw-h)" opacity=".55"/>'
        f'<g clip-path="url(#pwcw-fl)" fill="none" stroke-width="{f(sw)}" stroke-linejoin="miter" stroke-miterlimit="2.6">'
        f'<path class="cw-dr cw-hl" pathLength="1" d="{g["left"]}" stroke="url(#pwcw-l)"/>'
        f'<path class="cw-dr cw-hr" pathLength="1" d="{g["right"]}" stroke="url(#pwcw-r)"/>'
        f'<path class="cw-pl" pathLength="1" d="{g["left"]}" stroke="#FFFFFF" stroke-width="{pw}" stroke-linecap="round" opacity="0"/>'
        f'<path class="cw-pl" pathLength="1" d="{g["right"]}" stroke="#FFFFFF" stroke-width="{pw}" stroke-linecap="round" opacity="0"/>'
        f'</g>'
        f'<rect class="cw-bar" x="{f(x0)}" y="{f(y0)}" width="{f(x1 - x0)}" height="{f(y1 - y0)}" fill="{i}"/>'
        f'<circle class="cw-n cw-nl" cx="{f(L[0])}" cy="{f(L[1])}" r="{f(rn)}" fill="{a}"/>'
        f'<circle class="cw-n cw-nr" cx="{f(R[0])}" cy="{f(R[1])}" r="{f(rn)}" fill="{a}"/>'
        f'<circle class="cw-n cw-burst" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj)}" fill="none" stroke="{b}" stroke-width="1.6" opacity="0"/>'
        f'<circle class="cw-n cw-ring" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj)}" fill="none" stroke="{b}" stroke-width="1.2" opacity="0"/>'
        f'<circle class="cw-n cw-jw" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj)}" fill="{b}"/>'
        f'<circle class="cw-n cw-flash" cx="{f(J[0])}" cy="{f(J[1])}" r="{f(rj * 0.62)}" fill="#FFFFFF" opacity="0"/>'
        f'</g>')
    vb = f"{f(MX0)} {f(BOX_Y)} {f(MX1 - MX0)} {f(BOX_H)}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="cw" viewBox="{vb}" aria-hidden="true" focusable="false">'
            f'<defs>{defs}</defs>{body}</svg>\n')


def inline_wordmark():
    d, w = outline(WORD, WORD_SIZE, 0, WORD_BASE, WORD_TRACK)
    vb = f"0 {f(BOX_Y)} {w + 0.5:.2f} {f(BOX_H)}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="cw-word" viewBox="{vb}" aria-hidden="true" focusable="false">'
            f'<path fill="currentColor" d="{d}"/></svg>\n')


def build_inline():
    write(BRAND / "inline" / "mark.svg", inline_mark())
    write(BRAND / "inline" / "wordmark.svg", inline_wordmark())


if __name__ == "__main__":
    build_icon()
    build_inline()
