"""Inter Bold shaping and outlining (Inter is SIL OFL 1.1).

The font is not in the repository: install Inter (https://rsms.me/inter/) or
point PATHWARDEN_INTER_BOLD at Inter-Bold.ttf.
"""
import os
from functools import lru_cache

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

FONT_BOLD = os.environ.get("PATHWARDEN_INTER_BOLD", "C:/Windows/Fonts/Inter-Bold-slnt=0.ttf")
FONT_STACK = "Inter, 'Segoe UI Variable Display', 'Segoe UI', system-ui, -apple-system, 'Helvetica Neue', Arial, sans-serif"
WORD = "Pathwarden"
TAG = "DEFEND EVERY PATH TO PRIVILEGE."
TAG_TRACK = 0.2
WORD_TRACK = -0.012
CAP = 0.727  # Inter cap height / em


@lru_cache(None)
def _font(path):
    blob = hb.Blob.from_file_path(path)
    face = hb.Face(blob)
    font = hb.Font(face)
    tt = TTFont(path)
    return font, tt.getGlyphSet(), tt.getGlyphOrder(), face.upem


def shape(text, size, tracking=0.0):
    font, gs, order, upem = _font(FONT_BOLD)
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": True})
    s = size / upem
    x, out, track = 0.0, [], tracking * size
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        out.append((order[info.codepoint], x + pos.x_offset * s))
        x += pos.x_advance * s + track
    return out, (x - track if out else 0)


def width(text, size, tracking=0.0):
    return shape(text, size, tracking)[1]


def outline(text, size, x0, y0, tracking=0.0):
    font, gs, order, upem = _font(FONT_BOLD)
    glyphs, w = shape(text, size, tracking)
    s = size / upem
    parts = []
    for name, gx in glyphs:
        pen = SVGPathPen(gs)
        gs[name].draw(TransformPen(pen, (s, 0, 0, -s, x0 + gx, y0)))
        if pen.getCommands():
            parts.append(pen.getCommands())
    return " ".join(parts), w


def text_el(text, x, y, size, color, outlined, tracking=0.0, center=False, cls=""):
    w = width(text, size, tracking)
    if center:
        x -= w / 2
    c = f' class="{cls}"' if cls else ""
    if outlined:
        d, _ = outline(text, size, x, y, tracking)
        return f'<path{c} fill="{color}" d="{d}"/>', w
    ls = f' letter-spacing="{tracking * size:.2f}"' if tracking else ""
    return (f'<text{c} x="{x:.2f}" y="{y:.2f}" font-family="{FONT_STACK}" font-weight="700" font-size="{size}"{ls} '
            f'fill="{color}">{text}</text>'), w
