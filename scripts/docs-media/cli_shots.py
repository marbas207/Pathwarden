"""Screenshots of the CLI for the docs: runs real commands against the demo
data with colors on, renders the ANSI output in a terminal window, and saves
PNGs to docs/images/.

    python scripts/docs-media/cli_shots.py [path/to/pathwarden]

Needs Node 22+ and Chrome (see record.mjs).
"""
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "release" / ("pathwarden.exe" if os.name == "nt" else "pathwarden")
OUT = ROOT / "docs" / "images"
WORK = ROOT / "target" / "docs-media"

# (file name, command line shown, arguments, lines to keep)
SHOTS = [
    ("cli-posture", "pathwarden posture -i demo", ["posture", "-i", "demo"], None),
    ("cli-findings", "pathwarden findings -i demo --min-severity high", ["findings", "-i", "demo", "--min-severity", "high"], 34),
    ("cli-plan", "pathwarden plan -i demo", ["plan", "-i", "demo"], None),
]

PALETTE = ["#1b2130", "#f2557a", "#7ce46b", "#e9e05a", "#4a9ae0", "#9d5cff", "#56c2d6", "#d7dce4",
           "#5c6577", "#ff7b97", "#9cf08d", "#f3ed8a", "#7ab8ee", "#b994ff", "#86dcea", "#ffffff"]


def color256(n):
    if n < 16:
        return PALETTE[n]
    if n < 232:
        n -= 16
        r, g, b = n // 36, (n // 6) % 6, n % 6
        to = lambda v: 0 if v == 0 else 55 + v * 40
        return f"#{to(r):02x}{to(g):02x}{to(b):02x}"
    v = 8 + (n - 232) * 10
    return f"#{v:02x}{v:02x}{v:02x}"


# Block characters a terminal draws as solid shapes: (top, bottom) halves
# (or left/right for the vertical halves) filled with the foreground.
BLOCKS = {"\u2580": "top", "\u2584": "bottom", "\u2588": "full", "\u258c": "left", "\u2590": "right"}
DIAGONALS = "╱╲"
# Quadrant blocks by bit pattern: 1 top left, 2 top right, 4 bottom left, 8
# bottom right.
QUADRANTS = " \u2598\u259d\u2580\u2596\u258c\u259e\u259b\u2597\u259a\u2590\u259c\u2584\u2599\u259f\u2588"


def cell(ch, fg, bg):
    """A block character as a cell-sized box, so shapes tile without the
    gaps fonts leave between block glyphs."""
    fg = fg or "currentColor"
    bg = bg or "transparent"
    kind = BLOCKS.get(ch)
    if kind == "full":
        paint = fg
    elif kind == "top":
        paint = f"linear-gradient({fg} 50%,{bg} 50%)"
    elif kind == "bottom":
        paint = f"linear-gradient({bg} 50%,{fg} 50%)"
    elif kind == "left":
        paint = f"linear-gradient(90deg,{fg} 50%,{bg} 50%)"
    elif kind == "right":
        paint = f"linear-gradient(90deg,{bg} 50%,{fg} 50%)"
    elif "▁" <= ch <= "▇":  # lower eighths
        pct = 100 - (ord(ch) - 0x2580) * 12.5
        paint = f"linear-gradient({bg} {pct}%,{fg} {pct}%)"
    elif ch == "▔":  # upper eighth
        paint = f"linear-gradient({fg} 12.5%,{bg} 12.5%)"
    elif ch in DIAGONALS:  # corner to corner, as terminals draw them
        way = "to bottom right" if ch == "╱" else "to top right"
        paint = (f"linear-gradient({way},{bg} calc(50% - 1px),{fg} calc(50% - 1px),"
                 f"{fg} calc(50% + 1px),{bg} calc(50% + 1px))")
    elif ch in QUADRANTS:
        bits = QUADRANTS.index(ch)
        spots = [pos for i, pos in enumerate(("0 0", "100% 0", "0 100%", "100% 100%")) if bits >> i & 1]
        paint = ",".join(f"linear-gradient({fg},{fg}) {p}/50% 50% no-repeat" for p in spots) + f",{bg}"
    else:  # shades and other block elements: an even tint
        paint = f"color-mix(in srgb,{fg} 55%,{bg if bg != 'transparent' else '#0b0e14'})"
    return f'<i class="c" style="background:{paint}"></i>'


def chunk_html(text, fg, bg, bold, dim, ul, art):
    if art and any(is_cell(ch) for ch in text):
        parts = []
        run = ""
        for ch in text:
            if is_cell(ch):
                if run:
                    parts.append(chunk_html(run, fg, bg, bold, dim, ul, False))
                    run = ""
                parts.append(cell(ch, fg, bg))
            elif ch == " " and bg:
                if run:
                    parts.append(chunk_html(run, fg, bg, bold, dim, ul, False))
                    run = ""
                parts.append(f'<i class="c" style="background:{bg}"></i>')
            else:
                run += ch
        if run:
            parts.append(chunk_html(run, fg, bg, bold, dim, ul, False))
        return "".join(parts)
    chunk = html.escape(text)
    style = []
    if fg:
        style.append(f"color:{fg}")
    if bg:
        style.append(f"background:{bg}")
    if bold:
        style.append("font-weight:700")
    if dim:
        style.append("opacity:.62")
    if ul:
        style.append("text-decoration:underline")
    return f'<span style="{";".join(style)}">{chunk}</span>' if style else chunk


def ansi_to_html(text, art=False):
    out, fg, bg, bold, dim, ul = [], None, None, False, False, False
    pos = 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", text):
        if m.start() > pos:
            out.append(chunk_html(text[pos:m.start()], fg, bg, bold, dim, ul, art))
        codes = [int(c) if c else 0 for c in m.group(1).split(";")]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg = bg = None
                bold = dim = ul = False
            elif c == 1:
                bold = True
            elif c == 2:
                dim = True
            elif c == 22:
                bold = dim = False
            elif c == 4:
                ul = True
            elif c == 24:
                ul = False
            elif 30 <= c <= 37:
                fg = PALETTE[c - 30]
            elif 90 <= c <= 97:
                fg = PALETTE[c - 90 + 8]
            elif 40 <= c <= 47:
                bg = PALETTE[c - 40]
            elif 100 <= c <= 107:
                bg = PALETTE[c - 100 + 8]
            elif c == 39:
                fg = None
            elif c == 49:
                bg = None
            elif c in (38, 48) and i + 1 < len(codes):
                if codes[i + 1] == 2 and i + 4 < len(codes):
                    value = "#{:02x}{:02x}{:02x}".format(*codes[i + 2:i + 5])
                    i += 4
                elif codes[i + 1] == 5 and i + 2 < len(codes):
                    value = color256(codes[i + 2])
                    i += 2
                else:
                    value = None
                if c == 38:
                    fg = value
                else:
                    bg = value
            i += 1
        pos = m.end()
    if pos < len(text):
        out.append(chunk_html(text[pos:], fg, bg, bold, dim, ul, art))
    return "".join(out)


def is_cell(ch):
    """Characters a terminal draws itself, filling the cell exactly."""
    return "\u2580" <= ch <= "\u259f" or ch in DIAGONALS


def is_art(text):
    """A line of the banner (block elements and box-drawing diagonals)."""
    return any(is_cell(ch) for ch in text)


def line_html(text):
    """One output line. Banner lines become rows of exact-size cells (a
    terminal's grid, without font gaps); other text keeps normal spacing."""
    if is_art(text):
        return f'<span class="art">{ansi_to_html(text, art=True) or " "}</span>'
    return ansi_to_html(text) + "\n"


PAGE = """<!doctype html><meta charset="utf-8"><style>
body {{ margin: 0; padding: 28px; background: #e9ebf0; }}
.term {{ display: inline-block; min-width: 900px; border-radius: 12px; overflow: hidden; background: #0b0e14;
  box-shadow: 0 18px 40px rgba(11,14,20,.35), 0 0 0 1px rgba(255,255,255,.06) inset; }}
.bar {{ display: flex; align-items: center; gap: 8px; padding: 11px 14px; background: #161b26; }}
.bar i {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
.bar span {{ flex: 1; text-align: center; margin-right: 52px; color: #8b95a7; font: 12.5px "Segoe UI", system-ui, sans-serif; }}
pre {{ margin: 0; padding: 16px 20px 20px; color: #d7dce4; font: 13.5px/1.42 "Cascadia Mono", "Cascadia Code", Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; max-width: 118ch; }}
.prompt {{ color: #7ce46b; }} .cmd {{ color: #ffffff; font-weight: 600; }}
.art {{ display: block; height: 1.3213em; line-height: 1.3213em; white-space: pre; }}
.c {{ display: inline-block; width: 1ch; height: 1.3213em; vertical-align: top; }}
</style>
<div class="term"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>Windows PowerShell</span></div>
<pre><span class="prompt">PS C:\\Pathwarden&gt;</span> <span class="cmd">{cmd}</span>
{body}</pre></div>"""


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    # Color forced on, as in Windows Terminal at 100 columns: the hero banner
    # in truecolor (see crates/pathwarden-cli/src/logo.rs).
    env = dict(os.environ, CLICOLOR_FORCE="1", WT_SESSION="1", COLUMNS="100")
    env.pop("NO_COLOR", None)
    steps = []
    for name, shown, args, keep in SHOTS:
        res = subprocess.run([str(EXE), *args], cwd=ROOT, env=env, capture_output=True)
        text = (res.stdout + res.stderr).decode("utf-8", "replace").replace("\r\n", "\n").rstrip("\n")
        lines = text.split("\n")
        if keep and len(lines) > keep:
            lines = lines[:keep] + ["\x1b[2m  ...\x1b[0m"]
        page = WORK / f"{name}.html"
        page.write_text(PAGE.format(cmd=html.escape(shown), body="".join(line_html(t) for t in lines)), encoding="utf-8")
        steps.append({"do": "goto", "url": page.resolve().as_uri(), "ms": 500})
        steps.append({"do": "shot", "sel": ".term", "out": str(OUT / f"{name}.png")})
    scenario = WORK / "cli.json"
    scenario.write_text(json.dumps({"url": "about:blank", "width": 1300, "height": 900, "scale": 2, "steps": steps}), encoding="utf-8")
    subprocess.run(["node", str(Path(__file__).with_name("record.mjs")), str(scenario), str(WORK / "cli-frames")], check=True)
    for name, *_ in SHOTS:
        print("wrote", (OUT / f"{name}.png").relative_to(ROOT))


if __name__ == "__main__":
    main()
