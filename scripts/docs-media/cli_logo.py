"""Previews of every terminal logo variant (crates/pathwarden-cli/src/logo.rs):
runs the real binary with the environment of each kind of terminal, renders
the ANSI output in a terminal window, and saves one PNG per variant plus a
contact sheet.

    python scripts/docs-media/cli_logo.py [path/to/pathwarden] [--out DIR]

Also refreshes the reference copies in assets/brand/cli/. Needs Node 22+,
Chrome and Pillow (see record.mjs).
"""
import argparse
import html
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from cli_shots import ansi_to_html  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
ap = argparse.ArgumentParser()
ap.add_argument("exe", nargs="?", default=str(ROOT / "target" / "release" / ("pathwarden.exe" if os.name == "nt" else "pathwarden")))
ap.add_argument("--out", default=str(ROOT / "target" / "docs-media" / "cli-logo"))
a = ap.parse_args()
OUT = Path(a.out)
WORK = ROOT / "target" / "docs-media" / "cli-logo-work"
BRAND_CLI = ROOT / "assets" / "brand" / "cli"

# Variables that decide the variant; cleared, then set per terminal.
CLEAR = ["NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "COLORTERM", "TERM", "TERM_PROGRAM", "WT_SESSION",
         "ConEmuANSI", "LC_ALL", "LC_CTYPE", "LANG", "COLUMNS"]
FORCE = {"CLICOLOR_FORCE": "1"}
UTF8 = {"LANG": "en_US.UTF-8"}

# (file, title, environment, args, lines kept, columns, light theme)
SHOTS = [
    ("hero-truecolor", "Hero, truecolor (Windows Terminal, COLORTERM=truecolor)", {**FORCE, "WT_SESSION": "1", "COLUMNS": "100"}, [], 7, 80, False),
    ("hero-truecolor-light", "Hero, truecolor, light theme", {**FORCE, "WT_SESSION": "1", "COLUMNS": "100"}, [], 7, 80, True),
    ("hero-256", "Hero, 256 colors (TERM=xterm-256color)", {**FORCE, **UTF8, "TERM": "xterm-256color", "COLUMNS": "100"}, [], 7, 80, False),
    ("hero-16", "Hero, 16 colors (TERM=xterm)", {**FORCE, **UTF8, "TERM": "xterm", "COLUMNS": "100"}, [], 7, 80, False),
    ("ascii-color", "ASCII, color (classic Windows console, no UTF-8 locale)", {**FORCE, "COLUMNS": "100"}, [], 7, 80, False),
    ("ascii-plain", "ASCII, no color (NO_COLOR, TERM=dumb)", {**FORCE, "NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "100"}, [], 7, 80, False),
    ("narrow", "Narrow terminal (under 80 columns)", {**FORCE, "WT_SESSION": "1", "COLUMNS": "60"}, [], 3, 60, False),
    ("narrow-ascii", "Narrow, ASCII", {**FORCE, "NO_COLOR": "1", "COLUMNS": "60"}, [], 3, 60, False),
    ("header", "Header line: pathwarden demo / pathwarden ui", {**FORCE, "WT_SESSION": "1", "COLUMNS": "100"}, ["demo", "-o", "{tmp}"], 1, 80, False),
    ("piped", "Piped or redirected: no logo", {"WT_SESSION": "1"}, [], 1, 80, False),
]

PAGE = """<!doctype html><meta charset="utf-8"><style>
body {{ margin: 0; padding: 20px; background: transparent; }}
.term {{ display: inline-block; border-radius: 10px; overflow: hidden; background: {bg};
  box-shadow: 0 10px 28px rgba(11,14,20,.28), 0 0 0 1px rgba(127,127,127,.15) inset; }}
.bar {{ display: flex; align-items: center; gap: 8px; padding: 9px 12px; background: {bar}; }}
.bar i {{ width: 11px; height: 11px; border-radius: 50%; display: inline-block; }}
.bar span {{ flex: 1; text-align: center; margin-right: 48px; color: #8b95a7; font: 12px "Segoe UI", system-ui, sans-serif; }}
pre {{ margin: 0; padding: 14px 18px 18px; color: {fg}; font: 15px/1.3213 "Cascadia Mono", Consolas, monospace; white-space: pre; width: {cols}ch; }}
.art {{ display: block; height: 1.3213em; line-height: 1.3213em; white-space: pre; }}
.c {{ display: inline-block; width: 1ch; height: 1.3213em; vertical-align: top; }}
</style>
<div class="term"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>{title}</span></div>
<pre>{body}</pre></div>"""


def capture(env_extra, args, keep):
    env = {k: v for k, v in os.environ.items() if k not in CLEAR}
    env.update(env_extra)
    with tempfile.TemporaryDirectory() as tmp:
        args = [x.replace("{tmp}", str(Path(tmp) / "demo.html")) for x in args]
        res = subprocess.run([a.exe, *args], cwd=tmp, env=env, capture_output=True)
    text = res.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    return lines[:keep]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    steps, done = [], []
    for name, title, env, args, keep, cols, light in SHOTS:
        lines = capture(env, args, keep)
        if name == "hero-truecolor":
            BRAND_CLI.mkdir(parents=True, exist_ok=True)
            (BRAND_CLI / "pathwarden-cli.ans").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        if name == "ascii-plain":
            (BRAND_CLI / "pathwarden-cli-ascii.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        # Every line on the cell grid, as a terminal draws it.
        body = "".join(f'<span class="art">{ansi_to_html(t, art=True) or " "}</span>' for t in lines)
        colors = dict(bg="#f7f7f7", bar="#e2e4ea", fg="#1b2130") if light else dict(bg="#0c0c0c", bar="#1f1f1f", fg="#cccccc")
        page = WORK / f"{name}.html"
        page.write_text(PAGE.format(body=body, title=html.escape(title), cols=cols, **colors), encoding="utf-8")
        steps += [{"do": "goto", "url": page.resolve().as_uri(), "ms": 400}, {"do": "shot", "sel": ".term", "out": str(OUT / f"{name}.png")}]
        done.append(name)
    scenario = WORK / "scenario.json"
    scenario.write_text(json.dumps({"url": "about:blank", "width": 1400, "height": 900, "scale": 2, "steps": steps}), encoding="utf-8")
    subprocess.run(["node", str(Path(__file__).with_name("record.mjs")), str(scenario), str(WORK / "frames")], check=True)
    contact_sheet([OUT / f"{n}.png" for n in done], OUT / "contact.png")
    print("wrote", OUT)


def contact_sheet(paths, out):
    from PIL import Image
    ims = [Image.open(p) for p in paths]
    pad = 24
    col_w = max(i.width for i in ims)
    # Two columns, in order.
    left, right = ims[0::2], ims[1::2]
    h = max(sum(i.height for i in left), sum(i.height for i in right)) + pad * (len(left) + 1)
    sheet = Image.new("RGB", (col_w * 2 + pad * 3, h), "#e9ebf0")
    for c, column in enumerate((left, right)):
        y = pad
        for im in column:
            sheet.paste(im, (pad + c * (col_w + pad), y), im if im.mode == "RGBA" else None)
            y += im.height + pad
    sheet.save(out)


if __name__ == "__main__":
    main()
