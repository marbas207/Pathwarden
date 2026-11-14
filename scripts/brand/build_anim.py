"""Animated SVGs (assets/brand/animated), optionally with GIF and MP4 previews.

    python scripts/brand/build_anim.py              (SVGs only)
    python scripts/brand/build_anim.py --previews   (also captures frames headlessly
                                                     and encodes target/brand-work/previews)
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image

import anim

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "assets" / "brand"
WORK = REPO / "target" / "brand-work" / "frames"
PREVIEWS = REPO / "target" / "brand-work" / "previews"
FFMPEG = None


def write(rel, s):
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8", newline="\n")
    return p


ITEMS = [
    # name, svg factory, (w, h), seconds captured, gif width
    ("banner-animated-dark", lambda: anim.banner_animated(), (1280, 400), 10.75, 720),
    ("banner-animated-light", lambda: anim.banner_animated(p="cwl", light=True), (1280, 400), 10.75, 720),
]


def sel():
    only = [a.split('=', 1)[1] for a in sys.argv if a.startswith('--only=')]
    return [it for it in ITEMS if not only or it[0] in only]


def build_svgs():
    out = {}
    write("animated/mark-animated-dark.svg", anim.mark_animated("cwd", "dark", 256))
    write("animated/mark-animated-light.svg", anim.mark_animated("cwk", "light", 256))
    for name, fn, *_ in ITEMS:
        s = fn()
        write(f"animated/{name}.svg", s)
        out[name] = s
    return out


def capture(svgs, fps=25):
    jobs = []
    for name, fn, (w, h), secs, _ in sel():
        d = WORK / name
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        page = WORK / f"{name}.html"
        page.write_text(f'<!doctype html><html><body style="margin:0;background:#0B0E14">{svgs[name]}</body></html>', encoding="utf-8")
        n = int(round(secs * fps))
        jobs.append(dict(url=page.as_uri(), out=str(d / "f{i}.png"), w=w, h=h, wait=300, frames=dict(n=n, dur=secs * 1000)))
    jf = WORK / "jobs.json"
    jf.write_text(json.dumps(jobs), encoding="utf-8")
    subprocess.run(["node", str(Path(__file__).with_name("render.mjs")), str(jf)], check=True)


def encode(fps=25):
    import imageio_ffmpeg
    ff = imageio_ffmpeg.get_ffmpeg_exe()
    PREVIEWS.mkdir(parents=True, exist_ok=True)
    for name, fn, (w, h), secs, gw in sel():
        d = WORK / name
        files = sorted(d.glob("f*.png"))
        # MP4 at full resolution (hero scaled to 1280 wide), even dimensions
        vf = "scale=1280:-2" if w > 1280 else "scale=trunc(iw/2)*2:trunc(ih/2)*2"
        subprocess.run([ff, "-y", "-loglevel", "error", "-framerate", str(fps), "-i", str(d / "f%03d.png"),
                        "-vf", vf, "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "slow",
                        "-movflags", "+faststart", str(PREVIEWS / f"{name}.mp4")], check=True)
        # GIF: half frame rate, crossfade the tail back to the first frame for a clean loop
        frames = [Image.open(p).convert("RGB") for p in files[::2]]
        gh = round(h * gw / w)
        frames = [im.resize((gw, gh), Image.LANCZOS) for im in frames]
        tail = 6
        first = frames[0]
        for i in range(tail):
            a = (i + 1) / (tail + 1)
            frames[-tail + i] = Image.blend(frames[-tail + i], first, a)
        # one shared palette built from a strip of representative frames, to avoid flicker
        picks = [frames[k] for k in range(0, len(frames) - tail, max(1, (len(frames) - tail) // 14))]
        strip = Image.new("RGB", (gw, gh * len(picks)))
        for k, im in enumerate(picks):
            strip.paste(im, (0, gh * k))
        pal = strip.quantize(colors=255, method=Image.Quantize.MEDIANCUT)
        dith = Image.Dither.NONE if name == 'hero-intro' else Image.Dither.FLOYDSTEINBERG
        q = [im.quantize(palette=pal, dither=dith) for im in frames]
        q[0].save(PREVIEWS / f"{name}.gif", save_all=True, append_images=q[1:], duration=int(2000 / fps), loop=0, optimize=True)
        print("encoded", name, len(files), "frames")


if __name__ == "__main__":
    svgs = build_svgs()
    if "--previews" in sys.argv:
        if "--encode" not in sys.argv:
            capture(svgs)
        encode()
