"""Turns recorded frames (record.mjs) into a small looping GIF.

    python make_gif.py <frames-dir> <out.gif> [--width 960] [--hold-end 2500] [--fps 12]
                       [--fast FROM-TO:FACTOR ...] [--cut FROM-TO ...]

Each frame keeps its real duration; runs of identical frames are merged, so
still moments cost almost nothing. Frames are capped at --fps: the rail's
Crown W pulses and glows all the time, so without a cap every screencast
frame would be a new GIF frame. The last frame is held so the loop
doesn't restart abruptly. --fast plays a stretch of the recording (seconds
from the start) FACTOR times faster, such as a long wait for an analysis;
--cut leaves a stretch out. --scenario reads more of these options from the
scenario's "gif" list, so each GIF's settings live with its scenario.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from PIL import Image

ap = argparse.ArgumentParser()
ap.add_argument("frames")
ap.add_argument("out")
ap.add_argument("--width", type=int, default=960)
ap.add_argument("--hold-end", type=int, default=2500)
ap.add_argument("--colors", type=int, default=255)
ap.add_argument("--fps", type=float, default=12)
ap.add_argument("--fast", action="append", default=[])
ap.add_argument("--cut", action="append", default=[])
ap.add_argument("--scenario")
a = ap.parse_args()
if a.scenario:
    a = ap.parse_args(json.loads(Path(a.scenario).read_text(encoding="utf8")).get("gif", []) + sys.argv[1:])
spans = []
for f in a.fast:
    rng, fac = f.split(":")
    lo, hi = (float(x) * 1000 for x in rng.split("-"))
    spans.append((lo, hi, float(fac)))
for c in a.cut:
    lo, hi = (float(x) * 1000 for x in c.split("-"))
    spans.append((lo, hi, float("inf")))


def remap(t):
    """Recording time to GIF time, with the --fast and --cut stretches shrunk."""
    out = t
    for lo, hi, fac in spans:
        if t > lo:
            out -= (min(t, hi) - lo) * (1 - 1 / fac)
    return out


src = Path(a.frames)
files = sorted(src.glob("f*.png"))
times = [remap(t) for t in json.loads((src / "times.json").read_text())]
assert len(times) >= len(files), "times.json and frames disagree"

frames, durations, last_hash = [], [], None
for i, f in enumerate(files):
    img = Image.open(f).convert("RGB")
    if img.width != a.width:
        img = img.resize((a.width, round(img.height * a.width / img.width)), Image.LANCZOS)
    h = hashlib.md5(img.tobytes()).hexdigest()
    nxt = times[i + 1] if i + 1 < len(files) else times[i] + 100
    dur = nxt - times[i]
    if dur <= 0 and frames:
        continue
    if h == last_hash:
        durations[-1] += dur
        continue
    if frames and durations[-1] < 1000 / a.fps:
        # Too soon after the last kept frame: show this one in its place.
        frames[-1] = img
        durations[-1] += dur
        last_hash = h
        continue
    frames.append(img)
    durations.append(dur)
    last_hash = h
durations[-1] += a.hold_end
durations = [max(20, round(d)) for d in durations]

# One palette for the whole animation (so frames store only what changed),
# built from every frame: a palette sampled from a few frames drops accents
# that appear in only some of them, like the orange exposure ring.
thumb_w = frames[0].width // 3
thumb_h = frames[0].height // 3
cols = 16
rows = (len(frames) + cols - 1) // cols
mosaic = Image.new("RGB", (thumb_w * cols, thumb_h * rows))
for k, fr in enumerate(frames):
    mosaic.paste(fr.resize((thumb_w, thumb_h), Image.BILINEAR), ((k % cols) * thumb_w, (k // cols) * thumb_h))
# Brand and severity colors are reserved: thin accents (a severity card's top
# border) are too few pixels to win a palette slot on their own.
KEY = ["#9d5cff", "#7ce46b", "#f2557a", "#ff8a3d", "#e9e05a", "#8b9ab0", "#6b778c",
       "#6b00d6", "#1f7a33", "#c8264a", "#c45200", "#8a6d00", "#5f6f86",
       "#f7f7f7", "#e9e3f7", "#0b0e14", "#0e131c", "#121925", "#172030", "#1a2332", "#222c3c", "#f2f4f8", "#9aa7b8"]
# They go into the palette exactly, beside the colors quantized from the
# frames, so the Crown W's violet and green stay true.
rgb = [tuple(int(c[i:i + 2], 16) for i in (1, 3, 5)) for c in KEY]
rest = mosaic.quantize(colors=a.colors - len(KEY), method=Image.Quantize.FASTOCTREE)
found = rest.getpalette()[: 3 * (a.colors - len(KEY))]
palette = Image.new("P", (1, 1))
palette.putpalette([v for c in rgb for v in c] + found + [0] * (768 - 3 * len(rgb) - len(found)))
pal = [fr.quantize(palette=palette, dither=Image.Dither.NONE) for fr in frames]
pal[0].save(a.out, save_all=True, append_images=pal[1:], duration=durations, loop=0, optimize=True, disposal=1)
size = Path(a.out).stat().st_size
print(f"{a.out}: {len(frames)} frames, {sum(durations) / 1000:.1f} s, {size / 1e6:.2f} MB")
