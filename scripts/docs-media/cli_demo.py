"""An animated terminal session for the docs: runs real commands, records
their output with timestamps, and replays them in a terminal window (typed
commands, real output, long waits shortened with a visible "sped up" badge and
a real elapsed clock), recorded to a GIF.

    python scripts/docs-media/cli_demo.py [--input data/scale] [--out docs/images/cli-demo.gif]
        [--exe PATH] [--shown-input data/scale]

--shown-input is what the typed commands show (default: --input), for an
--input given as an absolute path; --exe defaults to target/release.

Commands run as in Windows Terminal at 100 columns (the hero banner in
truecolor). Needs Node 22+, Chrome and Pillow.
"""
import argparse
import html
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from cli_shots import line_html  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
EXE = ROOT / "target" / "release" / ("pathwarden.exe" if os.name == "nt" else "pathwarden")
WORK = ROOT / "target" / "docs-media" / "cli-demo"

ap = argparse.ArgumentParser()
ap.add_argument("--input", default="data/scale")
ap.add_argument("--out", default=str(ROOT / "docs" / "images" / "cli-demo.gif"))
ap.add_argument("--exe", default=str(EXE))
ap.add_argument("--shown-input")
a = ap.parse_args()
EXE = Path(a.exe)
shown_input = (a.shown_input or a.input).replace("/", "\\")


def run(args):
    """Runs pathwarden, returning [(seconds since start, line), ...] and the total time."""
    env = dict(os.environ, CLICOLOR_FORCE="1", WT_SESSION="1", COLUMNS="100")
    env.pop("NO_COLOR", None)
    start = time.perf_counter()
    proc = subprocess.Popen([str(EXE), *args], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []
    for raw in proc.stdout:
        lines.append((time.perf_counter() - start, raw.decode("utf-8", "replace").rstrip("\r\n")))
    proc.wait()
    total = time.perf_counter() - start
    return lines, total


SESSION = [
    ("pathwarden", []),
    (f"pathwarden summary -i {shown_input}", ["summary", "-i", a.input]),
    (f"pathwarden posture -i {shown_input}", ["posture", "-i", a.input]),
]

events = []
for shown, args in SESSION:
    print("running:", shown)
    lines, total = run(args)
    events.append({
        "cmd": shown,
        "total": round(total, 2),
        "lines": [{"t": round(t, 3), "html": line_html(text)} for t, text in lines],
    })

PAGE = """<!doctype html><meta charset="utf-8"><style>
html, body {{ margin: 0; background: #e9ebf0; }}
body {{ padding: 22px; }}
.term {{ width: 1020px; height: 716px; border-radius: 12px; overflow: hidden; background: #0b0e14; display: flex; flex-direction: column;
  box-shadow: 0 18px 40px rgba(11,14,20,.35), 0 0 0 1px rgba(255,255,255,.06) inset; }}
.bar {{ display: flex; align-items: center; gap: 8px; padding: 11px 14px; background: #161b26; position: relative; }}
.bar i {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
.bar .title {{ position: absolute; left: 0; right: 0; text-align: center; color: #8b95a7; font: 12.5px "Segoe UI", system-ui, sans-serif; }}
.badge {{ margin-left: auto; z-index: 1; font: 600 11.5px "Segoe UI", system-ui, sans-serif; color: #0b0e14; background: #e9e05a;
  border-radius: 999px; padding: 3px 10px; opacity: 0; transition: opacity .2s; }}
.badge.on {{ opacity: 1; }}
#screen {{ flex: 1; overflow: hidden; padding: 14px 18px; display: flex; flex-direction: column; justify-content: flex-end; }}
pre {{ margin: 0; color: #d7dce4; font: 13px/1.38 "Cascadia Mono", "Cascadia Code", Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }}
.prompt {{ color: #7ce46b; }} .cmd {{ color: #fff; font-weight: 600; }}
.art {{ display: block; height: 2.05ch; line-height: 2.05ch; white-space: pre; }}
.c {{ display: inline-block; width: 1ch; height: 2.05ch; vertical-align: top; }}
.caret {{ display: inline-block; width: 8px; height: 15px; background: #d7dce4; vertical-align: -2px; animation: blink 1s steps(1) infinite; }}
@keyframes blink {{ 50% {{ opacity: 0; }} }}
</style>
<div class="term"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i>
<span class="title">Windows PowerShell</span><span class="badge" id="badge"></span></div>
<div id="screen"><pre id="out"></pre></div></div>
<script>
const EVENTS = {events};
const out = document.getElementById("out");
const badge = document.getElementById("badge");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PROMPT = '<span class="prompt">PS C:\\\\Pathwarden&gt;</span> ';
function caret(on) {{ const c = out.querySelector(".caret"); if (c) c.remove(); if (on) out.insertAdjacentHTML("beforeend", '<span class="caret"></span>'); }}
async function typeCmd(text) {{
  out.insertAdjacentHTML("beforeend", PROMPT + '<span class="cmd"></span>');
  const spans = out.querySelectorAll(".cmd"); const cmd = spans[spans.length - 1];
  caret(true); await sleep(500);
  for (const ch of text) {{ caret(false); cmd.textContent += ch; caret(true); await sleep(38); }}
  await sleep(350); caret(false); out.insertAdjacentHTML("beforeend", "\\n");
}}
// Waits longer than LIMIT play at a faster rate, with a badge saying so and
// the real elapsed time counting up.
const LIMIT = 1.2, FAST = 2400;
async function wait(fromT, toT) {{
  const gap = toT - fromT;
  if (gap <= LIMIT) {{ await sleep(gap * 1000); return; }}
  badge.classList.add("on");
  const steps = 24;
  for (let i = 1; i <= steps; i++) {{
    badge.textContent = "sped up · " + (fromT + gap * i / steps).toFixed(1) + " s";
    await sleep(FAST / steps);
  }}
  badge.classList.remove("on");
}}
(async () => {{
  await sleep(600);
  for (const ev of EVENTS) {{
    await typeCmd(ev.cmd);
    let t = 0;
    for (const line of ev.lines) {{
      await wait(t, line.t);
      t = Math.max(t, line.t);
      out.insertAdjacentHTML("beforeend", line.html);
      await sleep(16);
    }}
    await wait(t, ev.total);
    await sleep(1600);
  }}
  out.insertAdjacentHTML("beforeend", PROMPT); caret(true);
  window.__done = true;
}})();
</script>"""

WORK.mkdir(parents=True, exist_ok=True)
page = WORK / "demo.html"
page.write_text(PAGE.format(events=json.dumps(events)), encoding="utf-8")

# Long enough for the whole replay: typing, compressed waits, output, pauses.
duration_ms = 1500
for ev in events:
    duration_ms += 900 + 38 * len(ev["cmd"]) + 16 * len(ev["lines"]) + 1600
    prev = 0.0
    for t in [l["t"] for l in ev["lines"]] + [ev["total"]]:
        gap = t - prev
        duration_ms += 2400 if gap > 1.2 else gap * 1000
        prev = max(prev, t)
duration_ms += 2500

frames = WORK / "frames"
if frames.exists():
    for f in frames.iterdir():
        f.unlink()
scenario = WORK / "scenario.json"
scenario.write_text(json.dumps({
    "url": page.resolve().as_uri(), "width": 1064, "height": 760,
    "steps": [{"do": "eval", "js": 'document.getElementById("__cur")?.remove()', "ms": 100},
              {"do": "wait", "ms": int(duration_ms)}],
}), encoding="utf-8")
subprocess.run(["node", str(Path(__file__).with_name("record.mjs")), str(scenario), str(frames)], check=True)
subprocess.run([sys.executable, str(Path(__file__).with_name("make_gif.py")), str(frames), a.out, "--width", "1064"], check=True)
for ev in events:
    print(f"  {ev['cmd']}: {ev['total']:.1f} s, {len(ev['lines'])} lines")
