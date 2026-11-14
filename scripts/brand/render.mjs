// Headless Chrome renderer (no dependencies; Node 22 built-in WebSocket).
//   node render.mjs jobs.json
// jobs: [{url, out, w, h, scale?, full?, selector?, frames?: {n, dur, dir}}]
//  - selector: capture each matching element to out (with {i} replaced by index)
//  - frames: pause all CSS/SMIL animations and capture n frames across dur ms
import { spawn } from "node:child_process";
import { writeFileSync, mkdirSync, mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

const jobs = JSON.parse(readFileSync(process.argv[2], "utf8"));
const chrome = ["C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"].find((c) => existsSync(c));
const port = 9800 + Math.floor(Math.random() * 400);
const profile = mkdtempSync(join(tmpdir(), "pw-brand-"));
const proc = spawn(chrome, ["--headless=new", "--disable-gpu", "--hide-scrollbars", "--allow-file-access-from-files",
  `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "--no-first-run", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 80 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === "page"); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0;
const pending = new Map();
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
});
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
await send("Page.enable");
await send("Runtime.enable");

for (const job of jobs) {
  const scale = job.scale || 1;
  await send("Emulation.setDeviceMetricsOverride", { width: job.w, height: job.h, deviceScaleFactor: scale, mobile: false });
  await send("Emulation.setDefaultBackgroundColorOverride", job.transparent ? { color: { r: 0, g: 0, b: 0, a: 0 } } : {});
  await send("Page.navigate", { url: job.url });
  await sleep(job.wait || 800);
  mkdirSync(dirname(job.out), { recursive: true });
  if (job.frames) {
    const { n, dur } = job.frames;
    for (let k = 0; k < n; k++) {
      const t = (dur * k) / n;
      if (job.frames.expr) await evaluate(job.frames.expr.replace("{t}", String(t / 1000)));
      else await evaluate(`(() => {
        document.getAnimations().forEach(a => { a.pause(); a.currentTime = ${t}; });
        document.querySelectorAll('svg').forEach(s => { if (s.pauseAnimations) { s.pauseAnimations(); s.setCurrentTime(${t / 1000}); } });
        return 1; })()`);
      await sleep(30);
      const shot = await send("Page.captureScreenshot", job.clip ? { format: "png", clip: { ...job.clip, scale: 1 } } : { format: "png" });
      writeFileSync(job.out.replace("{i}", String(k).padStart(3, "0")), Buffer.from(shot.result.data, "base64"));
    }
    console.log("frames", job.out, n);
    continue;
  }
  if (job.selector) {
    const rects = await evaluate(`Array.from(document.querySelectorAll(${JSON.stringify(job.selector)})).map(e => { const r = e.getBoundingClientRect(); return {x: r.x + scrollX, y: r.y + scrollY, w: r.width, h: r.height}; })`);
    const H = await evaluate(`document.documentElement.scrollHeight`);
    await send("Emulation.setDeviceMetricsOverride", { width: job.w, height: Math.min(H, 16000), deviceScaleFactor: scale, mobile: false });
    await sleep(500);
    for (let k = 0; k < rects.length; k++) {
      const r = rects[k];
      const shot = await send("Page.captureScreenshot", { format: "png", clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 1 }, captureBeyondViewport: true });
      writeFileSync(job.out.replace("{i}", String(k + 1).padStart(2, "0")), Buffer.from(shot.result.data, "base64"));
    }
    console.log("sections", job.out, rects.length);
    continue;
  }
  if (job.full) {
    const H = await evaluate(`document.documentElement.scrollHeight`);
    await send("Emulation.setDeviceMetricsOverride", { width: job.w, height: Math.min(H, 16000), deviceScaleFactor: scale, mobile: false });
    await sleep(600);
  }
  const shot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(job.out, Buffer.from(shot.result.data, "base64"));
  console.log("shot", job.out);
}
ws.close();
proc.kill();
process.exit(0);
