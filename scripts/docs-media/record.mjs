// Records a scripted browser session as numbered PNG frames, for the GIFs in
// the docs. Drives headless Chrome over the DevTools protocol (no packages
// needed; Node 22+ for the built-in WebSocket).
//
//   node record.mjs <scenario.json> <frames-dir> [url]
//
// The optional url replaces the scenario's (the web UI's one-time link, or
// where the report was written).
//
// A scenario is {"url", "width", "height", "chrome"?, "steps": [...]};
// steps are {"do": "wait", "ms"}, {"do": "goto", "url"}, {"do": "click",
// "sel"}, {"do": "hover", "sel"}, {"do": "scroll", "sel", "block"?},
// {"do": "scrollBy", "y"}, {"do": "eval", "js"}, {"do": "shot", "sel", "out"}
// (a still PNG of one element), {"do": "dblclick", "sel"}, {"do": "type",
// "sel", "text", "clear"?, "delay"?} (types into a field a key at a time),
// "env" in place of "text" types the value of that environment variable (a
// password, kept out of the scenario; type it only into a password field),
// {"do": "select", "sel", "value"} (sets a drop-down, date or time field),
// {"do": "upload", "sel", "files"} (puts files, relative to the repository,
// in a file input, as browsing for them does), {"do": "waitFor", "sel" or
// "js", "timeout"?} (until the element exists or the condition is true) and
// {"do": "node", "label", "event"?} (taps, or with "dbltap" expands, the
// Explore graph's node with that label). Steps that take "ms" wait that long
// after acting.
//
// Selectors: "css >> text" is the first visible match whose text contains
// text. A selector starting with "report:" is inside the run page's report,
// a sandboxed iframe that Chrome runs in a process of its own; "eval" and
// "waitFor" with "js" take "frame": true for the same.
//
// "scale" sets the device pixel ratio. A drawn cursor glides to each element
// in "move" ms (default 650) before it is clicked, so viewers can follow along.
// "settle" (ms, default 1200) is how long the first page runs before recording
// starts: long enough for the rail's Crown W to finish drawing itself in
// (about 2.8 s), so a GIF doesn't open on the intro. "startAt" names a link on
// that first page to open before recording (a.rr-link: the newest run on
// Home), and "startSettle" how long that page gets. "colorScheme" ("dark" by
// default) is the emulated prefers-color-scheme. "gif" holds make_gif.py's
// options for this scenario (make_gif.py --scenario reads them).
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const [scenarioPath, outDir] = process.argv.slice(2);
const sc = JSON.parse(readFileSync(scenarioPath, "utf8"));
if (process.argv[4]) sc.url = process.argv[4];
const chrome = sc.chrome || process.env.CHROME || "C:/Program Files/Google/Chrome/Application/chrome.exe";
mkdirSync(outDir, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "pw-rec-"));
const port = 9400 + Math.floor(Math.random() * 400);
const proc = spawn(chrome, ["--headless=new", "--disable-gpu", `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`, "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let target;
for (let i = 0; i < 60 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === "page"); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0;
const pending = new Map();
// The report on a run page is a sandboxed iframe, which Chrome runs in a
// process of its own: its session (from auto-attach) is kept here.
const frames = new Map();
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  if (d.method === "Target.attachedToTarget" && d.params.targetInfo.type === "iframe") {
    frames.set(d.params.sessionId, d.params.targetInfo.url);
    send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: sc.colorScheme || "dark" }] }, d.params.sessionId);
  }
  if (d.method === "Target.detachedFromTarget") frames.delete(d.params.sessionId);
});
const send = (method, params = {}, sessionId) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params, ...(sessionId ? { sessionId } : {}) })); });
const evaluate = async (js) => (await send("Runtime.evaluate", { expression: js, awaitPromise: true, returnByValue: true })).result?.result?.value;

await send("Emulation.setDeviceMetricsOverride", { width: sc.width, height: sc.height, deviceScaleFactor: sc.scale || 1, mobile: false });
await send("Page.setBypassCSP", { enabled: true });
// Downloads (the run page's Download menu) go into the throwaway profile,
// never the Downloads folder of the account recording.
await send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: join(profile, "downloads"), eventsEnabled: false });
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: sc.colorScheme || "dark" }] });
await send("Page.enable");
// Copy buttons work as in a focused window (headless Chrome refuses the
// clipboard otherwise, and the page says it couldn't copy).
await send("Emulation.setFocusEmulationEnabled", { enabled: true });
try {
  await send("Browser.grantPermissions", { origin: new URL(sc.url).origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
} catch {}
await send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });

// The drawn cursor: an arrow that glides between targets in "move" ms.
const MOVE = sc.move ?? 650;
const CURSOR = `(() => {
  if (document.getElementById("__cur")) return;
  const c = document.createElement("div");
  c.id = "__cur";
  c.innerHTML = '<svg width="22" height="26" viewBox="0 0 22 26"><path d="M2 2 L2 21 L7 16 L11 24 L14.5 22.5 L10.5 14.8 L17.5 14.8 Z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg>';
  Object.assign(c.style, { position: "fixed", left: (window.__curX || ${sc.width / 2}) + "px", top: (window.__curY || ${sc.height / 2}) + "px",
    zIndex: 2147483647, pointerEvents: "none", transition: "left ${MOVE * 0.85}ms cubic-bezier(.4,0,.2,1), top ${MOVE * 0.85}ms cubic-bezier(.4,0,.2,1)",
    filter: "drop-shadow(0 2px 3px rgba(0,0,0,.5))" });
  document.documentElement.appendChild(c);
})()`;
// A selector that starts with "report:" is inside the run page's report
// (the sandboxed #report-frame); the rest are in the page itself.
const parse = (sel) => (sel.startsWith("report:") ? { f: true, s: sel.slice(7).trim() } : { f: false, s: sel });
// "sel >> text" is the first element matching sel whose text contains text.
const Q = (s) => {
  const [css, text] = s.split(" >> ");
  return text === undefined
    ? `document.querySelector(${JSON.stringify(css)})`
    : `[...document.querySelectorAll(${JSON.stringify(css)})].find((e) => e.offsetParent && e.textContent.includes(${JSON.stringify(text)}))`;
};
let worldKey = null, worldId = null;
const frameCtx = async () => {
  const walk = (n) => (n.frame.url.includes("/report") && n.frame.parentId ? n.frame : (n.childFrames || []).map(walk).find(Boolean));
  const fr = walk((await send("Page.getFrameTree")).result.frameTree);
  if (!fr) return null;
  const key = `${fr.id}:${fr.loaderId}`;
  if (key !== worldKey) {
    worldId = (await send("Page.createIsolatedWorld", { frameId: fr.id, worldName: "rec", grantUniveralAccess: true })).result?.executionContextId;
    worldKey = key;
  }
  return worldId;
};
const run = async (f, js) => {
  if (!f) return evaluate(js);
  const params = { expression: js, awaitPromise: true, returnByValue: true };
  // The newest attached iframe is the report on the page shown now.
  let sid = null;
  for (const k of frames.keys()) {
    const href = (await send("Runtime.evaluate", { expression: "location.href", returnByValue: true }, k)).result?.result?.value || "";
    if (href.includes("/report")) sid = k;
  }
  if (sid) return (await send("Runtime.evaluate", params, sid)).result?.result?.value;
  const ctx = await frameCtx();
  if (!ctx) return null;
  return (await send("Runtime.evaluate", { ...params, contextId: ctx })).result?.result?.value;
};
// Waits up to ms for js (a condition) to be true.
const until = async (f, js, ms) => {
  const end = Date.now() + ms;
  for (;;) {
    if (await run(f, js).catch(() => false)) return true;
    if (Date.now() > end) return false;
    await sleep(200);
  }
};
const moveTo = async (sel) => {
  const { f, s } = parse(sel);
  if (!(await until(f, `!!${Q(s)}`, 8000))) throw new Error(`no element for ${sel}`);
  const r = await run(f, `(() => { const b = ${Q(s)}.getBoundingClientRect(); return [b.left, b.top, b.width, b.height]; })()`);
  const o = f ? await evaluate(`(() => { const b = document.getElementById("report-frame").getBoundingClientRect(); return [b.left, b.top]; })()`) : [0, 0];
  const x = o[0] + r[0] + Math.min(r[2] / 2, 60), y = o[1] + r[1] + r[3] / 2;
  await evaluate(`(() => { ${CURSOR}; const c = document.getElementById("__cur"); c.style.left = ${x} + "px"; c.style.top = ${y} + "px";
    window.__curX = ${x}; window.__curY = ${y}; })()`);
  await sleep(MOVE);
  return [x, y];
};
const pulse = () => evaluate(`(() => { const c = document.getElementById("__cur"); if (!c) return;
  c.animate([{ transform: "scale(1)" }, { transform: "scale(.82)" }, { transform: "scale(1)" }], { duration: 220 }); })()`);


await send("Page.navigate", { url: sc.url });
await sleep(sc.settle ?? 1200);
if (sc.startAt) {
  // Start on the page a link of the first page goes to (the newest run on
  // Home: its address changes with every workspace).
  const href = await evaluate(`${Q(sc.startAt)}?.href`);
  if (!href) throw new Error(`no link for ${sc.startAt}`);
  await send("Page.navigate", { url: href });
  await sleep(sc.startSettle ?? 3000);
}
await evaluate(CURSOR);
// Frames come from Chrome's screencast: it pushes a frame whenever the page
// changes, including while a new page loads (polling for screenshots stalls
// then and misses fast transitions). The last frame is repeated at the end
// so still moments keep their length.
let frame = 0;
const started = Date.now();
const times = [];
let lastData = null;
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.method !== "Page.screencastFrame") return;
  lastData = d.params.data;
  writeFileSync(join(outDir, `f${String(frame).padStart(5, "0")}.png`), Buffer.from(lastData, "base64"));
  times.push(Date.now() - started);
  frame++;
  ws.send(JSON.stringify({ id: ++id, method: "Page.screencastFrameAck", params: { sessionId: d.params.sessionId } }));
});
await send("Page.startScreencast", { format: "png", maxWidth: sc.width, maxHeight: sc.height, everyNthFrame: 1 });

for (const st of sc.steps) {
  const { f, s } = st.sel ? parse(st.sel) : { f: !!st.frame, s: null };
  switch (st.do) {
    case "wait": await sleep(st.ms); break;
    case "waitFor":
      // Until an element exists, or a condition ("js") is true.
      if (!(await until(f, st.js || `!!${Q(s)}`, st.timeout ?? 30000))) throw new Error(`timed out waiting for ${st.sel || st.js}`);
      await sleep(st.ms ?? 0);
      break;
    case "goto": await send("Page.navigate", { url: st.url }); await sleep(st.ms ?? 1200); await evaluate(CURSOR); break;
    case "hover": await moveTo(st.sel); await sleep(st.ms ?? 0); break;
    case "click":
      await moveTo(st.sel);
      await pulse();
      await sleep(120);
      await run(f, `${Q(s)}.click()`);
      await sleep(st.ms ?? 500);
      await evaluate(CURSOR);
      break;
    case "dblclick":
      await moveTo(st.sel);
      await pulse();
      await sleep(90);
      await pulse();
      await run(f, `(() => { const e = ${Q(s)};
        const r = e.getBoundingClientRect(), o = { bubbles: true, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2 };
        e.dispatchEvent(new MouseEvent("dblclick", o)); })()`);
      await sleep(st.ms ?? 500);
      break;
    case "node": {
      // A node of the Explore graph (Cytoscape draws on a canvas): the
      // cursor goes to the node with this label, then "tap" or "dbltap".
      const find = `(() => { const c = document.getElementById("xp-cy"), cy = c && c._cyreg && c._cyreg.cy;
        return cy && cy.nodes().filter((n) => n.data("label") === ${JSON.stringify(st.label)})[0]; })()`;
      if (!(await until(false, `!!${find}`, 8000))) throw new Error(`no node ${st.label}`);
      const [x, y] = await evaluate(`(() => { const n = ${find}, b = document.getElementById("xp-cy").getBoundingClientRect(), p = n.renderedPosition();
        return [b.left + p.x, b.top + p.y]; })()`);
      await evaluate(`(() => { ${CURSOR}; const c = document.getElementById("__cur"); c.style.left = ${x} + "px"; c.style.top = ${y} + "px";
        window.__curX = ${x}; window.__curY = ${y}; })()`);
      await sleep(MOVE);
      await pulse();
      if (st.event === "dbltap") { await sleep(90); await pulse(); }
      await sleep(120);
      await evaluate(`${find}.emit(${JSON.stringify(st.event || "tap")})`);
      await sleep(st.ms ?? 500);
      break;
    }
    case "type": {
      await moveTo(st.sel);
      await run(f, `${Q(s)}.focus()`);
      if (st.clear) await run(f, `(() => { const e = ${Q(s)}; e.value = ""; e.dispatchEvent(new Event("input", { bubbles: true })); })()`);
      const text = st.env ? process.env[st.env] : st.text;
      if (text == null) throw new Error(`${st.env} is not set`);
      for (const ch of text) {
        await run(f, `(() => { const e = ${Q(s)};
          const set = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(e), "value").set;
          set.call(e, e.value + ${JSON.stringify(ch)});
          e.dispatchEvent(new InputEvent("input", { bubbles: true, data: ${JSON.stringify(ch)} })); })()`);
        await sleep(st.delay ?? 45);
      }
      await run(f, `${Q(s)}.dispatchEvent(new Event("change", { bubbles: true }))`);
      await sleep(st.ms ?? 400);
      break;
    }
    case "select":
      await moveTo(st.sel);
      await pulse();
      await run(f, `(() => { const e = ${Q(s)}; e.value = ${JSON.stringify(st.value)};
        e.dispatchEvent(new Event("input", { bubbles: true })); e.dispatchEvent(new Event("change", { bubbles: true })); })()`);
      await sleep(st.ms ?? 500);
      break;
    case "upload": {
      const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
      const doc = await send("DOM.getDocument", { depth: 0 });
      const q = await send("DOM.querySelector", { nodeId: doc.result.root.nodeId, selector: s });
      await send("DOM.setFileInputFiles", { nodeId: q.result.nodeId, files: st.files.map((p) => resolve(repo, p)) });
      await sleep(st.ms ?? 800);
      break;
    }
    case "scroll":
      await run(f, `${Q(s)}.scrollIntoView({ behavior: "smooth", block: ${JSON.stringify(st.block || "start")} })`);
      await sleep(st.ms ?? 900);
      break;
    case "scrollBy":
      await run(f, `window.scrollBy({ top: ${st.y}, behavior: "smooth" })`);
      await sleep(st.ms ?? 900);
      break;
    case "eval": await run(f, st.js); await sleep(st.ms ?? 300); break;
    case "shot": {
      // A still image of one element (e.g. a terminal window), at the
      // scenario's scale, written to st.out.
      await evaluate(`document.getElementById("__cur")?.remove()`);
      const r = await evaluate(`(() => { const b = ${Q(s)}.getBoundingClientRect();
        return { x: b.left + scrollX, y: b.top + scrollY, width: b.width, height: b.height }; })()`);
      const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { ...r, scale: 1 } });
      writeFileSync(st.out, Buffer.from(shot.result.data, "base64"));
      break;
    }
    default: throw new Error(`unknown step ${st.do}`);
  }
}
await send("Page.stopScreencast");
await sleep(200);
if (lastData) {
  // Close the timeline: a final copy of the last frame at the end time.
  writeFileSync(join(outDir, `f${String(frame).padStart(5, "0")}.png`), Buffer.from(lastData, "base64"));
  times.push(Date.now() - started);
  frame++;
}
writeFileSync(join(outDir, "times.json"), JSON.stringify(times));
ws.close();
proc.kill();
try { rmSync(profile, { recursive: true, force: true }); } catch {}
console.log(`${frame} frames in ${((Date.now() - started) / 1000).toFixed(1)} s`);
process.exit(0);
