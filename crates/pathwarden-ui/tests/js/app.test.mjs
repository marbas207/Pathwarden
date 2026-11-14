// The parts of the page script (src/assets/app.js) that work without the
// server: zipDomains (the domains files read out of a chosen .zip) and the
// where/ask state machine (PathwardenWhere). Run with `node --test`
// (Node 20.12 or later, for File and DecompressionStream("deflate-raw");
// tests/page_scripts.rs runs it under cargo test). Each part is
// cut out of app.js by its markers and run with stand-ins for the page.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import zlib from "node:zlib";

const APP = readFileSync(new URL("../../src/assets/app.js", import.meta.url), "utf8");

/** The text of app.js from `start` up to (not including) `end`. */
function cut(start, end) {
  const a = APP.indexOf(start);
  assert.ok(a >= 0, `app.js has no ${JSON.stringify(start)}`);
  const b = APP.indexOf(end, a);
  assert.ok(b > a, `app.js has no ${JSON.stringify(end)} after it`);
  return APP.slice(a, b);
}

// ------------------------------------------------------------ zipDomains

const zipDomains = new Function(
  cut("  var DOMAINS_MAX", "  window.PathwardenZipDomains") + "\nreturn zipDomains;",
)();

/**
 * A .zip of `entries` ({name, data, method: 0 stored or 8 deflated, usize:
 * the size its headers declare}). `zip64`: the end record points to a ZIP64
 * directory, as a large archive's does.
 */
function zip(entries, { zip64 = false } = {}) {
  const parts = [];
  const central = [];
  let off = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name);
    const raw = Buffer.from(e.data);
    const data = e.method === 8 ? zlib.deflateRawSync(raw) : raw;
    const usize = e.usize ?? raw.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(e.method, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(usize, 22);
    local.writeUInt16LE(name.length, 26);
    parts.push(local, name, data);
    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0);
    dir.writeUInt16LE(e.method, 10);
    dir.writeUInt32LE(data.length, 20);
    dir.writeUInt32LE(usize, 24);
    dir.writeUInt16LE(name.length, 28);
    dir.writeUInt32LE(off, 42);
    central.push(dir, name);
    off += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(zip64 ? 0xffffffff : off, 16);
  return new File([...parts, cd, end], "collection.zip");
}

const DOMAINS = JSON.stringify({ data: [{ Properties: { name: "ESSOS.LOCAL" } }] });
const texts = async (blobs) => Promise.all(blobs.map((b) => b.text()));

test("zipDomains reads stored and deflated domains files only", async () => {
  const file = zip([
    { name: "20261001_users.json", data: "{}".repeat(1000), method: 8 },
    { name: "20261001_domains.json", data: DOMAINS, method: 0 },
    { name: "sub/20261002_Domains.json", data: DOMAINS, method: 8 },
  ]);
  assert.deepEqual(await texts(await zipDomains(file)), [DOMAINS, DOMAINS]);
});

test("zipDomains finds nothing without domains files", async () => {
  const file = zip([{ name: "20261001_users.json", data: "{}", method: 8 }]);
  assert.deepEqual(await zipDomains(file), []);
});

test("zipDomains leaves ZIP64 archives and other files to the server", async () => {
  const file = zip([{ name: "x_domains.json", data: DOMAINS, method: 0 }], { zip64: true });
  assert.deepEqual(await zipDomains(file), []);
  assert.deepEqual(await zipDomains(new File(["not a zip"], "x.zip")), []);
});

test("zipDomains stops inflating an entry larger than its header says", async () => {
  // 9 MB of spaces deflate to a few KB; the header claims 100 bytes.
  const big = " ".repeat(9 * 1024 * 1024);
  const file = zip([
    { name: "a_domains.json", data: big, method: 8, usize: 100 },
    { name: "b_domains.json", data: big, method: 0, usize: 100 },
    { name: "c_domains.json", data: DOMAINS, method: 8 },
  ]);
  // Count what each inflation delivers, and whether it was cancelled: the
  // bound is on memory, not only on the result.
  const Real = globalThis.DecompressionStream;
  const streams = [];
  globalThis.DecompressionStream = class {
    constructor(format) {
      const real = new Real(format);
      const seen = { bytes: 0, cancelled: false };
      streams.push(seen);
      const reader = real.readable.getReader();
      this.writable = real.writable;
      this.readable = new ReadableStream(
        {
          async pull(c) {
            const r = await reader.read();
            if (r.done) return c.close();
            seen.bytes += r.value.length;
            c.enqueue(r.value);
          },
          cancel(why) {
            seen.cancelled = true;
            return reader.cancel(why);
          },
        },
        { highWaterMark: 0 },
      );
    }
  };
  try {
    assert.deepEqual(await texts(await zipDomains(file)), [DOMAINS]);
  } finally {
    globalThis.DecompressionStream = Real;
  }
  const MAX = 8 * 1024 * 1024;
  const [a, c] = streams;
  assert.equal(streams.length, 2, "the stored entry is never inflated");
  assert.ok(a.cancelled, "the oversized entry's inflation is cancelled");
  assert.ok(a.bytes > MAX && a.bytes <= MAX + 1024 * 1024, `inflated ${a.bytes} bytes`);
  assert.ok(!c.cancelled && c.bytes === DOMAINS.length);
});

// ------------------------------------------------- the where/ask state

/** A stand-in element: attributes, `hidden`, listeners, and the elements
 * the script looks for. */
class El {
  constructor(props = {}) {
    Object.assign(this, { hidden: false, checked: false, value: "", attrs: {}, on: {} }, props);
  }
  getAttribute(n) {
    return n in this.attrs ? this.attrs[n] : null;
  }
  setAttribute(n, v) {
    this.attrs[n] = String(v);
  }
  removeAttribute(n) {
    delete this.attrs[n];
  }
  addEventListener(type, f) {
    (this.on[type] ||= []).push(f);
  }
  fire(type) {
    (this.on[type] || []).forEach((f) => f({ target: this }));
  }
  focus() {}
  closest() {
    return this.label;
  }
}

/** The elements of a rendered block (env_where.rs), by its `html`. */
function block(html) {
  const radio = (value, checked) => new El({ value, checked });
  const els = { radios: [], names: [] };
  if (html === "match" || html === "ask") {
    const goad = radio("env:goad-lab", html === "match");
    const other = radio("env:other", false);
    const fresh = radio("new", false);
    const name = new El({ value: "" });
    fresh.label = { querySelector: (s) => (s.includes("ew-name") ? name : fresh) };
    name.label = fresh.label;
    els.radios = [goad, other, fresh];
    els.names = [name];
    els.cards = new El({ hidden: html === "match" });
    if (html === "match") {
      els.line = new El();
      els.hint = new El();
      els.open = new El();
    }
  }
  return els;
}

/** The box the script drives: setting innerHTML swaps in that block. */
class Box extends El {
  constructor(html) {
    super();
    this.innerHTML = html;
  }
  set innerHTML(html) {
    this._html = html;
    this.els = block(html);
    const checked = () => this.els.radios.find((r) => r.checked) || null;
    this.els.cards &&
      (this.els.cards.querySelector = (s) => (s.includes(":checked") ? checked() : this.els.radios[0]));
  }
  get innerHTML() {
    return this._html;
  }
  querySelector(s) {
    const e = this.els;
    if (s === "[data-ew-change]") return e.open || null;
    if (s === "#ew-cards") return e.cards || null;
    if (s === "#ew-line") return e.line || null;
    if (s === "#ew-hint") return e.hint || null;
    if (s === "input[name=ew-pick]:checked") return e.radios.find((r) => r.checked) || null;
    if (s === "input[name=ew-pick]") return e.radios[0] || null;
    return null;
  }
  querySelectorAll(s) {
    if (s === "input[name=ew-pick]") return this.els.radios;
    if (s === "input[name=ew-name]") return this.els.names;
    return [];
  }
}

const whereSrc = cut("  window.PathwardenWhere = function", "\n\n  // The collector's domains files");

/** PathwardenWhere on a fresh box, with `fetch` answering from `answers`
 * (in order; each {json} or {fail}, released when its `gate` resolves). */
function where(answers) {
  const window = {};
  const toasts = [];
  const calls = [];
  const fetch = () => {
    const a = answers[calls.length];
    calls.push(a);
    return (a.gate || Promise.resolve()).then(() =>
      a.fail
        ? Promise.reject(new Error(a.fail))
        : { ok: true, text: () => Promise.resolve(JSON.stringify(a.json)) },
    );
  };
  new Function("window", "$", "localize", "toast", "fetch", whereSrc)(
    window,
    () => null,
    () => {},
    (m) => toasts.push(m),
    fetch,
  );
  const box = new Box("initial");
  box.setAttribute("data-state", "unknown");
  let changes = 0;
  const w = window.PathwardenWhere(box, () => changes++);
  return { w, box, toasts, changes: () => changes };
}

test("a block nobody changed lets the data decide", () => {
  const { w } = where([]);
  assert.deepEqual(w.choice(), {});
});

test("a match is the page's own choice until the user changes it", async () => {
  const { w, box } = where([{ json: { state: "match", html: "match" } }]);
  const loading = w.load(null, null);
  assert.equal(box.getAttribute("data-state"), "loading");
  assert.equal(w.choice(), null, "Start waits while it loads");
  await loading;
  assert.equal(box.getAttribute("data-state"), "match");
  assert.deepEqual(w.choice(), { env: "goad-lab", env_auto: "1" });
  // change: the cards open, the line hides, the pick is the user's.
  box.els.open.fire("click");
  assert.ok(!box.els.cards.hidden && box.els.line.hidden && box.els.hint.hidden);
  assert.equal(box.getAttribute("data-changed"), "1");
  assert.deepEqual(w.choice(), { env: "goad-lab", env_auto: "0" });
  // New environment needs a name; typing one picks it.
  box.els.radios[0].checked = false;
  box.els.radios[2].checked = true;
  assert.equal(w.choice(), null);
  box.els.radios[2].checked = false;
  box.els.names[0].value = " Lab ";
  box.els.names[0].fire("input");
  assert.ok(box.els.radios[2].checked);
  assert.deepEqual(w.choice(), { new_env: "Lab", env_auto: "0" });
});

test("a question waits for a pick", async () => {
  const { w, box } = where([{ json: { state: "ask", html: "ask" } }]);
  await w.load(null, null);
  assert.equal(w.choice(), null);
  box.els.radios[1].checked = true;
  assert.deepEqual(w.choice(), { env: "other", env_auto: "0" });
});

test("an older answer arriving last is dropped", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const { w, box } = where([
    { json: { state: "ask", html: "ask" }, gate },
    { json: { state: "match", html: "match" } },
  ]);
  const first = w.load(null, null);
  await w.load(null, null);
  release();
  await first;
  assert.equal(box.getAttribute("data-state"), "match");
  assert.equal(box.innerHTML, "match");
});

test("a failed read goes back to the start and says why", async () => {
  const { w, box, toasts } = where([{ fail: "Could not read the domains." }]);
  await w.load(null, null);
  assert.equal(box.getAttribute("data-state"), "unknown");
  assert.equal(box.innerHTML, "initial");
  assert.deepEqual(toasts, ["Could not read the domains."]);
  assert.deepEqual(w.choice(), {});
});

test("the answer shown so far is marked busy while a new one loads", async () => {
  const { w, box } = where([{ json: { state: "match", html: "match", found: "files" } }]);
  const found = new El({ innerHTML: "old files" });
  w.busy(found);
  assert.equal(box.getAttribute("data-state"), "loading");
  assert.equal(box.getAttribute("aria-busy"), "true");
  assert.equal(found.getAttribute("aria-busy"), "true");
  const loading = w.load(null, found);
  assert.equal(found.getAttribute("aria-busy"), "true");
  await loading;
  assert.equal(box.getAttribute("aria-busy"), null);
  assert.equal(found.getAttribute("aria-busy"), null);
  assert.equal(found.innerHTML, "files");
  // A failed read and a reset clear it too.
  w.busy(found);
  w.reset(found);
  assert.equal(box.getAttribute("aria-busy"), null);
  assert.equal(found.getAttribute("aria-busy"), null);
});

test("reset forgets the answer and any load under way", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const { w, box } = where([{ json: { state: "match", html: "match" }, gate }]);
  const late = w.load(null, null);
  w.reset(null);
  release();
  await late;
  assert.equal(box.getAttribute("data-state"), "unknown");
  assert.equal(box.innerHTML, "initial");
});

// ------------------------------------------------------------ PathwardenTime

const T = new Function(
  cut("  var FORMS = {", "  // Local times in `root`") +
    "\nreturn { local: localTime, utc: utcTime, date: dateOnly };",
)();

test("times are US style", () => {
  const at = (s) => Date.parse(s) / 1000;
  // Midnight and noon, UTC.
  assert.equal(T.utc(at("2026-11-01T00:00:00Z")), "Nov 1, 2026, 12:00 AM UTC");
  assert.equal(T.utc(at("2026-11-01T12:00:00Z")), "Nov 1, 2026, 12:00 PM UTC");
  // A single-digit day; the date form has no zone label.
  assert.equal(T.utc(at("2026-03-07T21:07:00Z")), "Mar 7, 2026, 9:07 PM UTC");
  assert.equal(T.utc(at("2026-03-07T21:07:00Z"), "date"), "Mar 7, 2026");
  // A year boundary.
  assert.equal(T.utc(at("2026-12-31T23:59:59Z")), "Dec 31, 2026, 11:59 PM UTC");
  assert.equal(T.utc(at("2027-01-01T00:00:00Z")), "Jan 1, 2027, 12:00 AM UTC");
  // Local time: the same form, in this computer's zone.
  assert.match(T.local(at("2026-11-01T12:00:00Z")), /^[A-Z][a-z]{2} \d{1,2}, \d{4}, \d{1,2}:\d{2} [AP]M$/);
  assert.equal(T.local("x"), "");
});

test("a date alone keeps its day", () => {
  assert.equal(T.date("2027-01-01"), "Jan 1, 2027");
  // A time: its local day.
  const t = Date.parse("2026-10-22T23:59:59-02:00") / 1000;
  assert.equal(T.date("2026-10-22T23:59:59-02:00"), T.local(t, "date"));
  assert.equal(T.date("last Tuesday"), "last Tuesday");
  assert.equal(T.date(null), "");
});

// ------------------------------------------------------- PathwardenFiles
// The files chosen on Analyze and in the Collect page's "Analyze other
// data with it": which are taken, and the files of a dropped folder.

const Files = new Function(
  cut("  var PathwardenFiles = (function", "  window.PathwardenFiles = PathwardenFiles;") +
    "\nreturn PathwardenFiles;",
)();

test("only .zip and .json files are taken, each once", () => {
  const chosen = [];
  const f = (name, size = 10) => ({ name, size });
  const rejected = Files.take(
    [f("contoso-azurehound.json"), f("taskhound_opengraph.JSON", 4), f("notes.txt"), f("20261105_BloodHound.zip")],
    chosen,
  );
  assert.deepEqual(rejected, ["notes.txt"]);
  assert.deepEqual(chosen.map((c) => c.name), ["contoso-azurehound.json", "taskhound_opengraph.JSON", "20261105_BloodHound.zip"]);
  // The same file again (name and size) is not listed twice; another
  // file of the same name is.
  Files.take([f("contoso-azurehound.json"), f("contoso-azurehound.json", 99)], chosen);
  assert.equal(chosen.length, 4);
  assert.equal(Files.size(1536), "2 KB");
  assert.equal(Files.size(38.2 * (1 << 20)), "38.2 MB");
});

/** A dropped file, as webkitGetAsEntry gives it. */
function fileEntry(name) {
  return { isFile: true, isDirectory: false, name, file: (ok) => ok({ name, size: name.length }) };
}
/** A dropped folder: its entries come in batches, then an empty one. */
function dirEntry(name, children, batch = 2) {
  return {
    isFile: false, isDirectory: true, name,
    createReader() {
      let at = 0;
      return { readEntries(ok) { const b = children.slice(at, at + batch); at += batch; ok(b); } };
    },
  };
}
const item = (entry) => ({ kind: "file", webkitGetAsEntry: () => entry, getAsFile: () => ({ name: entry.name, size: 1 }) });

test("a dropped folder gives its collector files, in its folders too", async () => {
  const folder = dirEntry("contoso", [
    fileEntry("azurehound.json"),
    fileEntry("readme.txt"),
    dirEntry("opengraph", [fileEntry("taskhound_opengraph.json"), fileEntry("taskhound.log")]),
    fileEntry("20261105_BloodHound.zip"),
  ]);
  const got = await Files.dropped({ items: [item(folder), item(fileEntry("extra.txt"))], files: [] });
  // In a folder, only .zip and .json; a file dropped by itself is kept
  // (and refused when taken, with its name).
  assert.deepEqual(
    got.map((f) => f.name),
    ["azurehound.json", "taskhound_opengraph.json", "20261105_BloodHound.zip", "extra.txt"],
  );
});

test("dropped files without a folder are the drop's own list", async () => {
  const files = [{ name: "a.json", size: 1 }, { name: "b.zip", size: 2 }];
  const got = await Files.dropped({ items: files.map((f) => item(fileEntry(f.name))), files });
  assert.deepEqual(got, files);
  assert.deepEqual(await Files.dropped(null), []);
});
