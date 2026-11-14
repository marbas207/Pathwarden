// The Collect page's progress view: progressView in
// src/assets/collect.js, cut out by its markers and run on job states as
// the job API gives them. Run with `node --test` (tests/page_scripts.rs
// runs it under cargo test).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const JS = readFileSync(new URL("../../src/assets/collect.js", import.meta.url), "utf8");
const start = JS.indexOf("  var progressView = (function");
const end = JS.indexOf("  // ---- end progressView", start);
assert.ok(start >= 0 && end > start, "collect.js has progressView between its markers");
const progressView = new Function(JS.slice(start, end) + "\nreturn progressView;")();

const n = (x) => x.toLocaleString();
const NOW = 1_800_000_000;

/** A collecting job of `states` (one letter a domain: d done, f failed, a active, w waiting). */
function job(states, { status = {}, elapsed = 600, collect = {} } = {}) {
  const NAMES = ["CONTOSO.COM", "FABRIKAM.COM", "ADVENTURE.LOCAL", "WINGTIP.COM", "TAILSPIN.LOCAL",
    "LITWARE.ORG", "NORTHWIND.COM", "WOODGROVE.COM", "PROSEWARE.COM", "FOURTHCOFFEE.COM",
    "LUCERNE.LOCAL", "TREYRESEARCH.NET", "CONTOSO.LOCAL", "ALPINE.LOCAL", "COHO.LOCAL"];
  const ST = { d: "done", f: "failed", a: "active", w: "waiting" };
  const TEXT = { d: "Done · 4 min", f: "Couldn't reach a domain controller.", a: "Collecting", w: "Waiting" };
  return {
    status: "collecting",
    started_at: NOW - elapsed,
    collect: {
      domain: "CONTOSO.COM",
      domains: [...states].map((s, i) => ({ name: NAMES[i], state: ST[s], text: TEXT[s] })),
      status: {
        step: 2, steps: 6, phase: "Reading the directory", percent: 40, eta_secs: 531,
        done: 20389, total: 50000, unit: "objects", objects: {}, expected: {}, ...status,
      },
      ...collect,
    },
  };
}

test("fifteen domains: the title, where it is and the time left in all", () => {
  const p = progressView(job("dfawwwwwwwwwwww"), NOW);
  assert.equal(p.title, "Collecting 15 domains");
  // 2 finished in 600 s with the third 40% in: 250 s a domain; 12 waiting
  // and the current one's own 531 s.
  assert.equal(p.sub, "3 of 15 · about 59 min left");
  assert.equal(p.panelName, "ADVENTURE.LOCAL");
  assert.equal(p.phase, "Reading the directory");
  assert.equal(p.step, "Step 2 of 6");
});

test("the time left in all waits for a domain to finish", () => {
  const p = progressView(job("awwwwwwwwwwwwww"), NOW);
  assert.equal(p.sub, "1 of 15");
});

test("finished, skipped and waiting domains fold into one row each", () => {
  const p = progressView(job("ddfawwwwwwwwwww"), NOW);
  assert.equal(p.groups.done.head, "2 done");
  assert.equal(p.groups.done.text, "CONTOSO.COM, FABRIKAM.COM");
  assert.deepEqual(p.groups.done.rows[0], { name: "CONTOSO.COM", text: "Done · 4 min" });
  assert.equal(p.groups.done.more, true);
  assert.equal(p.groups.skipped.head, "1 skipped");
  // One skipped: its reason in the row, nothing more behind Show.
  assert.equal(p.groups.skipped.text, "ADVENTURE.LOCAL: Couldn't reach a domain controller.");
  assert.equal(p.groups.skipped.more, false);
  assert.equal(p.groups.waiting.head, "11 waiting");
  assert.equal(p.groups.waiting.text, "TAILSPIN.LOCAL, LITWARE.ORG, NORTHWIND.COM and 8 more");
  assert.equal(p.groups.waiting.rows.length, 11);
  assert.equal(p.groups.waiting.more, true);
  // The current domain is the panel, in none of the folded rows.
  assert.equal(p.panelName, "WINGTIP.COM");
  for (const g of Object.values(p.groups)) assert.ok(!g.rows.some((r) => r.name === "WINGTIP.COM"));
});

test("several skipped: their names, the reasons behind Show", () => {
  const p = progressView(job("ffaw"), NOW);
  assert.equal(p.groups.skipped.head, "2 skipped");
  assert.equal(p.groups.skipped.text, "CONTOSO.COM, FABRIKAM.COM");
  assert.equal(p.groups.skipped.more, true);
  assert.equal(p.groups.done, null);
  assert.equal(p.groups.waiting.text, "WINGTIP.COM");
  assert.equal(p.groups.waiting.more, false);
});

test("one domain: its name in the title, no rows, no name in the panel", () => {
  const j = job("");
  delete j.collect.domains;
  const p = progressView(j, NOW);
  assert.equal(p.title, "Collecting CONTOSO.COM");
  assert.equal(p.sub, "");
  assert.equal(p.multi, false);
  assert.equal(p.panelName, "");
  assert.deepEqual(p.groups, { done: null, skipped: null, waiting: null });
  assert.equal(p.phase, "Reading the directory");
});

test("the counts: the main kinds in one line, all of them behind All counts", () => {
  const p = progressView(job("", {
    status: {
      objects: { users: 20389, computers: 2656, groups: 8486, gpos: 1714, ous: 312, containers: 90, certtemplates: 33 },
      expected: { users: 21000 },
    },
  }), NOW);
  assert.deepEqual(p.counts.line, [
    { n: n(20389), word: "users", title: "of ~" + n(21000) },
    { n: n(2656), word: "computers", title: "" },
    { n: n(8486), word: "groups", title: "" },
    { n: n(1714), word: "GPOs", title: "" },
  ]);
  // Read counts leave out containers until the written ones.
  assert.deepEqual(p.counts.tiles.map((t) => t.dt),
    ["Users", "Computers", "Groups", "OUs", "GPOs", "Certificate templates"]);
  assert.equal(p.counts.more, true);
  assert.equal(p.counts.readSoFar, true);
});

test("a collector that only counts: the totals in the line, no All counts", () => {
  const p = progressView(job("", { status: { rate: 312 } }), NOW);
  assert.deepEqual(p.counts.line.map((l) => l.word), ["objects", "expected", "per second"]);
  assert.equal(p.counts.more, false);
  assert.equal(p.counts.readSoFar, false);
});

test("the checklist is one line while collecting and opens out after", () => {
  assert.equal(progressView(job("dawww"), NOW).stepsFolded, true);
  const p = progressView({ ...job("ddddd"), status: "running", phase: "reading" }, NOW);
  assert.equal(p.stepsFolded, false);
  assert.equal(p.title, "Analyzing");
  assert.equal(p.phase, "Collection finished");
  assert.equal(p.panelName, "");
  assert.equal(p.groups.done.head, "5 done");
});

test("collected, the panel goes; while collecting it stays", () => {
  assert.equal(progressView(job("dawww"), NOW).panel, true);
  assert.equal(progressView({ ...job("ddddd"), status: "running", phase: "reading" }, NOW).panel, false);
});

test("the notes: each message once, with the domains it was about, in order", () => {
  const W = {
    ldaps: "LDAPS certificates were not checked, so a machine in the middle could read or change the collection.",
    smb: "SMB signing was not required, so a machine in the middle could change what computers answered.",
    dc: "This collection read only the domain controllers, so it has no sessions or local groups.",
  };
  const warnings = [
    `CONTOSO.COM: ${W.ldaps}`, `CONTOSO.COM: ${W.smb}`, W.dc,
    `FABRIKAM.COM: ${W.ldaps}`, `FABRIKAM.COM: ${W.smb}`, `FABRIKAM.COM: ${W.smb}`,
    `ADVENTURE.LOCAL: ${W.ldaps}`, W.dc,
  ];
  const p = progressView(job("ddd", { collect: { warnings } }), NOW);
  assert.deepEqual(p.notes, [
    { text: W.ldaps, domains: ["CONTOSO.COM", "FABRIKAM.COM", "ADVENTURE.LOCAL"] },
    { text: W.smb, domains: ["CONTOSO.COM", "FABRIKAM.COM"] },
    { text: W.dc, domains: [] },
  ]);
});

test("no notes, and a colon in a sentence is not a domain", () => {
  assert.deepEqual(progressView(job("d"), NOW).notes, []);
  const t = "NTLM was allowed for computers: a computer without a Kerberos name got an NTLM response.";
  assert.deepEqual(progressView(job("d", { collect: { warnings: [t, 7, ""] } }), NOW).notes, [{ text: t, domains: [] }]);
});

test("the files analyzed with it are named in one row, while collecting and after", () => {
  // None: no row.
  assert.equal(progressView(job("a"), NOW).also, "");
  const also = ["contoso-azurehound.json", "taskhound_opengraph.json"];
  assert.equal(
    progressView(job("a", { collect: { also } }), NOW).also,
    "contoso-azurehound.json, taskhound_opengraph.json",
  );
  const analyzing = { ...job("d", { collect: { also } }), status: "running", phase: "reading" };
  assert.equal(progressView(analyzing, NOW).also, "contoso-azurehound.json, taskhound_opengraph.json");
  // Anything but names is left out.
  assert.equal(progressView(job("a", { collect: { also: [null, 3, "", "x.json"] } }), NOW).also, "x.json");
});
