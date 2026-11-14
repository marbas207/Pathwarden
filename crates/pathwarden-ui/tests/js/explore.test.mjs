// Explore's graph script (src/assets/explore.js): bundles (more than 3
// edges of one kind at one end lose their labels, and nothing on the
// object counts them) and the edge styles. The part from the colours to the styles
// is cut out of explore.js and run with a stand-in for the page's theme.
// Run with `node --test`; tests/page_scripts.rs runs it under cargo test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const EXPLORE = readFileSync(new URL("../../src/assets/explore.js", import.meta.url), "utf8");

function cut(start, end) {
  const a = EXPLORE.indexOf(start);
  assert.ok(a >= 0, `explore.js has no ${JSON.stringify(start)}`);
  const b = EXPLORE.indexOf(end, a);
  assert.ok(b > a, `explore.js has no ${JSON.stringify(end)} after it`);
  return EXPLORE.slice(a, b);
}

const LIGHT = { "--accent": "#6d28d9", "--accent2": "#15803d", "--page": "#ffffff", "--ink": "#111111" };
const DARK = { "--accent": "#a78bfa", "--accent2": "#4ade80", "--page": "#0b0b10", "--ink": "#eeeeee" };

/** The cut-out part with the theme `vars`: {bundleEdges, styles}. */
function load(vars) {
  const document = { documentElement: {} };
  const getComputedStyle = () => ({ getPropertyValue: (n) => vars[n] || "#888888" });
  return new Function(
    "document",
    "getComputedStyle",
    cut("  function hex(c)", "  // ------------------------------------------------------------ state") +
      "\nreturn { bundleEdges: bundleEdges, styles: styles };",
  )(document, getComputedStyle);
}

const { bundleEdges } = load(LIGHT);

/** `n` edges of `kind` from n1.. into `hub`. */
function into(hub, kind, n, from = 1) {
  return Array.from({ length: n }, (_, i) => ({ id: `e${from + i}-${hub}-${kind}`, s: `n${from + i}`, t: hub, k: kind }));
}

test("more than 3 edges of one kind into one object are a bundle", () => {
  const edges = into("hub", "MemberOf", 4);
  const b = bundleEdges(edges);
  for (const e of edges) assert.ok(b.edges[e.id], `${e.id} is bundled`);
});

test("3 edges of one kind keep their labels", () => {
  const b = bundleEdges(into("hub", "MemberOf", 3));
  assert.deepEqual(b.edges, {});
});

test("kinds are counted apart, and outgoing bundles too", () => {
  const edges = [
    ...into("hub", "MemberOf", 40),
    ...into("hub", "AdminTo", 3, 100),
    ...Array.from({ length: 5 }, (_, i) => ({ id: `o${i}`, s: "hub", t: `m${i}`, k: "GenericAll" })),
    ...into("hub", "HasSession", 1200, 200),
  ];
  const b = bundleEdges(edges);
  assert.deepEqual(b.edges["e1-hub-MemberOf"], ["in hub MemberOf"]);
  assert.deepEqual(b.edges["e200-hub-HasSession"], ["in hub HasSession"]);
  assert.equal(b.edges["e100-hub-AdminTo"], undefined, "3 AdminTo keep their labels");
  assert.deepEqual(b.edges.o0, ["out hub GenericAll"]);
});

test("an edge in two bundles (both ends) knows both", () => {
  const edges = [
    ...into("hub", "MemberOf", 4),
    ...Array.from({ length: 3 }, (_, i) => ({ id: `x${i}`, s: "n1", t: `g${i}`, k: "MemberOf" })),
  ];
  const b = bundleEdges(edges);
  assert.deepEqual(b.edges["e1-hub-MemberOf"], ["in hub MemberOf", "out n1 MemberOf"]);
});

function rule(styles, selector) {
  const i = styles.findIndex((r) => r.selector === selector);
  assert.ok(i >= 0, `no ${selector} rule`);
  return { i, style: styles[i].style };
}

test("bundled edges have no label, but path, selected and hovered edges keep theirs", () => {
  const s = load(LIGHT).styles();
  const hidden = rule(s, "edge.bundled, edge.nolabel");
  const kept = rule(s, "edge.path, edge:selected, edge.hover");
  assert.equal(hidden.style["text-opacity"], 0);
  assert.equal(kept.style["text-opacity"], 1);
  assert.ok(kept.i > hidden.i, "the keep rule comes after (wins over) the bundle rule");
  // Nothing on the object counts its bundle: its label is its name alone.
  assert.ok(!s.some((r) => r.selector === "node.bundle"));
  assert.equal(rule(s, "node").style.label, "data(label)");
});

test("a hovered edge stands out in the accent colour, in both themes; its bundle fades", () => {
  for (const vars of [LIGHT, DARK]) {
    const s = load(vars).styles();
    const hover = rule(s, "edge.hover");
    assert.equal(hover.style.width, 3.5);
    assert.equal(hover.style["arrow-scale"], 1.8);
    assert.equal(hover.style["line-color"], vars["--accent"]);
    assert.equal(hover.style["target-arrow-color"], vars["--accent"]);
    assert.ok(hover.style["z-index"] > rule(s, "edge.path").style["z-index"]);
    // Last, so it wins over the path and selected looks.
    assert.equal(hover.i, s.length - 1);
    assert.equal(rule(s, "edge.fade").style.opacity, 0.4);
  }
});
