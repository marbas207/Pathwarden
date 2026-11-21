// Pathwarden Explore: a run's graph in Cytoscape.js. Every query runs on the
// server (/api/runs/<id>/explore/...); this script draws the answers.
//
// Object names come from the directory and may hold markup: they are only
// ever set with textContent, or drawn by Cytoscape on a canvas as text.
(function () {
  "use strict";
  var root = document.getElementById("xp");
  if (!root || typeof cytoscape !== "function") return;

  var RUN = root.getAttribute("data-run");
  var API = "/api/runs/" + encodeURIComponent(RUN) + "/explore";
  var DENSE = 150;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function num(n) { return Number(n || 0).toLocaleString("en-US"); }
  function plural(n, one, many) { return num(n) + " " + (n === 1 ? one : many); }
  function toast(message) {
    var t = $("toast");
    if (!t) return;
    t.textContent = message;
    t.classList.remove("kept"); // app.js may have left a note's look
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.hidden = true; }, 5000);
  }
  function busy(on, text) {
    $("xp-busy").hidden = !on;
    if (text) $("xp-busy-text").textContent = text;
  }

  var reanalyze = false;
  function get(path, params) {
    var q = [];
    Object.keys(params || {}).forEach(function (k) {
      if (params[k] != null && params[k] !== "") q.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
    });
    var url = API + path + (q.length ? "?" + q.join("&") : "");
    return fetch(url, { credentials: "same-origin" }).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) {}
        if (!r.ok) {
          if (j && j.reanalyze) reanalyze = true;
          throw new Error((j && j.error) || "Explore couldn't load this. Reload the page.");
        }
        return j;
      });
    });
  }
  function fail(e) { busy(false); toast(e.message || String(e)); }

  // ------------------------------------------------------------ glyphs
  // The report's line icons (report.rs ICONS), drawn as node images.
  var GLYPHS = {
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    group: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.8 2.9-6 6.5-6s6.5 2.2 6.5 6"/><path d="M15.5 4.8a3.5 3.5 0 0 1 0 6.4M17.5 14.3c2.4.6 4 2.6 4 5.7"/>',
    computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    domain: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    policy: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 12h7M9 16h7"/>',
    cert: '<circle cx="12" cy="9" r="5"/><path d="M9 13.5 7.5 21l4.5-2.5 4.5 2.5-1.5-7.5"/>',
    object: '<rect x="4" y="4" width="16" height="16" rx="3"/>'
  };
  // Icons mapping packs may name (pack.rs ICONS; Font Awesome names), drawn
  // here in the same line style. Unknown names get the generic shape.
  var EXT_GLYPHS = {
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
    gears: '<circle cx="9" cy="10" r="3"/><path d="M9 3.5v2M9 14.5v2M2.5 10h2M13.5 10h2M4.4 5.4l1.4 1.4M12.2 13.2l1.4 1.4M4.4 14.6l1.4-1.4M12.2 6.8l1.4-1.4"/><circle cx="17" cy="17" r="2.2"/><path d="M17 13.3v1.5M17 19.2v1.5M13.3 17h1.5M19.2 17h1.5"/>',
    gear: '<circle cx="12" cy="12" r="3.2"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>',
    database: '<ellipse cx="12" cy="6" rx="7" ry="2.8"/><path d="M5 6v12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8V6M5 12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    sitemap: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
    "user-gear": '<circle cx="10" cy="8" r="4"/><path d="M3 21c0-4.2 3.1-7 7-7 1.3 0 2.5.3 3.5.9"/><circle cx="18" cy="17.5" r="2"/><path d="M18 13.8v1.7M18 19.5v1.7M14.3 17.5H16M20 17.5h1.7"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12 20 3M16.5 6.5l2.5 2.5M14 9l2 2"/>',
    cloud: '<path d="M7 18h10.5a4 4 0 0 0 .4-8A6 6 0 0 0 6.3 9.5 4.3 4.3 0 0 0 7 18z"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.8 2.9-6 6.5-6s6.5 2.2 6.5 6"/><path d="M15.5 4.8a3.5 3.5 0 0 1 0 6.4M17.5 14.3c2.4.6 4 2.6 4 5.7"/>',
    "user-shield": '<circle cx="9" cy="8" r="4"/><path d="M2.5 21c0-4.2 2.9-7 6.5-7 1 0 1.9.2 2.7.5"/><path d="M17.5 12.5 14 14v2.8c0 2.2 1.5 3.8 3.5 4.7 2-.9 3.5-2.5 3.5-4.7V14z"/>',
    lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    shield: '<path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6z"/>',
    terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M12.5 15H17"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    file: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/>',
    desktop: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "network-wired": '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2.5" y="16" width="6" height="5" rx="1"/><rect x="15.5" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5.5 16v-4h13v4"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2"/>',
    "id-card": '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M5.8 16c.5-1.6 1.7-2.5 3.2-2.5s2.7.9 3.2 2.5M14.5 10h4M14.5 13.5h3"/>',
    certificate: '<circle cx="12" cy="9" r="5"/><path d="M9 13.5 7.5 21l4.5-2.5 4.5 2.5-1.5-7.5"/>',
    box: '<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/>',
    cube: '<path d="M12 3 4 7.5v9L12 21l8-4.5v-9z"/><path d="M4 7.5 12 12l8-4.5M12 12v9"/>',
    circle: '<circle cx="12" cy="12" r="8"/>'
  };
  Object.keys(EXT_GLYPHS).forEach(function (k) { GLYPHS["x-" + k] = EXT_GLYPHS[k]; });

  // External (OpenGraph) kinds of this run, from /api/runs/{id}/explore:
  // label, icon, color (validated on the server and again here) and, for
  // relationship kinds, whether they are paths and which sources had them.
  var EXT = { nodes: {}, edges: {} };
  var hiddenSources = {};
  function extNode(kind) { return Object.prototype.hasOwnProperty.call(EXT.nodes, kind) ? EXT.nodes[kind] : null; }
  function extEdge(kind) { return Object.prototype.hasOwnProperty.call(EXT.edges, kind) ? EXT.edges[kind] : null; }
  function extColor(kind) {
    var k = extNode(kind);
    return k && /^#[0-9a-f]{3}([0-9a-f]{3})?$/i.test(k.color || "") ? hex(k.color) : null;
  }
  function kindLabel(kind) {
    var k = extNode(kind);
    return (k && k.label) || kind;
  }
  // Context only: an external kind that is not a path (no pack, an
  // untrusted pack, or a "(context)" twin).
  function isContext(kind) {
    var k = extEdge(kind);
    return !!k && !k.traversable;
  }
  function edgeHidden(kind) {
    var k = extEdge(kind);
    if (!k || !k.sources || !k.sources.length) return false;
    return k.sources.every(function (s) { return hiddenSources[s]; });
  }
  function glyphKey(n) {
    switch (n.kind) {
      case "User": return "user";
      case "Group": return "group";
      case "Computer": return n.server || n.dc ? "server" : "computer";
      case "Domain": return "domain";
      case "OU": case "Container": return "folder";
      case "GPO": return "policy";
      case "CertTemplate": case "EnterpriseCA": case "RootCA": case "AIACA": case "NTAuthStore": case "IssuancePolicy": return "cert";
      default:
        var k = extNode(n.kind);
        return k && k.icon && GLYPHS["x-" + k.icon] ? "x-" + k.icon : "object";
    }
  }
  var glyphCache = {};
  function glyph(key, color) {
    var k = key + color;
    if (!glyphCache[k]) {
      glyphCache[k] = "data:image/svg+xml;utf8," + encodeURIComponent(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="' + color +
        '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + GLYPHS[key] + "</svg>");
    }
    return glyphCache[k];
  }
  function kindIcon(n) {
    var img = el("img", "xp-kic");
    img.alt = "";
    img.src = glyph(glyphKey(n), extColor(n.kind) || colors().accent);
    return img;
  }

  // ------------------------------------------------------------ colors
  function hex(c) {
    c = (c || "").trim();
    if (/^#[0-9a-f]{3}$/i.test(c)) c = "#" + c[1] + c[1] + c[2] + c[2] + c[3] + c[3];
    return /^#[0-9a-f]{6}$/i.test(c) ? c : "#888888";
  }
  function mix(a, b, t) {
    a = hex(a); b = hex(b);
    var out = "#";
    for (var i = 1; i < 7; i += 2) {
      var v = Math.round(parseInt(a.substr(i, 2), 16) * (1 - t) + parseInt(b.substr(i, 2), 16) * t);
      out += ("0" + v.toString(16)).slice(-2);
    }
    return out;
  }
  function colors() {
    var cs = getComputedStyle(document.documentElement);
    var v = function (n) { return hex(cs.getPropertyValue(n)); };
    return {
      page: v("--page"), card: v("--card"), line: v("--line"), ink: v("--ink"), muted: v("--muted"),
      accent: v("--accent"), accent2: v("--accent2"), critical: v("--critical"), chip: v("--chip")
    };
  }

  // Edge labels stay readable at any zoom: their font grows as the graph
  // zooms out so they show at least EDGE_PX on screen, up to EDGE_MAX graph
  // pixels; past that, only path, selected and hovered edges keep a label.
  var EDGE_PX = 11, EDGE_MAX = 22;
  var edgeLabel = { size: EDGE_PX, all: true };

  // ------------------------------------------------------------ bundles
  // More than BUNDLE_MAX edges of one kind sharing an end (the same target,
  // or the same source) are a bundle. `edges`: [{id, s, t, k}], the edges
  // shown. Returns {edges: edge id -> the keys of its bundles}.
  var BUNDLE_MAX = 3;
  function bundleEdges(edges) {
    var groups = {}, order = [];
    edges.forEach(function (e) {
      [["in", e.t], ["out", e.s]].forEach(function (end) {
        var key = end[0] + " " + end[1] + " " + e.k;
        if (!groups[key]) { groups[key] = { ids: [] }; order.push(key); }
        groups[key].ids.push(e.id);
      });
    });
    var out = { edges: {} };
    order.forEach(function (key) {
      var g = groups[key];
      if (g.ids.length <= BUNDLE_MAX) return;
      g.ids.forEach(function (id) { (out.edges[id] = out.edges[id] || []).push(key); });
    });
    return out;
  }

  function styles() {
    var c = colors();
    var font = '"Segoe UI", system-ui, -apple-system, Roboto, sans-serif';
    return [
      { selector: "node", style: {
        shape: "ellipse", width: 44, height: 44,
        "background-color": function (n) { return mix(c.card, n.data("color") || c.accent, 0.16); },
        "background-image": function (n) { return glyph(n.data("glyph"), n.data("color") || c.accent); },
        "background-width": "52%", "background-height": "52%", "background-clip": "none",
        "border-width": 1.5, "border-color": mix(c.line, c.accent, 0.25),
        label: "data(label)", "font-family": font, "font-size": 11, "font-weight": 600, color: c.ink,
        "text-valign": "bottom", "text-halign": "center", "text-margin-y": 6,
        "text-wrap": "ellipsis", "text-max-width": 150,
        "text-background-color": c.page, "text-background-opacity": 0.82,
        "text-background-padding": 2, "text-background-shape": "roundrectangle",
        "overlay-opacity": 0, "transition-property": "border-color, border-width", "transition-duration": "120ms"
      } },
      { selector: "node.zone", style: { "border-style": "dashed", "border-width": 2.5, "border-color": c.accent2 } },
      { selector: "node.t0", style: {
        "background-color": mix(c.card, c.critical, 0.14),
        "outline-width": 2.5, "outline-color": c.critical, "outline-offset": 3, "outline-opacity": 0.9
      } },
      { selector: "node.start", style: { "border-width": 3.5, "border-style": "solid", "border-color": c.accent2 } },
      { selector: "node.target", style: { "border-width": 3.5, "border-style": "solid", "border-color": c.critical, "background-color": mix(c.card, c.critical, 0.22) } },
      { selector: "node.ph, node.disabled", style: { opacity: 0.55 } },
      { selector: "node.dim", style: { opacity: 0.3 } },
      // "Explore <domain>": the other domains' objects are hidden.
      { selector: "node.offdom", style: { display: "none" } },
      { selector: "node:selected", style: {
        "border-width": 3.5, "border-color": c.accent, "border-style": "solid",
        "underlay-color": c.accent, "underlay-opacity": 0.2, "underlay-padding": 9, "underlay-shape": "ellipse"
      } },
      { selector: "edge", style: {
        width: 2, "line-color": mix(c.muted, c.ink, 0.3), "target-arrow-color": mix(c.muted, c.ink, 0.3),
        "target-arrow-shape": "triangle", "target-arrow-fill": "filled", "arrow-scale": 1.35,
        // The head stops clear of the target's border and Tier Zero
        // outline (3 px out, 2.5 px wide), so it is never under the node.
        "target-distance-from-node": 7, "source-distance-from-node": 2, "curve-style": "bezier",
        label: "data(label)", "font-family": 'ui-monospace, "Cascadia Code", Consolas, Menlo, monospace',
        "font-size": edgeLabel.size, "font-weight": 600, color: c.accent, "text-rotation": "autorotate",
        "text-background-color": c.page, "text-background-opacity": 0.9, "text-background-padding": 2,
        "text-background-shape": "roundrectangle", "overlay-opacity": 0,
        "text-opacity": edgeLabel.all ? 1 : 0
      } },
      // A bundle's labels would pile up where its edges meet, so they have
      // none (the shared end counts them); nor do many crossing links.
      { selector: "edge.bundled, edge.nolabel", style: { "text-opacity": 0 } },
      // Path, selected and hovered edges always keep their label: in a
      // bundle, and zoomed far out.
      { selector: "edge.path, edge:selected, edge.hover", style: { "text-opacity": 1 } },
      { selector: "edge.inh", style: { "line-style": "dashed", "line-dash-pattern": [6, 4] } },
      { selector: "edge.weak", style: { "line-style": "dotted", opacity: 0.65 } },
      // OpenGraph relationships that are context only (no trusted mapping).
      { selector: "edge.ctx", style: { "line-style": "dashed", "line-dash-pattern": [3, 4], opacity: 0.75, color: c.muted } },
      { selector: "edge.srchid", style: { display: "none" } },
      { selector: "edge.path", style: { width: 3.5, "line-color": c.accent, "target-arrow-color": c.accent, "arrow-scale": 1.5, "z-index": 10 } },
      // The rest of a hovered edge's bundle steps back.
      { selector: "edge.fade", style: { opacity: 0.4 } },
      { selector: "edge.dim", style: { opacity: 0.2 } },
      { selector: "edge:selected", style: { width: 3.5, "line-color": c.accent2, "target-arrow-color": c.accent2, "arrow-scale": 1.5 } },
      // A hovered edge stands out, its label a size up, over the others.
      { selector: "edge.hover", style: {
        width: 3.5, "line-color": c.accent, "target-arrow-color": c.accent, "arrow-scale": 1.8,
        opacity: 1, "font-size": edgeLabel.size * 1.25, "z-index": 30
      } }
    ];
  }

  // ------------------------------------------------------------ state
  var cy = cytoscape({
    container: $("xp-cy"),
    style: styles(),
    minZoom: 0.08,
    maxZoom: 3,
    boxSelectionEnabled: true,
    selectionType: "additive"
  });
  // Follow the app's theme switch.
  new MutationObserver(function () { cy.style(styles()); if (mode === "list") renderList(); })
    .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  // Edge label size follows the zoom (restyled once per frame, and only
  // when the size changes by half a pixel or more).
  var edgeFrame = 0;
  function sizeEdgeLabels() {
    edgeFrame = 0;
    var want = EDGE_PX / cy.zoom();
    var size = Math.round(Math.min(EDGE_MAX, Math.max(EDGE_PX, want)) * 2) / 2;
    var all = want <= EDGE_MAX;
    if (size === edgeLabel.size && all === edgeLabel.all) return;
    edgeLabel = { size: size, all: all };
    cy.style(styles());
  }
  cy.on("zoom", function () { if (!edgeFrame) edgeFrame = requestAnimationFrame(sizeEdgeLabels); });
  // Hovering an edge shows its label and fades the rest of its bundle.
  cy.on("mouseover", "edge", function (ev) {
    var e = ev.target, keys = e.scratch("pwBundles") || [];
    e.addClass("hover");
    if (!keys.length) return;
    cy.edges(".bundled").forEach(function (x) {
      var its = x.scratch("pwBundles") || [];
      if (x !== e && its.some(function (k) { return keys.indexOf(k) >= 0; })) x.addClass("fade");
    });
  });
  cy.on("mouseout", "edge", function (ev) {
    ev.target.removeClass("hover");
    cy.edges(".fade").removeClass("fade");
  });

  // Bundles are worked out again whenever edges come or go, or a filter
  // hides some: once per change, before the next draw.
  var bundlesQueued = false;
  function queueBundles() {
    if (bundlesQueued) return;
    bundlesQueued = true;
    Promise.resolve().then(applyBundles);
  }
  function applyBundles() {
    bundlesQueued = false;
    var shown = cy.edges().filter(function (x) {
      return !x.hasClass("srchid") && !x.source().hasClass("offdom") && !x.target().hasClass("offdom");
    });
    var b = bundleEdges(shown.map(function (x) {
      return { id: x.id(), s: x.source().id(), t: x.target().id(), k: x.data("kind") };
    }));
    cy.batch(function () {
      cy.edges().forEach(function (x) {
        var keys = b.edges[x.id()] || null;
        x.scratch("pwBundles", keys);
        if (keys) x.addClass("bundled"); else x.removeClass("bundled");
      });
    });
  }
  cy.on("add remove", "edge", queueBundles);

  var known = {};          // ix -> node JSON from the server
  var findings = [];       // the run's findings, in report order
  var current = null;      // the finding on screen
  var focus = null;        // the selected object's ix
  var basket = {};         // ix -> {name, adds_as}: the zone draft
  var mode = "graph";
  var forceGraph = false;
  var info = null;

  function nid(ix) { return "n" + ix; }
  function eid(e) { return "e" + e.s + "-" + e.t + "-" + e.k; }

  // `JDOE@CONTOSO.LOCAL` -> `JDOE`; a computer's FQDN -> its host name.
  function shortName(n) {
    var s = n.name || n.id;
    var at = s.indexOf("@");
    if (at > 0) s = s.slice(0, at);
    else if (n.kind === "Computer" && s.indexOf(".") > 0) s = s.slice(0, s.indexOf("."));
    return s.length > 28 ? s.slice(0, 27) + "…" : s;
  }

  function remember(nodes) { (nodes || []).forEach(function (n) { known[n.ix] = n; }); }

  function addNode(n, pos) {
    known[n.ix] = n;
    var existing = cy.getElementById(nid(n.ix));
    if (existing.nonempty()) return existing;
    var cls = [];
    if (n.t0) cls.push("t0");
    if (n.zone) cls.push("zone");
    if (n.ph) cls.push("ph");
    if (n.disabled) cls.push("disabled");
    return cy.add({
      group: "nodes",
      data: { id: nid(n.ix), ix: n.ix, label: shortName(n), glyph: glyphKey(n), color: extColor(n.kind) || undefined },
      position: pos || { x: 0, y: 0 },
      classes: cls.join(" ")
    });
  }

  function addEdge(e, extra) {
    if (cy.getElementById(nid(e.s)).empty() || cy.getElementById(nid(e.t)).empty()) return null;
    var id = eid(e);
    var existing = cy.getElementById(id);
    if (existing.nonempty()) { if (extra) existing.addClass(extra); return existing; }
    var cls = [];
    if (e.inh) cls.push("inh");
    if (e.weak) cls.push("weak");
    if (isContext(e.k)) cls.push("ctx");
    if (edgeHidden(e.k)) cls.push("srchid");
    if (extra) cls.push(extra);
    return cy.add({ group: "edges", data: { id: id, source: nid(e.s), target: nid(e.t), label: e.k, kind: e.k, inh: !!e.inh }, classes: cls.join(" ") });
  }

  function clearGraph() {
    cy.elements().remove();
    $("xp-note").hidden = true;
    focus = null;
    forceGraph = false;
  }

  function afterChange() {
    $("xp-empty").hidden = cy.nodes().length > 0 || mode === "forest";
    applyDomainFilter();
    var dense = cy.nodes().length > DENSE;
    var note = $("xp-dense");
    if (dense && !forceGraph && mode === "graph") {
      setMode("list");
      note.hidden = false;
      note.textContent = "";
      note.appendChild(el("span", null, "Too many objects for a graph (" + num(cy.nodes().length) + "): shown as a list. "));
      var b = el("button", "linkish", "Show the graph anyway");
      b.type = "button";
      b.addEventListener("click", function () { forceGraph = true; note.hidden = true; root.classList.remove("noted"); setMode("graph"); });
      note.appendChild(b);
    } else if (!dense) {
      note.hidden = true;
    }
    root.classList.toggle("noted", !note.hidden);
    if (mode === "list") renderList();
    updateTools();
  }

  // Fits `eles` (or everything), keeping labels readable: never closer than
  // 1.4 and, when `center` is given, never farther than 0.7 around it.
  // The zoom and pan are worked out first and animated to in one go: a clamp
  // applied after the animation raced it and often lost (small findings
  // opened at the maximum zoom).
  function fit(eles, center) {
    var target = eles && eles.nonempty() ? eles : cy.elements();
    if (target.empty()) return;
    var pad = 50, w = cy.width(), h = cy.height();
    var bb = target.boundingBox();
    var z = Math.min((w - 2 * pad) / Math.max(bb.w, 1), (h - 2 * pad) / Math.max(bb.h, 1));
    var focus = { x: bb.x1 + bb.w / 2, y: bb.y1 + bb.h / 2 };
    var keep = null;
    if (z > 1.4) z = 1.4;
    else if (center && center.nonempty() && z < 0.7) {
      // Too big to fit readably: as much of it as fits, shifted only as far
      // as needed to keep `center` (the start) in view.
      z = 0.7;
      keep = center.position();
    }
    z = Math.max(cy.minZoom(), Math.min(cy.maxZoom(), z));
    var pan = { x: w / 2 - z * focus.x, y: h / 2 - z * focus.y };
    if (keep) {
      // When the graph is wider (taller) than the canvas, start from its
      // edge on the start's side rather than its middle.
      if (bb.w * z > w - 2 * pad) pan.x = keep.x < focus.x ? pad - z * bb.x1 : w - pad - z * bb.x2;
      if (bb.h * z > h - 2 * pad) pan.y = keep.y < focus.y ? pad - z * bb.y1 : h - pad - z * bb.y2;
      var kx = z * keep.x + pan.x, ky = z * keep.y + pan.y;
      if (kx < pad) pan.x += pad - kx; else if (kx > w - pad) pan.x -= kx - (w - pad);
      if (ky < pad) pan.y += pad - ky; else if (ky > h - pad) pan.y -= ky - (h - pad);
    }
    cy.stop();
    cy.animate({ zoom: z, pan: pan, duration: 250 });
  }

  // Left to right, by layers from the roots (the start of paths).
  function tidy(roots) {
    if (cy.nodes().empty()) return;
    var r = roots && roots.nonempty() ? roots : cy.nodes().roots();
    cy.layout({
      name: "breadthfirst", directed: true, roots: r.nonempty() ? r : undefined,
      spacingFactor: 1.05, avoidOverlap: true, nodeDimensionsIncludeLabels: true,
      transform: function (n, p) { return { x: p.y * 1.7, y: p.x * 0.75 }; },
      animate: true, animationDuration: 280, fit: false,
      // Fit with the readability floor around the start, as everywhere else:
      // the layout's own fit shrank long paths to unreadable labels.
      stop: function () { fit(cy.elements(), r.nonempty() ? r.first() : null); }
    }).run();
  }

  // Objects per row of a path, so it stays readable on this canvas.
  function perRow() { return Math.max(2, Math.floor((cy.width() - 60) / 190)); }

  // A path left to right (as the report's diagrams), turning back at the
  // edge of the canvas so each step stays next to the one before.
  function pathPosition(i, origin) {
    var n = perRow();
    var row = Math.floor(i / n), col = i % n;
    if (row % 2 === 1) col = n - 1 - col;
    return { x: (origin ? origin.x : 0) + col * 190, y: (origin ? origin.y : 0) + row * 150 };
  }

  function layoutPaths(paths, origin) {
    var placed = {};
    var y = origin ? origin.y : 0;
    paths.forEach(function (p) {
      var rows = Math.ceil(p.length / perRow());
      p.forEach(function (ix, i) {
        if (placed[ix]) return;
        placed[ix] = true;
        cy.getElementById(nid(ix)).position(pathPosition(i, { x: origin ? origin.x : 0, y: y }));
      });
      y += rows * 150 + 40;
    });
  }

  // New neighbors in columns beside `center` (outbound to the right,
  // inbound to the left), in the nearest free slots.
  // Columns of `added` beside `center` (side 1: right, -1: left), as wide
  // as their widest label so no two labels overlap, around what is there.
  function placeAround(center, added, side) {
    if (!added.length) return;
    var GAP = 28, ROWS = 6;
    var c = cy.getElementById(nid(center));
    var addedSet = {};
    added.forEach(function (ix) { addedSet[ix] = true; });
    // Each node's box with its label, relative to its position.
    var shape = function (n) {
      var b = n.boundingBox({ includeLabels: true }), p = n.position();
      return { l: p.x - b.x1, r: b.x2 - p.x, t: p.y - b.y1, b: b.y2 - p.y };
    };
    var taken = cy.nodes().filter(function (n) { return !addedSet[n.data("ix")]; }).map(function (n) {
      return n.boundingBox({ includeLabels: true });
    });
    var clear = function (q) {
      for (var i = 0; i < taken.length; i++) {
        var t = taken[i];
        if (q.x1 < t.x2 + GAP && t.x1 < q.x2 + GAP && q.y1 < t.y2 + 10 && t.y1 < q.y2 + 10) return false;
      }
      return true;
    };
    var queue = added.map(function (ix) {
      var n = cy.getElementById(nid(ix));
      return { n: n, s: shape(n) };
    });
    var rowH = 0;
    queue.forEach(function (q) { rowH = Math.max(rowH, q.s.t + q.s.b); });
    rowH += 14;
    var cb = c.boundingBox({ includeLabels: true });
    var cy0 = c.position().y;
    // The column's edge nearest the center.
    var edge = side > 0 ? cb.x2 + 70 : cb.x1 - 70;
    for (var col = 0; queue.length && col < 60; col++) {
      var width = 0;
      for (var k = 0; k < ROWS * 2 && queue.length; k++) {
        var offset = k % 2 ? -Math.ceil(k / 2) : Math.ceil(k / 2);
        var q = queue[0], s = q.s;
        var x = side > 0 ? edge + s.l : edge - s.r;
        var y = cy0 + offset * rowH;
        var box = { x1: x - s.l, x2: x + s.r, y1: y - s.t, y2: y + s.b };
        if (!clear(box)) continue;
        queue.shift();
        q.n.position({ x: x, y: y });
        taken.push(box);
        width = Math.max(width, s.l + s.r);
      }
      edge += side * ((width || 160) + GAP * 2);
    }
  }

  // A path's ends: the start ring, and the Tier Zero target ring only when
  // the end is Tier Zero (a query's or Path between's end may be anything).
  function markEnds(start, end) {
    cy.getElementById(nid(start)).addClass("start");
    var n = known[end];
    if (n && n.t0) cy.getElementById(nid(end)).addClass("target");
  }

  function markPath(edges) {
    cy.edges().removeClass("path");
    (edges || []).forEach(function (e) {
      var x = cy.getElementById(eid(e));
      if (x.nonempty()) x.addClass("path");
    });
  }

  // A finding's title breaks after "@" and "." rather than inside a
  // name ("ADMINSDHOLDER@" / "SCALE.LOCAL").
  function nameBreaks(node) {
    var text = node.textContent;
    node.textContent = "";
    text.split(/(?<=[@.])/).forEach(function (part, i) {
      if (i) node.appendChild(document.createElement("wbr"));
      node.appendChild(document.createTextNode(part));
    });
    return node;
  }

  // ------------------------------------------------------------ tabs
  var tabs = ["trust", "finding", "object", "reach", "zones", "findings", "query"];
  function showTab(name) {
    tabs.forEach(function (t) {
      $("xt-" + t).setAttribute("aria-selected", t === name ? "true" : "false");
      $("xp-p-" + t).hidden = t !== name;
    });
    // Findings and Query sit under More, so the side tabs keep one row:
    // More takes the name of the one that is open.
    var inMore = name === "findings" || name === "query";
    $("xt-more").classList.toggle("on", inMore);
    $("xt-more-name").textContent = inMore ? $("xt-" + name).textContent : "More";
    closeMore();
  }
  function closeMore() {
    $("xp-more-menu").hidden = true;
    $("xt-more").setAttribute("aria-expanded", "false");
  }
  $("xt-more").addEventListener("click", function (e) {
    e.stopPropagation();
    var open = $("xp-more-menu").hidden;
    $("xp-more-menu").hidden = !open;
    $("xt-more").setAttribute("aria-expanded", open ? "true" : "false");
  });
  document.addEventListener("click", function (e) {
    if (!$("xp-more-menu").hidden && !$("xp-more-menu").contains(e.target)) closeMore();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !$("xp-more-menu").hidden) closeMore();
  });
  tabs.forEach(function (t) {
    $("xt-" + t).addEventListener("click", function () {
      showTab(t);
      if (t === "zones") loadSuggestions();
      if (t === "query") {
        if (!$("xp-p-query").firstChild || (query.mode === "prepared" && !prep.list)) renderQuery();
        else if (prep.measure) prep.measure();
        loadOwned();
      }
      // Opened by its tab: who can reach the selected object, unless the
      // tab already shows it.
      if (t === "reach" && focus != null && known[focus] && reachFor !== focus) loadReach(focus, 0, null);
    });
  });

  // ------------------------------------------------------------ query
  // The Query tab: prepared queries (the pinned BloodHound Query Library,
  // as `pathwarden query --prepared` runs them) or Cypher on this run, as
  // `pathwarden query --run` runs it. Returned paths page through the
  // pager, as findings do.
  var DEFAULT_QUERY = "MATCH p=shortestPath((s:User)-[:AD_ATTACK_PATHS*1..]->(t:Tag_Tier_Zero))\nWHERE s.hasspn = true AND s<>t\nRETURN p\nLIMIT 1000";
  // `from`: the prepared query (its GUID) the answer is of, null for Cypher.
  // `origin`: the prepared query the Cypher box was opened from.
  var query = { text: DEFAULT_QUERY, d: null, sel: -1, active: false, owned: null, error: null, mode: "prepared", from: null, title: null, origin: null };

  function post(path, body) {
    return fetch(API + path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) {}
        if (!r.ok) {
          if (j && j.reanalyze) reanalyze = true;
          throw new Error((j && j.error) || "Explore couldn't load this. Reload the page.");
        }
        return j;
      });
    });
  }

  function ownedLine() {
    return "Owned: " + (query.owned && query.owned.count ? num(query.owned.count) : "none");
  }

  function showOwned(o) {
    query.owned = o;
    var s = $("xp-qowned");
    if (s) { s.textContent = ownedLine(); s.title = o.text; }
  }

  function loadOwned() { get("/owned").then(showOwned).catch(function () {}); }

  // A path's steps, as the Finding tab lists them; a step against its
  // relationship is marked with an arrow.
  function stepsList(nodes, edges) {
    var ol = el("ol", "xp-steps");
    edges.forEach(function (e, i) {
      var li = el("li");
      if (i === 0) li.appendChild(el("span", "xp-step-node start", known[nodes[0]].name));
      var arrow = el("span", "xp-step-edge");
      arrow.appendChild(el("code", null, e.s === nodes[i] ? e.k : "\u2190 " + e.k));
      if (e.inh) arrow.appendChild(el("span", "muted small", " inherited"));
      li.appendChild(arrow);
      var to = known[nodes[i + 1]];
      li.appendChild(el("span", "xp-step-node" + (i === edges.length - 1 && to.t0 ? " target" : ""), to.name));
      ol.appendChild(li);
    });
    return ol;
  }

  function renderCypherQuery() {
    var p = panel("query");
    modeSwitch(p);
    section(p, "Cypher query").classList.add("xp-qfirst");
    var ta = el("textarea", "xp-cypher");
    ta.id = "xp-cypher";
    ta.spellcheck = false;
    ta.value = query.text;
    ta.setAttribute("aria-label", "Cypher query");
    ta.addEventListener("input", function () {
      query.text = ta.value;
      if (from) from.hidden = !fromOrigin();
    });
    ta.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); }
    });
    p.appendChild(ta);
    var from = originLine(p);
    var row = el("div", "xp-qrow");
    row.appendChild(button("Run", "primary", function () { runQuery(); }, "Run the query on this run (Ctrl+Enter)"));
    row.appendChild(el("span", "grow"));
    var o = el("span", "muted small", ownedLine());
    o.id = "xp-qowned";
    if (query.owned) o.title = query.owned.text;
    row.appendChild(o);
    p.appendChild(row);
    if (query.from == null) renderResult(p);
  }

  // Whether the Cypher box still holds the prepared query it was opened from.
  function fromOrigin() {
    return !!query.origin && (query.text || "").trim() === query.origin.query.trim();
  }

  // "From the prepared query ...", with its finding, while the text is unchanged.
  function originLine(p) {
    var q = query.origin;
    if (!q) return null;
    var line = el("p", "muted small xp-porigin", "From the prepared query " + q.name + ".");
    var f = findingLink(q);
    if (f) { line.appendChild(document.createTextNode(" Finding ")); line.appendChild(f); line.appendChild(document.createTextNode(".")); }
    line.hidden = !fromOrigin();
    p.appendChild(line);
    return line;
  }

  function renderResult(p) {
    if (query.error) { p.appendChild(el("p", "xp-qmsg err", query.error)); return; }
    var d = query.d;
    if (!d) return;
    var a = d.answer;
    var paths = d.draw;
    if (a.paths) {
      section(p, "Result \u00b7 " + plural(paths.length, "path", "paths"));
      if (paths.length) {
        var starts = {}, ends = {};
        paths.forEach(function (x) { starts[x.nodes[0]] = 1; ends[x.nodes[x.nodes.length - 1]] = 1; });
        p.appendChild(el("p", "xp-qmsg muted", "From " + plural(Object.keys(starts).length, "object", "objects") + " to " + num(Object.keys(ends).length) + "."));
      }
    } else {
      section(p, "Result \u00b7 " + plural(d.objects.length, "object", "objects"));
    }
    (a.stopped || []).forEach(function (m) { p.appendChild(el("p", "xp-qmsg cap", m)); });
    (a.warnings || []).forEach(function (w) { p.appendChild(el("p", "xp-qmsg muted", w)); });
    if (a.paths && paths.length) {
      var ol = el("ol", "xp-qpaths");
      paths.forEach(function (x, i) {
        var li = el("li");
        if (i === query.sel) li.className = "sel";
        var b = el("button");
        b.type = "button";
        var e = el("span", "ends");
        e.appendChild(document.createTextNode(known[x.nodes[0]].name));
        e.appendChild(el("span", "arrow", "\u2192"));
        e.appendChild(document.createTextNode(known[x.nodes[x.nodes.length - 1]].name));
        b.appendChild(e);
        b.appendChild(el("span", "n", plural(x.edges.length, "step", "steps")));
        b.title = known[x.nodes[0]].name + " to " + known[x.nodes[x.nodes.length - 1]].name;
        b.addEventListener("click", function () { showQueryPath(i); });
        li.appendChild(b);
        ol.appendChild(li);
      });
      p.appendChild(ol);
      var sel = ol.querySelector("li.sel");
      if (sel) ol.scrollTop = sel.offsetTop - ol.offsetTop - 70;
      if (query.sel >= 0) {
        var x = paths[query.sel];
        section(p, "Path " + num(query.sel + 1) + " \u00b7 " + plural(x.edges.length, "step", "steps"));
        p.appendChild(stepsList(x.nodes, x.edges));
      }
    } else if (!a.paths && d.objects.length) {
      var ul = el("ul", "xp-objlist");
      d.objects.forEach(function (ix) { if (known[ix]) ul.appendChild(objectRow(known[ix])); });
      p.appendChild(ul);
    }
  }


  // ------------------------------------------------------------ prepared
  // Prepared queries: the pinned BloodHound Query Library's queries that
  // Pathwarden runs (GET /api/prepared, the list `pathwarden query
  // --list-prepared` prints), by category. Run sends the query's GUID; the
  // server runs its pinned text.
  // `measure`: shows the description's More once the panel is visible.
  var prep = { list: null, error: null, search: "", open: {}, item: null, measure: null };

  function tipEl(about, text) {
    var id = "xp-tip-" + (tipEl.n = (tipEl.n || 0) + 1);
    var s = el("span", "tip");
    var b = el("button", "tip-btn");
    b.type = "button";
    b.setAttribute("aria-label", "About: " + about);
    b.setAttribute("aria-describedby", id);
    b.appendChild(iconEl("i-info"));
    s.appendChild(b);
    var t = el("span", "tip-text", text);
    t.id = id;
    t.setAttribute("role", "tooltip");
    s.appendChild(t);
    return s;
  }

  function modeSwitch(p) {
    var seg = el("span", "segmented xp-qmode");
    seg.setAttribute("role", "radiogroup");
    seg.setAttribute("aria-label", "Query");
    [["prepared", "Prepared"], ["cypher", "Cypher"]].forEach(function (m) {
      var l = el("label");
      var i = el("input");
      i.type = "radio"; i.name = "xp-qmode"; i.value = m[0]; i.checked = query.mode === m[0];
      i.addEventListener("change", function () { query.mode = m[0]; renderQuery(); });
      l.appendChild(i);
      l.appendChild(document.createTextNode(m[1]));
      seg.appendChild(l);
    });
    p.appendChild(seg);
  }

  function renderQuery() {
    if (query.mode === "cypher") { renderCypherQuery(); return; }
    var p = panel("query");
    modeSwitch(p);
    prep.measure = null;
    // A failed load is shown once; the next visit tries again.
    if (prep.error) { p.appendChild(el("p", "xp-qmsg err", prep.error)); prep.error = null; return; }
    if (!prep.list) { p.appendChild(el("p", "muted small", "Loading…")); loadPrepared(); return; }
    if (prep.item) renderPrepItem(p, prep.item); else renderPrepList(p);
  }

  function loadPrepared() {
    if (loadPrepared.busy) return;
    loadPrepared.busy = true;
    fetch("/api/prepared", { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) throw new Error("The prepared queries couldn't be loaded. Reload the page.");
      return r.json();
    }).then(function (d) {
      prep.list = d;
      prep.open[(d.queries[0] || {}).category] = true;
    }).catch(function (e) {
      prep.error = e.message;
    }).then(function () {
      loadPrepared.busy = false;
      if (query.mode === "prepared") renderQuery();
    });
  }

  function prepMatches(q, text) {
    if (!text) return true;
    return [q.name, q.description || "", q.category, q.finding ? q.finding.rule : ""].join(" ").toLowerCase().indexOf(text.toLowerCase()) >= 0;
  }

  function renderPrepList(p) {
    var d = prep.list;
    var input = el("input", "input xp-psearch");
    input.type = "search";
    input.placeholder = "Find a prepared query";
    input.value = prep.search;
    input.setAttribute("aria-label", "Find a prepared query");
    p.appendChild(input);
    var lead = el("p", "muted small xp-plead", plural(d.queries.length, "query", "queries") + " from the " + d.library.library + ".");
    lead.appendChild(tipEl("Prepared queries",
      "A copy of the " + d.library.library + " (" + d.library.tag + "), built in; works offline."));
    p.appendChild(lead);
    var box = el("div", "xp-plist");
    p.appendChild(box);
    var foot = el("div", "muted small xp-pfoot");
    foot.appendChild(el("p", null, d.notice));
    p.appendChild(foot);
    input.addEventListener("input", function () { prep.search = input.value; fillPrepList(box); });
    fillPrepList(box);
  }

  // The categories in the server's order, each a <details> with its count.
  function fillPrepList(box) {
    box.textContent = "";
    var cats = [], by = {};
    prep.list.queries.forEach(function (q) {
      if (!prepMatches(q, prep.search)) return;
      if (!by[q.category]) { by[q.category] = []; cats.push(q.category); }
      by[q.category].push(q);
    });
    cats.forEach(function (cat) {
      var items = by[cat];
      var d = el("details", "xp-pcat");
      d.open = !!prep.search || !!prep.open[cat];
      d.addEventListener("toggle", function () { if (!prep.search) prep.open[cat] = d.open; });
      var s = el("summary");
      s.appendChild(el("span", "xp-pcat-name", cat));
      s.appendChild(el("span", "muted xp-pcat-n", num(items.length)));
      d.appendChild(s);
      var ul = el("ul", "xp-prows");
      items.forEach(function (q) {
        var li = el("li");
        var b = el("button", "xp-prow");
        b.type = "button";
        b.appendChild(el("span", "xp-prow-name", q.name));
        var sub = el("span", "xp-prow-sub");
        if (q.edit_first) sub.appendChild(el("span", "tag muted-tag", "Needs editing"));
        if (q.finding) sub.appendChild(el("span", "tag muted-tag", q.finding.rule));
        b.appendChild(sub);
        b.addEventListener("click", function () { prep.item = q; renderQuery(); });
        li.appendChild(b);
        ul.appendChild(li);
      });
      d.appendChild(ul);
      box.appendChild(d);
    });
    if (!cats.length) box.appendChild(el("p", "muted small", "No prepared query matches."));
  }

  // A link to the run's first instance of the finding `q` overlaps, if the
  // run has one.
  function findingLink(q) {
    var hit = q.finding && firstOf(q.finding.rule);
    if (!hit) return null;
    var fb = el("button", "linkish", q.finding.rule + " " + q.finding.title);
    fb.type = "button";
    fb.addEventListener("click", function () { openFinding(hit.fp); });
    return fb;
  }

  // The run's first instance of a rule, if it has one.
  function firstOf(rule) {
    return (findings || []).filter(function (f) { return f.rule === rule; })[0];
  }

  function renderPrepItem(p, q) {
    var lib = prep.list.library;
    var back = el("button", "linkish small xp-pback", "‹ Prepared queries");
    back.type = "button";
    back.addEventListener("click", function () { prep.item = null; renderQuery(); });
    p.appendChild(back);
    p.appendChild(el("h2", "xp-name", q.name));
    var tags = el("div", "xp-tags");
    tags.appendChild(el("span", "tag muted-tag", q.category));
    tags.appendChild(el("span", "tag muted-tag", q.returns === "paths" ? "Paths" : "Objects"));
    if (q.edit_first) tags.appendChild(el("span", "tag muted-tag", "Needs editing"));
    p.appendChild(tags);
    if (q.description) {
      var desc = el("p", "xp-summary xp-pdesc clamp", q.description);
      p.appendChild(desc);
      var more = el("button", "linkish small xp-pmore", "More");
      more.type = "button";
      more.hidden = true;
      more.setAttribute("aria-expanded", "false");
      more.addEventListener("click", function () {
        var c = desc.classList.toggle("clamp");
        more.textContent = c ? "More" : "Less";
        more.setAttribute("aria-expanded", c ? "false" : "true");
      });
      p.appendChild(more);
      // Measured once laid out; a hidden panel measures when its tab opens.
      prep.measure = function () {
        if (!desc.isConnected || !desc.clientHeight || !desc.classList.contains("clamp")) return;
        more.hidden = desc.scrollHeight <= desc.clientHeight + 1;
      };
      requestAnimationFrame(prep.measure);
    }
    var dl = el("dl", "xp-facts xp-pfacts");
    function fact(k, v) {
      dl.appendChild(el("dt", null, k));
      var dd = el("dd");
      if (typeof v === "string") dd.textContent = v; else dd.appendChild(v);
      dl.appendChild(dd);
    }
    if (q.acknowledgements.length) fact("By", q.acknowledgements.join(", "));
    var src = el("span");
    src.appendChild(document.createTextNode(lib.library));
    src.appendChild(tipEl("Source", "Revision " + q.revision + ", " + lib.tag + " release."));
    fact("Source", src);
    var links = q.resources.filter(function (u) { return /^https:\/\//i.test(u); });
    if (links.length) {
      var rs = el("span");
      links.forEach(function (u, i) {
        if (i) rs.appendChild(document.createTextNode(", "));
        var a = el("a", null, u.replace(/^https:\/\/(www\.)?/i, "").split("/")[0]);
        a.href = u; a.rel = "noreferrer"; a.target = "_blank";
        a.title = u;
        rs.appendChild(a);
      });
      fact("Read more", rs);
    }
    var fb = findingLink(q);
    if (fb) fact("Finding", fb);
    p.appendChild(dl);
    var row = el("div", "xp-actions");
    // Text typed in the Cypher box is kept: only an empty box, the starting
    // query or an earlier prepared query is replaced.
    function asCypher() {
      var t = (query.text || "").trim();
      if (!t || t === DEFAULT_QUERY.trim() || fromOrigin()) { query.text = q.query; query.origin = q; }
      query.mode = "cypher";
      renderQuery();
    }
    if (q.edit_first) {
      row.appendChild(button("Edit", "primary", asCypher, "Replace the placeholder, then run it"));
    } else {
      row.appendChild(button("Run", "primary", function () { runQuery(q); }, "Run the query on this run"));
      row.appendChild(button("Open as Cypher", null, asCypher, "Edit a copy of the query"));
    }
    p.appendChild(row);
    if (query.from === q.guid) renderResult(p);
  }

  // Runs the Cypher box, or prepared query `q`.
  function runQuery(q) {
    var body;
    if (q) body = { prepared: q.guid };
    else {
      var text = (query.text || "").trim();
      if (!text) return;
      body = { cypher: text };
    }
    query.from = q ? q.guid : null;
    query.title = q ? q.name : fromOrigin() ? query.origin.name : null;
    busy(true, "Running the query");
    post("/query", body).then(function (d) {
      busy(false);
      query.error = null;
      query.d = d;
      query.owned = d.owned;
      query.sel = -1;
      remember(d.nodes);
      if (d.draw.length) showQueryPath(0);
      else { query.active = false; renderQuery(); updatePager(); }
    }).catch(function (e) {
      busy(false);
      query.error = e.message;
      query.d = null;
      query.active = false;
      renderQuery();
      updatePager();
    });
  }

  // Draws returned path `i` as a finding's path is drawn, and pages to it.
  function showQueryPath(i) {
    var d = query.d;
    if (!d || !d.draw[i]) return;
    if (mode === "forest") setMode("graph");
    domainFilter = null;
    query.sel = i;
    query.active = true;
    current = null;
    var x = d.draw[i];
    clearGraph();
    x.nodes.forEach(function (ix) { addNode(known[ix]); });
    x.edges.forEach(function (e) { addEdge(e, "path"); });
    layoutPaths([x.nodes]);
    markEnds(x.nodes[0], x.nodes[x.nodes.length - 1]);
    afterChange();
    if (mode === "graph") fit();
    renderQuery();
    showTab("query");
    updatePager();
  }

  function panel(name) {
    var p = $("xp-p-" + name);
    p.textContent = "";
    return p;
  }

  function section(p, title, sub) {
    var h = el("h3", "xp-h", title);
    p.appendChild(h);
    if (sub) p.appendChild(el("p", "muted small xp-sub", sub));
    return h;
  }

  function button(text, cls, onClick, title) {
    var b = el("button", "btn small-btn" + (cls ? " " + cls : ""), text);
    b.type = "button";
    if (title) b.title = title;
    b.addEventListener("click", onClick);
    return b;
  }

  function sevPill(sev) {
    var s = el("span", "pill " + sev);
    s.appendChild(el("span", "dot"));
    s.appendChild(document.createTextNode(sev.charAt(0).toUpperCase() + sev.slice(1)));
    return s;
  }

  // A clickable object row: icon, name, kind and domain.
  function objectRow(n, extra) {
    var li = el("li", "xp-obj");
    var b = el("button", "xp-obj-main");
    b.type = "button";
    b.appendChild(kindIcon(n));
    var t = el("span", "xp-obj-text");
    t.appendChild(el("span", "xp-obj-name", n.name));
    var sub = kindLabel(n.kind) + (n.domain ? " · " + n.domain : "");
    t.appendChild(el("span", "xp-obj-sub", sub));
    b.appendChild(t);
    if (n.t0) b.appendChild(el("span", "tag t0", "Tier Zero"));
    b.title = n.name;
    b.addEventListener("click", function () { reveal(n); });
    li.appendChild(b);
    if (extra) li.appendChild(extra);
    return li;
  }

  // Puts an object on the graph (beside what is there) and selects it.
  function reveal(n) {
    if (mode === "forest") setMode("graph");
    // An object of another domain, opened on purpose: the domain filter
    // would hide it, so it ends.
    if (domainFilter && n.domain && n.domain.toUpperCase() !== domainFilter.toUpperCase()) {
      domainFilter = null;
      toast("Showing all domains: " + n.name + " is in another domain.");
    }
    var fresh = cy.getElementById(nid(n.ix)).empty();
    var pos = null;
    if (fresh && cy.nodes().nonempty()) {
      var bb = cy.nodes().boundingBox();
      pos = { x: bb.x1 + bb.w / 2, y: bb.y2 + 110 };
    }
    var node = addNode(n, pos);
    afterChange();
    select(n.ix);
    if (mode === "graph") cy.animate({ center: { eles: node }, duration: 220 });
  }

  // ------------------------------------------------------------ selection
  cy.on("tap", "node", function (ev) { select(ev.target.data("ix"), true); });
  cy.on("dbltap", "node", function (ev) { expand(ev.target.data("ix"), "both", []); });
  cy.on("select unselect", function () { updateTools(); });
  // Selection order (cy.nodes(":selected") is in insertion order), for Path between.
  var picked = [];
  cy.on("select", "node", function (ev) { picked = picked.filter(function (ix) { return ix !== ev.target.data("ix"); }).concat([ev.target.data("ix")]); });
  cy.on("unselect", "node", function (ev) { picked = picked.filter(function (ix) { return ix !== ev.target.data("ix"); }); });

  function select(ix, fromGraph) {
    focus = ix;
    if (!fromGraph) {
      cy.nodes().unselect();
      cy.getElementById(nid(ix)).select();
    }
    showTab("object");
    renderObject(ix);
    if (mode === "list") renderList();
    setUrl(null, ix);
  }

  function renderObject(ix) {
    var p = panel("object");
    var n = known[ix];
    if (!n) return;
    var head = el("div", "xp-objhead");
    head.appendChild(kindIcon(n));
    var t = el("div", "xp-objtitle");
    t.appendChild(el("h2", "xp-name", n.name));
    t.appendChild(el("p", "muted small", kindLabel(n.kind) + (n.domain ? " · " + n.domain : "")));
    head.appendChild(t);
    p.appendChild(head);
    var loading = el("p", "muted small", "Loading…");
    p.appendChild(loading);
    get("/node", { ix: ix }).then(function (d) {
      if (focus !== ix) return;
      loading.remove();
      remember([d.node]);
      var tags = el("div", "xp-tags");
      var tag = function (text, cls, title) { var s = el("span", "tag " + (cls || ""), text); if (title) s.title = title; tags.appendChild(s); };
      if (d.node.t0) tag("Tier Zero", "t0");
      if (d.node.dc) tag("Domain controller", "t0");
      if (d.node.server) tag("Server");
      if (d.admin_count) tag("Protected (adminCount)", "warn", "Protected by AdminSDHolder: privileged now or once.");
      if (d.node.disabled) tag("Disabled", "muted-tag");
      if (d.node.ph) tag("Not collected", "muted-tag", "Referenced by other objects but not in the collected data.");
      if (d.broad) tag("Everyone", "warn", "Holds (nearly) every user or computer.");
      if (d.owned) tag("Owned", "warn", "Marked as owned (an attacker controls it).");
      d.zones.forEach(function (z) { tag("Zone: " + z, "zone-tag"); });
      if (tags.childNodes.length) p.appendChild(tags);

      var facts = el("dl", "xp-facts");
      var fact = function (k, v, mono) {
        if (v == null || v === "") return;
        facts.appendChild(el("dt", null, k));
        facts.appendChild(el("dd", mono ? "mono" : null, v));
      };
      if (d.tier_zero_reason) fact("Why Tier Zero", d.tier_zero_reason);
      if (!d.node.t0) {
        fact("Path to Tier Zero", d.t0_hops != null
          ? plural(d.t0_hops, "step", "steps") + (d.t0_next ? ", first through " + d.t0_next.name : "")
          : "None found");
      }
      fact("Distinguished name", d.dn, true);
      fact("Object ID", d.node.id, true);
      p.appendChild(facts);

      // Actions
      var acts = el("div", "xp-actions");
      acts.appendChild(button("Expand outbound", "primary", function () { expand(ix, "out", chosenKinds("out")); }, "What this object controls (double-click an object to expand both ways)"));
      acts.appendChild(button("Expand inbound", "", function () { expand(ix, "in", chosenKinds("in")); }, "Who has rights over this object"));
      if (!d.node.t0) acts.appendChild(button("Path to Tier Zero", "", function () { pathTo(ix, "t0", 1); }));
      if (!d.node.t0) acts.appendChild(button("3 shortest paths", "", function () { pathTo(ix, "t0", 3); }));
      acts.appendChild(button("Who can reach it", "", function () { loadReach(ix, 0, null); }));
      acts.appendChild(button(d.owned ? "Unmark as owned" : "Mark as owned", "", function () {
        post("/owned", { ix: ix, owned: !d.owned }).then(function (o) {
          showOwned({ count: o.count, text: o.text });
          toast(o.text);
          renderObject(ix);
        }).catch(fail);
      }, "Marked for this environment; queries can match it as Tag_Owned."));
      var inBasket = !!basket[ix];
      acts.appendChild(button(inBasket ? "Remove from zone draft" : "Add to zone draft", "", function () {
        toggleBasket(d.node);
        renderObject(ix);
      }, "Add to a draft for a new zone (Suggested zones tab)"));
      p.appendChild(acts);

      // Relationship counts, as kind filters for expanding.
      var kinds = function (dir, list, total) {
        section(p, (dir === "out" ? "Outbound" : "Inbound") + " · " + num(total),
          list.length ? "Pick kinds to expand only those." : (dir === "out" ? "This object holds no rights over others." : "Nothing points to this object."));
        if (!list.length) return;
        var box = el("div", "xp-kinds");
        box.setAttribute("data-dir", dir);
        list.forEach(function (kc) {
          var lab = el("label", "kchip");
          var input = el("input");
          input.type = "checkbox";
          input.value = kc[0];
          lab.appendChild(input);
          var s = el("span");
          s.appendChild(document.createTextNode(kc[0] + " "));
          s.appendChild(el("b", null, num(kc[1])));
          lab.appendChild(s);
          box.appendChild(lab);
        });
        p.appendChild(box);
      };
      kinds("out", d.out, d.out_total);
      kinds("in", d.in, d.in_total);
    }).catch(function (e) { loading.textContent = e.message; });
  }

  function chosenKinds(dir) {
    var box = document.querySelector('.xp-kinds[data-dir="' + dir + '"]');
    if (!box) return [];
    return Array.prototype.map.call(box.querySelectorAll("input:checked"), function (i) { return i.value; });
  }

  // ------------------------------------------------------------ expand
  function expand(ix, dir, kinds) {
    busy(true, "Expanding");
    get("/neighbors", { ix: ix, dir: dir, kinds: (kinds || []).join(","), limit: 40 }).then(function (d) {
      busy(false);
      remember(d.nodes);
      if (cy.getElementById(nid(ix)).empty()) addNode(known[ix]);
      var outAdded = [], inAdded = [];
      d.nodes.forEach(function (n) {
        if (cy.getElementById(nid(n.ix)).nonempty()) return;
        addNode(n);
        var isOut = d.edges.some(function (e) { return e.s === ix && e.t === n.ix; });
        (isOut ? outAdded : inAdded).push(n.ix);
      });
      d.edges.forEach(function (e) { addEdge(e); });
      placeAround(ix, outAdded, 1);
      placeAround(ix, inAdded, -1);
      afterChange();
      if (mode === "graph") fit(cy.getElementById(nid(ix)).closedNeighborhood(), cy.getElementById(nid(ix)));
      var what = dir === "out" ? "outbound" : dir === "in" ? "inbound" : "";
      if (d.total === 0) toast("No " + (what ? what + " " : "") + "relationships" + (kinds && kinds.length ? " of those kinds." : "."));
      else if (d.total > d.shown) toast("Showing " + num(d.shown) + " of " + num(d.total) + " " + (what ? what + " " : "") + "relationships, Tier Zero first. Pick kinds to narrow it.");
    }).catch(fail);
  }

  // ------------------------------------------------------------ paths
  // `either`: two objects picked on the graph, with no direction meant; try
  // the other way round before saying there is no path. A path only through
  // Tier Zero (up to its first Tier Zero object) is shown only when the
  // other way has no path of its own: `fallback` holds it meanwhile.
  function pathTo(from, to, k, either, fallback) {
    busy(true, k > 1 ? "Finding paths" : "Finding the shortest path");
    get("/path", { from: from, to: to, k: k }).then(function (d) {
      busy(false);
      if (either && (!d.paths.length || d.through_tier_zero)) {
        pathTo(to, from, k, false, d.paths.length ? { d: d, from: from } : null);
        return;
      }
      if (fallback && (!d.paths.length || d.through_tier_zero)) { d = fallback.d; from = fallback.from; }
      $("xp-note").hidden = true;
      if (!d.paths.length) {
        toast(either === false ? "No attack path between these objects, in either direction." : (d.note || "No path found."));
        return;
      }
      remember(d.nodes);
      var origin = cy.getElementById(nid(from)).nonempty() ? cy.getElementById(nid(from)).position() : null;
      var rows = [];
      d.paths.forEach(function (p) {
        rows.push([p[0].s].concat(p.map(function (e) { return e.t; })));
      });
      var fresh = {};
      rows.forEach(function (r) { r.forEach(function (ix) { if (cy.getElementById(nid(ix)).empty()) fresh[ix] = true; addNode(known[ix]); }); });
      var all = [];
      d.paths.forEach(function (p) { p.forEach(function (e) { addEdge(e); all.push(e); }); });
      // Lay out only what was not on the graph yet.
      var placed = {};
      var o = origin || { x: 0, y: 0 };
      if (!origin && cy.nodes().length > Object.keys(fresh).length) {
        var bb = cy.nodes().filter(function (x) { return !fresh[x.data("ix")]; }).boundingBox();
        o = { x: bb.x1, y: bb.y2 + 150 };
      }
      var y = o.y;
      rows.forEach(function (r) {
        r.forEach(function (ix, i) {
          if (!fresh[ix] || placed[ix]) return;
          placed[ix] = true;
          cy.getElementById(nid(ix)).position(pathPosition(i, { x: o.x, y: y }));
        });
        y += Math.ceil(r.length / perRow()) * 150 + 40;
      });
      markPath(all);
      // This path's ends replace the earlier ones (a finding's, or the last path's).
      cy.nodes().removeClass("start target");
      markEnds(from, rows[0][rows[0].length - 1]);
      afterChange();
      if (mode === "graph") fit(cy.collection(all.map(function (e) { return cy.getElementById(eid(e)); })).connectedNodes());
      if (d.through_tier_zero) {
        $("xp-note").textContent = d.through_tier_zero;
        $("xp-note").hidden = false;
      } else if (k > 1 && d.paths.length < k) toast("Found " + plural(d.paths.length, "path", "paths") + ".");
    }).catch(fail);
  }

  // ------------------------------------------------------------ reach
  var reachState = null;
  var reachFor = null;     // the object the tab shows (or is loading)
  function loadReach(ix, offset, cls) {
    showTab("reach");
    var p = $("xp-p-reach");
    if (!offset) { reachFor = ix; p.textContent = ""; p.appendChild(el("p", "muted small", "Searching every route to it…")); }
    get("/reach", { ix: ix, offset: offset, limit: 100, "class": cls == null ? "" : cls }).then(function (d) {
      if (ix !== reachFor) return;   // another object's, asked for since
      remember([d.target]);
      if (!offset) renderReachHead(d, cls);
      reachState = { ix: ix, cls: cls, next: d.offset + d.items.length, total: d.filtered };
      var list = $("xp-reach-list");
      var lastClass = list.getAttribute("data-last");
      d.items.forEach(function (r) {
        remember([r.node, r.via]);
        if (String(r.class) !== lastClass && cls == null) {
          lastClass = String(r.class);
          var h = el("li", "xp-group-head", d.class_names[r.class] + " · " + num(d.classes[r.class]));
          list.appendChild(h);
        }
        var extra = el("div", "xp-reach-extra");
        var how = el("span", "xp-how");
        how.appendChild(el("b", null, plural(r.hops, "step", "steps")));
        how.appendChild(document.createTextNode(" · first step "));
        how.appendChild(el("code", null, r.first.k));
        how.appendChild(document.createTextNode(" to " + shortName(r.via)));
        extra.appendChild(how);
        var showPath = el("button", "linkish", "Show path");
        showPath.type = "button";
        showPath.addEventListener("click", function () { pathTo(r.node.ix, d.target.ix, 1); });
        extra.appendChild(showPath);
        list.appendChild(objectRow(r.node, extra));
      });
      list.setAttribute("data-last", lastClass || "");
      var more = $("xp-reach-more");
      more.hidden = reachState.next >= reachState.total;
      more.textContent = "Show more (" + num(reachState.total - reachState.next) + ")";
    }).catch(function (e) {
      if (ix !== reachFor) return;   // another object's, asked for since
      reachFor = null;               // so the tab tries again
      p.textContent = ""; p.appendChild(el("p", "muted small", e.message));
    });
  }

  function renderReachHead(d, cls) {
    var p = panel("reach");
    var h = el("h2", "xp-name");
    h.appendChild(document.createTextNode("Who can reach "));
    h.appendChild(el("span", "accent-text", shortName(d.target)));
    p.appendChild(h);
    // The line comes from the server, as `pathwarden reach` prints it.
    p.appendChild(el("p", "muted small", d.summary));
    // Kerberoasting and AS-REP roasting need no path: say so when the
    // object is the open finding's weak account.
    var roast = current && { "PW-006": "Kerberoasting", "PW-007": "AS-REP roasting" }[current.finding.rule];
    if (roast && ((current.affected || []).indexOf(d.target.ix) >= 0 ||
        (current.path && current.path.nodes[0] === d.target.ix))) {
      var note = el("p", "xp-roast small");
      note.appendChild(el("strong", null, roast + " needs no path. "));
      note.appendChild(document.createTextNode((current.finding.rule === "PW-006"
        ? "Any domain account can request this account's ticket and crack its password offline."
        : "Anyone on the network can request this account's authentication data, without credentials, and crack its password offline.")));
      p.appendChild(note);
    }
    if (d.total) {
      var filt = el("div", "xp-kinds");
      var mk = function (label, value, count) {
        var lab = el("label", "kchip");
        var input = el("input");
        input.type = "radio";
        input.name = "xp-reach-class";
        input.checked = (cls == null && value == null) || cls === value;
        input.addEventListener("change", function () { loadReach(d.target.ix, 0, value); });
        lab.appendChild(input);
        var s = el("span");
        s.appendChild(document.createTextNode(label + " "));
        s.appendChild(el("b", null, num(count)));
        lab.appendChild(s);
        filt.appendChild(lab);
      };
      mk("All", null, d.total);
      d.class_names.forEach(function (name, i) { if (d.classes[i]) mk(name, i, d.classes[i]); });
      p.appendChild(filt);
    }
    var list = el("ul", "xp-objlist");
    list.id = "xp-reach-list";
    p.appendChild(list);
    var more = el("button", "btn small-btn xp-more", "Show more");
    more.type = "button";
    more.id = "xp-reach-more";
    more.hidden = true;
    more.addEventListener("click", function () { loadReach(reachState.ix, reachState.next, reachState.cls); });
    p.appendChild(more);
  }

  // ------------------------------------------------------------ findings
  function setUrl(fp, ix) {
    var q = fp ? "?finding=" + encodeURIComponent(fp) : ix != null ? "?node=" + ix : "";
    try { history.replaceState(null, "", location.pathname + q); } catch (e) {}
  }

  function openFinding(fp) {
    query.active = false;
    if (mode === "forest") setMode("graph");
    domainFilter = null;
    busy(true, "Opening the finding");
    get("/finding", { fp: fp }).then(function (d) {
      busy(false);
      current = d;
      remember(d.nodes);
      clearGraph();
      var f = d.finding;
      if (d.path.nodes.length) {
        d.path.nodes.forEach(function (ix) { addNode(known[ix]); });
        d.path.edges.forEach(function (e) { addEdge(e, "path"); });
        layoutPaths([d.path.nodes]);
        markEnds(d.path.nodes[0], d.path.nodes[d.path.nodes.length - 1]);
      } else {
        // No path: the affected objects, in a grid; with the relationships
        // among them (a Tier Zero account's sessions), around what they
        // lead to.
        var all = d.affected.length ? d.affected : d.hits;
        // Only the links that touch the hub are drawn, so every edge runs
        // straight into it and none crosses the other objects. The hub is
        // always among the 24 shown, however long the list.
        var hub = (d.links || []).length ? d.hits.filter(function (ix) { return all.indexOf(ix) >= 0; })[0] : undefined;
        var show = (hub === undefined ? all : [hub].concat(all.filter(function (ix) { return ix !== hub; }))).slice(0, 24);
        var links = (d.links || []).filter(function (e) {
          return show.indexOf(e.s) >= 0 && show.indexOf(e.t) >= 0 && (e.s === hub || e.t === hub);
        });
        if (!links.length) hub = undefined;
        if (hub === undefined) {
          show.forEach(function (ix, i) {
            addNode(known[ix], { x: (i % 6) * 190, y: Math.floor(i / 6) * 110 });
          });
        } else {
          addNode(known[hub], { x: 0, y: 0 });
          var rest = show.filter(function (ix) { return ix !== hub; });
          rest.forEach(function (ix) { addNode(known[ix], { x: 0, y: 0 }); });
          // Into the account (sessions point at it): on its left, one
          // column of up to 12; more go in a column on its right, so no
          // edge runs through another object.
          placeAround(hub, rest.slice(0, 12), -1);
          placeAround(hub, rest.slice(12), 1);
          if (known[hub] && known[hub].t0) cy.getElementById(nid(hub)).addClass("target");
          links.forEach(function (e) { addEdge(e); });
        }
      }
      afterChange();
      if (mode === "graph") fit();
      renderFinding(d);
      showTab("finding");
      updatePager();
      setUrl(f.fp);
    }).catch(function (e) {
      // Never leave the tab on "Loading…" (an unknown or outdated link).
      var p = panel("finding");
      p.appendChild(el("p", "muted small", "This finding couldn't be opened: " + e.message + " Pick one from the Findings tab."));
      showTab("finding");
      fail(e);
    });
  }

  function renderFinding(d) {
    var p = panel("finding");
    var f = d.finding;
    var top = el("div", "xp-fhead");
    top.appendChild(sevPill(f.severity));
    top.appendChild(el("span", "xp-rule", f.rule));
    if (f.suppressed) top.appendChild(el("span", "tag muted-tag", "Accepted risk"));
    p.appendChild(top);
    p.appendChild(nameBreaks(el("h2", "xp-name", f.title)));
    if (f.exposure != null) {
      p.appendChild(el("p", "xp-expo", f.everyone
        ? "Any authenticated user can abuse it."
        // As share_percent words it: never rounded to all or none.
        : (f.exposure <= 0 ? "0%" : f.exposure < 0.01 ? "Under 0.01%" : f.exposure >= 100 ? "100%" : f.exposure > 99.99 ? "99.99%" : f.exposure.toFixed(2) + "%") + " exposed: " + plural(f.exposed || 0, "user or computer", "users and computers") + " can reach its entry points."));
    }
    if (f.summary) p.appendChild(el("p", "xp-summary", f.summary));

    var acts = el("div", "xp-actions");
    if (d.path.nodes.length) {
      var start = d.path.nodes[0];
      acts.appendChild(button("Who can reach the start", "primary", function () { loadReach(start, 0, null); },
        "Every object with a route to where this path starts, unprivileged users first"));
      acts.appendChild(button("Other paths", "", function () {
        pathTo(start, d.path.nodes[d.path.nodes.length - 1], 3);
      }, "The 3 shortest paths between the same two objects"));
    }
    if (d.entry.length) {
      acts.appendChild(button("Show entry points", "", function () {
        var added = [];
        d.entry.slice(0, 30).forEach(function (ix) { if (cy.getElementById(nid(ix)).empty()) { addNode(known[ix]); added.push(ix); } });
        if (d.path.nodes.length) placeAround(d.path.nodes[0], added, -1);
        else layoutPaths(added.map(function (ix) { return [ix]; }));
        afterChange();
        if (mode === "graph") fit();
      }, "Add the entry points to the graph"));
    }
    p.appendChild(acts);

    var list = function (title, ixs, total, sub) {
      if (!ixs.length) return;
      section(p, title + " · " + num(total), sub);
      var ul = el("ul", "xp-objlist");
      ixs.forEach(function (ix) { if (known[ix]) ul.appendChild(objectRow(known[ix])); });
      p.appendChild(ul);
      if (total > ixs.length) p.appendChild(el("p", "muted small", "Showing the first " + num(ixs.length) + ". The report lists them all."));
    };
    if (d.path.nodes.length) {
      section(p, "Attack path · " + plural(d.path.edges.length, "step", "steps"));
      var ol = el("ol", "xp-steps");
      d.path.edges.forEach(function (e, i) {
        var li = el("li");
        if (i === 0) li.appendChild(el("span", "xp-step-node start", known[e.s].name));
        var arrow = el("span", "xp-step-edge");
        arrow.appendChild(el("code", null, e.k));
        if (e.inh) arrow.appendChild(el("span", "muted small", " inherited"));
        li.appendChild(arrow);
        var to = known[e.t];
        li.appendChild(el("span", "xp-step-node" + (i === d.path.edges.length - 1 && to.t0 ? " target" : ""), to.name));
        ol.appendChild(li);
      });
      p.appendChild(ol);
    }
    list("Entry points", d.entry, f.entry_total, "Whoever controls one of these can abuse the finding.");
    list("Affected", d.affected, f.affected_total);
    list("Leads to", d.hits, f.hits_total);
    if (!d.path.nodes.length && !d.affected.length && !d.hits.length) {
      p.appendChild(el("p", "muted small", "This finding has no objects to show on the graph."));
    }
  }

  function updatePager() {
    var sev = $("xp-sev");
    if (query.active && query.d && query.d.draw[query.sel]) {
      var n = query.d.draw.length, x = query.d.draw[query.sel];
      $("xp-prev").disabled = query.sel <= 0;
      $("xp-next").disabled = query.sel >= n - 1;
      $("xp-prev").title = "Previous path ( [ )";
      $("xp-next").title = "Next path ( ] )";
      sev.textContent = "Query result";
      sev.className = "pill";
      sev.hidden = false;
      $("xp-ctitle").textContent = query.title || known[x.nodes[0]].name + " to " + known[x.nodes[x.nodes.length - 1]].name;
      $("xp-pos").textContent = num(query.sel + 1) + " of " + num(n);
      return;
    }
    $("xp-prev").title = "Previous finding ( [ )";
    $("xp-next").title = "Next finding ( ] )";
    var i = current ? current.position : -1;
    $("xp-prev").disabled = !current || current.prev == null;
    $("xp-next").disabled = !findings.length || (current && current.next == null);
    sev.textContent = "";
    if (current) {
      sev.className = "pill " + current.finding.severity;
      sev.appendChild(el("span", "dot"));
      sev.appendChild(document.createTextNode(cap(current.finding.severity)));
      sev.hidden = false;
      $("xp-ctitle").textContent = current.finding.title;
      $("xp-pos").textContent = num(i + 1) + " of " + num(current.count);
    } else {
      sev.hidden = true;
      $("xp-ctitle").textContent = findings.length ? "Findings" : "No findings";
      $("xp-pos").textContent = findings.length ? plural(findings.length, "finding", "findings") : "";
    }
    var items = document.querySelectorAll("#xp-flist li");
    Array.prototype.forEach.call(items, function (li) {
      li.classList.toggle("current", !!current && li.getAttribute("data-fp") === current.finding.fp);
    });
  }

  $("xp-prev").addEventListener("click", function () {
    if (query.active) { showQueryPath(query.sel - 1); return; }
    if (current && current.prev) openFinding(current.prev);
  });
  $("xp-next").addEventListener("click", function () {
    if (query.active) { showQueryPath(query.sel + 1); return; }
    if (current && current.next) openFinding(current.next);
    else if (!current && findings.length) openFinding(findings[0].fp);
  });
  $("xp-current").addEventListener("click", function () {
    if (query.active) { showTab("query"); return; }
    showTab("findings");
    var c = document.querySelector("#xp-flist li.current");
    if (c) c.scrollIntoView({ block: "center" });
    var input = $("xp-ffilter");
    if (input) input.focus();
  });
  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
    if (e.key === "[") $("xp-prev").click();
    else if (e.key === "]") $("xp-next").click();
  });

  function renderFindings() {
    var p = panel("findings");
    p.appendChild(el("p", "muted small", "In the report's order. " + (info.findings_total > findings.length ? "Showing the first " + num(findings.length) + "." : "")));
    var input = el("input", "input");
    input.type = "search";
    input.id = "xp-ffilter";
    input.placeholder = "Filter findings";
    input.setAttribute("aria-label", "Filter findings");
    p.appendChild(input);
    var ul = el("ul", "xp-flist");
    ul.id = "xp-flist";
    findings.forEach(function (f, i) {
      var li = el("li");
      li.setAttribute("data-fp", f.fp);
      var b = el("button", "xp-frow");
      b.type = "button";
      b.appendChild(el("span", "xp-fnum muted", String(i + 1)));
      var d = el("span", "dot " + f.severity);
      d.title = cap(f.severity);
      b.appendChild(d);
      var t = el("span", "xp-ftitle");
      t.appendChild(el("span", "xp-rule", f.rule));
      t.appendChild(document.createTextNode(" " + f.title));
      b.appendChild(t);
      if (f.path) b.appendChild(el("span", "tag", "Path"));
      b.addEventListener("click", function () { openFinding(f.fp); });
      li.appendChild(b);
      ul.appendChild(li);
    });
    p.appendChild(ul);
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      Array.prototype.forEach.call(ul.children, function (li, i) {
        var f = findings[i];
        li.hidden = !!q && (f.title + " " + f.rule).toLowerCase().indexOf(q) < 0;
      });
    });
    if (!findings.length) p.appendChild(el("p", "muted", "This run has no findings. Search for an object to explore."));
  }

  // ------------------------------------------------------------ zones
  var suggestionsLoaded = false;
  function toggleBasket(n, as) {
    if (basket[n.ix]) delete basket[n.ix];
    else basket[n.ix] = { name: n.name, kind: n.kind, as: as || (n.kind === "Group" ? "group" : n.kind === "OU" || n.kind === "Container" ? "ou" : "member") };
    refreshCount();
    renderBasket();
  }

  function loadSuggestions() {
    if (suggestionsLoaded) return;
    suggestionsLoaded = true;
    var p = panel("zones");
    p.appendChild(el("p", "muted small", "Finding zone candidates…"));
    get("/suggestions").then(renderSuggestions).catch(function (e) {
      suggestionsLoaded = false;
      p.textContent = e.message;
    });
  }

  function renderSuggestions(d) {
    var p = panel("zones");
    p.appendChild(el("h2", "xp-name", "Suggested zones"));
    // The words come from the server, as `pathwarden zones suggest` prints them.
    p.appendChild(el("p", "muted small", d.intro + " Tick the ones to put in a zone, then create it."));
    var basketBox = el("div", "xp-basket card");
    basketBox.id = "xp-basket";
    p.appendChild(basketBox);
    var groups = {};
    d.items.forEach(function (s) { (groups[s.heuristic] = groups[s.heuristic] || []).push(s); });
    d.heuristics.forEach(function (h) {
      var items = groups[h.key] || [];
      section(p, h.title + " · " + num(items.length), h.about);
      if (!items.length) { p.appendChild(el("p", "muted small", "None in this run.")); return; }
      var ul = el("ul", "xp-objlist xp-sugg");
      items.forEach(function (s) {
        remember([s.node]);
        var extra = el("div", "xp-sugg-extra");
        var top = el("div", "xp-sugg-top");
        var lab = el("label", "xp-check");
        var cb = el("input");
        cb.type = "checkbox";
        cb.checked = !!basket[s.node.ix];
        cb.setAttribute("data-ix", s.node.ix);
        cb.addEventListener("change", function () { toggleBasket(s.node, s.adds_as); syncChecks(); });
        lab.appendChild(cb);
        lab.appendChild(document.createTextNode(" In the zone draft"));
        top.appendChild(lab);
        top.appendChild(el("span", "tag tier" + s.tier, "Tier " + s.tier));
        s.zones.forEach(function (z) { top.appendChild(el("span", "tag zone-tag", "Zone: " + z)); });
        extra.appendChild(top);
        extra.appendChild(el("p", "xp-reason", s.reason));
        ul.appendChild(objectRow(s.node, extra));
      });
      p.appendChild(ul);
    });
    renderBasket();
  }

  function syncChecks() {
    document.querySelectorAll(".xp-sugg input[type=checkbox]").forEach(function (cb) {
      cb.checked = !!basket[cb.getAttribute("data-ix")];
    });
  }

  function renderBasket() {
    var box = $("xp-basket");
    if (!box) return;
    box.textContent = "";
    var ixs = Object.keys(basket);
    var h = el("h3", "xp-h first", "Zone draft · " + num(ixs.length));
    box.appendChild(h);
    if (!ixs.length) {
      box.appendChild(el("p", "muted small", "Tick suggestions below, or use “Add to zone draft” on any object."));
      return;
    }
    var ul = el("ul", "xp-picks");
    ixs.forEach(function (ix) {
      var b = basket[ix];
      var li = el("li");
      li.appendChild(el("span", "xp-pick-name", b.name));
      li.appendChild(el("span", "muted small", b.as === "group" ? "Group and everyone in it" : b.as === "ou" ? "OU and everything below it" : "Just this object"));
      var x = el("button", "fl-remove", "×");
      x.type = "button";
      x.setAttribute("aria-label", "Remove " + b.name);
      x.addEventListener("click", function () { delete basket[ix]; refreshCount(); renderBasket(); syncChecks(); });
      li.appendChild(x);
      ul.appendChild(li);
    });
    box.appendChild(ul);
    var row = el("div", "xp-basket-go");
    var name = el("input", "input");
    name.id = "xp-zone-name";
    name.maxLength = 100;
    name.value = suggestName();
    name.setAttribute("aria-label", "Zone name");
    row.appendChild(name);
    row.appendChild(button("Create zone from these", "primary", function () { createZone(name.value); },
      "Opens a new zone with these. Nothing is saved yet."));
    box.appendChild(row);
    box.appendChild(el("p", "muted small", "Opens a new zone with these. Nothing is saved yet."));
  }

  function refreshCount() {
    var count = Object.keys(basket).length;
    var c = $("xp-basket-count");
    c.hidden = count === 0;
    c.textContent = num(count);
  }

  function suggestName() {
    var tier2 = document.querySelectorAll(".xp-sugg input:checked").length > 0 &&
      Array.prototype.every.call(document.querySelectorAll(".xp-sugg input:checked"), function (cb) {
        var li = cb.closest("li");
        return li && li.querySelector(".tag.tier2");
      });
    return tier2 ? "Tier 2 candidates" : "Tier 1 candidates";
  }

  function createZone(name) {
    var body = { name: (name || "").trim() || "Tier 1 candidates", members: [], groups: [], ous: [] };
    Object.keys(basket).forEach(function (ix) {
      var b = basket[ix];
      (b.as === "group" ? body.groups : b.as === "ou" ? body.ous : body.members).push(b.name);
    });
    fetch("/api/zones/draft", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j.error || "Couldn't open the new zone. Try again.");
        location.href = j.url;
      });
    }).catch(fail);
  }

  // ------------------------------------------------------------ list mode
  function setMode(m) {
    var was = mode;
    mode = m;
    document.querySelectorAll('input[name="xp-mode"]').forEach(function (i) { i.checked = i.value === m; });
    $("xp-cy").hidden = m !== "graph";
    $("xp-list").hidden = m !== "list";
    $("fm").hidden = m !== "forest";
    root.classList.toggle("listing", m === "list");
    // The Forest view has its own strip, legend and tabs.
    var forest = m === "forest";
    root.classList.toggle("foresting", forest);
    $("xp-pager").hidden = forest;
    $("fm-strip").hidden = !forest;
    $("xp-legend").hidden = forest;
    $("fm-legend").hidden = !forest;
    $("xt-trust").hidden = !forest;
    ["finding", "reach", "zones"].forEach(function (t) { $("xt-" + t).hidden = forest; });
    $("xp-empty").hidden = forest || cy.nodes().length > 0;
    if (forest) {
      $("xp-dense").hidden = true;
      $("xp-filter").hidden = true;
      root.classList.remove("noted");
      showForest();
    } else if (was === "forest") {
      // Back to the object graph: its panels again.
      if (focus != null && known[focus]) { showTab("object"); renderObject(focus); }
      else { panel("object"); showTab(current ? "finding" : "findings"); }
      applyDomainFilter();
      setUrl(current ? current.finding.fp : null, current ? null : focus);
    }
    if (m === "list") renderList();
    else if (m === "graph") { cy.resize(); if (cy.nodes().length) fit(); }
    updateTools();
    carryView();
  }
  document.querySelectorAll('input[name="xp-mode"]').forEach(function (i) {
    i.addEventListener("change", function () {
      if (i.value === "graph") forceGraph = true;
      setMode(i.value);
    });
  });

  function table(cols) {
    var t = el("table", "xp-table");
    var tr = el("tr");
    cols.forEach(function (c) { tr.appendChild(el("th", null, c)); });
    var thead = el("thead");
    thead.appendChild(tr);
    t.appendChild(thead);
    var tb = el("tbody");
    t.appendChild(tb);
    return t;
  }

  function nameCell(n) {
    var td = el("td", "xp-tname");
    var b = el("button", "linkish");
    b.type = "button";
    b.appendChild(kindIcon(n));
    b.appendChild(el("span", "xp-tn", n.name));
    b.title = n.name;
    b.addEventListener("click", function () { select(n.ix); });
    td.appendChild(b);
    if (n.t0) td.appendChild(el("span", "tag t0", "Tier Zero"));
    return td;
  }

  function renderList() {
    var box = $("xp-list");
    box.textContent = "";
    if (cy.nodes().empty()) { box.appendChild(el("p", "muted", "Nothing on the graph yet.")); return; }
    var edges = cy.edges().map(function (e) {
      return { s: Number(e.source().data("ix")), t: Number(e.target().data("ix")), k: e.data("kind"), inh: e.data("inh"), path: e.hasClass("path") };
    });
    var groupBy = function (list, key) {
      var g = {};
      list.forEach(function (e) { (g[e.k] = g[e.k] || []).push(e[key]); });
      return g;
    };
    var grouped = function (title, g) {
      var kinds = Object.keys(g).sort(function (a, b) { return g[b].length - g[a].length; });
      if (!kinds.length) return;
      box.appendChild(el("h3", "xp-h", title));
      kinds.forEach(function (k) {
        var t = table([k + " · " + num(g[k].length), "Kind", "Domain"]);
        g[k].forEach(function (ix) {
          var n = known[ix];
          var tr = el("tr");
          tr.appendChild(nameCell(n));
          tr.appendChild(el("td", null, kindLabel(n.kind)));
          tr.appendChild(el("td", "muted", n.domain || ""));
          t.tBodies[0].appendChild(tr);
        });
        box.appendChild(t);
      });
    };
    if (focus != null && known[focus]) {
      var n = known[focus];
      var head = el("div", "xp-listhead");
      head.appendChild(kindIcon(n));
      head.appendChild(el("strong", null, n.name));
      box.appendChild(head);
      grouped("Inbound: who has rights over it", groupBy(edges.filter(function (e) { return e.t === focus; }), "s"));
      grouped("Outbound: what it has rights over", groupBy(edges.filter(function (e) { return e.s === focus; }), "t"));
      var more = el("p", "muted small");
      var b = el("button", "linkish", "Who can reach it");
      b.type = "button";
      b.addEventListener("click", function () { loadReach(focus, 0, null); });
      more.appendChild(b);
      more.appendChild(document.createTextNode(" lists every object with a route to it, unprivileged users first."));
      box.appendChild(more);
    }
    box.appendChild(el("h3", "xp-h", "Relationships on the graph · " + num(edges.length)));
    var t = table(["From", "Relationship", "To"]);
    t.classList.add("rel");
    edges.sort(function (a, b) { return (b.path - a.path) || a.k.localeCompare(b.k); }).forEach(function (e) {
      var tr = el("tr");
      if (e.path) tr.className = "on-path";
      tr.appendChild(nameCell(known[e.s]));
      var k = el("td");
      k.appendChild(el("code", null, e.k));
      if (e.inh) k.appendChild(el("span", "muted small", " inherited"));
      tr.appendChild(k);
      tr.appendChild(nameCell(known[e.t]));
      t.tBodies[0].appendChild(tr);
    });
    box.appendChild(t);
    box.appendChild(el("h3", "xp-h", "Objects on the graph · " + num(cy.nodes().length)));
    var t2 = table(["Name", "Kind", "Domain"]);
    cy.nodes().map(function (x) { return known[x.data("ix")]; }).sort(function (a, b) {
      return (a.t0 - b.t0) || a.name.localeCompare(b.name);
    }).forEach(function (n) {
      var tr = el("tr");
      tr.appendChild(nameCell(n));
      tr.appendChild(el("td", null, kindLabel(n.kind)));
      tr.appendChild(el("td", "muted", n.domain || ""));
      t2.tBodies[0].appendChild(tr);
    });
    box.appendChild(t2);
  }

  // ------------------------------------------------------------ tools
  function updateTools() {
    var sel = cy.nodes(":selected");
    var between = document.querySelector('[data-tool="between"]');
    between.disabled = sel.length !== 2;
    document.querySelectorAll('[data-tool="fit"],[data-tool="in"],[data-tool="out"],[data-tool="layout"]').forEach(function (b) {
      b.disabled = mode === "list";
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = el("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(new Error("copy failed")); } catch (e) { reject(e); }
      ta.remove();
    });
  }

  document.querySelectorAll("[data-tool]").forEach(function (b) {
    b.addEventListener("click", function () {
      var t = b.getAttribute("data-tool");
      if (mode === "forest") { forestTool(t); return; }
      if (t === "fit") fit();
      else if (t === "in" || t === "out") {
        cy.zoom({ level: cy.zoom() * (t === "in" ? 1.25 : 0.8), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
      } else if (t === "layout") tidy(cy.nodes(".start"));
      else if (t === "clear") {
        clearGraph();
        current = null;
        domainFilter = null;
        // The panels describe what was on the graph: empty them too.
        panel("finding");
        panel("object");
        updatePager();
        afterChange();
        setUrl(null, null);
      } else if (t === "between") {
        var sel = cy.nodes(":selected");
        // In the order they were picked; pathTo tries the reverse too.
        if (sel.length === 2) {
          var a = picked.filter(function (ix) { return sel.some(function (n) { return n.data("ix") === ix; }); });
          if (a.length !== 2) a = [sel[0].data("ix"), sel[1].data("ix")];
          pathTo(a[0], String(a[1]), 1, true);
        }
      } else if (t === "copy") {
        var nodes = cy.nodes(":selected");
        if (nodes.empty()) nodes = cy.nodes();
        var names = nodes.map(function (n) { return known[n.data("ix")].name; });
        if (!names.length) { toast("Nothing to copy."); return; }
        copyText(names.join("\n")).then(function () {
          toast("Copied " + plural(names.length, "name", "names") + ".");
        }, function () { toast("Couldn't copy to the clipboard."); });
      }
    });
  });

  // ------------------------------------------------------------ search
  var q = $("xp-q"), results = $("xp-results"), searchTimer = null, searchSeq = 0;
  function closeResults() { results.hidden = true; q.setAttribute("aria-expanded", "false"); }
  q.addEventListener("input", function () {
    clearTimeout(searchTimer);
    var text = q.value.trim();
    if (!text) { closeResults(); return; }
    searchTimer = setTimeout(function () {
      var seq = ++searchSeq;
      get("/search", { q: text }).then(function (d) {
        if (seq !== searchSeq) return;
        results.textContent = "";
        if (!d.results.length) {
          results.appendChild(el("li", "muted small xp-noresult", "No objects match."));
        }
        d.results.forEach(function (n, i) {
          var li = el("li");
          li.setAttribute("role", "option");
          li.id = "xp-r" + i;
          var b = el("button", "xp-result");
          b.type = "button";
          b.appendChild(kindIcon(n));
          var t = el("span", "xp-obj-text");
          t.appendChild(el("span", "xp-obj-name", n.name));
          t.appendChild(el("span", "xp-obj-sub", kindLabel(n.kind) + (n.domain ? " · " + n.domain : "")));
          b.appendChild(t);
          if (n.t0) b.appendChild(el("span", "tag t0", "Tier Zero"));
          b.addEventListener("click", function () { closeResults(); q.value = ""; openObject(n); });
          li.appendChild(b);
          results.appendChild(li);
        });
        results.hidden = false;
        q.setAttribute("aria-expanded", "true");
      }).catch(fail);
    }, 140);
  });
  q.addEventListener("keydown", function (e) {
    var buttons = results.querySelectorAll("button");
    if (e.key === "Escape") closeResults();
    else if (e.key === "Enter" && buttons.length && !results.hidden) { e.preventDefault(); buttons[0].click(); }
    else if (e.key === "ArrowDown" && buttons.length) { e.preventDefault(); buttons[0].focus(); }
  });
  results.addEventListener("keydown", function (e) {
    var buttons = Array.prototype.slice.call(results.querySelectorAll("button"));
    var i = buttons.indexOf(document.activeElement);
    if (e.key === "ArrowDown" && i < buttons.length - 1) { e.preventDefault(); buttons[i + 1].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); (i > 0 ? buttons[i - 1] : q).focus(); }
    else if (e.key === "Escape") { closeResults(); q.focus(); }
  });
  document.addEventListener("click", function (e) {
    if (!results.contains(e.target) && e.target !== q) closeResults();
  });

  // An object from search: on its own graph unless something is shown.
  function openObject(n) {
    if (current) { clearGraph(); current = null; updatePager(); }
    var fresh = cy.nodes().empty();
    reveal(n);
    if (fresh) expand(n.ix, "both", []);
  }

  // ------------------------------------------------------------ domain filter
  // "Explore <domain>" from the Forest view: the object graph, showing only
  // that domain's objects until "Show all".
  var domainFilter = null;
  function applyDomainFilter() {
    var note = $("xp-filter");
    if (!note) return;
    var d = domainFilter ? domainFilter.toUpperCase() : null;
    cy.nodes().forEach(function (x) {
      var n = known[x.data("ix")];
      var off = !!d && !!n && !!n.domain && n.domain.toUpperCase() !== d;
      if (off) x.addClass("offdom"); else x.removeClass("offdom");
    });
    queueBundles();
    note.hidden = !domainFilter || mode !== "graph";
    if (note.hidden) return;
    note.textContent = "";
    var hidden = cy.nodes(".offdom").length;
    note.appendChild(el("span", null, "Only objects of " + domainFilter + " are shown" +
      (hidden ? " (" + plural(hidden, "other object", "other objects") + " hidden). " : ". ")));
    var b = el("button", "linkish", "Show all");
    b.type = "button";
    b.addEventListener("click", function () { domainFilter = null; applyDomainFilter(); });
    note.appendChild(b);
  }

  // ------------------------------------------------------------ forest view
  // The run's domains by forest and each trust once (/explore/forest, the
  // map `pathwarden summary` prints), drawn as SVG: forests as dashed hulls,
  // domains as cards, trusts as lines with a label on each.
  var SVG = "http://www.w3.org/2000/svg";
  var FM = null;           // the map, with its headline
  var fmState = null;      // layout: positions, view box, selection
  var fmLoading = false;
  var CW = 268, CH = 100;  // a domain card
  // What each ⓘ says, and the other fixed words: from core
  // (pathwarden_core::forest::definitions), on the page as data-defs. Every
  // other word of the view comes with the map (its word fields).
  var DEF = {};
  try { DEF = JSON.parse(root.getAttribute("data-defs") || "{}"); } catch (e) {}
  function cap(s) { s = String(s || ""); return s.charAt(0).toUpperCase() + s.slice(1); }
  function roleText(d) { return cap(d.role_text || d.role); }

  function svg(tag, attrs, parent) {
    var e = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (parent) parent.appendChild(e);
    return e;
  }
  function svgText(parent, x, y, cls, text) {
    var t = svg("text", { x: x, y: y, "class": cls }, parent);
    if (text != null) t.textContent = text;
    return t;
  }
  function firstLabel(name) { return String(name).split(".")[0]; }
  // The flag a list of trusts tags it with (TrustFlag::is_tag).
  function tagOf(t) {
    var f = (t.flags || []).filter(function (x) { return x.kind === "takeover" || x.kind === "abuse" || x.kind === "unknown"; })[0];
    return f ? { text: f.kind === "takeover" ? f.text : f.text.replace(" · PW-012", ""), cls: { takeover: "fm-tag-t", abuse: "fm-tag-x", unknown: "fm-tag-u" }[f.kind] } : null;
  }
  function trustKind(t) { return t.intra_forest ? "c" : t.abusable_sid_history ? "x" : "m"; }
  function domainOf(name) {
    for (var i = 0; i < FM.domains.length; i++) if (FM.domains[i].name.toUpperCase() === String(name).toUpperCase()) return FM.domains[i];
    return null;
  }

  // An ⓘ: its words on hover and, on click or tap, in a bubble.
  function infoBtn(key, about) {
    var b = el("button", "fm-i", "i");
    b.type = "button";
    b.setAttribute("data-def", DEF[key] || key);
    b.title = DEF[key] || key;
    b.setAttribute("aria-label", "About: " + (about || "this"));
    return b;
  }
  var pop = null;
  function showDef(anchor, text) {
    if (!pop) {
      pop = el("div", "fm-pop card");
      pop.setAttribute("role", "tooltip");
      document.body.appendChild(pop);
    }
    if (!pop.hidden && pop.anchor === anchor) { pop.hidden = true; return; }
    pop.textContent = text;
    pop.anchor = anchor;
    pop.hidden = false;
    var r = anchor.getBoundingClientRect();
    var w = Math.min(320, window.innerWidth - 24);
    pop.style.width = w + "px";
    var left = Math.max(12, Math.min(window.innerWidth - w - 12, r.left + r.width / 2 - w / 2));
    pop.style.left = left + "px";
    var below = r.bottom + 8;
    pop.style.top = below + "px";
    var h = pop.offsetHeight;
    if (below + h > window.innerHeight - 8 && r.top - h - 8 > 0) pop.style.top = (r.top - h - 8) + "px";
  }
  document.addEventListener("click", function (e) {
    var t = e.target.closest ? e.target.closest(".fm-i, .fm-si") : null;
    if (t) {
      e.preventDefault();
      e.stopPropagation();
      showDef(t, t.getAttribute("data-def") || "");
    } else if (pop && !pop.hidden && !pop.contains(e.target)) {
      pop.hidden = true;
    }
  }, true);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && pop) { pop.hidden = true; return; }
    // An ⓘ in the map is SVG text: Enter or Space opens it, and nothing
    // under it (the trust or card) is selected too.
    var t = e.target && e.target.closest ? e.target.closest(".fm-si") : null;
    if (t && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      e.stopPropagation();
      showDef(t, t.getAttribute("data-def") || "");
    }
  }, true);
  // An ⓘ inside the map: focusable, a button by role, named for its term.
  function svgInfo(parent, x, y, key, about) {
    var ic = svg("text", { x: x, y: y, "class": "fm-si", tabindex: 0, role: "button", "aria-label": "About: " + about, "data-def": DEF[key] || "" }, parent);
    ic.textContent = "ⓘ";
    ic.appendChild(svg("title", {})).textContent = DEF[key] || "";
    return ic;
  }
  function svgInfoSpan(parent, key, about) {
    var ic = svg("tspan", { "class": "fm-si", tabindex: 0, role: "button", "aria-label": "About: " + about, "data-def": DEF[key] || "" }, parent);
    ic.textContent = "ⓘ";
    return ic;
  }
  window.addEventListener("scroll", function () { if (pop) pop.hidden = true; }, true);

  function showForest() {
    showTab("trust");
    setForestUrl();
    if (FM) { drawForest(false); return; }
    if (fmLoading) return;
    fmLoading = true;
    var box = $("fm");
    box.textContent = "";
    box.appendChild(el("p", "muted fm-wait", "Loading the domains and trusts…"));
    get("/forest").then(function (d) {
      fmLoading = false;
      FM = d;
      renderStrip();
      fmState = null;
      if (mode === "forest") drawForest(true);
      var pick = FM.headline.focus;
      if (pick != null) selectTrust(pick, true);
      else if (FM.domains.length) selectDomain(FM.domains[0].name, true);
      // A map too big to read whole opens around what is selected.
      if (mode === "forest" && fmState && fmState.content) { fmState.vb = fitBox(fmState); applyView(); }
    }).catch(function (e) {
      fmLoading = false;
      box.textContent = "";
      var note = el("div", "note fm-note");
      note.appendChild(el("p", null, e.message));
      box.appendChild(note);
      var p = panel("trust");
      p.appendChild(el("p", "muted small", e.message));
    });
  }
  function setForestUrl() {
    try { history.replaceState(null, "", location.pathname + "?view=forest"); } catch (e) {}
  }

  // The run and environment menus open the same view: they carry
  // ?view=forest while it is open.
  function carryView() {
    var forest = mode === "forest";
    document.querySelectorAll(".xp-crumb .run-picker a[href]").forEach(function (a) {
      var h = a.getAttribute("href").split("?")[0];
      a.setAttribute("href", forest ? h + "?view=forest" : h);
    });
    document.querySelectorAll(".xp-crumb .env-picker form[action]").forEach(function (f) {
      var act = f.getAttribute("action").replace(/&then=[^&]*/, "");
      f.setAttribute("action", act + "&then=" + encodeURIComponent(forest ? "/explore?view=forest" : "/explore"));
    });
  }

  function renderStrip() {
    var h = FM.headline;
    $("fm-lead").textContent = h.lead;
    $("fm-detail").textContent = " · " + h.detail;
    // Trusted domains not collected: collect them, from the chip.
    if (h.not_collected > 0) {
      var collect = el("a", "fm-collect", "Collect these domains");
      collect.href = "/runs/" + encodeURIComponent(RUN) + "/collect";
      $("fm-detail").appendChild(document.createTextNode(" "));
      $("fm-detail").appendChild(collect);
    }
    var tags = $("fm-status");
    tags.textContent = "";
    h.status.forEach(function (s) {
      tags.appendChild(el("span", "tag " + (s.kind === "abuse" ? "fm-tag-x" : s.kind === "unknown" ? "fm-tag-u" : "muted-tag"), s.text));
    });
  }

  // ---- layout
  function narrowCanvas() { return $("fm").clientWidth < 620 || window.innerWidth <= 760; }

  // Forests on a grid: the biggest (most trusts between forests on a tie)
  // first, each next one in a free cell beside the forest it trusts most,
  // right, then below, left, above; at most `cols` columns.
  function placeForests(cols) {
    var n = FM.forests.length;
    var links = [];
    for (var i = 0; i < n; i++) { links.push([]); for (var j = 0; j < n; j++) links[i].push(0); }
    FM.trusts.forEach(function (t) {
      var a = domainOf(t.source), b = domainOf(t.target);
      if (!a || !b || a.forest === b.forest) return;
      links[a.forest][b.forest]++;
      links[b.forest][a.forest]++;
    });
    var deg = function (f) { return links[f].reduce(function (s, x) { return s + x; }, 0); };
    var size = function (f) { return FM.forests[f].domains.length; };
    var order = [];
    var left = [];
    for (i = 0; i < n; i++) left.push(i);
    var cell = {}, at = {};
    var key = function (c, r) { return c + "," + r; };
    var free = function (c, r) { return c >= 0 && c < cols && !at[key(c, r)]; };
    while (left.length) {
      left.sort(function (a, b) {
        var la = order.reduce(function (s, f) { return s + links[a][f]; }, 0);
        var lb = order.reduce(function (s, f) { return s + links[b][f]; }, 0);
        return (lb - la) || (size(b) - size(a)) || (deg(b) - deg(a)) || FM.forests[a].name.localeCompare(FM.forests[b].name);
      });
      var f = left.shift();
      var spot = null;
      if (!order.length) spot = [0, 0];
      else {
        // Beside the placed forest it trusts most, else the nearest free cell.
        var anchor = order.slice().sort(function (a, b) { return links[f][b] - links[f][a]; })[0];
        if (links[f][anchor] > 0) {
          var ac = cell[anchor];
          [[1, 0], [0, 1], [-1, 0], [0, -1]].some(function (d) {
            if (free(ac[0] + d[0], ac[1] + d[1])) { spot = [ac[0] + d[0], ac[1] + d[1]]; return true; }
            return false;
          });
          if (!spot) {
            var best = null;
            for (var r = -n; r <= n; r++) for (var c = 0; c < cols; c++) {
              if (!free(c, r)) continue;
              var dist = Math.abs(c - ac[0]) + Math.abs(r - ac[1]);
              if (!best || dist < best[2]) best = [c, r, dist];
            }
            spot = [best[0], best[1]];
          }
        } else {
          for (r = 0; !spot; r++) for (c = 0; c < cols && !spot; c++) if (free(c, r)) spot = [c, r];
        }
      }
      cell[f] = spot;
      at[key(spot[0], spot[1])] = true;
      order.push(f);
    }
    cell.rank = {};
    order.forEach(function (f2, k) { cell.rank[f2] = k; });
    return cell;
  }

  // A forest's domains, root first, each child under its parent (by the
  // trusts inside the forest), then pulled up or down toward the forests
  // their other trusts lead to.
  function forestOrder(f, cell) {
    var names = FM.domains.filter(function (d) { return d.forest === f; }).map(function (d) { return d.name; });
    var adj = {};
    names.forEach(function (x) { adj[x] = []; });
    var pull = {};
    names.forEach(function (x) { pull[x] = 0; });
    FM.trusts.forEach(function (t) {
      var a = domainOf(t.source), b = domainOf(t.target);
      if (!a || !b) return;
      if (a.forest === f && b.forest === f) { adj[a.name].push(b.name); adj[b.name].push(a.name); }
      else if (a.forest === f) pull[a.name] += Math.sign(cell[b.forest][1] - cell[f][1]);
      else if (b.forest === f) pull[b.name] += Math.sign(cell[a.forest][1] - cell[f][1]);
    });
    var seen = {}, out = [];
    var visit = function (x) {
      if (seen[x]) return;
      seen[x] = true;
      out.push(x);
      adj[x].slice().sort().forEach(visit);
    };
    names.forEach(visit); // the core's order: the forest root first
    var pos = {};
    out.forEach(function (x, i) { pos[x] = i; });
    return out.sort(function (a, b) { return (pull[a] - pull[b]) || (pos[a] - pos[b]); });
  }

  // A one-column forest beside one placed before it, on the same row: its
  // domains trusted across move level with their partners, so the lines
  // run straight across.
  function alignOrder(f, cell, orders) {
    var order = orders[f];
    var want = {};
    FM.trusts.forEach(function (t) {
      var a = domainOf(t.source), b = domainOf(t.target);
      if (!a || !b || a.forest === b.forest) return;
      var mine = a.forest === f ? a : b.forest === f ? b : null;
      if (!mine) return;
      var other = mine === a ? b : a;
      if (cell[other.forest][1] !== cell[f][1] || cell.rank[other.forest] > cell.rank[f]) return;
      if (orders[other.forest].length > 3) return;
      if (want[mine.name] == null) want[mine.name] = Math.min(order.length - 1, orders[other.forest].indexOf(other.name));
    });
    if (!Object.keys(want).length || order.length > 3) return order;
    var out = new Array(order.length);
    order.forEach(function (n) { if (want[n] != null && out[want[n]] == null) out[want[n]] = n; });
    var rest = order.filter(function (n) { return out.indexOf(n) < 0; });
    for (var k = 0; k < out.length; k++) if (out[k] == null) out[k] = rest.shift();
    return out;
  }

  function layoutForest() {
    var narrow = narrowCanvas();
    var cols = narrow ? 1 : FM.forests.length > 4 ? 3 : 2;
    var cell = placeForests(cols);
    var PAD = 22, HEAD = 58, VGAP = 140, IN_GAP = 64, FGAP = narrow ? 150 : 200, FVGAP = 150;
    // Each forest's block: its domains in one column, or two when many.
    var orders = FM.forests.map(function (f, i) { return forestOrder(i, cell); });
    FM.forests.map(function (f, i) { return i; })
      .sort(function (a, b) { return cell.rank[a] - cell.rank[b]; })
      .forEach(function (i) { if (!narrow) orders[i] = alignOrder(i, cell, orders); });
    var blocks = FM.forests.map(function (f, i) {
      var order = orders[i];
      var per = narrow || order.length <= 3 ? 1 : 2;
      var rows = Math.ceil(order.length / per);
      return {
        order: order, per: per,
        w: per * CW + (per - 1) * IN_GAP + 2 * PAD,
        h: HEAD + rows * CH + (rows - 1) * VGAP + PAD
      };
    });
    var colW = {}, rowH = {}, minR = 0, maxR = 0;
    blocks.forEach(function (b, i) {
      var c = cell[i][0], r = cell[i][1];
      colW[c] = Math.max(colW[c] || 0, b.w);
      rowH[r] = Math.max(rowH[r] || 0, b.h);
      minR = Math.min(minR, r); maxR = Math.max(maxR, r);
    });
    var colX = {}, x = 0;
    for (var c = 0; c < cols; c++) { colX[c] = x; x += (colW[c] || 0) + (colW[c] ? FGAP : 0); }
    var rowY = {}, y = 0;
    for (var r = minR; r <= maxR; r++) { rowY[r] = y; y += (rowH[r] || 0) + (rowH[r] ? FVGAP : 0); }
    var pos = {};
    var hulls = blocks.map(function (b, i) {
      var c = cell[i][0], r = cell[i][1];
      var hx = colX[c] + ((colW[c] || b.w) - b.w) / 2, hy = rowY[r];
      b.order.forEach(function (name, k) {
        var col = k % b.per, row = Math.floor(k / b.per);
        pos[name] = { x: hx + PAD + col * (CW + IN_GAP) + CW / 2, y: hy + HEAD + row * (CH + VGAP) + CH / 2 };
      });
      return { f: i, x: hx, y: hy, w: b.w, h: b.h };
    });
    return { pos: pos, hulls: hulls, narrow: narrow };
  }

  // Hulls follow their cards (they move when a card is dragged).
  function hullsOf(st) {
    var PAD = 22, HEAD = 58;
    return FM.forests.map(function (f, i) {
      var ds = FM.domains.filter(function (d) { return d.forest === i; });
      var x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
      ds.forEach(function (d) {
        var p = st.pos[d.name];
        x1 = Math.min(x1, p.x - CW / 2); x2 = Math.max(x2, p.x + CW / 2);
        y1 = Math.min(y1, p.y - CH / 2); y2 = Math.max(y2, p.y + CH / 2);
      });
      return { f: i, x: x1 - PAD, y: y1 - HEAD, w: x2 - x1 + 2 * PAD, h: y2 - y1 + HEAD + PAD };
    });
  }

  // ---- geometry
  function rectOf(p, pad) { return { x1: p.x - CW / 2 - pad, y1: p.y - CH / 2 - pad, x2: p.x + CW / 2 + pad, y2: p.y + CH / 2 + pad }; }
  function overlaps(a, b) { return a.x1 < b.x2 && b.x1 < a.x2 && a.y1 < b.y2 && b.y1 < a.y2; }
  // Where the line from `a` toward `b` leaves a's card.
  function clip(a, b, pad) {
    var dx = b.x - a.x, dy = b.y - a.y;
    var t = Math.min(dx ? (CW / 2 + pad) / Math.abs(dx) : 1e9, dy ? (CH / 2 + pad) / Math.abs(dy) : 1e9);
    return { x: a.x + dx * t, y: a.y + dy * t };
  }
  function segHitsRect(p, q, r) {
    // Sampled: cards are large next to the step.
    for (var i = 1; i < 40; i++) {
      var t = i / 40, x = p.x + (q.x - p.x) * t, y = p.y + (q.y - p.y) * t;
      if (x > r.x1 && x < r.x2 && y > r.y1 && y < r.y2) return true;
    }
    return false;
  }
  function bez(p, c1, c2, q, t) {
    var u = 1 - t;
    return {
      x: u * u * u * p.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t * t * t * q.x,
      y: u * u * u * p.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t * t * t * q.y
    };
  }

  // A trust's route: straight between the cards, or around the right of
  // any card in the way. `at(t)` is a point on it, for its label.
  function route(t, st) {
    var a = st.pos[t.source], b = st.pos[t.target];
    if (!a || !b) return null;
    var da = domainOf(t.source), db = domainOf(t.target);
    var between = da && db && da.forest !== db.forest;
    // Nearly one above the other across forests: off center, clear of the
    // lower forest's name.
    if (between && Math.abs(a.x - b.x) < CW / 2) {
      a = { x: a.x + CW * 0.2, y: a.y };
      b = { x: b.x + CW * 0.2, y: b.y };
    }
    var p = clip(st.pos[t.source], b, 7), q = clip(st.pos[t.target], a, 7);
    if (between && Math.abs(st.pos[t.source].x - st.pos[t.target].x) < CW / 2) {
      p = { x: a.x, y: a.y + Math.sign(b.y - a.y) * (CH / 2 + 7) };
      q = { x: b.x, y: b.y + Math.sign(a.y - b.y) * (CH / 2 + 7) };
    }
    var blocked = Object.keys(st.pos).some(function (n) {
      if (n.toUpperCase() === t.source.toUpperCase() || n.toUpperCase() === t.target.toUpperCase()) return false;
      return segHitsRect(p, q, rectOf(st.pos[n], 10));
    });
    if (!blocked) {
      return {
        d: "M" + p.x.toFixed(1) + " " + p.y.toFixed(1) + "L" + q.x.toFixed(1) + " " + q.y.toFixed(1),
        at: function (s) { return { x: p.x + (q.x - p.x) * s, y: p.y + (q.y - p.y) * s }; }
      };
    }
    // Around: out of the right of each card, past every card between.
    var A = st.pos[t.source], B = st.pos[t.target];
    var lo = Math.min(A.y, B.y), hi = Math.max(A.y, B.y), right = Math.max(A.x, B.x) + CW / 2;
    Object.keys(st.pos).forEach(function (n) {
      var c = st.pos[n];
      if (c.y + CH / 2 >= lo - CH / 2 && c.y - CH / 2 <= hi + CH / 2) right = Math.max(right, c.x + CW / 2);
    });
    var bx = right + 90;
    st.bendX = Math.max(st.bendX, right + 70);
    var P = { x: A.x + CW / 2 + 7, y: A.y }, Q = { x: B.x + CW / 2 + 7, y: B.y };
    var c1 = { x: bx, y: P.y }, c2 = { x: bx, y: Q.y };
    return {
      d: "M" + P.x.toFixed(1) + " " + P.y.toFixed(1) + "C" + c1.x.toFixed(1) + " " + c1.y.toFixed(1) + " " + c2.x.toFixed(1) + " " + c2.y.toFixed(1) + " " + Q.x.toFixed(1) + " " + Q.y.toFixed(1),
      at: function (s) { return bez(P, c1, c2, Q, s); }
    };
  }

  // Where a w×h label goes on route `r`: along the line clear of cards and
  // labels; else beside the line (either side, a step further each time);
  // else anywhere along or beside it clear of cards. Never over a card.
  function labelSpot(r, w, h, taken, cards) {
    var along = [0.5, 0.42, 0.58, 0.35, 0.65, 0.28, 0.72, 0.2, 0.8, 0.14, 0.86, 0.08, 0.92];
    var box = function (m) { return { x1: m.x - w / 2, y1: m.y - h / 2, x2: m.x + w / 2, y2: m.y + h / 2 }; };
    var beside = function (f, k) {
      var a = r.at(Math.max(0, f - 0.02)), b = r.at(Math.min(1, f + 0.02)), m = r.at(f);
      var dx = b.x - a.x, dy = b.y - a.y, len = Math.sqrt(dx * dx + dy * dy) || 1;
      var nx = -dy / len, ny = dx / len;
      var step = Math.abs(nx) * (w / 2 + 8) + Math.abs(ny) * (h / 2 + 8);
      return { x: m.x + nx * step * k, y: m.y + ny * step * k };
    };
    var clear = function (b, list) { return !list.some(function (o) { return overlaps(o, b); }); };
    var tries = [];
    along.forEach(function (f) { tries.push(r.at(f)); });
    [1, -1, 2, -2, 3, -3, 4, -4].forEach(function (k) { along.forEach(function (f) { tries.push(beside(f, k)); }); });
    for (var i = 0; i < tries.length; i++) if (clear(box(tries[i]), taken)) return box(tries[i]);
    // Crowded: clear of cards, over as few labels as can be.
    var best = null, fewest = Infinity;
    tries.forEach(function (m) {
      var b = box(m);
      if (!clear(b, cards)) return;
      var n = taken.filter(function (o) { return overlaps(o, b); }).length;
      if (n < fewest) { fewest = n; best = b; }
    });
    return best || box(beside(0.5, 5));
  }

  // A label's lines: the trust's kind and way, then its flags (TrustFlag,
  // from core), each with its ⓘ.
  var FLAG_LOOK = {
    takeover: ["fm-lt-t", "takeover"], not_collected: ["fm-lt-m", null], abuse: ["fm-lt-x", "sidhist"],
    unknown: ["fm-lt-u", "unknown"], filtering_on: ["fm-lt-m", null], filtering_off: ["fm-lt-x", null],
    filtering_unknown: ["fm-lt-m", "unknown"]
  };
  function labelLines(t) {
    var lines = [{ text: t.trust_type + " · " + t.way_word, cls: "fm-lt" }];
    (t.flags || []).forEach(function (f) {
      var look = FLAG_LOOK[f.kind] || ["fm-lt-m", null];
      lines.push({ text: f.text, cls: look[0], def: look[1] });
    });
    return lines;
  }
  var measureCtx = null;
  function textWidth(s, font) {
    if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
    measureCtx.font = font;
    return measureCtx.measureText(s).width;
  }
  var FONT = getComputedStyle(document.body).fontFamily || "sans-serif";
  var DISPLAY = getComputedStyle(document.documentElement).getPropertyValue("--display").trim() || FONT;

  // ---- drawing
  function drawForest(fresh) {
    var box = $("fm");
    if (!FM) return;
    if (!fmState || fresh || !fmState.layout) {
      var l = layoutForest();
      fmState = { pos: l.pos, narrow: l.narrow, layout: true, sel: fmState ? fmState.sel : null, vb: null, svg: fmState ? fmState.svg : null };
    }
    var st = fmState;
    st.tall = window.innerWidth <= 760;
    if (!FM.domains.length) {
      box.textContent = "";
      box.appendChild(el("p", "muted fm-wait", "This run has no domains to map."));
      return;
    }
    // One <svg>, redrawn in place: a card being dragged keeps the pointer.
    var s = st.svg;
    if (!s || s.parentNode !== box) {
      box.textContent = "";
      s = svg("svg", { "class": "fm", role: "group", "aria-label": "Domains by forest, and their trusts" }, box);
      st.svg = s;
      wireCanvas(s);
    }
    while (s.firstChild) s.removeChild(s.firstChild);
    st.bendX = -Infinity;
    st.labels = {};
    var defs = svg("defs", {}, s);
    ["c", "x", "m"].forEach(function (k) {
      var m = svg("marker", { id: "fm-ah-" + k, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" }, defs);
      svg("path", { d: "M0 0L10 5L0 10z", "class": "fm-ah-" + k }, m);
    });
    var hulls = hullsOf(st);
    hulls.forEach(function (h) {
      var g = svg("g", { "class": "fm-hull" }, s);
      svg("rect", { x: h.x, y: h.y, width: h.w, height: h.h, rx: 22 }, g);
      var name = "FOREST · " + FM.forests[h.f].name;
      var lab = svgText(g, h.x + 18, h.y + 26, "fm-hull-label", fitText(name, h.w - 36, "700 11px " + DISPLAY, 0.09 * 11));
      lab.appendChild(svg("title", {})).textContent = name;
      svgText(g, h.x + 18, h.y + 43, "fm-meta", plural(FM.forests[h.f].domains.length, "domain", "domains"));
    });
    var edgeLayer = svg("g", {}, s);
    var cardLayer = svg("g", {}, s);
    var labelLayer = svg("g", {}, s);
    var cards = Object.keys(st.pos).map(function (n) { return rectOf(st.pos[n], 4); });
    var taken = cards.slice();
    FM.trusts.forEach(function (t, i) {
      var r = route(t, st);
      if (!r) return;
      var kind = trustKind(t);
      var into = {};
      t.ways.forEach(function (w) { into[w.to.toUpperCase()] = true; });
      var sel = st.sel && st.sel.trust === i;
      var attrs = { d: r.d, "class": "fm-e fm-e-" + kind + (t.ways.length ? "" : " fm-e-off") + (sel ? " sel" : "") };
      if (into[t.source.toUpperCase()]) attrs["marker-start"] = "url(#fm-ah-" + kind + ")";
      if (into[t.target.toUpperCase()]) attrs["marker-end"] = "url(#fm-ah-" + kind + ")";
      attrs["data-trust"] = i;
      var path = svg("path", attrs, edgeLayer);
      // A wide, invisible stroke to click.
      var hit = svg("path", { d: r.d, "class": "fm-hit" }, edgeLayer);
      hit.addEventListener("click", function () { selectTrust(i); });
      path.addEventListener("click", function () { selectTrust(i); });
      // The label, on the line: the middle, or slid along it clear of
      // cards and other labels; failing that, beside the line, and never
      // over a card.
      var lines = labelLines(t);
      var w = 0;
      lines.forEach(function (ln) { w = Math.max(w, textWidth(ln.text, (ln.cls === "fm-lt" ? "600 11.5px " + FONT : "700 11px " + DISPLAY)) + (ln.def ? 18 : 0)); });
      w += 26;
      var h = 20 * lines.length + 10;
      var spot = labelSpot(r, w, h, taken, cards);
      taken.push(spot);
      st.labels[i] = spot;
      var g = svg("g", { "class": "fm-elabel " + kind + (sel ? " sel" : ""), transform: "translate(" + spot.x1.toFixed(1) + "," + spot.y1.toFixed(1) + ")", tabindex: 0, role: "button",
        "data-trust": i, "aria-label": "Trust " + t.source + " and " + t.target + ": " + lines.map(function (x) { return x.text; }).join(", ") }, labelLayer);
      svg("rect", { width: w.toFixed(1), height: h, rx: 9 }, g);
      lines.forEach(function (ln, k) {
        var tx = svgText(g, w / 2 - (ln.def ? 9 : 0), 20 + 20 * k, ln.cls, ln.text);
        tx.setAttribute("text-anchor", "middle");
        if (ln.def) {
          var tw = textWidth(ln.text, ln.cls === "fm-lt" ? "600 11.5px " + FONT : "700 11px " + DISPLAY);
          svgInfo(g, w / 2 - 9 + tw / 2 + 4, 20 + 20 * k, ln.def, ln.text.replace(" · PW-012", ""));
        }
      });
      g.addEventListener("click", function (e) { if (!e.target.closest(".fm-si")) selectTrust(i); });
      g.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectTrust(i); } });
    });
    FM.domains.forEach(function (d) { drawCard(cardLayer, d, st); });
    st.content = contentBox(st, hulls, taken);
    if (!st.vb) st.vb = fitBox(st);
    applyView();
  }

  // `s`, shortened with an ellipsis to fit `max` pixels.
  function fitText(s, max, font, spacing) {
    var width = function (x) { return textWidth(x, font) + (spacing || 0) * x.length; };
    if (width(s) <= max) return s;
    while (s.length > 1 && width(s + "…") > max) s = s.slice(0, -1);
    return s + "…";
  }

  function drawCard(layer, d, st) {
    var p = st.pos[d.name];
    var sel = st.sel && st.sel.domain && st.sel.domain.toUpperCase() === d.name.toUpperCase();
    var g = svg("g", { "class": "fm-node" + (d.collected ? "" : " dim") + (sel ? " sel" : ""), transform: "translate(" + (p.x - CW / 2) + "," + (p.y - CH / 2) + ")",
      tabindex: 0, role: "button", "aria-label": d.name + ", " + d.role_text }, layer);
    g.setAttribute("data-domain", d.name);
    svg("rect", { width: CW, height: CH, rx: 14 }, g);
    var glyphG = svg("g", { transform: "translate(14,14)", "class": "fm-glyph" }, g);
    svg("circle", { cx: 11, cy: 11, r: 10 }, glyphG);
    svg("path", { d: "M1 11h20M11 1c3 3 4.5 6.5 4.5 10S14 18 11 21M11 1C8 4 6.5 7.5 6.5 11S8 18 11 21" }, glyphG);
    var name = svgText(g, 44, 26, "fm-name", fitText(d.name, CW - 56, "700 13.5px " + DISPLAY));
    name.appendChild(svg("title", {})).textContent = d.name;
    var role = roleText(d);
    if (!d.collected) {
      svgText(g, 44, 44, "fm-meta", role);
      var tn = svgText(g, 14, 80, "fm-expo", (d.note || "") + " ");
      svgInfoSpan(tn, "not_collected", "not collected");
      return;
    }
    svgText(g, 44, 44, "fm-meta", fitText(role + " · " + plural(d.users, "user", "users") + " · " + plural(d.computers, "computer", "computers"), CW - 56, "11.5px " + FONT));
    if (!d.paths) {
      svgText(g, 14, 78, "fm-meta", d.note || "");
      return;
    }
    // The count leads; the percentage is secondary.
    var ex = svgText(g, 14, 72, "fm-expo");
    var num1 = svg("tspan", { "class": "fm-num" }, ex);
    num1.textContent = d.paths.count + " ";
    svgInfoSpan(ex, "attack", "attack paths");
    svgText(g, 14, 89, "fm-meta", d.paths.tail + " (" + d.paths.percent + ")");
  }

  function contentBox(st, hulls, labels) {
    var x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
    hulls.forEach(function (h) { x1 = Math.min(x1, h.x); y1 = Math.min(y1, h.y); x2 = Math.max(x2, h.x + h.w); y2 = Math.max(y2, h.y + h.h); });
    labels.forEach(function (b) { x1 = Math.min(x1, b.x1); y1 = Math.min(y1, b.y1); x2 = Math.max(x2, b.x2); y2 = Math.max(y2, b.y2); });
    // Routes around cards bend out to the right.
    x2 = Math.max(x2, st.bendX);
    return { x: x1, y: y1, w: x2 - x1, h: y2 - y1 };
  }
  // The whole map, padded.
  function fullBox(st) {
    var c = st.content, pad = 16;
    return { x: c.x - pad, y: c.y - pad, w: c.w + 2 * pad, h: c.h + 2 * pad };
  }
  // Below this scale text is too small to read: the view shows part of
  // the map at it (around the selection, else from the map's top left),
  // and panning or "-" shows the rest.
  var MIN_SCALE = 0.6;
  // On a phone the map is shown whole at its own height up to this; taller,
  // it scrolls in a box of its own.
  var PHONE_MAX = 3000;
  function canvasSize() {
    var b = $("fm");
    return { w: b.clientWidth || 600, h: b.clientHeight || 500 };
  }
  function fitBox(st) {
    var full = fullBox(st);
    if (st.tall) return full;
    var c = canvasSize();
    var scale = Math.min(c.w / full.w, c.h / full.h);
    if (scale >= MIN_SCALE) return full;
    var w = c.w / MIN_SCALE, h = c.h / MIN_SCALE;
    var at = focusPoint(st);
    var x = at ? at.x - w / 2 : full.x, y = at ? at.y - h / 2 : full.y;
    x = Math.max(full.x, Math.min(x, full.x + full.w - w));
    y = Math.max(full.y, Math.min(y, full.y + full.h - h));
    return { x: x, y: y, w: w, h: h };
  }
  // The selected domain, or the selected trust's label (where drawn; else
  // the middle of its route, which may bend around cards).
  function focusPoint(st) {
    var sel = st.sel || {};
    if (sel.domain && st.pos[sel.domain]) return st.pos[sel.domain];
    var t = sel.trust != null && FM ? FM.trusts[sel.trust] : null;
    if (!t) return null;
    var b = st.labels && st.labels[sel.trust];
    if (b) return { x: (b.x1 + b.x2) / 2, y: (b.y1 + b.y2) / 2 };
    var r = route(t, st);
    return r ? r.at(0.5) : null;
  }
  function applyView() {
    var st = fmState;
    if (!st || !st.svg || !st.vb) return;
    var vb = st.vb;
    st.svg.setAttribute("viewBox", vb.x.toFixed(1) + " " + vb.y.toFixed(1) + " " + vb.w.toFixed(1) + " " + vb.h.toFixed(1));
    var box = $("fm");
    if (st.tall) {
      // On a phone the whole map, at its own height: the page scrolls, or
      // past PHONE_MAX the map's own box does.
      var w = box.clientWidth || 360;
      var h = Math.round(w * vb.h / vb.w);
      st.svg.style.height = h + "px";
      box.classList.toggle("fm-scroll", h > PHONE_MAX);
    } else {
      st.svg.style.height = "";
      box.classList.remove("fm-scroll");
    }
    // Say so when only part of the map is in view.
    var full = fullBox(st);
    var part = !st.tall && (vb.x > full.x + 1 || vb.y > full.y + 1 || vb.x + vb.w < full.x + full.w - 1 || vb.y + vb.h < full.y + full.h - 1);
    var hint = $("fm-hint");
    if (!hint) {
      hint = el("p", "fm-hint", "Drag to move around; zoom out to see the whole map.");
      hint.id = "fm-hint";
    }
    if (hint.parentNode !== box) box.appendChild(hint);
    hint.hidden = !part;
  }
  function zoomBy(f, cx, cy2) {
    var vb = fmState.vb;
    var px = cx == null ? vb.x + vb.w / 2 : cx, py = cy2 == null ? vb.y + vb.h / 2 : cy2;
    var w = vb.w * f, h = vb.h * f;
    var full = fullBox(fmState), c = canvasSize();
    // Out to the whole map (and a little), in to 2.5 times.
    if (f > 1 && w > full.w * 1.3 && h > full.h * 1.3) return;
    if (f < 1 && c.w / w > 2.5) return;
    fmState.vb = { x: px - (px - vb.x) * f, y: py - (py - vb.y) * f, w: w, h: h };
    applyView();
  }
  function forestTool(t) {
    if (!FM || !fmState) return;
    if (t === "fit") { fmState.vb = fitBox(fmState); applyView(); }
    else if (t === "in") zoomBy(0.8);
    else if (t === "out") zoomBy(1.25);
    else if (t === "layout") { fmState.vb = null; drawForest(true); }
  }

  // Mouse: drag the background to pan, a card to move it, the wheel to
  // zoom. Touch scrolls the page as usual.
  function svgPoint(s, e) {
    var pt = s.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    var m = s.getScreenCTM();
    return m ? pt.matrixTransform(m.inverse()) : { x: 0, y: 0 };
  }
  function wireCanvas(s) {
    var drag = null;
    s.addEventListener("pointerdown", function (e) {
      if (e.pointerType !== "mouse" || e.button !== 0) return;
      if (e.target.closest && e.target.closest(".fm-si")) return;
      var card = e.target.closest ? e.target.closest(".fm-node") : null;
      var p = svgPoint(s, e);
      if (card) {
        var name = card.getAttribute("data-domain");
        drag = { card: name, from: p, at: { x: fmState.pos[name].x, y: fmState.pos[name].y }, moved: false };
      } else if (!(e.target.closest && e.target.closest(".fm-elabel, .fm-hit, .fm-e"))) {
        drag = { pan: true, from: { x: e.clientX, y: e.clientY }, vb: { x: fmState.vb.x, y: fmState.vb.y }, moved: false };
      }
      if (drag) s.setPointerCapture(e.pointerId);
    });
    s.addEventListener("pointermove", function (e) {
      if (!drag) return;
      if (drag.pan) {
        var r = s.getBoundingClientRect();
        var k = Math.max(fmState.vb.w / r.width, fmState.vb.h / r.height);
        var dx = (e.clientX - drag.from.x) * k, dy = (e.clientY - drag.from.y) * k;
        if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
        fmState.vb.x = drag.vb.x - dx;
        fmState.vb.y = drag.vb.y - dy;
        applyView();
      } else {
        var p = svgPoint(s, e);
        var nx = drag.at.x + p.x - drag.from.x, ny = drag.at.y + p.y - drag.from.y;
        if (Math.abs(p.x - drag.from.x) + Math.abs(p.y - drag.from.y) > 3) drag.moved = true;
        if (drag.moved) {
          fmState.pos[drag.card] = { x: nx, y: ny };
          redrawKeepingView();
          drag.from = p;
          drag.at = { x: nx, y: ny };
        }
      }
    });
    var end = function (e) {
      if (!drag) return;
      var d = drag;
      drag = null;
      if (d.card && !d.moved) selectDomain(d.card);
      try { s.releasePointerCapture(e.pointerId); } catch (x) {}
    };
    s.addEventListener("pointerup", end);
    s.addEventListener("pointercancel", end);
    s.addEventListener("wheel", function (e) {
      if (fmState.tall) return;
      e.preventDefault();
      var p = svgPoint(s, e);
      zoomBy(e.deltaY < 0 ? 0.9 : 1.1, p.x, p.y);
    }, { passive: false });
    // Touch and keyboard: a tap or Enter on a card opens it.
    s.addEventListener("click", function (e) {
      var g = e.target.closest ? e.target.closest(".fm-node") : null;
      if (g && e.pointerType && e.pointerType !== "mouse") selectDomain(g.getAttribute("data-domain"));
    });
    s.addEventListener("keydown", function (e) {
      var g = e.target.closest ? e.target.closest(".fm-node") : null;
      if (g && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); selectDomain(g.getAttribute("data-domain")); }
    });
  }
  var redrawFrame = 0;
  function redrawKeepingView() {
    if (redrawFrame) return;
    redrawFrame = requestAnimationFrame(function () {
      redrawFrame = 0;
      var keep = fmState.vb;
      drawForest(false);
      fmState.vb = keep;
      applyView();
    });
  }

  // ---- the panel: a trust
  function trustHeading(t, h) {
    var dir = t.direction;
    var a = dir === "Inbound" ? t.target : t.source, b = dir === "Inbound" ? t.source : t.target;
    h.appendChild(document.createTextNode(a + " "));
    h.appendChild(el("span", dir === "Bidirectional" ? "accent-text" : "muted", dir === "Bidirectional" ? "⇄" : dir === "Disabled" ? "–" : "trusts"));
    h.appendChild(document.createTextNode(" " + b + (dir === "Disabled" ? " (disabled)" : "")));
    return h;
  }
  function findingOf(t) {
    for (var i = 0; i < t.findings.length; i++) {
      for (var j = 0; j < findings.length; j++) if (findings[j].fp.toLowerCase() === t.findings[i].toLowerCase()) return findings[j];
    }
    return null;
  }

  function selectTrust(i, quiet) {
    var t = FM.trusts[i];
    if (!t) return;
    fmState = fmState || { pos: {}, sel: null };
    fmState.sel = { trust: i };
    reselect();
    renderTrust(t, i);
    if (!quiet || mode === "forest") showTab("trust");
  }
  // The selection, toggled in place: no redraw, so the focused card or
  // label keeps the focus.
  function reselect() {
    if (!fmState || !fmState.svg) return;
    var sel = fmState.sel || {};
    fmState.svg.querySelectorAll("[data-trust]").forEach(function (x) {
      x.classList.toggle("sel", sel.trust != null && String(sel.trust) === x.getAttribute("data-trust"));
    });
    fmState.svg.querySelectorAll(".fm-node").forEach(function (g) {
      g.classList.toggle("sel", !!sel.domain && sel.domain.toUpperCase() === g.getAttribute("data-domain").toUpperCase());
    });
  }

  function renderTrust(t, i) {
    var p = panel("trust");
    var f = findingOf(t);
    var top = el("div", "xp-fhead");
    if (f) top.appendChild(sevPill(f.severity));
    top.appendChild(el("span", "xp-rule", t.findings.length ? "Trust · PW-012" : "Trust"));
    p.appendChild(top);
    p.appendChild(trustHeading(t, el("h2", "xp-name")));
    var rec = t.records.length > 1 ? "Both domains recorded it." : t.records.length ? "Only " + t.records[0].source + " recorded it." : "";
    p.appendChild(el("p", "xp-summary", t.trust_type + " trust " + (t.intra_forest ? "inside one forest" : "between two forests") + ", " +
      t.way_word + ", " + (t.transitive ? "transitive" : "not transitive") + ". " + rec));
    if (t.records_disagree) {
      p.appendChild(el("p", "fm-fact fm-bad", "The records disagree: " + t.records.map(function (r) { return r.source + " says " + r.direction; }).join(", ") + "."));
    }

    var abuse = t.ways.filter(function (w) { return w.abuse_text; });
    if (abuse.length) {
      var c = el("div", "fm-callout");
      c.appendChild(iconEl("i-alert"));
      var tx = el("p");
      tx.appendChild(el("strong", null, "SID history can be forged across this trust"));
      tx.appendChild(infoBtn("sidhist", "SID history abuse"));
      tx.appendChild(document.createTextNode(". " + abuse.map(function (w) { return cap(w.abuse_text) + "."; }).join(" ") + " " + DEF.not_a_path_step));
      c.appendChild(tx);
      p.appendChild(c);
    } else if (t.pw012_note) {
      var u = el("div", "fm-callout fm-unknown");
      u.appendChild(iconEl("i-info"));
      var ut = el("p");
      ut.appendChild(el("strong", null, "SID filtering unknown"));
      ut.appendChild(infoBtn("unknown", "SID filtering unknown"));
      ut.appendChild(document.createTextNode(". " + t.pw012_note + ". " + DEF.not_a_path_step));
      u.appendChild(ut);
      p.appendChild(u);
    }
    if (t.enables_forest_takeover) {
      var ft = el("p", "fm-fact");
      ft.appendChild(el("strong", null, "Forest takeover"));
      ft.appendChild(infoBtn("takeover", "forest takeover"));
      var missing = (t.flags || []).filter(function (x) { return x.kind === "not_collected"; })[0];
      ft.appendChild(document.createTextNode(missing ? ". " + missing.text + "." : "."));
      p.appendChild(ft);
    }

    var acts = el("div", "xp-actions");
    if (f) acts.appendChild(button("Open the finding (" + f.rule + ")", "primary", function () { openFinding(f.fp); }, "The PW-012 finding on the object graph"));
    [t.source, t.target].forEach(function (n) {
      var d = domainOf(n);
      if (d && d.collected) acts.appendChild(button("Explore " + firstLabel(n), "", function () { exploreDomain(d); }, "The object graph, showing only " + n + "'s objects"));
    });
    p.appendChild(acts);

    if (!t.intra_forest) {
      var h = section(p, "Each way");
      h.appendChild(infoBtn("ways", "each way"));
      var ul = el("ul", "fm-ways");
      t.ways.forEach(function (w) {
        var li = el("li");
        var dir = el("span", "fm-dir");
        dir.appendChild(document.createTextNode(w.from + " "));
        dir.appendChild(el("span", "muted", "into"));
        dir.appendChild(document.createTextNode(" " + w.to));
        li.appendChild(dir);
        var line = el("span");
        line.appendChild(el("span", w.sid_filtering === false ? "fm-bad" : w.sid_filtering == null ? "muted" : null, w.filtering));
        if (w.filtering_note) {
          var ib = infoBtn("unknown", w.filtering);
          ib.setAttribute("data-def", w.filtering + ": " + w.filtering_note + ".");
          ib.title = w.filtering + ": " + w.filtering_note + ".";
          line.appendChild(ib);
        }
        line.appendChild(el("span", "muted", " · " + w.selective));
        li.appendChild(line);
        ul.appendChild(li);
      });
      if (!t.ways.length) ul.appendChild(el("li", "muted", "Disabled."));
      p.appendChild(ul);
    }

    var hc = section(p, "What crosses it");
    hc.appendChild(infoBtn("crossing", "what crosses it"));
    if (t.crossing_note) p.appendChild(el("p", "muted small fm-t0", t.crossing_note + "."));
    crossingList(p, t.crossing, "Nothing crosses it.");

    if (FM.indirect.length) {
      section(p, "Rights between domains no trust joins directly");
      crossingList(p, FM.indirect, "");
    }

    // Every trust and domain, folded on a phone.
    var wide = !window.matchMedia || window.matchMedia("(min-width: 761px)").matches;
    var all = el("details", "fm-more");
    all.open = wide;
    var sum = el("summary", "xp-h");
    sum.appendChild(document.createTextNode("All trusts "));
    sum.appendChild(el("span", "muted", "· " + num(FM.trusts.length)));
    all.appendChild(sum);
    var tl = el("ul", "fm-trusts");
    FM.trusts.forEach(function (u, k) {
      var li = el("li", k === i ? "sel" : null);
      var b = el("button");
      b.type = "button";
      b.appendChild(trustHeading(u, el("span", "fm-tn")));
      b.appendChild(el("span", "muted", u.trust_type + " · " + (u.intra_forest ? "inside one forest" : "between forests")));
      var tag = tagOf(u);
      if (tag) b.appendChild(el("span", "tag " + tag.cls, tag.text));
      b.addEventListener("click", function () { selectTrust(k); });
      li.appendChild(b);
      tl.appendChild(li);
    });
    all.appendChild(tl);
    p.appendChild(all);
    p.appendChild(domainsTable(wide));
  }

  function iconEl(name) {
    var s2 = document.createElementNS(SVG, "svg");
    s2.setAttribute("class", "ic");
    s2.setAttribute("aria-hidden", "true");
    var use = document.createElementNS(SVG, "use");
    use.setAttribute("href", "#" + name);
    s2.appendChild(use);
    return s2;
  }

  // Crossings, each with "Show" (its rights on the object graph); the
  // first four, then "Show more".
  function crossingList(p, list, none) {
    var ul = el("ul", "fm-cross");
    if (!list.length && none) ul.appendChild(el("li", "muted", none));
    list.forEach(function (c, k) {
      var li = el("li");
      if (k >= 4) li.hidden = true;
      var dir = el("span", "fm-dir");
      dir.appendChild(document.createTextNode(c.from + " "));
      dir.appendChild(el("span", "muted", "→"));
      dir.appendChild(document.createTextNode(" " + c.to));
      li.appendChild(dir);
      li.appendChild(el("span", null, c.counts));
      var b = el("button", "linkish", "Show");
      b.type = "button";
      b.title = (c.rights || []).length ? "Draw these rights on the object graph" : "This run doesn't list these rights; analyze the collection again.";
      b.disabled = !(c.rights || []).length;
      b.addEventListener("click", function () { showCrossing(c); });
      li.appendChild(b);
      ul.appendChild(li);
    });
    p.appendChild(ul);
    if (list.length > 4) {
      var more = el("button", "btn small-btn xp-more", "Show more (" + num(list.length - 4) + ")");
      more.type = "button";
      more.addEventListener("click", function () {
        Array.prototype.forEach.call(ul.children, function (li) { li.hidden = false; });
        more.remove();
      });
      p.appendChild(more);
    }
  }

  function domainsTable(open) {
    var box = el("details", "fm-more");
    box.open = open;
    var sum = el("summary", "xp-h");
    sum.appendChild(document.createTextNode("Domains "));
    sum.appendChild(el("span", "muted", "· " + num(FM.domains.length)));
    box.appendChild(sum);
    var t = el("table", "fm-dtable");
    var hr = el("tr");
    hr.appendChild(el("th", null, "Domain"));
    var th = el("th", "num", "Attack paths");
    th.appendChild(infoBtn("attack", "attack paths"));
    hr.appendChild(th);
    var thead = el("thead");
    thead.appendChild(hr);
    t.appendChild(thead);
    var tb = el("tbody");
    FM.domains.forEach(function (d) {
      var tr = el("tr");
      var td = el("td");
      var b = el("button", "linkish fm-dname", d.name);
      b.type = "button";
      b.addEventListener("click", function () { selectDomain(d.name); });
      td.appendChild(b);
      td.appendChild(el("span", "muted fm-role", roleText(d) + " · forest " + firstLabel(FM.forests[d.forest].name)));
      tr.appendChild(td);
      var v = el("td", "num");
      if (!d.paths) v.appendChild(el("span", "muted", d.collected ? "no accounts outside Tier Zero" : "not collected"));
      else {
        v.appendChild(document.createTextNode(num(d.exposed) + " of " + num(d.relevant_population) + " "));
        v.appendChild(el("span", "muted", "· " + d.paths.percent));
      }
      tr.appendChild(v);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    box.appendChild(t);
    return box;
  }

  // ---- the panel: a domain (the Object tab)
  function selectDomain(name, quiet) {
    var d = domainOf(name);
    if (!d) return;
    fmState = fmState || { pos: {}, sel: null };
    fmState.sel = { domain: d.name };
    reselect();
    var p = panel("object");
    var head = el("div", "xp-objhead");
    var t = el("div", "xp-objtitle");
    t.appendChild(el("h2", "xp-name", d.name));
    t.appendChild(el("p", "muted small", roleText(d) + " · forest " + FM.forests[d.forest].name));
    head.appendChild(t);
    p.appendChild(head);
    if (!d.collected) {
      var tags = el("div", "xp-tags");
      tags.appendChild(el("span", "tag muted-tag", d.note || ""));
      p.appendChild(tags);
      var n = el("p", "muted small");
      n.appendChild(document.createTextNode(DEF.not_collected));
      p.appendChild(n);
    } else {
      var facts = el("dl", "xp-facts");
      var fact = function (k, v) { facts.appendChild(el("dt", null, k)); facts.appendChild(el("dd", null, v)); };
      fact("Users", num(d.users));
      fact("Computers", num(d.computers));
      fact("Tier Zero objects", num(d.tier_zero));
      fact("Attack paths", d.paths ? d.paths.count + " " + d.paths.tail + " (" + d.paths.percent + ")" : d.note || "");
      p.appendChild(facts);
      var acts = el("div", "xp-actions");
      acts.appendChild(button("Explore " + firstLabel(d.name), "primary", function () { exploreDomain(d); }, "The object graph, showing only this domain's objects"));
      p.appendChild(acts);
    }
    var mine = [];
    FM.trusts.forEach(function (u, k) {
      if (u.source.toUpperCase() === d.name.toUpperCase() || u.target.toUpperCase() === d.name.toUpperCase()) mine.push(k);
    });
    section(p, "Trusts · " + num(mine.length));
    var ul = el("ul", "fm-trusts");
    mine.forEach(function (k) {
      var u = FM.trusts[k];
      var li = el("li");
      var b = el("button");
      b.type = "button";
      b.appendChild(trustHeading(u, el("span", "fm-tn")));
      b.appendChild(el("span", "muted", u.trust_type + " · " + (u.intra_forest ? "inside one forest" : "between forests")));
      b.addEventListener("click", function () { selectTrust(k); });
      li.appendChild(b);
      ul.appendChild(li);
    });
    p.appendChild(ul);
    if (!quiet) showTab("object");
  }

  // "Explore <domain>": the object graph from its domain object, showing
  // only that domain's objects.
  function exploreDomain(d) {
    busy(true, "Opening " + d.name);
    get("/search", { q: d.sid, kinds: "Domain" }).then(function (r) {
      busy(false);
      var n = (r.results || [])[0];
      if (!n) { toast(d.name + " has no domain object in this run."); return; }
      setMode("graph");
      clearGraph();
      current = null;
      updatePager();
      domainFilter = d.name;
      openObject(n);
    }).catch(fail);
  }

  // A crossing's rights on the object graph: principals on the left, what
  // they hold rights over on the right.
  function showCrossing(c) {
    busy(true, "Drawing the rights across this trust…");
    get("/crossing", { from: c.from, to: c.to }).then(function (d) {
      busy(false);
      setMode("graph");
      domainFilter = null;
      clearGraph();
      current = null;
      updatePager();
      remember(d.nodes);
      var froms = [], tos = [];
      d.edges.forEach(function (e) {
        if (froms.indexOf(e.s) < 0) froms.push(e.s);
        if (tos.indexOf(e.t) < 0) tos.push(e.t);
      });
      froms.forEach(function (ix, k) { addNode(known[ix], { x: 0, y: k * 90 }); });
      tos.forEach(function (ix, k) { if (cy.getElementById(nid(ix)).empty()) addNode(known[ix], { x: 420, y: k * 90 }); });
      d.edges.forEach(function (e) { addEdge(e, d.edges.length > 12 ? "nolabel" : undefined); });
      afterChange();
      if (mode === "graph") fit();
      var p = panel("finding");
      p.appendChild(el("h2", "xp-name", "What crosses from " + d.from + " into " + d.to));
      p.appendChild(el("p", "xp-summary", d.counts + (d.listed < d.counted ? ". The first " + num(d.listed) + " are drawn." : ".")));
      var back = button("Back to Forest view", "", function () { setMode("forest"); });
      var acts = el("div", "xp-actions");
      acts.appendChild(back);
      p.appendChild(acts);
      showTab("finding");
      setUrl(null, null);
    }).catch(fail);
  }

  window.addEventListener("resize", function () {
    if (mode !== "forest" || !FM || !fmState) return;
    var narrow = narrowCanvas();
    if (narrow !== fmState.narrow) { fmState.vb = null; drawForest(true); }
    else applyView();
  });

  // ------------------------------------------------------------ start
  window.addEventListener("resize", function () { cy.resize(); });
  showTab("finding");
  panel("finding").appendChild(el("p", "muted small", "Loading…"));
  busy(true, "Loading the graph…");
  get("").then(function (d) {
    busy(false);
    info = d;
    setKinds(d.kinds);
    findings = d.findings;
    renderFindings();
    updatePager();
    var fp = root.getAttribute("data-finding");
    var node = root.getAttribute("data-node");
    var view = root.getAttribute("data-view");
    if (view === "forest" && !fp && !node) { intro(); afterChange(); setMode("forest"); }
    else if (fp) openFinding(fp);
    else if (node !== "" && node != null) {
      get("/node", { ix: node }).then(function (x) { remember([x.node]); openObject(x.node); }).catch(fail);
      intro();
    } else if (findings.length) {
      // The first finding with a path to show, in report order.
      var first = findings.filter(function (f) { return f.path && !f.suppressed; })[0] || findings[0];
      openFinding(first.fp);
    } else {
      intro();
      afterChange();
    }
    // ?view=list: the same, as tables.
    if (view === "list") setMode("list");
  }).catch(function (e) {
    busy(false);
    var p = panel("finding");
    var note = el("div", "note");
    note.appendChild(el("p", null, e.message));
    p.appendChild(note);
    if (reanalyze) root.classList.add("unavailable");
    afterChange();
  });

  // The run's external kinds, and a legend entry per OpenGraph source to
  // show or hide its relationships.
  function setKinds(k) {
    if (!k) return;
    (k.nodes || []).forEach(function (n) { EXT.nodes[n.name] = n; });
    (k.edges || []).forEach(function (e) { EXT.edges[e.name] = e; });
    var sources = [];
    (k.edges || []).forEach(function (e) {
      (e.sources || []).forEach(function (s) { if (sources.indexOf(s) < 0) sources.push(s); });
    });
    var legend = root.querySelector(".xp-legend");
    if (!legend || !(k.edges || []).length) return;
    var ctx = el("li", "xp-lg-ctx");
    ctx.appendChild(el("span", "lg lg-ctx"));
    ctx.appendChild(document.createTextNode("Context only (OpenGraph)"));
    ctx.title = "From an OpenGraph file; not part of any attack path until its mapping is trusted.";
    legend.appendChild(ctx);
    sources.sort().forEach(function (s) {
      var li = el("li", "xp-src");
      var lab = el("label");
      var cb = el("input");
      cb.type = "checkbox";
      cb.checked = true;
      cb.addEventListener("change", function () {
        hiddenSources[s] = !cb.checked;
        cy.edges().forEach(function (edge) {
          if (edgeHidden(edge.data("kind"))) edge.addClass("srchid"); else edge.removeClass("srchid");
        });
        queueBundles();
      });
      lab.appendChild(cb);
      lab.appendChild(document.createTextNode(" " + s));
      lab.title = "Show relationships from " + s;
      li.appendChild(lab);
      legend.appendChild(li);
    });
  }

  function intro() {
    var p = panel("finding");
    p.appendChild(el("h2", "xp-name", num(info.objects) + " objects in this run"));
    p.appendChild(el("p", "muted small", "Open a finding, or search for an object. Double-click an object to expand it."));
  }
})();
