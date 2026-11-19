// What the Pathwarden app adds to a report it shows in its run page: on
// each open finding a Retest button (on the row) and an action bar (Retest,
// Accept risk, Open in Explore, Copy ID, then the finding actions set up),
// the records finding actions keep with their follow-ups and Activity, on
// each accepted finding a bar with Add a note, retest results per finding and per rule, and the frame's
// height and scroll requests so the page scrolls as one. The app adds this script, and a "pathwarden-retest" meta (its origin,
// and per open finding whether a targeted retest is possible and the latest
// result), only when it embeds a report; a downloaded report has neither.
//
// Every message to the app names a type and at most a fingerprint, a
// number or the report's place (its URL's #hash). The app checks where it came from and what it names, and nothing
// that changes anything happens until the user confirms in the app. Values
// coming back are shown as text.
(function () {
  "use strict";
  // The app puts its data right before this script: only that element is
  // read, never a meta the report holds itself.
  var me = document.currentScript;
  var meta = me && me.previousElementSibling;
  if (!meta || meta.tagName !== "META" || meta.getAttribute("name") !== "pathwarden-retest" ||
      window.parent === window) return;
  var data;
  try { data = JSON.parse(meta.getAttribute("content")); } catch (e) { return; }
  if (!data || typeof data.origin !== "string" || !data.f ||
      !/^(http:\/\/(127\.0\.0\.1|localhost):\d{1,5}|https?:\/\/pathwarden\.localhost|pathwarden:\/\/localhost)$/.test(data.origin)) return;
  var own = Object.prototype.hasOwnProperty;
  var LABEL = { fixed: "Fixed ✓", still_open: "Still open", cant_tell: "Can't tell" };
  var KIND = { fixed: "fixed", still_open: "open", cant_tell: "unknown" };
  var accepted = Object.create(null);
  (Array.isArray(data.acc) ? data.acc : []).forEach(function (fp) {
    if (typeof fp === "string") accepted[fp] = true;
  });
  // Findings an accepted risk covers now: they can take a note.
  var notable = Object.create(null);
  (Array.isArray(data.a) ? data.a : []).forEach(function (fp) {
    if (typeof fp === "string") notable[fp] = true;
  });
  function send(m) { window.parent.postMessage(m, data.origin); }
  // A tab clicked shows no focus ring; one reached by the keyboard does.
  var html = document.documentElement;
  document.addEventListener("pointerdown", function () { html.classList.add("pw-pointer"); }, true);
  document.addEventListener("keydown", function () { html.classList.remove("pw-pointer"); }, true);

  // The Run details tab the app adds: its buttons and links can't act in
  // this frame, so they ask the page around it, which confirms (Remove), signs in (Sign in) or
  // goes there. Only these, by name, and only from the panel the app
  // put in: the section carrying the nonce this frame's address was given
  // (`rd`); the nonce is taken off the panel once read, and the page
  // checks it.
  var RUN_ACTIONS = { remove: true, performance: true, settings: true, "settings-folders": true, schedule: true, history: true, "sign-in": true, collect: true, "add-data": true, mappings: true };
  var runPanel = null, runTab = null, runNonce = "";
  (function () {
    var m = /[?&]rd=([0-9a-f]{32})(?:&|$)/.exec(location.search);
    if (!m) return;
    var all = document.querySelectorAll("section[data-pw-nonce]");
    for (var i = 0; i < all.length; i++) {
      if (all[i].getAttribute("data-pw-nonce") === m[1]) { runPanel = all[i]; runNonce = m[1]; }
      all[i].removeAttribute("data-pw-nonce");
    }
    var tabs = document.querySelectorAll("a[data-pw-tab]");
    for (var j = 0; j < tabs.length; j++) {
      if (runNonce && tabs[j].getAttribute("data-pw-tab") === runNonce) runTab = tabs[j];
      tabs[j].removeAttribute("data-pw-tab");
    }
  })();
  // Whether Run details, with its Remove, can be seen. A report from a
  // run history is another computer's file, and its styles could hide
  // or cover the tab or the panel; the run page then shows its own Run
  // details with Remove. Strict: any doubt is "can't be seen".
  function alpha(c) {
    if (!c || c === "transparent") return 0;
    var m = /rgba?\(([^)]*)\)/.exec(c);
    if (m) {
      var p = m[1].split(/[\s,\/]+/).filter(Boolean);
      return p.length > 3 ? Number(p[3]) : 1;
    }
    m = /\/\s*([\d.]+%?)\s*\)/.exec(c);
    if (m) return m[1].slice(-1) === "%" ? Number(m[1].slice(0, -1)) / 100 : Number(m[1]);
    return 1;
  }
  function meets(a, b) {
    return a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
  }
  // Drawn: every ancestor displayed, visible, opaque, unclipped and
  // unfiltered; of a size; inside the frame.
  function drawn(el, min) {
    if (!el || !el.isConnected) return null;
    var r = el.getBoundingClientRect();
    if (r.width < min || r.height < min) return null;
    if (r.left < 0 || r.top < 0 || r.right > window.innerWidth || r.bottom > window.innerHeight) return null;
    for (var n = el; n && n.nodeType === 1; n = n.parentElement) {
      var s = getComputedStyle(n);
      if (s.display === "none" || s.visibility !== "visible" || Number(s.opacity) < 0.9) return null;
      if ((s.clipPath && s.clipPath !== "none") || (s.clip && s.clip !== "auto")) return null;
      if ((s.filter && s.filter !== "none") || (s.mixBlendMode && s.mixBlendMode !== "normal")) return null;
      if (s.contentVisibility && s.contentVisibility !== "visible") return null;
    }
    return r;
  }
  // Text that can be read: not see-through, not tiny.
  function legible(el) {
    var s = getComputedStyle(el);
    return alpha(s.color) >= 0.5 && alpha(s.webkitTextFillColor || s.color) >= 0.5 &&
      parseFloat(s.fontSize) >= 9 && (el.textContent || "").trim().length > 0;
  }
  // On top at its centre, and nothing see-through for the pointer over it:
  // an element or a ::before/::after that lets clicks through.
  function onTop(el, r) {
    var hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (!hit || !(hit === el || el.contains(hit))) return false;
    // Only what is drawn: a hidden panel, a closed row's contents or
    // anything else not displayed draws nothing, nor do its ::before and
    // ::after. Skipping them keeps this quick in a report of thousands of
    // findings, where reading every element's style took a minute.
    var walk = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_ELEMENT, {
      acceptNode: function (m) {
        var up = m.parentElement;
        if (up && up.tagName === "DETAILS" && !up.open && m !== up.querySelector(":scope > summary")) return NodeFilter.FILTER_REJECT;
        var ms = getComputedStyle(m);
        if (ms.display === "none" || ms.contentVisibility === "hidden") return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    for (var n = document.documentElement, s; n; n = walk.nextNode()) {
      if (n !== el && !n.contains(el) && !el.contains(n)) {
        s = getComputedStyle(n);
        if (s.pointerEvents === "none" && s.display !== "none" && s.visibility === "visible" &&
            Number(s.opacity) > 0 && meets(n.getBoundingClientRect(), r)) return false;
      }
      // Not laid out (inside a hidden panel): draws nothing.
      if (!n.getClientRects().length) continue;
      for (var k = 0; k < 2; k++) {
        var p = getComputedStyle(n, k ? "::after" : "::before");
        if (!p.content || p.content === "none" || p.content === "normal") continue;
        if (p.pointerEvents !== "none" || p.display === "none" || p.visibility !== "visible" || Number(p.opacity) === 0) continue;
        if (p.position === "fixed") return false;
        if (p.position === "absolute") {
          if (getComputedStyle(n).position === "static") return false;
          if (meets(n.getBoundingClientRect(), r)) return false;
        }
      }
    }
    return true;
  }
  function seen(el, min) {
    var r = drawn(el, min);
    return !!r && onTop(el, r);
  }
  // The tab, its name; and when its panel is open, the panel, Remove this
  // run and its button.
  function detailsSeen() {
    if (!runTab || !runPanel) return false;
    var label = runTab.querySelector(".tl");
    if (!seen(runTab, 8) || !label || !drawn(label, 4) || !legible(label)) return false;
    if (getComputedStyle(runPanel).display === "none" && !runPanel.classList.contains("active")) return true;
    var box = runPanel.querySelector(".rd-remove");
    var button = box && box.querySelector('[data-pw-run="remove"]');
    var words = button && button.querySelector("span");
    return !!drawn(runPanel, 16) && !!drawn(box, 16) && seen(button, 16) &&
      !!words && !!drawn(words, 4) && legible(words);
  }
  if (runPanel) {
    var told = function () {
      send({ type: "pathwarden:run-details", nonce: runNonce, shown: detailsSeen() });
    };
    // At load, and each time the tab may have opened (the frame may still
    // be growing to its height: checked again a moment later).
    var check = function () { setTimeout(told, 250); setTimeout(told, 1200); };
    if (document.readyState === "complete") check();
    else window.addEventListener("load", check);
    window.addEventListener("hashchange", check);
    if (window.MutationObserver) {
      new MutationObserver(check).observe(runPanel, { attributes: true, attributeFilter: ["class", "hidden", "style"] });
    }
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest("[data-pw-run]");
    if (!a || !runPanel || !runPanel.contains(a)) return;
    var what = a.getAttribute("data-pw-run");
    e.preventDefault();
    if (!own.call(RUN_ACTIONS, what)) return;
    send({ type: "pathwarden:run-action", action: what, nonce: runNonce });
  });

  var fmt;
  // "Oct 9, 2026, 9:29 PM", local time: US style, as PathwardenTime in
  // app.js (not loaded in this frame) writes it.
  try { fmt = new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }); } catch (e) { fmt = null; }
  function when(unix) {
    var d = new Date(unix * 1000);
    if (isNaN(d.getTime())) return "";
    return (fmt ? fmt.format(d) : d.toLocaleString("en-US")).replace(/[  ]/g, " ");
  }
  var SVG = "http://www.w3.org/2000/svg";
  var ICONS = {
    retest: ["M19.5 12a7.5 7.5 0 1 1-2.2-5.3", "M19.5 4.5v4.2h-4.2", "m9 12.2 2.2 2.2L15.5 10"],
    accept: ["M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6z", "m8.8 12 2.3 2.3 4.3-4.6"],
    note: ["M5 4.5h10.5L19 8v11.5H5z", "M8.5 10h7M8.5 13.5h7M8.5 17h4"],
    explore: ["M7.8 10.9 16.2 6.6M7.8 13.1l8.4 4.3", "M5.5 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 1 0 0-5", "M18.5 3a2.5 2.5 0 1 0 0 5 2.5 2.5 0 1 0 0-5", "M18.5 16a2.5 2.5 0 1 0 0 5 2.5 2.5 0 1 0 0-5"],
    copy: ["M10 8h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2", "M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"]
  };
  function icon(name) {
    var svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("class", "ic");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    ICONS[name].forEach(function (d) {
      var p = document.createElementNS(SVG, "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    });
    return svg;
  }
  function button(cls, name, text, title, onClick) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = cls;
    b.title = title;
    b.appendChild(icon(name));
    var label = document.createElement("span");
    label.textContent = text;
    b.appendChild(label);
    b.addEventListener("click", function (e) {
      // Not a click on the row: the row stays as it is.
      e.preventDefault();
      e.stopPropagation();
      onClick(b, label);
    });
    return b;
  }

  // ----------------------------------------------------------- Copy ID
  function copy(text, done) {
    function fallback() {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (err) {}
      document.body.removeChild(area);
      done(ok);
    }
    try {
      navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
    } catch (err) { fallback(); }
  }

  // ------------------------------------------------- per finding and rule
  var latest = Object.create(null); // fingerprint -> latest verdict
  var badges = Object.create(null);
  var notes = Object.create(null); // fingerprint -> the "accepted" note
  var hints = Object.create(null); // fingerprint -> the held finding's line
  function show(badge, r) {
    if (!r || !own.call(LABEL, r.v)) { badge.hidden = true; return; }
    badge.hidden = false;
    badge.className = "rt-badge " + KIND[r.v];
    badge.textContent = LABEL[r.v];
    var t = typeof r.at === "number" ? when(r.at) : "";
    var tip = (r.src === "run" ? "Compared with the run of " : "Retested ") + t;
    if (typeof r.d === "string" && r.d) tip += "\n" + r.d;
    badge.title = tip;
  }
  function markAccepted(fp) {
    var n = notes[fp];
    if (!n) return;
    n.hidden = false;
    n.textContent = "Accepted risk: from the next analysis this finding is shown as accepted, not open.";
    var b = n.parentNode.querySelector(".fa-accept");
    if (b) b.disabled = true;
  }

  // "2 of 10 fixed" on each rule's row, from the findings' latest results.
  var groups = [];
  function groupSummaries() {
    groups.forEach(function (g) {
      var retested = 0, fixed = 0;
      g.fps.forEach(function (fp) {
        var v = latest[fp];
        if (!v) return;
        retested++;
        if (v === "fixed") fixed++;
      });
      g.chip.hidden = retested === 0;
      g.chip.className = "rt-gsum" + (fixed === g.fps.length ? " all" : fixed ? " some" : "");
      g.chip.textContent = fixed + " of " + g.fps.length + " fixed";
      g.chip.title = retested + " of " + g.fps.length + " open findings retested, " + fixed + " fixed";
    });
  }

  // Add a note: opens the app's dialog for the accepted risk that covers
  // the finding; nothing is saved until the user confirms there.
  function noteButton(fp) {
    return button("fa-btn", "note", "Add a note", "Add a note to the accepted risk, in the app's settings",
      function () { send({ type: "pathwarden:note", fingerprint: fp }); });
  }
  function exploreButton(fp) {
    return button("fa-btn", "explore", "Open in Explore",
      "Draw this finding's path on the run's graph",
      function () { send({ type: "pathwarden:explore", fingerprint: fp }); });
  }
  function copyButton(fp) {
    return button("fa-btn", "copy", "Copy ID", "Copy the finding ID " + fp,
      function (b, label) {
        copy(fp, function (ok) {
          label.textContent = ok ? "Copied" : fp;
          setTimeout(function () { label.textContent = "Copy ID"; }, 1600);
        });
      });
  }

  // Accepted findings: no Retest or Accept risk, but a note can be added.
  document.querySelectorAll("details.finding").forEach(function (d) {
    if (d.id.indexOf("f-") !== 0) return;
    var fp = d.id.slice(2);
    if (own.call(data.f, fp) || !notable[fp]) return;
    var body = d.querySelector(":scope > .body");
    if (!body) return;
    var bar = document.createElement("div");
    bar.className = "fa-bar";
    bar.setAttribute("role", "group");
    bar.setAttribute("aria-label", "Actions for this finding");
    var done = button("fa-btn", "accept", "Accepted", "This finding is an accepted risk", function () {});
    done.disabled = true;
    bar.appendChild(done);
    bar.appendChild(noteButton(fp));
    if (data.x === 1) bar.appendChild(exploreButton(fp));
    bar.appendChild(copyButton(fp));
    body.insertBefore(bar, body.firstChild);
  });

  document.querySelectorAll("details.finding").forEach(function (d) {
    if (d.id.indexOf("f-") !== 0) return;
    var fp = d.id.slice(2);
    if (!own.call(data.f, fp)) return;
    var info = data.f[fp] || {};
    var summary = d.querySelector(":scope > summary");
    if (!summary) return;
    var title = summary.querySelector(".title");
    var name = fp;
    if (title) {
      // Its title, without the Introduced badge in front of it.
      var copy = title.cloneNode(true);
      var ib = copy.querySelector(".ibadge");
      if (ib) copy.removeChild(ib);
      var tag = copy.querySelector(".ar-tag");
      if (tag) copy.removeChild(tag);
      name = copy.textContent;
    }
    function retest() { send({ type: "pathwarden:retest", fingerprint: fp }); }
    var retestTip = info.t === 1
      ? "Re-read this finding's objects and check again"
      : "Retest this finding with a new collection";

    // The row: a badge and the Retest button in the last column.
    if (!summary.querySelector(":scope > .aside")) {
      var gap = document.createElement("span");
      gap.className = "aside";
      summary.appendChild(gap);
    }
    var cell = document.createElement("span");
    cell.className = "rt-cell";
    cell.setAttribute("aria-live", "polite");
    var badge = document.createElement("span");
    badge.className = "rt-badge";
    badge.hidden = true;
    var rowButton = button("rt-btn", "retest", "Retest", retestTip, retest);
    rowButton.setAttribute("aria-label", "Retest: " + name);
    cell.appendChild(badge);
    cell.appendChild(rowButton);
    summary.appendChild(cell);
    show(badge, info.r);
    badges[fp] = badge;
    if (info.r && own.call(LABEL, info.r.v)) latest[fp] = info.r.v;

    // The details: an action bar at the top.
    var body = d.querySelector(":scope > .body");
    if (!body) return;
    var bar = document.createElement("div");
    bar.className = "fa-bar";
    bar.setAttribute("role", "group");
    bar.setAttribute("aria-label", "Actions for this finding");
    bar.appendChild(button("fa-btn", "retest", "Retest", retestTip, retest));
    // Held by a later run that didn't read what it rests on: one line
    // next to Retest, until a retest answers.
    if (typeof info.h === "string" && info.h) {
      var hint = document.createElement("span");
      hint.className = "fa-hint";
      hint.textContent = info.h.slice(0, 200);
      bar.appendChild(hint);
      hints[fp] = hint;
    }
    bar.appendChild(button("fa-btn fa-accept", "accept", "Accept risk",
      "Accept this risk with a reason, in the app's settings",
      function () { send({ type: "pathwarden:accept", fingerprint: fp }); }));
    // Accepted since this run: a note can be added to it now.
    if (notable[fp]) bar.appendChild(noteButton(fp));
    if (data.x === 1) bar.appendChild(exploreButton(fp));
    bar.appendChild(copyButton(fp));
    var note = document.createElement("p");
    note.className = "fa-note";
    note.hidden = true;
    bar.appendChild(note);
    notes[fp] = note;
    body.insertBefore(bar, body.firstChild);
    if (accepted[fp]) markAccepted(fp);
  });

  // ---------------------------------------------------- finding actions
  // The app's actions on each finding (data.ac, actions_ui::page_data):
  // a button per action after the built-in ones, behind a divider (past
  // three, More actions); the records' chips under the title; and one box
  // with the records, their follow-ups and the latest Activity. All of it
  // text. A click only asks the app, which checks it and opens its dialog.
  var ac = data.ac && typeof data.ac === "object" ? data.ac : null;
  var acActs = ac && ac.acts && typeof ac.acts === "object" ? ac.acts : {};
  var acFindings = ac && ac.f && typeof ac.f === "object" ? ac.f : {};
  var acRows = Object.create(null); // fingerprint -> its details.finding
  var AC_ICONS = {
    bolt: ["M13 3 5.5 13.5H11l-1 7.5 7.5-10.5H12z"],
    chev: ["m6 9 6 6 6-6"],
    ticket: ["M4 7.5A1.5 1.5 0 0 1 5.5 6h13A1.5 1.5 0 0 1 20 7.5V10a2 2 0 0 0 0 4v2.5a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 16.5V14a2 2 0 0 0 0-4z"],
    ext: ["M14 4h6v6", "M20 4 11 13", "M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"],
    check: ["m5 12.5 4.5 4.5L19 7.5"]
  };
  Object.keys(AC_ICONS).forEach(function (k) { if (!ICONS[k]) ICONS[k] = AC_ICONS[k]; });
  // Bidi controls shown, not obeyed (pathwarden_core::text::is_bidi_control).
  function visible(s) {
    return String(s == null ? "" : s).replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, function (c) {
      return "\\u{" + c.charCodeAt(0).toString(16) + "}";
    });
  }
  function text(tag, cls, t) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (t != null) e.textContent = visible(t);
    return e;
  }
  function actLabel(addr) {
    var a = own.call(acActs, addr) ? acActs[addr] : null;
    return a && typeof a.label === "string" ? a.label : addr;
  }
  function ask(fp, addr, recordId) {
    var m = { type: "pathwarden:action", fingerprint: fp, action: addr };
    if (recordId) m.record = recordId;
    send(m);
  }
  function https(u) { return typeof u === "string" && /^https:\/\/\S+$/i.test(u) && u.length <= 2048; }
  // A record's chip: "RITM0001234 · Open"; on a fixed finding whose record
  // is still open, "Fixed — RITM0001234 still Open".
  function chip(rv, fixed) {
    var r = rv || {};
    var name = r.number || r.label || r.id || "";
    var status = r.status || (r.open ? "Open" : "Closed");
    var stale = fixed && r.open;
    var c = text("span", "ac-chip" + (stale ? " stale" : r.open ? "" : " closed"));
    c.title = visible(typeof r.chip === "string" ? r.chip : name);
    c.appendChild(icon("ticket"));
    if (stale) c.appendChild(document.createTextNode("Fixed — "));
    c.appendChild(text("span", "num", name));
    c.appendChild(document.createTextNode(visible(stale ? " still " + status : " · " + status)));
    return c;
  }
  function mini(cls, name, label, title, onClick) {
    var b = button("ac-mini" + (cls ? " " + cls : ""), name, label, title || label, onClick);
    return b;
  }
  function views(fp) {
    var f = own.call(acFindings, fp) ? acFindings[fp] : null;
    return f && f.view && typeof f.view === "object" ? f.view : null;
  }
  function list(v, k) { return v && Array.isArray(v[k]) ? v[k] : []; }

  function renderActions(fp) {
    var d = acRows[fp];
    var v = views(fp);
    if (!d || !v) return;
    var fixed = acFindings[fp].status === "fixed";
    var summary = d.querySelector(":scope > summary");
    var title = summary && summary.querySelector(".title");
    var body = d.querySelector(":scope > .body");
    if (!body) return;
    var bar = body.querySelector(":scope > .fa-bar");
    if (!bar) {
      bar = document.createElement("div");
      bar.className = "fa-bar";
      bar.setAttribute("role", "group");
      bar.setAttribute("aria-label", "Actions for this finding");
      body.insertBefore(bar, body.firstChild);
    }
    // The report's own copies (from its analysis) give way to these.
    if (title) {
      var old = title.querySelectorAll(".ac-rowchips");
      for (var i = 0; i < old.length; i++) old[i].remove();
    }
    var stat = body.querySelectorAll(":scope > .ac-static, :scope > .ac-box");
    for (var j = 0; j < stat.length; j++) stat[j].remove();
    var prev = bar.querySelector(".fa-acts");
    if (prev) prev.remove();

    // The buttons: three, then More actions.
    var offered = list(v, "offered").filter(function (a) { return typeof a === "string" && own.call(acActs, a); });
    if (offered.length) {
      var grp = text("span", "fa-acts");
      grp.setAttribute("role", "group");
      grp.setAttribute("aria-label", "Actions");
      var sep = text("span", "fa-sep");
      sep.setAttribute("aria-hidden", "true");
      grp.appendChild(sep);
      var shown = offered.length > 3 ? offered.slice(0, 3) : offered;
      shown.forEach(function (addr) {
        grp.appendChild(button("fa-btn fa-act", "bolt", actLabel(addr), acActs[addr].description || actLabel(addr),
          function () { ask(fp, addr, null); }));
      });
      if (offered.length > 3) {
        var more = text("details", "fa-more");
        var sum = text("summary", "fa-btn", "More actions ");
        var chev = icon("chev");
        chev.setAttribute("class", "ic chev");
        sum.appendChild(chev);
        more.appendChild(sum);
        var menu = text("div", "fa-menu");
        menu.setAttribute("role", "menu");
        offered.slice(3).forEach(function (addr) {
          var b = button("", "bolt", actLabel(addr), acActs[addr].description || actLabel(addr), function () {
            more.open = false;
            ask(fp, addr, null);
          });
          b.setAttribute("role", "menuitem");
          menu.appendChild(b);
        });
        more.appendChild(menu);
        more.addEventListener("click", function (e) { e.stopPropagation(); });
        grp.appendChild(more);
      }
      var note = bar.querySelector(".fa-note");
      bar.insertBefore(grp, note || null);
    }

    var records = list(v, "records");
    // On the row, under the title: the first record's chip, and how many more.
    if (title && records.length) {
      var rc = text("span", "ac-rowchips");
      rc.appendChild(chip(records[0], fixed));
      if (records.length > 1) {
        var n = text("span", "ac-more", "+" + (records.length - 1));
        n.title = "And " + (records.length - 1) + " more " + (records.length === 2 ? "record" : "records");
        rc.appendChild(n);
      }
      // After "first seen …", so the title keeps its width.
      (title.querySelector(".seen") || title).appendChild(rc);
    }
    d.setAttribute("data-records", String(records.length));

    var activity = list(v, "activity");
    if (records.length || activity.length) {
      var box = text("div", "ac-box");
      if (records.length) {
        var recs = text("div", "ac-recs");
        records.forEach(function (rv) {
          var r = rv || {};
          var row = text("div", "ac-rec");
          row.appendChild(chip(rv, fixed));
          if (r.kind) row.appendChild(text("span", "ac-what", r.kind));
          var fu = text("span", "ac-follow");
          // A fixed finding's follow-up (Close request) first, then Open,
          // then the others, then Copy.
          var follow = list(rv, "follow_ups").filter(function (addr) { return own.call(acActs, addr); });
          var urgent = function (addr) { return fixed && acActs[addr].fixed === true; };
          var add = function (addr) {
            var warn = urgent(addr);
            fu.appendChild(mini(warn ? "warn" : "", warn ? "check" : "retest", actLabel(addr), acActs[addr].description,
              function () { ask(fp, addr, r.id); }));
          };
          follow.filter(urgent).forEach(add);
          if (https(r.url)) {
            var a = text("a", "ac-mini");
            a.href = r.url;
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            a.title = r.url;
            a.appendChild(icon("ext"));
            a.appendChild(text("span", null, "Open"));
            a.addEventListener("click", function (e) { e.stopPropagation(); });
            fu.appendChild(a);
          }
          follow.filter(function (addr) { return !urgent(addr); }).forEach(add);
          var name = r.number || r.label || r.id || "";
          fu.appendChild(mini("", "copy", "Copy", "Copy " + name, function (b, label) {
            copy(String(name), function (ok) {
              label.textContent = ok ? "Copied" : name;
              setTimeout(function () { label.textContent = "Copy"; }, 1600);
            });
          }));
          row.appendChild(fu);
          recs.appendChild(row);
        });
        box.appendChild(recs);
      }
      if (activity.length) {
        var act = text("div", "ac-act");
        act.appendChild(text("h5", null, "Activity"));
        var ol = text("ol");
        var total = Number(v.activity_count) || activity.length;
        var all = false;
        var drawList = function () {
          ol.textContent = "";
          (all ? activity : activity.slice(0, 3)).forEach(function (e) {
            var li = text("li", e.ok === false ? "bad" : "");
            var st = text("span", "st");
            st.setAttribute("aria-hidden", "true");
            li.appendChild(st);
            var line = text("span");
            line.appendChild(text("span", "what", e.summary || e.line || ""));
            var who = [e.by, e.on, typeof e.at_unix === "number" ? when(e.at_unix) : e.at].filter(function (x) { return typeof x === "string" && x; });
            if (who.length) line.appendChild(text("span", "who", " — " + who.join(", ")));
            var full = typeof e.message === "string" ? e.message.trim() : "";
            if (e.ok === false && full && full !== e.summary) {
              var more = text("span", "ac-full", full);
              more.hidden = true;
              var b = text("button", "ac-link", "Show details");
              b.type = "button";
              b.addEventListener("click", function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                more.hidden = !more.hidden;
                b.textContent = more.hidden ? "Show details" : "Hide details";
              });
              line.appendChild(b);
              line.appendChild(more);
            }
            // Its log, on the computer that ran it: the app opens it.
            if (e.ok === false && typeof e.log === "string" && e.log && typeof e.at === "string") {
              var lg = text("button", "ac-link", "Open log");
              lg.type = "button";
              lg.addEventListener("click", function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                send({ type: "pathwarden:open-log", fingerprint: fp, at: e.at });
              });
              line.insertBefore(lg, line.querySelector(".ac-full"));
            }
            li.appendChild(line);
            ol.appendChild(li);
          });
          if (all && total > activity.length) {
            ol.appendChild(text("li", "ac-earlier", "and " + (total - activity.length) + " earlier"));
          }
        };
        drawList();
        act.appendChild(ol);
        if (total > 3) {
          var showAll = text("button", "ac-all", "Show all (" + total + ")");
          showAll.type = "button";
          showAll.addEventListener("click", function (ev) {
            ev.preventDefault();
            all = !all;
            showAll.textContent = all ? "Show fewer" : "Show all (" + total + ")";
            drawList();
          });
          act.appendChild(showAll);
        }
        box.appendChild(act);
      }
      bar.parentNode.insertBefore(box, bar.nextSibling);
    }
  }

  // Has a record / No record, and "N findings have records" on the
  // Overview's Open findings tile (only with a report that has the filter).
  var recFilter = document.querySelector(".f-recs");
  var ovRecs = null;
  function recordCounts() {
    if (!recFilter) return;
    var n = 0;
    Object.keys(acFindings).forEach(function (fp) { if (list(views(fp), "records").length) n++; });
    if (ac && (ac.on === true || n > 0)) recFilter.hidden = false;
    if (!ovRecs) {
      var cards = document.querySelectorAll(".ov-card");
      for (var i = 0; i < cards.length; i++) {
        var l = cards[i].querySelector(".ov-label");
        if (l && /^Open findings/.test(l.textContent)) {
          var sub = cards[i].querySelector(".ov-sub");
          if (!sub) break;
          ovRecs = text("a", "ov-recs");
          ovRecs.href = "#findings";
          ovRecs.setAttribute("data-records-only", "");
          ovRecs.title = "Show the findings with a record";
          sub.appendChild(document.createElement("br"));
          sub.appendChild(ovRecs);
          break;
        }
      }
    }
    if (ovRecs) {
      ovRecs.hidden = n === 0;
      ovRecs.previousSibling.hidden = n === 0;
      ovRecs.textContent = n + (n === 1 ? " finding has records" : " findings have records");
    }
    // The list follows the records as they change.
    var picked = document.querySelector('input[name="f-records"]:checked');
    if (picked && picked.value) picked.dispatchEvent(new Event("change"));
  }

  if (ac) {
    document.querySelectorAll("details.finding").forEach(function (d) {
      if (d.id.indexOf("f-") !== 0) return;
      var fp = d.id.slice(2);
      if (!own.call(acFindings, fp)) return;
      acRows[fp] = d;
      renderActions(fp);
    });
    recordCounts();
  }

  // A new path (Findings, Introduced) opens its start in Explore.
  if (data.x === 1) {
    document.querySelectorAll("button.ip-xp[data-node]").forEach(function (b) {
      var node = b.getAttribute("data-node");
      if (!/^\d{1,10}$/.test(node)) return;
      b.hidden = false;
      b.addEventListener("click", function () { send({ type: "pathwarden:explore-node", node: +node }); });
    });
  }

  document.querySelectorAll("details.group").forEach(function (g) {
    var fps = [];
    g.querySelectorAll("details.finding").forEach(function (d) {
      var fp = d.id.slice(2);
      if (d.id.indexOf("f-") === 0 && badges[fp]) fps.push(fp);
    });
    var aside = g.querySelector(":scope > summary > .aside");
    if (!fps.length || !aside) return;
    var chip = document.createElement("span");
    chip.className = "rt-gsum";
    chip.hidden = true;
    aside.insertBefore(chip, aside.firstChild);
    groups.push({ fps: fps, chip: chip });
  });
  groupSummaries();
  document.documentElement.classList.add("rt-on");

  // --------------------------------------------- one scroll, in the app
  // The app sizes the frame to the report, so the page scrolls as one. The
  // report's own scrolling (a tab to its top, a link to a finding) becomes
  // a request to the app, with the place as a number.
  var lastHeight = 0, queued = false;
  function reportHeight() {
    queued = false;
    // The body, not the document: the document is never shorter than the
    // frame, so it could grow but never shrink.
    var h = Math.ceil(document.body.getBoundingClientRect().height);
    if (h === lastHeight) return;
    lastHeight = h;
    send({ type: "pathwarden:height", height: h });
  }
  // A timeout, not requestAnimationFrame: a frame out of view (below the
  // fold on a phone) gets no animation frames, so it would keep its first
  // height until scrolled to.
  function queueHeight() {
    if (queued) return;
    queued = true;
    setTimeout(reportHeight, 0);
  }
  if (window.ResizeObserver) new ResizeObserver(queueHeight).observe(document.body);
  document.addEventListener("toggle", queueHeight, true);
  window.addEventListener("load", queueHeight);
  queueHeight();

  function scrollRequest(y) {
    if (isFinite(y)) send({ type: "pathwarden:scroll", y: Math.max(0, Math.round(y)) });
  }
  var scrollTo = window.scrollTo;
  window.scrollTo = function (x, y) {
    if (typeof x === "number" && typeof y === "number") scrollRequest(y);
    return scrollTo.apply(window, arguments);
  };
  var into = Element.prototype.scrollIntoView;
  Element.prototype.scrollIntoView = function () {
    scrollRequest(this.getBoundingClientRect().top + window.pageYOffset);
    return into.apply(this, arguments);
  };

  // ------------------------------------------------- the report's place
  // The tab or finding shown (the #hash) goes into the run page's address,
  // so reload, Back and a shared link come back to it. report.js moves with
  // pushState, which fires no event: wrapped like the scrolling above.
  var lastPlace = null;
  function place() {
    var h = location.hash.slice(1);
    if (h === lastPlace) return;
    lastPlace = h;
    send({ type: "pathwarden:place", hash: h });
  }
  ["pushState", "replaceState"].forEach(function (name) {
    var original = history[name];
    if (typeof original !== "function") return;
    history[name] = function () {
      var r = original.apply(history, arguments);
      place();
      return r;
    };
  });
  window.addEventListener("hashchange", place);
  window.addEventListener("popstate", place);
  place();

  // The tab bar stays in view while the app's page scrolls past the report.
  var rail = document.querySelector(".rail");
  function pin(shift) {
    if (!rail) return;
    var max = Math.max(0, document.body.getBoundingClientRect().height - rail.offsetHeight);
    var y = Math.min(max, Math.max(0, shift));
    rail.style.transform = y ? "translateY(" + y + "px)" : "";
    rail.classList.toggle("rt-pinned", y > 0);
  }

  // Messages from the app.
  window.addEventListener("message", function (e) {
    if (e.source !== window.parent) return;
    var m = e.data;
    if (!m || typeof m !== "object" || typeof m.type !== "string") return;
    if (m.type === "pathwarden:viewport") {
      var shift = Number(m.shift);
      if (isFinite(shift)) pin(shift);
      return;
    }
    if (m.type === "pathwarden:action-view") {
      // What an action did, just now: the finding's buttons, chips and box.
      if (typeof m.fingerprint !== "string" || !acRows[m.fingerprint] ||
          !m.view || typeof m.view !== "object") return;
      acFindings[m.fingerprint].view = m.view;
      renderActions(m.fingerprint);
      recordCounts();
      return;
    }
    if (typeof m.fingerprint !== "string" || !badges[m.fingerprint]) return;
    if (m.type === "pathwarden:accepted") {
      accepted[m.fingerprint] = true;
      markAccepted(m.fingerprint);
      // Accepted now: a note can be added to it at once.
      var bar = notes[m.fingerprint] && notes[m.fingerprint].parentNode;
      if (bar && !notable[m.fingerprint]) {
        notable[m.fingerprint] = true;
        var acc = bar.querySelector(".fa-accept");
        bar.insertBefore(noteButton(m.fingerprint), acc ? acc.nextSibling : bar.firstChild);
      }
      return;
    }
    if (m.type !== "pathwarden:retest-result" || !own.call(LABEL, m.verdict)) return;
    latest[m.fingerprint] = m.verdict;
    if (hints[m.fingerprint]) hints[m.fingerprint].hidden = true;
    show(badges[m.fingerprint], {
      v: m.verdict,
      at: Number(m.at),
      src: "targeted",
      d: typeof m.detail === "string" ? m.detail.slice(0, 300) : ""
    });
    groupSummaries();
  });
})();
