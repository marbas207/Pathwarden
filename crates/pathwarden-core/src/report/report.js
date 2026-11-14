// Theme: dark by default; the button switches to light and the choice is
// remembered in this browser (when storage is available).
(function () {
  var root = document.documentElement;
  var button = document.getElementById("theme-toggle");
  function set(theme) {
    root.setAttribute("data-theme", theme);
    if (button) {
      var label = button.querySelector(".tt-label") || button;
      label.textContent = theme === "dark" ? "Light mode" : "Dark mode";
      button.setAttribute("aria-pressed", theme === "light");
      // The icon of the theme it switches to: a sun in dark mode.
      var use = button.querySelector("use");
      if (use) use.setAttribute("href", theme === "dark" ? "#i-sun" : "#i-theme");
    }
  }
  var theme = root.getAttribute("data-theme") || "dark";
  try {
    var saved = localStorage.getItem("pathwarden-theme");
    if (saved === "light" || saved === "dark") theme = saved;
  } catch (e) {}
  set(theme);
  if (button) {
    button.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      set(next);
      try { localStorage.setItem("pathwarden-theme", next); } catch (e) {}
    });
  }
})();

// Times: written in UTC (US style, labeled), shown in the reader's local
// time, US style, the UTC value kept as the tooltip.
(function () {
  // data-fmt as app.js reads it: "full" (the default), "fullsec", "date"
  // (Oct 29, 2026), "day" (Oct 29), "dayclock" (Oct 29, 4:07 PM),
  // "dayclocksec" (with the seconds) or "time" (4:07 PM).
  var FORMS = {
    full: { dateStyle: "medium", timeStyle: "short" },
    fullsec: { dateStyle: "medium", timeStyle: "medium" },
    date: { dateStyle: "medium" },
    day: { month: "short", day: "numeric" },
    dayclock: { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" },
    dayclocksec: { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" },
    time: { hour: "numeric", minute: "2-digit" }
  };
  var made = {};
  function fmt(key) {
    if (!Object.prototype.hasOwnProperty.call(FORMS, key)) key = "full";
    if (!(key in made)) {
      try { made[key] = new Intl.DateTimeFormat("en-US", FORMS[key]); } catch (e) { made[key] = null; }
    }
    return made[key];
  }
  document.querySelectorAll("[data-unix]").forEach(function (t) {
    var d = new Date(Number(t.getAttribute("data-unix")) * 1000);
    var f = fmt(t.getAttribute("data-fmt"));
    if (f && !isNaN(d.getTime())) t.textContent = f.format(d).replace(/[  ]/g, " ");
  });
})();

// Tabs: one section at a time, remembered in the URL hash. Without this
// script every section is shown, one after another.
(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tablist [role="tab"]'));
  var panels = Array.prototype.slice.call(document.querySelectorAll(".panel"));
  if (!tabs.length || !panels.length) return;
  document.documentElement.classList.add("js");

  function activate(id) {
    var found = false;
    panels.forEach(function (p) {
      var on = p.id === id;
      p.classList.toggle("active", on);
      if (on) found = true;
    });
    if (!found) return activate(panels[0].id);
    tabs.forEach(function (t) {
      var on = t.getAttribute("aria-controls") === id;
      t.setAttribute("aria-selected", on);
      t.tabIndex = on ? 0 : -1;
    });
  }

  // A hash names a tab, or something inside one (a guide, a finding): show
  // that tab, open the rows around the target and bring it into view.
  function route() {
    var id = decodeURIComponent(location.hash.slice(1));
    var el = id && document.getElementById(id);
    // A period for the Introduced filter: the filter itself.
    if (!el && /^introduced-/.test(id)) el = document.getElementById("f-intro");
    if (!el) { activate(panels[0].id); return; }
    var panel = el.closest(".panel");
    if (!panel) { activate(panels[0].id); return; }
    activate(panel.id);
    // A tab starts at the top (the browser would scroll to the section,
    // past the header on small screens).
    if (el === panel) { setTimeout(function () { window.scrollTo(0, 0); }, 0); return; }
    for (var d = el; d; d = d.parentElement) {
      if (d.tagName === "DETAILS") { d.open = true; d.hidden = false; }
    }
    el.scrollIntoView({ block: "start" });
  }

  function go(id) {
    if (location.hash.slice(1) === id) { route(); return; }
    try { history.pushState(null, "", "#" + id); route(); } catch (e) { location.hash = id; }
  }

  tabs.forEach(function (t, i) {
    t.addEventListener("click", function (e) {
      e.preventDefault();
      go(t.getAttribute("aria-controls"));
    });
    t.addEventListener("keydown", function (e) {
      var j = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 :
        e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
      if (j === null) return;
      e.preventDefault();
      var next = tabs[(j + tabs.length) % tabs.length];
      next.focus();
      go(next.getAttribute("aria-controls"));
    });
  });

  // In-page links to a tab or into one (tiles, "see all", guide links).
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (!a || a.getAttribute("role") === "tab") return;
    var id = a.getAttribute("href").slice(1);
    if (!document.getElementById(id)) return;
    e.preventDefault();
    go(id);
  });

  try { history.scrollRestoration = "manual"; } catch (e) {}
  window.addEventListener("hashchange", route);
  window.addEventListener("popstate", route);
  route();
})();

// Findings filter: severity chips, category, text search, suppressed toggle.
// It hides findings that don't match and rule groups left with none. With a
// remediation path, "Group by" switches between the rule groups and the
// findings under the change that fixes them; the filters apply to both.
// A report of the run that left the findings state also has Introduced: a
// period, a badge on each finding new in it (New, Back, +N objects: what
// counts is Badge::of in introduced.rs), its objects that appeared in it
// marked, and the new members and paths in it. Without a period, the
// badges are the last run's. The summary for the periods offered is the
// core's lines (data-lines, as pathwarden changes prints them); for a date
// range it counts the same things here, in the same words. #introduced-7
// (last, 30, or FROM_TO as YYYY-MM-DD, either left out) opens the tab with
// that period picked: the app's Progress page links there.
(function () {
  var groups = Array.prototype.slice.call(document.querySelectorAll("details.group"));
  var fixGroups = Array.prototype.slice.call(document.querySelectorAll("details.fixgroup"));
  var fixItems = Array.prototype.slice.call(document.querySelectorAll(".byfix li[data-sev]"));
  var modes = Array.prototype.slice.call(document.querySelectorAll('input[name="f-group"]'));
  var groupBy = document.querySelector(".group-by");
  var byRule = document.querySelector(".rows.groups");
  var byFix = document.querySelector(".byfix");
  var cards = Array.prototype.slice.call(document.querySelectorAll("details.finding"));
  var chips = Array.prototype.slice.call(document.querySelectorAll(".chips input"));
  var categories = Array.prototype.slice.call(document.querySelectorAll('input[name="f-category"]'));
  var search = document.getElementById("f-search");
  var showSuppressed = document.getElementById("f-suppressed");
  var expand = document.getElementById("f-expand");
  var count = document.getElementById("f-count");
  if (!cards.length || !categories.length) return;
  // Least to most severe, as the rows' data-sev values.
  var SEVS = ["info", "low", "medium", "high", "critical"];
  var pick = document.querySelector(".intro-pick");
  var introSel = document.getElementById("f-intro");
  var introRange = pick && pick.querySelector(".intro-range");
  var introFrom = document.getElementById("f-intro-from");
  var introTo = document.getElementById("f-intro-to");
  var introSum = document.getElementById("f-intro-sum");
  var introNote = document.getElementById("f-intro-note");
  var paths = document.getElementById("intro-paths");
  var pathsAll = paths && paths.querySelector(".ip-all");
  var pathsOpen = false;
  // New members, and apart new paths, listed before "Show all".
  var PATHS_SHOWN = 5;
  var DAY = 86400;
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  // "Oct 18" (a UTC day), with the year when it isn't the latest run's
  // ("Oct 18, 2025"), as pathwarden_core::introduced::day writes it.
  function day(t, latest) {
    var d = new Date(t * 1000), l = new Date(latest * 1000);
    var s = MONTHS[d.getUTCMonth()] + " " + d.getUTCDate();
    return d.getUTCFullYear() === l.getUTCFullYear() ? s : s + ", " + d.getUTCFullYear();
  }

  function data(name) {
    try { return JSON.parse(pick.getAttribute(name) || "null"); } catch (e) { return null; }
  }

  // The period chosen: its first and last second, how to say it, and its
  // lines from the core when it is one the page offers; null for Any time.
  // A To day before the From day is no period: `bad` says so.
  function period() {
    if (!pick || !introSel) return null;
    var at = +pick.getAttribute("data-at");
    var v = introSel.value;
    var lines = data("data-lines") || {};
    if (introRange) introRange.hidden = v !== "range";
    if (v === "last") return { from: at, to: at, words: pick.getAttribute("data-last"), lines: lines.last, last: true };
    // A run exactly 7 days before the latest is not in "7 days" (Period::bounds).
    if (v === "7" || v === "30") return { from: at - v * DAY + 1, to: at, words: pick.getAttribute("data-d" + v), lines: lines[v] };
    if (v !== "range") return null;
    var f = Date.parse(introFrom.value), t = Date.parse(introTo.value);
    if (isNaN(f) && isNaN(t)) return null;
    if (!isNaN(f) && !isNaN(t) && t < f) return { bad: "The To day is before the From day." };
    var from = isNaN(f) ? -Infinity : f / 1000;
    var to = isNaN(t) ? at : t / 1000 + DAY - 1;
    var words = isNaN(t) ? "since " + day(from, at)
      : isNaN(f) ? "up to " + day(to, at)
      : "from " + day(from, at) + " to " + day(to - DAY + 1, at);
    return { from: from, to: to, words: words };
  }

  // A period from the address: #introduced-7, -30, -last, or -FROM_TO.
  function fromHash() {
    var m = /^#introduced-(last|7|30|(\d{4}-\d{2}-\d{2})?_(\d{4}-\d{2}-\d{2})?)$/.exec(location.hash);
    if (!m || !introSel) return false;
    if (m[1] === "last" || m[1] === "7" || m[1] === "30") {
      if (!introSel.querySelector('option[value="' + m[1] + '"]')) return false;
      introSel.value = m[1];
    } else {
      introSel.value = "range";
      introFrom.value = m[2] || "";
      introTo.value = m[3] || "";
    }
    return true;
  }

  // The period the badges show: the one chosen, else the last run (when
  // there was a run before it).
  function badgePeriod(p) {
    if (p || !pick || pick.getAttribute("data-earlier") !== "true") return p;
    var at = +pick.getAttribute("data-at");
    return { from: at, to: at, words: pick.getAttribute("data-last") };
  }

  // How a finding (its details element) is new in `p`, as Badge::of.
  function badgeOf(d, p) {
    if (!p || !d || !d.hasAttribute("data-seen")) return null;
    function within(t) { return t >= p.from && t <= p.to; }
    if (within(+d.getAttribute("data-seen"))) return { cls: "new", text: "New" };
    var back = d.getAttribute("data-back");
    if (back && within(+back)) return { cls: "back", text: "Back" };
    var n = 0;
    (d.getAttribute("data-gained") || "").split(" ").forEach(function (g) {
      var x = g.split(":");
      if (x.length === 2 && within(+x[0])) n += +x[1];
    });
    if (!n) return null;
    return { cls: "gained", text: "+" + n.toLocaleString("en-US") + (n === 1 ? " object" : " objects"), n: n };
  }

  // A row of "Group by: change" stands for the finding it links to.
  function cardOf(el) {
    if (el.tagName === "DETAILS") return el;
    var a = el.querySelector('a[href^="#f-"]');
    return a ? document.getElementById(a.getAttribute("href").slice(1)) : null;
  }

  var introNow = null;
  function introOk(el) {
    return !introNow || !!introNow.bad || !!badgeOf(cardOf(el), introNow);
  }

  function plural(n, one, many) { return n.toLocaleString("en-US") + " " + (n === 1 ? one : many); }

  // "3 new paths into Tier Zero", "2 paths back into Tier Zero", "3 new
  // paths into Tier Zero, 2 back", as new_and_back words them.
  function newAndBack(n, b, newWords, backWords, newRest, backRest) {
    if (!b) return plural(n, newWords[0], newWords[1]) + " " + newRest;
    if (!n) return plural(b, backWords[0], backWords[1]) + " " + backRest;
    return plural(n, newWords[0], newWords[1]) + " " + newRest + ", " + b.toLocaleString("en-US") + " back";
  }

  // The lines for a date range, as Introduced::lines words them: new, back
  // and grown findings; per zone its new members and new paths (Tier Zero
  // first); then fixed findings, findings that lost objects, and per zone
  // the members that left and the paths gone.
  function rangeLines(p, counts, perZone) {
    function within(t) { return t >= p.from && t <= p.to; }
    var out = [];
    if (counts["new"]) out.push(plural(counts["new"], "new finding", "new findings"));
    if (counts.back) out.push(plural(counts.back, "finding", "findings") + " back after " + (counts.back === 1 ? "it was" : "they were") + " fixed");
    if (counts.gained) out.push(plural(counts.gained, "older finding", "older findings") + " gained " + plural(counts.objects, "object", "objects"));
    var zones = data("data-zones") || [];
    zones.forEach(function (z) {
      var c = perZone[z] || {};
      if (c.joined || c.joinedBack) out.push(newAndBack(c.joined, c.joinedBack, ["new member", "new members"], ["member", "members"], "of " + z, "back in " + z));
      if (c.paths || c.pathsBack) out.push(newAndBack(c.paths, c.pathsBack, ["new path", "new paths"], ["path", "paths"], "into " + z, "back into " + z));
    });
    var fixed = 0;
    (pick.getAttribute("data-fixed") || "").split(" ").forEach(function (t) {
      if (t && within(+t)) fixed++;
    });
    if (fixed) out.push(plural(fixed, "finding", "findings") + " fixed");
    if (counts.lost) out.push(plural(counts.lost, "finding", "findings") + " lost " + plural(counts.lostObjects, "object", "objects"));
    [["data-left", "member", "members", " left "], ["data-gone", "path", "paths", null]].forEach(function (k) {
      var by = {};
      (data(k[0]) || []).forEach(function (g) { if (within(g[0])) by[g[1]] = (by[g[1]] || 0) + g[2]; });
      zones.forEach(function (z) {
        if (!by[z]) return;
        out.push(k[3] ? plural(by[z], k[1], k[2]) + k[3] + z : plural(by[z], k[1], k[2]) + " into " + z + " gone");
      });
    });
    if (!out.length) out.push("Nothing new, and nothing fixed");
    return out;
  }

  // The badges, the objects that appeared in the period, the new paths and
  // what the period holds.
  function introduce(p) {
    if (!pick) return;
    if (p && p.bad) {
      if (introSum) { introSum.hidden = false; introSum.className = "intro-sum muted"; introSum.textContent = p.bad; }
      if (introNote) introNote.hidden = true;
      if (paths) paths.hidden = true;
      return;
    }
    var bp = badgePeriod(p);
    var counts = { "new": 0, back: 0, gained: 0, objects: 0, lost: 0, lostObjects: 0 };
    cards.forEach(function (d) {
      var b = badgeOf(d, bp);
      // Lost objects count for a finding not new or back in the period.
      if (p && d.getAttribute("data-suppressed") !== "true" && (!b || b.cls === "gained")) {
        var lost = 0;
        (d.getAttribute("data-lost") || "").split(" ").forEach(function (g) {
          var x = g.split(":");
          if (x.length === 2 && +x[0] >= p.from && +x[0] <= p.to) lost += +x[1];
        });
        if (lost) { counts.lost++; counts.lostObjects += lost; }
      }
      var el = d.querySelector(":scope > summary [data-ibadge]");
      if (el) {
        el.hidden = !b;
        el.className = "ibadge" + (b ? " " + b.cls : "");
        el.textContent = b ? b.text : "";
      }
      if (b && d.getAttribute("data-suppressed") !== "true") {
        counts[b.cls]++;
        if (b.n) counts.objects += b.n;
      }
      if (d.hasAttribute("data-gained")) {
        d.querySelectorAll("li[data-seen]").forEach(function (li) {
          var t = +li.getAttribute("data-seen");
          li.classList.toggle("in-period", !!bp && t >= bp.from && t <= bp.to);
        });
      }
    });
    var newPaths = 0, over = false, perZone = {};
    if (paths) {
      // Members and paths each show their first PATHS_SHOWN.
      paths.querySelectorAll("ul.ip-list").forEach(function (ul) {
        var n = 0;
        ul.querySelectorAll(":scope > li").forEach(function (li) {
          var t = +li.getAttribute("data-seen");
          li.hidden = !bp || t < bp.from || t > bp.to;
          if (!li.hidden) {
            n++;
            var z = li.getAttribute("data-zone");
            var c = perZone[z] = perZone[z] || { joined: 0, joinedBack: 0, paths: 0, pathsBack: 0 };
            var k = (li.classList.contains("ip-mem") ? "joined" : "paths") + (li.hasAttribute("data-back") ? "Back" : "");
            c[k]++;
          }
          li.classList.toggle("ip-over", !li.hidden && !pathsOpen && n > PATHS_SHOWN);
        });
        if (n > PATHS_SHOWN) over = true;
        newPaths += n;
        var head = ul.previousElementSibling;
        if (head && head.classList.contains("ip-sub")) head.hidden = !n;
      });
      if (pathsAll) {
        pathsAll.hidden = !over;
        pathsAll.textContent = pathsOpen ? "Show fewer" : "Show all " + newPaths.toLocaleString("en-US");
        pathsAll.setAttribute("aria-expanded", pathsOpen);
      }
      // Only for a period picked: Any time is the findings alone. Since
      // the last run, What changed names them, so the findings stand alone.
      paths.hidden = !p || !!p.last;
      var when = document.getElementById("ip-when");
      if (when && bp) when.textContent = bp.words;
      var none = paths.querySelector(".ip-none");
      if (none) none.hidden = newPaths > 0;
    }
    if (introSum) {
      introSum.hidden = !p || !!p.last;
      introSum.className = "intro-sum";
      if (p) {
        var parts = (p.lines || rangeLines(p, counts, perZone)).slice();
        // After a colon: "nothing new", not "Nothing new".
        if (parts.length === 1 && /^Nothing /.test(parts[0])) parts[0] = "n" + parts[0].slice(1);
        introSum.textContent = "Introduced " + p.words + ": " + parts.join(", ") + ".";
      }
    }
    if (introNote) {
      var since = pick.getAttribute("data-since");
      introNote.hidden = !p || (since !== "" && p.from > +since);
      introNote.textContent = pick.getAttribute("data-note");
    }
  }

  function mode() {
    var m = "rule";
    modes.forEach(function (c) { if (c.checked) m = c.value; });
    return m;
  }

  function apply() {
    var sev = {};
    chips.forEach(function (c) { sev[c.getAttribute("data-sev")] = c.checked; });
    var cat = "";
    categories.forEach(function (c) { if (c.checked) cat = c.value; });
    var q = search.value.trim().toLowerCase();
    introNow = period();
    introduce(introNow);
    function matches(d) {
      return sev[d.getAttribute("data-sev")] !== false &&
        (!cat || d.getAttribute("data-cat") === cat) &&
        (showSuppressed.checked || d.getAttribute("data-suppressed") !== "true") &&
        (!q || d.getAttribute("data-text").indexOf(q) !== -1) &&
        introOk(d);
    }
    var shown = 0;
    cards.forEach(function (d) {
      var ok = matches(d);
      d.hidden = !ok;
      if (ok) shown++;
    });
    fixItems.forEach(function (li) { li.hidden = !matches(li); });
    var fixShown = 0;
    fixGroups.forEach(function (g) {
      var all = g.querySelectorAll("li[data-sev]");
      var n = 0;
      for (var i = 0; i < all.length; i++) if (!all[i].hidden) n++;
      g.hidden = n === 0;
      if (n && !g.classList.contains("alone")) fixShown++;
      var c = g.querySelector(".gcount");
      if (c) c.textContent = (n === all.length ? "" : n + " of ") + all.length + (all.length === 1 ? " finding" : " findings");
    });
    var fix = mode() === "fix";
    if (byRule) byRule.hidden = fix;
    if (byFix) byFix.hidden = !fix;
    var groupsShown = 0;
    groups.forEach(function (g) {
      var all = g.querySelectorAll("details.finding");
      var n = 0, objects = 0, worst = -1;
      for (var i = 0; i < all.length; i++) {
        if (all[i].hidden) continue;
        n++;
        objects += +all[i].getAttribute("data-objects") || 0;
        worst = Math.max(worst, SEVS.indexOf(all[i].getAttribute("data-sev")));
      }
      g.hidden = n === 0;
      if (n) groupsShown++;
      var c = g.querySelector(".gcount");
      if (c) c.textContent = (n === all.length ? "" : n + " of ") + all.length + (all.length === 1 ? " finding" : " findings");
      // The badge and the object count follow the findings shown: the
      // worst severity among them, the objects they list.
      var badge = g.querySelector("summary > .badge");
      if (badge && worst >= 0) {
        badge.className = "badge " + SEVS[worst];
        badge.lastChild.textContent = SEVS[worst].charAt(0).toUpperCase() + SEVS[worst].slice(1);
      }
      var o = g.querySelector(".gobjects");
      if (o) {
        o.hidden = objects <= n;
        o.textContent = " · " + objects.toLocaleString("en-US") + " " + o.getAttribute(objects === 1 ? "data-one" : "data-many");
      }
    });
    count.textContent = shown + " of " + cards.length + " findings " + (fix
      ? "under " + fixShown + (fixShown === 1 ? " change" : " changes")
      : "in " + groupsShown + (groupsShown === 1 ? " rule" : " rules"));
  }

  if (groupBy) groupBy.hidden = false;
  modes.forEach(function (c) { c.addEventListener("change", apply); });
  // A finding listed under a change opens in the rule groups, where its
  // details are: switch back before the link is followed.
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('.byfix a[href^="#f-"]');
    if (!a) return;
    modes.forEach(function (c) { c.checked = c.value === "rule"; });
    apply();
  }, true);

  chips.forEach(function (c) { c.addEventListener("change", apply); });
  // A severity card on the Overview opens the findings of that severity
  // only (before the tab script follows its link): every other filter goes
  // back to its default, so the list holds what the card counts.
  document.addEventListener("click", function (e) {
    var card = e.target.closest && e.target.closest("a.sevcard[data-only], a.hero-crit[data-only]");
    if (!card) return;
    var want = card.getAttribute("data-only");
    chips.forEach(function (c) { c.checked = c.getAttribute("data-sev") === want; });
    categories.forEach(function (c) { c.checked = c.value === ""; });
    search.value = "";
    showSuppressed.checked = false;
    apply();
  }, true);
  categories.forEach(function (c) { c.addEventListener("change", apply); });
  // A category pill on a rule row filters to that category (click it again
  // for all), without opening the row.
  document.addEventListener("click", function (e) {
    var pill = e.target.closest && e.target.closest("button.cat");
    if (!pill) return;
    e.preventDefault();
    e.stopPropagation();
    var want = pill.getAttribute("data-cat");
    var current = categories.filter(function (c) { return c.checked; })[0];
    var next = current && current.value === want ? "" : want;
    categories.forEach(function (c) { c.checked = c.value === next; });
    apply();
  });
  search.addEventListener("input", apply);
  showSuppressed.addEventListener("change", apply);
  [introSel, introFrom, introTo].forEach(function (c) { if (c) c.addEventListener("change", apply); });
  // Opened from a link to what is new (#introduced-…, What changed): when
  // only a few findings match, their groups open, so the page shows them.
  function openFew() {
    var n = 0;
    cards.forEach(function (d) { if (!d.hidden) n++; });
    if (!n || n > 10 || mode() === "fix") return;
    groups.forEach(function (g) { if (!g.hidden) g.open = true; });
  }
  window.addEventListener("hashchange", function () { if (fromHash()) { apply(); openFew(); } });
  if (fromHash()) setTimeout(function () { apply(); openFew(); }, 0);
  if (pathsAll) {
    pathsAll.addEventListener("click", function () {
      pathsOpen = !pathsOpen;
      introduce(introNow);
    });
  }
  expand.addEventListener("click", function () {
    var open = expand.getAttribute("data-open") !== "true";
    groups.forEach(function (g) { if (!g.hidden) g.open = open; });
    fixGroups.forEach(function (g) { if (!g.hidden) g.open = open; });
    cards.forEach(function (d) { if (!d.hidden) d.open = open; });
    expand.setAttribute("data-open", open);
    expand.textContent = open ? "Collapse all" : "Expand all";
  });

  apply();
})();

// Definitions behind (i): shown on hover and focus by the stylesheet; a tap
// or click keeps one open until the next tap elsewhere or Escape. Each is
// nudged to stay inside its row or card, and inside the window.
(function () {
  function place(tip) {
    var text = tip.querySelector(".tip-text");
    if (!text) return;
    text.style.setProperty("--shift", "0px");
    var r = text.getBoundingClientRect();
    if (!r.width) return;
    var left = 12, right = document.documentElement.clientWidth - 12;
    // Its row or card, and any scrolling box it sits in (a wide table's):
    // what is visible of them.
    var boxes = [tip.closest("details.row, .card, section")];
    for (var el = tip.parentElement; el && el !== document.body; el = el.parentElement) {
      var ox = getComputedStyle(el).overflowX;
      if (ox === "auto" || ox === "scroll" || ox === "hidden") { boxes.push(el); break; }
    }
    boxes.forEach(function (box) {
      if (!box) return;
      var b = box.getBoundingClientRect();
      if (Math.min(right, b.right - 12) - Math.max(left, b.left + 12) > r.width) {
        left = Math.max(left, b.left + 12);
        right = Math.min(right, b.right - 12);
      }
    });
    var shift = r.right > right ? right - r.right : r.left < left ? left - r.left : 0;
    text.style.setProperty("--shift", Math.round(shift) + "px");
  }
  function closeAll(except) {
    document.querySelectorAll(".tip.open").forEach(function (t) { if (t !== except) t.classList.remove("open"); });
  }
  document.addEventListener("mouseover", function (e) {
    var tip = e.target.closest && e.target.closest(".tip");
    if (tip) place(tip);
  });
  document.addEventListener("focusin", function (e) {
    var tip = e.target.closest && e.target.closest(".tip");
    if (tip) place(tip);
  });
  document.addEventListener("click", function (e) {
    var button = e.target.closest && e.target.closest(".tip-btn");
    if (!button) { closeAll(null); return; }
    e.preventDefault();
    var tip = button.parentNode;
    closeAll(tip);
    tip.classList.toggle("open");
    place(tip);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeAll(null);
  });
})();

// Printing shows everything.
window.addEventListener("beforeprint", function () {
  // Step-by-step guides stay as they are: opening every one makes a
  // 31-finding report print to well over 100 pages.
  document.querySelectorAll("details:not(.guide)").forEach(function (d) { d.open = true; d.hidden = false; });
});

// "Copy all names": every name listed for a finding, one per line, for a
// script or a change ticket.
document.addEventListener("click", function (e) {
  var button = e.target.closest && e.target.closest("button.copy-names");
  if (!button) return;
  var box = button.closest(".affected");
  var names = Array.prototype.map.call(box.querySelectorAll("[data-name]"), function (li) {
    return li.getAttribute("data-name");
  }).join("\n");
  var label = button.querySelector("span");
  var original = label.textContent;
  function done(text) {
    label.textContent = text;
    setTimeout(function () { label.textContent = original; }, 1600);
  }
  function fallback() {
    var area = document.createElement("textarea");
    area.value = names;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) {}
    document.body.removeChild(area);
    done(ok ? "Copied" : "Select and copy the list by hand");
  }
  try {
    navigator.clipboard.writeText(names).then(function () { done("Copied"); }, fallback);
  } catch (err) { fallback(); }
});
