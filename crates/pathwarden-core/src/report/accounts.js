
// Account lists: which accounts each remediation step cuts off, and
// which reach Tier Zero now or no longer do since the last run. The page
// carries them as data (script.acc-data, JSON: names once, by index) beside
// empty lists (ul.acc-list[data-acc]); a list is drawn when it is first
// shown: SHOWN rows, then Show all. A step's list has a search (by name)
// and Copy names. Names are set as text, never as HTML. The report inlines
// this script after report.js; the app's Home loads it for the report's
// What changed (report/accounts.rs writes both).
(function () {
  "use strict";
  var SHOWN = 20;
  var SVG = "http://www.w3.org/2000/svg";

  function fmt(n) { return Number(n).toLocaleString("en-US"); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function kindIcon(id) {
    var s = document.createElementNS(SVG, "svg");
    s.setAttribute("class", "ic");
    s.setAttribute("aria-hidden", "true");
    var u = document.createElementNS(SVG, "use");
    u.setAttribute("href", "#" + (/^i-[a-z]+(-[a-z]+)*$/.test(id) ? id : "i-object"));
    s.appendChild(u);
    return s;
  }

  // The lists' data where `ul` is: What changed's, or the Remediation
  // path's. Read once.
  function rootOf(ul) { return ul.closest(".ov-since, .panel, .env-ov"); }
  function dataOf(root) {
    if (!root) return null;
    if (root.accData !== undefined) return root.accData;
    var block = root.querySelector("script.acc-data");
    var d = null;
    try { d = block ? JSON.parse(block.textContent) : null; } catch (e) { d = null; }
    if (!d || !d.nodes || !d.edges || !d.lists) d = null;
    root.accData = d;
    return d;
  }
  function node(d, i) { return d.nodes[i] || ["?", "i-object"]; }

  // "R00S03-U00719" and "@SCALE.LOCAL"; a computer's host name and the
  // rest of its name.
  function split(name, icon) {
    var i = name.indexOf("@");
    if (i <= 0 && icon === "i-computer") i = name.indexOf(".");
    return i > 0 ? [name.slice(0, i), name.slice(i)] : [name, ""];
  }
  // A name in a path, without its domain; a domain keeps its name.
  function short(name, icon) {
    if (icon === "i-domain") return name;
    var i = icon === "i-computer" ? name.indexOf(".") : name.indexOf("@");
    return i > 0 ? name.slice(0, i) : name;
  }

  function chip(d, a) {
    var n = node(d, a);
    var c = el("span", "objchip");
    c.appendChild(kindIcon(n[1]));
    var parts = split(n[0], n[1]);
    var nm = el("span", "nm", parts[0]);
    nm.title = n[0];
    if (parts[1]) nm.appendChild(el("span", "dom", parts[1]));
    c.appendChild(nm);
    return c;
  }

  // "3 hops MemberOf ADMINS AdminTo SRV HasSession DA"; past three hops,
  // the first two, "…" and the last.
  function path(d, r) {
    var span = el("span", "acc-path");
    var h = r.h || 0;
    span.appendChild(el("span", "hops", h === 1 ? "1 hop" : fmt(h) + " hops"));
    var p = r.p || [];
    p.forEach(function (hop, i) {
      if (i === p.length - 1 && h > p.length) span.appendChild(el("span", "muted", " … "));
      span.appendChild(el("span", "edge", d.edges[hop[0]] || ""));
      var n = node(d, hop[1]);
      var b = el("b", null, short(n[0], n[1]));
      b.title = n[0];
      span.appendChild(b);
    });
    return span;
  }

  // `on`: the day of the last run, for a path from then.
  function row(d, r, kind, base, on) {
    var li = el("li");
    li.appendChild(chip(d, r.a));
    if (kind === "step") {
      if (r.n) {
        li.className = "is-new";
        li.appendChild(el("span", "ibadge", "New"));
      } else {
        li.appendChild(el("span"));
      }
      li.appendChild(path(d, r));
    } else if (kind === "now") {
      li.appendChild(path(d, r));
      var end = el("span", "acc-end");
      if (r.s) {
        var a = el("a", "steplink", "step " + r.s + " cuts it off");
        a.setAttribute("href", base + "step-" + r.s);
        end.appendChild(a);
      } else {
        end.className = "acc-end muted";
        end.textContent = "No step cuts it off";
      }
      li.appendChild(end);
    } else {
      // No longer reach: its path in the last run, when that run's graph
      // was read.
      var then = r.p && r.p.length && on;
      li.appendChild(then ? path(d, r) : el("span"));
      li.appendChild(el("span", "acc-end muted", (r.w || "") + (then ? " · path on " + on : "")));
    }
    return li;
  }

  // Where a step link goes: this page's step, or the run page's (Home).
  function baseOf(root) {
    var a = root.querySelector("a.acc-base");
    var href = a ? a.getAttribute("href") || "#plan" : "#plan";
    return href.slice(0, href.length - "plan".length);
  }

  function draw(ul) {
    var root = rootOf(ul);
    var d = dataOf(root);
    var list = d && d.lists[ul.getAttribute("data-acc")];
    if (!list || !list.rows) return;
    var st = ul.accState || (ul.accState = { all: false, q: "" });
    var kind = ul.getAttribute("data-kind");
    var rows = list.rows;
    if (st.q) {
      var q = st.q.toLowerCase();
      rows = rows.filter(function (r) { return node(d, r.a)[0].toLowerCase().indexOf(q) !== -1; });
    }
    st.rows = rows;
    var shown = st.all ? rows.length : Math.min(SHOWN, rows.length);
    var base = baseOf(root);
    if (list.on) ul.classList.add("acc-then");
    var frag = document.createDocumentFragment();
    for (var i = 0; i < shown; i++) frag.appendChild(row(d, rows[i], kind, base, list.on));
    ul.textContent = "";
    ul.appendChild(frag);
    var listed = list.rows.length;
    var foot = ul.nextElementSibling;
    if (foot && foot.classList.contains("acc-foot")) {
      foot.textContent = "";
      var capped = ul.getAttribute("data-capped");
      if (shown < rows.length) {
        if (!st.q) foot.appendChild(el("span", null, "Showing " + fmt(shown) + " of " + fmt(list.total) + "."));
        var more = el("button", "ip-all acc-all",
          st.q ? "Show all " + fmt(rows.length)
            : listed < list.total ? "Show the first " + fmt(listed) : "Show all " + fmt(list.total));
        more.type = "button";
        foot.appendChild(more);
      } else if (!st.q && capped && listed < list.total) {
        foot.appendChild(el("span", null, capped));
      }
      foot.hidden = !foot.firstChild;
    }
    var body = ul.closest(".acc-body");
    var match = body && body.querySelector(".acc-match");
    if (match) {
      match.textContent = !st.q ? "" :
        fmt(rows.length) + " of " + (listed < list.total ? "the first " + fmt(listed) : fmt(list.total)) + " match." +
        (shown < rows.length ? " Showing the first " + fmt(shown) + "." : "");
    }
  }

  // Lists in `scope` that can be seen (no folded row around them) and
  // aren't drawn yet.
  function drawShown(scope) {
    Array.prototype.forEach.call(scope.querySelectorAll("ul.acc-list"), function (ul) {
      if (!ul.accState && !ul.closest("details:not([open])")) draw(ul);
    });
  }

  document.addEventListener("toggle", function (e) {
    if (e.target && e.target.tagName === "DETAILS" && e.target.open) drawShown(e.target);
  }, true);

  document.addEventListener("click", function (e) {
    var all = e.target.closest && e.target.closest("button.acc-all");
    if (all) {
      var ul = all.parentNode.previousElementSibling;
      if (ul && ul.accState) {
        ul.accState.all = true;
        draw(ul);
      }
      return;
    }
    var copy = e.target.closest && e.target.closest("button.acc-copy");
    if (!copy) return;
    var body = copy.closest(".acc-body");
    var list = body && body.querySelector("ul.acc-list");
    if (!list) return;
    if (!list.accState) draw(list);
    var d = dataOf(rootOf(list));
    var names = ((list.accState && list.accState.rows) || []).map(function (r) {
      return node(d, r.a)[0];
    }).join("\n");
    var label = copy.querySelector("span");
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

  document.addEventListener("input", function (e) {
    var search = e.target.closest && e.target.closest("input.acc-search");
    if (!search) return;
    var body = search.closest(".acc-body");
    var ul = body && body.querySelector("ul.acc-list");
    if (!ul) return;
    var st = ul.accState || (ul.accState = { all: false, q: "" });
    st.q = search.value.trim();
    st.all = false;
    draw(ul);
  });

  // Printing shows what each list shows.
  window.addEventListener("beforeprint", function () { drawShown(document); });
  drawShown(document);
})();
