// Progress charts: one tooltip for the run under the pointer or keyboard
// focus. Every value it shows is also labeled or in the table.
(function () {
  "use strict";
  var tip = document.getElementById("pv-tip");
  if (!tip) return;
  var active = null;

  function show(el, x, y) {
    if (active && active !== el) active.classList.remove("on");
    active = el;
    el.classList.add("on");
    var lines = (el.getAttribute("data-tip") || "").split("\n");
    // The first line is the run's time: local, as everywhere (app.js).
    var unix = el.getAttribute("data-tip-unix");
    if (unix && window.PathwardenTime) lines[0] = window.PathwardenTime.local(unix);
    tip.textContent = "";
    lines.forEach(function (l, i) {
      var row = document.createElement(i === 0 ? "strong" : "span");
      row.textContent = l;
      tip.appendChild(row);
    });
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    var left = Math.min(window.innerWidth - w - 8, Math.max(8, x + 14));
    var top = y - h - 12 < 8 ? y + 16 : y - h - 12;
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }
  function hide() {
    if (active) active.classList.remove("on");
    active = null;
    tip.hidden = true;
  }

  document.querySelectorAll(".pv-hit").forEach(function (el) {
    // The label and its <title> say the run's time as the tooltip does:
    // local, not the UTC the page was written with.
    var unix = el.getAttribute("data-tip-unix");
    var utc = (el.getAttribute("data-tip") || "").split("\n")[0];
    if (unix && utc && window.PathwardenTime) {
      var local = window.PathwardenTime.local(unix);
      var label = el.getAttribute("aria-label") || "";
      if (label.indexOf(utc) === 0) {
        label = local + label.slice(utc.length);
        el.setAttribute("aria-label", label);
        var title = el.querySelector("title");
        if (title) title.textContent = label;
      }
    }
    el.addEventListener("pointermove", function (e) { show(el, e.clientX, e.clientY); });
    el.addEventListener("pointerleave", hide);
    el.addEventListener("focus", function () {
      var r = el.getBoundingClientRect();
      show(el, r.left + r.width / 2, r.top + r.height / 3);
    });
    el.addEventListener("blur", hide);
  });
  window.addEventListener("scroll", hide, { passive: true });
  // On a narrow screen a chart scrolls sideways (its left column stays):
  // start with the latest run's labels at the right edge, which leaves as
  // many earlier runs in view as fit.
  function toLatest(el) {
    if (el.scrollWidth <= el.clientWidth) return;
    var right = 0;
    el.querySelectorAll(".pv-svg:not(.pv-axis) text").forEach(function (t) {
      right = Math.max(right, t.getBoundingClientRect().right);
    });
    var box = el.getBoundingClientRect();
    el.scrollLeft = Math.max(0, right - box.right + el.scrollLeft + 6);
  }
  // A label scrolled partly under the left column would read as another
  // number ("2" of "62"): hidden until it is clear of it again.
  function clip(el) {
    var axis = el.querySelector(".pv-axis");
    if (!axis) return;
    var edge = axis.getBoundingClientRect().right;
    el.querySelectorAll(".pv-svg:not(.pv-axis) text").forEach(function (t) {
      t.classList.toggle("pv-under", el.scrollLeft > 0 && t.getBoundingClientRect().left < edge);
    });
  }
  document.querySelectorAll(".pv-scroll").forEach(function (el) {
    toLatest(el);
    clip(el);
    el.addEventListener("scroll", function () { clip(el); }, { passive: true });
  });
  // The scale switch shows the other chart, hidden until now.
  document.querySelectorAll('input[name="pv-scale"]').forEach(function (r) {
    r.addEventListener("change", function () {
      document.querySelectorAll(".pv-tiers .pv-scroll").forEach(function (el) { toLatest(el); clip(el); });
    });
  });
})();
