// OpenGraph sources: the Detected sources panel and coverage form on
// Analyze, and the trust dialog on Mappings. The server renders every piece
// of HTML (escaped); this script only moves it into place and reads values.
(function () {
  "use strict";
  function $(id) { return document.getElementById(id); }
  function toast(message) {
    var t = $("toast");
    if (!t) return;
    t.textContent = message;
    t.classList.remove("kept"); // app.js may have left a note's look
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.hidden = true; }, 6000);
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
    }).then(function (r) {
      return r.text().then(function (text) {
        var j = null;
        try { j = text ? JSON.parse(text) : {}; } catch (e) {}
        if (!r.ok) throw new Error((j && j.error) || "Pathwarden didn't answer (" + r.status + "). Is it still running?");
        return j;
      });
    });
  }
  function lines(text) {
    return (text || "").split(/[\r\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  }

  // ------------------------------------------------------------ Analyze
  var panel = $("og-panel");
  if (panel) {
    var PEEK = 65536;
    var seq = 0;
    var timer = null;
    var sniff = function (files) {
      var mine = ++seq;
      var wanted = files.filter(function (f) { return /\.(json|zip)$/i.test(f.name); }).slice(0, 40);
      if (!wanted.some(function (f) { return /\.json$/i.test(f.name); })) {
        panel.hidden = true; panel.innerHTML = ""; return;
      }
      Promise.all(wanted.map(function (f) {
        if (/\.zip$/i.test(f.name)) return { name: f.name, size: f.size, head: "", tail: "" };
        return Promise.all([
          f.slice(0, PEEK).text(),
          f.slice(Math.max(0, f.size - PEEK)).text()
        ]).then(function (ends) { return { name: f.name, size: f.size, head: ends[0], tail: ends[1] }; });
      })).then(function (list) {
        return post("/api/opengraph/sniff", { files: list });
      }).then(function (d) {
        if (mine !== seq) return;
        panel.innerHTML = d.html || "";
        panel.hidden = !d.opengraph;
        wire(panel);
      }).catch(function () { if (mine === seq) panel.hidden = true; });
    };
    document.addEventListener("pw:files", function (e) {
      clearTimeout(timer);
      var files = e.detail || [];
      timer = setTimeout(function () { sniff(files); }, 150);
    });

    var wire = function (root) {
      Array.prototype.forEach.call(root.querySelectorAll("input.og-load"), function (input) {
        input.addEventListener("change", function () {
          var f = input.files && input.files[0];
          if (!f) return;
          if (f.size > 8 << 20) { toast("That list is larger than 8 MB."); input.value = ""; return; }
          f.text().then(function (t) {
            var area = input.closest(".og-declare").querySelector("textarea.og-ok");
            var have = lines(area.value);
            lines(t).forEach(function (l) { if (have.indexOf(l) < 0) have.push(l); });
            area.value = have.join("\n");
            input.value = "";
            var on = input.closest(".og-declare").querySelector(".og-enable");
            if (on) on.checked = true;
          });
        });
      });
      // Typing in a form turns it on.
      Array.prototype.forEach.call(root.querySelectorAll(".og-declare"), function (d) {
        d.addEventListener("input", function (ev) {
          if (ev.target.classList.contains("og-enable") || ev.target.classList.contains("og-complete")) return;
          var on = d.querySelector(".og-enable");
          if (on) on.checked = true;
        });
      });
    };

    // The declarations to send with the upload: a JSON list, "" for none,
    // or false when one is incomplete (the upload then waits).
    window.pwCoverage = function () {
      if (panel.hidden) return "";
      var out = [];
      var bad = null;
      Array.prototype.forEach.call(panel.querySelectorAll(".og-declare"), function (d) {
        var on = d.querySelector(".og-enable");
        if (!on || !on.checked) return;
        var domains = Array.prototype.map.call(d.querySelectorAll("input[name=og-dom]:checked"), function (c) { return c.value; })
          .concat(lines(d.querySelector(".og-dom-other").value));
        var ok = lines(d.querySelector("textarea.og-ok").value);
        if (!domains.length && !ok.length) { bad = bad || d; return; }
        out.push({
          file: d.getAttribute("data-file"),
          declaration: {
            all_in_domains: domains,
            ok: ok,
            failed: lines(d.querySelector("textarea.og-failed").value),
            complete: d.querySelector(".og-complete").checked
          }
        });
      });
      if (bad) {
        bad.open = true;
        toast("Say what " + (bad.getAttribute("data-file") || "the file") + "'s collector scanned (a domain or a list of computers), or untick Attach this coverage.");
        return false;
      }
      return out.length ? JSON.stringify(out) : "";
    };
  }

  // ------------------------------------------------------------ Mappings
  var dialog = $("og-trust");
  if (dialog) {
    var pack = null;
    var digest = null;
    var ok = $("og-trust-ok");
    var go = $("og-trust-go");
    var status = $("og-trust-status");
    ok.addEventListener("change", function () { go.disabled = !ok.checked; });
    Array.prototype.forEach.call(document.querySelectorAll("[data-og-trust]"), function (b) {
      b.addEventListener("click", function () {
        pack = b.getAttribute("data-og-trust");
        digest = b.getAttribute("data-digest") || null;
        $("og-trust-name").textContent = b.getAttribute("data-title") || pack;
        ok.checked = false; go.disabled = true; status.textContent = "";
        dialog.showModal();
      });
    });
    go.addEventListener("click", function () {
      if (!ok.checked || !pack) return;
      go.disabled = true;
      post("/api/mappings/trust", { pack: pack, trusted: true, confirm: true, digest: digest })
        .then(function () { location.reload(); })
        .catch(function (e) { status.textContent = e.message; go.disabled = false; });
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-og-untrust]"), function (b) {
      b.addEventListener("click", function () {
        var name = b.getAttribute("data-title") || b.getAttribute("data-og-untrust");
        if (!window.confirm("Stop trusting " + name + "? Its relationships become context only from the next analysis on.")) return;
        b.disabled = true;
        post("/api/mappings/trust", { pack: b.getAttribute("data-og-untrust"), trusted: false })
          .then(function () { location.reload(); })
          .catch(function (e) { toast(e.message); b.disabled = false; });
      });
    });
  }
})();
