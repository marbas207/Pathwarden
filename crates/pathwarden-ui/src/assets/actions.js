// Finding actions on the app's pages (actions_app.rs):
//
// - the run page: a finding's action button in the embedded report sends
//   { type: "pathwarden:action", fingerprint, action, record }. It is
//   accepted only from the report's frame (event.source), only for a
//   well-formed fingerprint of a finding the server listed on the dialog
//   (data-findings), and only for an action the server offered on it, or a
//   follow-up the server offered on that record. It only opens the dialog:
//   nothing runs until Run is clicked;
// - Plugins and actions: Test (a dry run, in the same progress view),
//   Remove, and the form that adds or changes an action program.
//
// Everything a program says (lines, messages, records, links) is shown as
// text; a link is opened only when it is https://. One action runs at a
// time; the server refuses a second (429) and one during an analysis (409).
(function () {
  "use strict";
  function $(id) { return document.getElementById(id); }
  var own = Object.prototype.hasOwnProperty;
  // As the server checks them: PW-003-0123456789abcdef.
  var FINGERPRINT = /^PW-[A-Za-z0-9-]{1,61}$/;
  // Bidi controls shown, not obeyed (pathwarden_core::text::is_bidi_control).
  function visible(s) {
    return String(s == null ? "" : s).replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, function (c) {
      return "\\u{" + c.charCodeAt(0).toString(16) + "}";
    });
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = visible(text);
    return e;
  }
  var SVG = "http://www.w3.org/2000/svg";
  function use(id, cls) {
    var s = document.createElementNS(SVG, "svg");
    s.setAttribute("class", "ic" + (cls ? " " + cls : ""));
    s.setAttribute("aria-hidden", "true");
    var u = document.createElementNS(SVG, "use");
    u.setAttribute("href", "#" + id);
    s.appendChild(u);
    return s;
  }
  function post(url, body, method) {
    return fetch(url, {
      method: method || "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = {};
        try { j = JSON.parse(t); } catch (e) {}
        if (!r.ok) { var err = new Error(j.error || "That didn't work. Try again."); err.status = r.status; throw err; }
        return j;
      });
    }, function () { throw new Error("Pathwarden is not answering. Is it still running?"); });
  }
  function anyDialogOpen() {
    return Array.prototype.some.call(document.querySelectorAll("dialog"), function (d) { return d.open; });
  }
  // "Open a service request" -> "Opening a service request".
  function doing(label) {
    var m = /^(\S+)(.*)$/.exec(label || "");
    if (!m) return label;
    var w = m[1], low = w.toLowerCase();
    if (/[^aeiou]e$/.test(low) && low !== "be") w = w.slice(0, -1) + "ing";
    else if (/^[^aeiou][aeiou][bdgmnprt]$/.test(low)) w = w + w.slice(-1) + "ing";
    else if (/ing$/.test(low)) return label;
    else w = w + "ing";
    return w + m[2];
  }
  function lowerFirst(s) { return s ? s.charAt(0).toLowerCase() + s.slice(1) : s; }
  function clock(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    return Math.floor(seconds / 60) + ":" + ("0" + (seconds % 60)).slice(-2);
  }
  function copyText(text, done) {
    function fallback() {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.className = "ac-copy-area";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (err) {}
      document.body.removeChild(area);
      done(ok);
    }
    try { navigator.clipboard.writeText(text).then(function () { done(true); }, fallback); } catch (err) { fallback(); }
  }
  function https(url) { return typeof url === "string" && /^https:\/\/[^\s]+$/i.test(url) && url.length <= 2048; }

  var dialog = $("ac-dialog");
  if (dialog) {
    var run = dialog.getAttribute("data-run");
    var acts = {}, findings = {};
    try { acts = JSON.parse(dialog.getAttribute("data-acts") || "{}") || {}; } catch (e) { acts = {}; }
    try { findings = JSON.parse(dialog.getAttribute("data-findings") || "{}") || {}; } catch (e) { findings = {}; }
    var current = null; // { fp, address, record, title }
    var busy = false, job = null, poll = null, tick = null, started = 0, last = null;

    var form = $("ac-form"), go = $("ac-go"), cancel = $("ac-cancel");
    var seeBtn = $("ac-see"), json = $("ac-json"), jsonNote = $("ac-json-note");
    var testBox = $("ac-test"), testWrap = $("ac-test-wrap");
    var closeX = dialog.querySelector(".rt-x");

    function setGo(text, primary, disabled) {
      go.textContent = "";
      go.appendChild(use("i-bolt"));
      go.appendChild(document.createTextNode(" "));
      go.appendChild(el("span", null, text));
      go.disabled = !!disabled;
      go.classList.toggle("busy", !!disabled);
      go.hidden = !primary;
    }
    function tag(box) {
      if (current && current.dry) box.appendChild(el("span", "ac-test-tag", "Test"));
    }
    // ---------------------------------------------------------- inputs
    function field(def) {
      var box = el("div", "ac-field");
      var id = "ac-in-" + def.id;
      var label = el("label");
      label.setAttribute("for", id);
      label.appendChild(document.createTextNode(visible(def.label)));
      if (!def.required) { label.appendChild(document.createTextNode(" ")); label.appendChild(el("span", "muted", "(optional)")); }
      var value = def["default"];
      if (def.type === "textarea" || def.type === "text") {
        var input = el(def.type === "textarea" ? "textarea" : "input");
        input.id = id;
        if (def.type === "textarea") input.rows = 3;
        input.maxLength = def.max || (def.type === "textarea" ? 2000 : 200);
        if (def.required) input.required = true;
        if (typeof value === "string") input.value = value;
        input.setAttribute("data-input", def.id);
        box.appendChild(label);
        box.appendChild(input);
      } else if (def.type === "choice") {
        var choices = Array.isArray(def.choices) ? def.choices : [];
        var pick = typeof value === "string" && choices.indexOf(value) >= 0 ? value : choices[0];
        label.removeAttribute("for");
        label.id = id + "-l";
        box.appendChild(label);
        if (choices.length <= 5) {
          var seg = el("span", "ac-seg");
          seg.setAttribute("role", "radiogroup");
          seg.setAttribute("aria-labelledby", id + "-l");
          seg.setAttribute("data-input", def.id);
          seg.setAttribute("data-value", pick || "");
          choices.forEach(function (c) {
            var b = el("button", null, c);
            b.type = "button";
            b.setAttribute("role", "radio");
            b.setAttribute("aria-checked", String(c === pick));
            b.addEventListener("click", function () {
              seg.setAttribute("data-value", c);
              Array.prototype.forEach.call(seg.children, function (x) { x.setAttribute("aria-checked", String(x === b)); });
              changed();
            });
            seg.appendChild(b);
          });
          box.appendChild(seg);
        } else {
          var sel = el("select", "ac-select");
          sel.setAttribute("aria-labelledby", id + "-l");
          sel.setAttribute("data-input", def.id);
          choices.forEach(function (c) { var o = el("option", null, c); o.value = c; if (c === pick) o.selected = true; sel.appendChild(o); });
          box.appendChild(sel);
        }
      } else if (def.type === "bool") {
        box.className = "ac-field ac-check";
        var cb = el("input");
        cb.type = "checkbox";
        cb.id = id;
        cb.checked = value === true;
        cb.setAttribute("data-input", def.id);
        label.insertBefore(cb, label.firstChild);
        box.appendChild(label);
      }
      return box;
    }
    function inputs() {
      var out = {};
      Array.prototype.forEach.call($("ac-inputs").querySelectorAll("[data-input]"), function (n) {
        var k = n.getAttribute("data-input");
        if (n.classList.contains("ac-seg")) out[k] = n.getAttribute("data-value") || "";
        else if (n.type === "checkbox") out[k] = n.checked;
        else out[k] = n.value;
      });
      return out;
    }
    function body() {
      return {
        fingerprint: current.fp,
        action: current.address,
        inputs: inputs(),
        dry_run: testBox.checked,
        record: current.record ? current.record.id : null
      };
    }
    // ------------------------------------------------- what's sent
    // The request as JSON, its keys marked: built as text nodes.
    function showJson(v) {
      json.textContent = "";
      var text = JSON.stringify(v, null, 2);
      text.split("\n").forEach(function (line, i) {
        if (i) json.appendChild(document.createTextNode("\n"));
        var m = /^(\s*)("(?:[^"\\]|\\.)*")(: )(.*)$/.exec(line);
        if (!m) { json.appendChild(document.createTextNode(visible(line))); return; }
        json.appendChild(document.createTextNode(m[1]));
        json.appendChild(el("span", "k", m[2]));
        json.appendChild(document.createTextNode(m[3] + visible(m[4])));
      });
    }
    var seq = 0;
    function refreshJson() {
      if (seeBtn.getAttribute("aria-expanded") !== "true" || !current || current.mode !== "run") return;
      var mine = ++seq;
      post("/api/runs/" + encodeURIComponent(run) + "/actions/request", body()).then(function (j) {
        if (mine === seq) showJson(j.request);
      }, function (err) {
        if (mine !== seq) return;
        json.textContent = err.message;
      });
    }
    var later = null;
    function changed() { clearTimeout(later); later = setTimeout(refreshJson, 300); }
    seeBtn.addEventListener("click", function () {
      var open = seeBtn.getAttribute("aria-expanded") !== "true";
      seeBtn.setAttribute("aria-expanded", String(open));
      json.hidden = !open;
      jsonNote.hidden = !open;
      if (open) { json.textContent = "…"; refreshJson(); }
    });
    $("ac-inputs").addEventListener("input", changed);
    $("ac-inputs").addEventListener("change", changed);
    testBox.addEventListener("change", changed);

    // ---------------------------------------------------------- views
    function show(part) {
      form.hidden = part !== "form";
      $("ac-run").hidden = part !== "run";
      $("ac-result").hidden = part !== "result";
      testWrap.hidden = part !== "form" || current.mode !== "run";
    }
    function head(eyebrow, title, desc) {
      var e = $("ac-eyebrow");
      e.textContent = visible(eyebrow);
      tag(e);
      $("ac-title").textContent = visible(title);
      $("ac-desc").textContent = visible(desc || "");
      $("ac-desc").hidden = !desc;
    }
    function openFor(fp, address, record) {
      var a = acts[address], f = findings[fp];
      current = { mode: "run", fp: fp, address: address, record: record, title: f.title, label: a.label, name: address.split("/")[0], dry: false };
      head(a.label, record ? record.chip + " · " + f.title : f.title, a.description);
      var box = $("ac-inputs");
      box.textContent = "";
      (Array.isArray(a.inputs) ? a.inputs : []).forEach(function (d) { box.appendChild(field(d)); });
      $("ac-sends-text").textContent = visible(a.sends || "the finding and your inputs.");
      seeBtn.setAttribute("aria-expanded", "false");
      json.hidden = true;
      jsonNote.hidden = true;
      jsonNote.textContent = "What Pathwarden gives the " + visible(current.name) + " program, with your inputs.";
      testBox.checked = false;
      $("ac-saved").textContent = "";
      cancel.textContent = "Cancel";
      setGo("Run", true, false);
      show("form");
      closeX.disabled = false;
      if (dialog.showModal) dialog.showModal(); else dialog.setAttribute("open", "");
      var first = box.querySelector("textarea, input, select, button");
      (first || go).focus();
    }
    // The progress: earlier lines ticked, the latest one now.
    function lines(list) {
      var ol = $("ac-lines");
      ol.textContent = "";
      list.forEach(function (l, i) {
        var li = el("li");
        if (i === list.length - 1 && busy) {
          li.className = "now";
          li.appendChild(el("span", "pulse"));
        } else {
          li.appendChild(use("i-tick"));
        }
        li.appendChild(el("span", null, l));
        ol.appendChild(li);
      });
    }
    function running(label) {
      busy = true;
      started = Date.now();
      var t = $("ac-run-title");
      t.textContent = visible(doing(label)) + "…";
      tag(t);
      $("ac-elapsed").textContent = "0:00";
      lines([]);
      show("run");
      $("ac-saved").textContent = "";
      cancel.textContent = "Cancel";
      cancel.disabled = false;
      setGo("Running…", true, true);
      closeX.disabled = true;
      tick = setInterval(function () { $("ac-elapsed").textContent = clock((Date.now() - started) / 1000); }, 500);
    }
    function stopTimers() {
      clearInterval(tick); tick = null;
      clearTimeout(poll); poll = null;
    }
    function start(url, b) {
      if (busy) return;
      running(current.label);
      post(url, b).then(function (j) {
        job = j.job;
        if (j.title && current.mode === "test") $("ac-title").textContent = visible(j.title);
        poll = setTimeout(check, 400);
      }, function (err) {
        busy = false;
        stopTimers();
        failed(err.message);
      });
    }
    function check() {
      fetch("/api/jobs/" + encodeURIComponent(job), { credentials: "same-origin" })
        .then(function (r) {
          if (!r.ok) {
            // The job is gone (Pathwarden restarted, say): say so, once.
            busy = false;
            stopTimers();
            failed("Pathwarden lost track of this action. Look at the finding's activity, then try again.");
            return null;
          }
          return r.json();
        })
        .then(function (j) {
          if (!j) return;
          var p = j.action || {};
          if (Array.isArray(p.lines)) lines(p.lines);
          if (j.status === "acted" && p.result) { busy = false; stopTimers(); result(p.result); return; }
          poll = setTimeout(check, 500);
        }, function () { poll = setTimeout(check, 1500); });
    }
    function failed(message) {
      var box = $("ac-result");
      box.className = "rt-result error ac-res";
      box.textContent = "";
      box.appendChild(el("strong", null, "Couldn't start it."));
      box.appendChild(el("p", null, message));
      show("result");
      closeX.disabled = false;
      cancel.textContent = "Close";
      cancel.disabled = false;
      setGo("Try again", current.mode === "run", false);
    }
    // A record: its chip, Open (https:// only) and Copy.
    function recordRow(r) {
      var row = el("div", "ac-rec");
      var chip = el("span", "ac-chip" + (r.open ? "" : " closed"));
      chip.appendChild(use("i-ticket"));
      var name = r.number || r.label || r.id;
      chip.appendChild(el("span", "num", name));
      chip.appendChild(document.createTextNode(" · " + visible(r.status || (r.open ? "Open" : "Closed"))));
      row.appendChild(chip);
      if (https(r.url)) {
        var a = el("a", "btn small-btn");
        a.href = r.url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.title = visible(r.url);
        a.appendChild(use("i-ext"));
        a.appendChild(document.createTextNode(" Open"));
        row.appendChild(a);
      }
      var c = el("button", "btn small-btn");
      c.type = "button";
      c.appendChild(use("i-copy"));
      var cl = el("span", null, "Copy");
      c.appendChild(document.createTextNode(" "));
      c.appendChild(cl);
      c.addEventListener("click", function () {
        copyText(String(name), function (ok) { cl.textContent = ok ? "Copied" : visible(name); setTimeout(function () { cl.textContent = "Copy"; }, 1600); });
      });
      row.appendChild(c);
      return row;
    }
    function result(r) {
      last = r;
      var box = $("ac-result");
      box.textContent = "";
      var cancelled = r.ended === "cancelled";
      var ok = r.ok === true;
      box.className = "rt-result ac-res " + (ok ? "fixed" : cancelled ? "unknown" : "error");
      var msg = String(r.message || "");
      var first = msg.split("\n")[0];
      var rest = msg.slice(first.length).trim();
      var strong;
      if (ok) {
        strong = el("strong", null, first || "Done.");
      } else if (cancelled) {
        strong = el("strong", null, "Cancelled.");
        rest = "It was stopped before it finished.";
      } else {
        strong = el("strong", null, "Couldn't " + lowerFirst(current.label || "run it") + ".");
        rest = msg;
      }
      tag(strong);
      box.appendChild(strong);
      if (rest) box.appendChild(el("p", null, rest));
      (Array.isArray(r.records) ? r.records : []).forEach(function (x) { box.appendChild(recordRow(x)); });
      (Array.isArray(r.links) ? r.links : []).forEach(function (l) {
        if (!https(l.url)) return;
        var a = el("a", "ac-link", l.label || l.url);
        a.href = l.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        box.appendChild(a);
      });
      (Array.isArray(r.problems) ? r.problems : []).forEach(function (p) { box.appendChild(el("p", "muted small", p)); });
      if (!ok) {
        var d = el("details");
        d.appendChild(el("summary", null, "Show details"));
        var text = (Array.isArray(r.progress) ? r.progress : []).slice();
        String(r.details || "").split("\n").filter(Boolean).forEach(function (l) { text.push("[stderr] " + l); });
        text.push((r.status ? r.status.charAt(0).toUpperCase() + r.status.slice(1) : "Ended") + " after " + clock((Date.now() - started) / 1000));
        d.appendChild(el("pre", null, text.join("\n")));
        box.appendChild(d);
      }
      show("result");
      closeX.disabled = false;
      $("ac-saved").textContent = visible(r.said || "");
      cancel.disabled = false;
      if (ok) {
        cancel.hidden = true;
        go.hidden = false;
        go.disabled = false;
        go.classList.remove("busy");
        go.textContent = "Done";
        go.setAttribute("data-done", "1");
      } else {
        cancel.hidden = false;
        cancel.textContent = "Close";
        setGo("Try again", current.mode === "run" || current.mode === "test", false);
      }
      // The finding's chip and Activity, in the report, at once.
      if (current.mode === "run" && r.view && own.call(findings, current.fp)) {
        findings[current.fp].view = r.view;
        tellReport({ type: "pathwarden:action-view", fingerprint: current.fp, view: r.view });
      }
    }
    function tellReport(m) {
      var frame = $("report-frame");
      if (!frame || !frame.contentWindow || frame.getAttribute("data-live") !== "1") return;
      frame.contentWindow.postMessage(m, "*");
    }
    function reset() {
      go.removeAttribute("data-done");
      cancel.hidden = false;
    }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (busy || !current) return;
      if (go.getAttribute("data-done") === "1") { reset(); dialog.close(); return; }
      if (!form.hidden && !form.reportValidity()) return;
      if (current.mode === "test") {
        current.dry = true;
        start("/api/actions/test", { name: current.name, action: current.id });
        return;
      }
      if (!$("ac-result").hidden) { show("form"); setGo("Run", true, false); cancel.textContent = "Cancel"; return; }
      current.dry = testBox.checked;
      head(current.label, $("ac-title").textContent, $("ac-desc").textContent);
      start("/api/runs/" + encodeURIComponent(run) + "/actions/run", body());
    });
    cancel.addEventListener("click", function () {
      if (busy && job) {
        cancel.disabled = true;
        post("/api/jobs/" + encodeURIComponent(job) + "/cancel", {}).catch(function () {});
        return;
      }
      if (!busy) { reset(); dialog.close(); }
    });
    // Escape while it runs doesn't close it: Cancel stops it first.
    dialog.addEventListener("cancel", function (e) { if (busy) e.preventDefault(); });
    dialog.addEventListener("close", function () { if (!busy) { reset(); current = current && current.mode === "test" ? null : current; } });

    // A finding's action in the report (see the top of this file).
    window.addEventListener("message", function (e) {
      var frame = $("report-frame");
      if (!frame || e.source !== frame.contentWindow) return;
      var m = e.data;
      if (!m || typeof m !== "object" || m.type !== "pathwarden:action") return;
      var fp = m.fingerprint;
      if (typeof fp !== "string" || fp.length > 64 || !FINGERPRINT.test(fp) || !own.call(findings, fp)) return;
      if (typeof m.action !== "string" || m.action.length > 130 || !own.call(acts, m.action)) return;
      var v = findings[fp].view || {};
      var rec = null;
      if (m.record != null) {
        if (typeof m.record !== "string") return;
        (Array.isArray(v.records) ? v.records : []).forEach(function (x) { if (x && x.id === m.record) rec = x; });
        if (!rec || !Array.isArray(rec.follow_ups) || rec.follow_ups.indexOf(m.action) < 0) return;
      } else if (!Array.isArray(v.offered) || v.offered.indexOf(m.action) < 0) {
        return;
      }
      if (busy || anyDialogOpen()) return;
      openFor(fp, m.action, rec);
    });

    // Plugins and actions: Test, in the same progress view.
    Array.prototype.forEach.call(document.querySelectorAll("[data-ac-test]"), function (b) {
      b.addEventListener("click", function () {
        if (busy || anyDialogOpen()) return;
        var name = b.getAttribute("data-ac-test"), id = b.getAttribute("data-action");
        var row = b.closest(".ac-act");
        var label = row ? row.querySelector("strong").textContent : id;
        current = { mode: "test", name: name, id: id, label: label, dry: true };
        head(label, "The first matching finding of the latest analysis", "");
        testWrap.hidden = true;
        cancel.hidden = false;
        if (dialog.showModal) dialog.showModal(); else dialog.setAttribute("open", "");
        start("/api/actions/test", { name: name, action: id });
      });
    });
  }

  // A small confirm, for Remove.
  function ask(title, text, okText) {
    var d = el("dialog", "card confirm ac-confirm");
    d.appendChild(el("h2", "sub", title));
    d.appendChild(el("p", "muted", text));
    var row = el("div", "dialog-actions");
    var no = el("button", "btn", "Cancel");
    no.type = "button";
    var yes = el("button", "btn danger", okText);
    yes.type = "button";
    row.appendChild(no); row.appendChild(yes);
    d.appendChild(row);
    document.body.appendChild(d);
    return new Promise(function (resolve) {
      var answer = false;
      no.addEventListener("click", function () { d.close(); });
      yes.addEventListener("click", function () { answer = true; d.close(); });
      d.addEventListener("close", function () { d.remove(); resolve(answer); });
      d.showModal();
      no.focus();
    });
  }
  Array.prototype.forEach.call(document.querySelectorAll("[data-ac-remove]"), function (b) {
    b.addEventListener("click", function () {
      var name = b.getAttribute("data-name");
      ask("Remove " + name + "?", "Its buttons go from every finding. What it did stays in the findings' activity.", "Remove").then(function (yes) {
        if (!yes) return;
        post("/api/actions/" + encodeURIComponent(b.getAttribute("data-ac-remove")), { expect: name }, "DELETE").then(function () {
          location.href = "/automate/ticketing#saved";
          location.reload();
        }, function (err) { var t = $("toast"); if (t) { t.textContent = err.message; t.hidden = false; } });
      });
    });
  });

  // The form that adds or changes an action program.
  var af = $("action-form");
  if (af) {
    var meta = {};
    try { meta = JSON.parse(af.getAttribute("data-action-form")) || {}; } catch (e) { meta = {}; }
    var how = function () { var r = af.querySelector("input[name=af-how]:checked"); return r ? r.value : "plugin"; };
    var toggle = function () {
      Array.prototype.forEach.call(af.querySelectorAll("[data-when-how]"), function (f) { f.hidden = f.getAttribute("data-when-how") !== how(); });
    };
    Array.prototype.forEach.call(af.querySelectorAll("input[name=af-how]"), function (r) { r.addEventListener("change", toggle); });
    toggle();
    af.addEventListener("click", function (e) {
      var rm = e.target.closest("[data-remove-kv]");
      if (rm && !rm.disabled) { rm.closest(".kv").remove(); return; }
      var add = e.target.closest("[data-add-kv]");
      if (add && !add.disabled) {
        var box = $(add.getAttribute("data-add-kv"));
        var first = box.querySelector(".kv");
        var row;
        if (first) {
          row = first.cloneNode(true);
          Array.prototype.forEach.call(row.querySelectorAll("input"), function (i) { i.value = ""; });
        } else {
          row = el("div", "kv");
          ["name", "value"].forEach(function (p, i) {
            var inp = el("input", "input" + (i ? "" : " mono"));
            inp.setAttribute(i ? "data-v" : "data-k", "");
            inp.placeholder = p;
            inp.setAttribute("aria-label", i ? "Value" : "Name");
            row.appendChild(inp);
          });
          var x = el("button", "fl-remove");
          x.type = "button";
          x.setAttribute("data-remove-kv", "");
          x.setAttribute("aria-label", "Remove");
          x.appendChild(use("i-x"));
          row.appendChild(x);
        }
        box.appendChild(row);
        row.querySelector("[data-k]").focus();
      }
    });
    af.addEventListener("submit", function (e) {
      e.preventDefault();
      var status = af.querySelector(".save-status");
      var settings = Array.prototype.map.call(af.querySelectorAll("#af-settings .kv"), function (r) {
        return [r.querySelector("[data-k]").value.trim(), r.querySelector("[data-v]").value];
      }).filter(function (p) { return p[0] || p[1].trim(); });
      var cats = [];
      if ($("af-cat-attack").checked) cats.push("attack_path");
      if ($("af-cat-hygiene").checked) cats.push("hygiene");
      var t = parseInt($("af-timeout").value, 10);
      var body = {
        index: meta.index == null ? null : meta.index,
        expect: meta.expect || null,
        name: $("af-name").value,
        how: how(),
        plugin: $("af-plugin").value,
        program: $("af-program").value,
        args: $("af-args").value.split("\n"),
        settings: settings,
        timeout_seconds: isFinite(t) ? t : null,
        min_severity: $("af-min").value,
        rules: $("af-rules").value.split(/[,\s]+/).filter(Boolean),
        categories: cats
      };
      status.textContent = "Saving…";
      post("/api/actions", body).then(function () {
        location.href = "/automate/ticketing#saved";
      }, function (err) { status.textContent = err.message; });
    });
  }
})();
