// The run page's side of the embedded report, beside retest.js (Retest):
//
// - the frame's height and scroll requests, so the page scrolls as one and
//   the report's tab bar stays in view;
// - Accept risk: opens a dialog here; only a confirmed save writes
//   pathwarden.toml (POST /api/settings/suppress, as Settings does);
// - Add a note: the same, for the accepted risk that covers a finding
//   (POST /api/settings/suppress/{index}/note);
// - Open in Explore: goes to this run's Explore page for the finding;
// - the report's place (its tab or finding, the #hash) kept in this page's
//   address, so reload, Back and a shared link land there (app.js passes
//   it on to the frame).
//
// Every message is accepted only from the report's frame (event.source),
// only with a known type, and only with a number (height, scroll), an
// element ID (place) or a well-formed fingerprint of one of this run's open findings, as the
// server listed them on the Retest dialog. Titles shown here come from the
// server, never from the report.
(function () {
  "use strict";
  function $(id) { return document.getElementById(id); }
  var frame = $("report-frame");
  var findingsBox = $("rt-dialog");
  if (!frame || !findingsBox) return;
  var run = findingsBox.getAttribute("data-run");
  var findings = {};
  try { findings = JSON.parse(findingsBox.getAttribute("data-findings")) || {}; } catch (e) { findings = {}; }
  var own = Object.prototype.hasOwnProperty;
  // "Oct 22, 2026" (PathwardenTime.date in app.js).
  function day(text) { return window.PathwardenTime.date(text); }
  // Bidi controls shown, not obeyed, as the server's pages show them
  // (pathwarden_core::text::is_bidi_control).
  function visible(s) {
    return String(s == null ? "" : s).replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, function (c) {
      return "\\u{" + c.charCodeAt(0).toString(16) + "}";
    });
  }
  // As the server checks them: PW-003-0123456789abcdef.
  var FINGERPRINT = /^PW-[A-Za-z0-9-]{1,61}$/;
  function known(fp) {
    return typeof fp === "string" && fp.length <= 64 && FINGERPRINT.test(fp) && own.call(findings, fp);
  }
  function anyDialogOpen() {
    return Array.prototype.some.call(document.querySelectorAll("dialog"), function (d) { return d.open; });
  }
  // Only while the frame still shows the report (see app.js and retest.js).
  function tellReport(m) {
    if (!frame.contentWindow || frame.getAttribute("data-live") !== "1") return;
    frame.contentWindow.postMessage(m, "*");
  }

  // ------------------------------------------------- height and scrolling
  var MIN = 320, MAX = 2000000;
  // The app's own bar that stays at the top while scrolling (the rail's
  // links on a narrow screen), which the report's tab bar goes under.
  function stickyTop() {
    var t = document.querySelector(".rail .tabs");
    if (!t || getComputedStyle(t).position !== "sticky") return 0;
    return t.offsetHeight;
  }
  var queued = false;
  function syncViewport() {
    queued = false;
    var top = frame.getBoundingClientRect().top;
    tellReport({ type: "pathwarden:viewport", shift: Math.round(stickyTop() - top) });
  }
  function queueSync() {
    if (queued) return;
    queued = true;
    requestAnimationFrame(syncViewport);
  }
  window.addEventListener("scroll", queueSync, { passive: true });
  window.addEventListener("resize", queueSync);
  frame.addEventListener("load", function () { setTimeout(queueSync, 0); });

  function scrollFrameTo(y) {
    var rect = frame.getBoundingClientRect();
    var bar = stickyTop();
    y = Math.min(Math.max(0, y), rect.height);
    if (y === 0) {
      // The report went to the top of a tab: follow only when that top is
      // out of view above.
      if (rect.top < bar) window.scrollTo(0, window.pageYOffset + rect.top - bar);
      return;
    }
    // Below the report's own tab bar, which is pinned there.
    var tabs = 56;
    window.scrollTo(0, window.pageYOffset + rect.top + y - bar - tabs);
  }

  // ---------------------------------------------------------- Accept risk
  var dialog = $("ar-dialog");
  var form = $("ar-form");
  var current = null;
  var busy = false;
  function result(kind, title, text) {
    var box = $("ar-result");
    box.hidden = false;
    box.className = "rt-result " + kind;
    box.textContent = "";
    var h = document.createElement("strong");
    h.textContent = title;
    box.appendChild(h);
    if (text) {
      var p = document.createElement("p");
      p.className = "muted small";
      p.textContent = text;
      box.appendChild(p);
    }
  }
  function openAccept(fp) {
    var f = findings[fp];
    current = fp;
    $("ar-title").textContent = visible(f.title);
    $("ar-fp").textContent = fp;
    $("ar-result").hidden = true;
    $("ar-reason").value = "";
    $("ar-expires").value = "";
    // From today: a day already over accepts nothing.
    $("ar-expires").min = new Date().toISOString().slice(0, 10);
    form.hidden = f.acc === 1;
    if (f.acc === 1) {
      result("fixed", "Already accepted",
        "pathwarden.toml already accepts this finding (or its whole rule). It shows as accepted from the next analysis; change or remove it in Settings.");
    }
    if (dialog.showModal) dialog.showModal(); else dialog.setAttribute("open", "");
    if (!form.hidden) $("ar-reason").focus();
  }
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!current || busy) return;
      var reason = $("ar-reason").value.trim();
      if (!reason) { $("ar-reason").focus(); return; }
      var submit = $("ar-submit");
      busy = true;
      submit.disabled = true;
      var fp = current;
      fetch("/api/settings/suppress", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          index: null,
          // Saved in this run's environment.
          run: run,
          risk: { fingerprint: fp, reason: reason, expires: $("ar-expires").value || null }
        })
      })
        .then(function (r) { return r.text().then(function (t) { return { ok: r.ok, text: t }; }); })
        .then(function (r) {
          var j = {};
          try { j = JSON.parse(r.text); } catch (e2) {}
          if (!r.ok) throw new Error(j.error || "The accepted risk couldn't be saved.");
          findings[fp].acc = 1;
          // Add a note works at once, for the entry just saved.
          if (j.entry && typeof j.entry === "object" && typeof j.entry.i === "number") {
            j.entry.title = findings[fp].title;
            notesFor[fp] = j.entry;
          }
          form.hidden = true;
          result("fixed", "Accepted",
            "Saved in pathwarden.toml. From the next analysis this finding is shown as an accepted risk, with your reason.");
          tellReport({ type: "pathwarden:accepted", fingerprint: fp });
        })
        .catch(function (err) { result("error", "Not saved", err.message); })
        .then(function () { busy = false; submit.disabled = false; });
    });
  }

  // --------------------------------------------------------- Add a note
  var noteDialog = $("an-dialog");
  var noteForm = $("an-form");
  var notesFor = {};
  if (noteDialog) {
    try { notesFor = JSON.parse(noteDialog.getAttribute("data-accepted")) || {}; } catch (e) { notesFor = {}; }
  }
  var noteFp = null;
  var noteBusy = false;
  function noteResult(kind, title, text) {
    var box = $("an-result");
    box.hidden = false;
    box.className = "rt-result " + kind;
    box.textContent = "";
    var h = document.createElement("strong");
    h.textContent = title;
    box.appendChild(h);
    if (text) {
      var p = document.createElement("p");
      p.className = "muted small";
      p.textContent = text;
      box.appendChild(p);
    }
  }
  // "Accepted by <b>user</b> on <b>computer</b>, Oct 22, 2026", as Settings
  // shows it, into `box`.
  function stamp(box, by, on, at) {
    var any = false;
    function text(t) { box.appendChild(document.createTextNode(t)); }
    function bold(t) { var b = document.createElement("b"); b.textContent = visible(t); box.appendChild(b); }
    if (by) { text(" by "); bold(by); any = true; } else if (on) { text(" by an unknown user"); any = true; }
    if (on) { text(" on "); bold(on); }
    if (at) { text((any ? ", " : " ") + day(at)); any = true; }
    return any;
  }
  function whoLine(box, a) {
    box.textContent = "";
    var lead = document.createTextNode("Accepted");
    box.appendChild(lead);
    if (!stamp(box, a.accepted_by, a.accepted_on, a.accepted_at)) {
      lead.textContent = "Who accepted it and when wasn't recorded";
    }
    var sep = function () { box.appendChild(document.createTextNode(" · ")); };
    if (a.changed_by || a.changed_on || a.changed_at) {
      sep();
      box.appendChild(document.createTextNode("changed"));
      stamp(box, a.changed_by, a.changed_on, a.changed_at);
    }
    if (a.whole_rule) { sep(); box.appendChild(document.createTextNode("for every finding of its rule")); }
    if (a.expires) { sep(); box.appendChild(document.createTextNode("review by " + day(a.expires))); }
    if (a.notes) { sep(); box.appendChild(document.createTextNode(a.notes + (a.notes === 1 ? " note" : " notes"))); }
  }
  function openNote(fp) {
    var a = notesFor[fp];
    noteFp = fp;
    $("an-title").textContent = visible(a.title);
    $("an-reason").textContent = visible(a.reason);
    whoLine($("an-who"), a);
    $("an-result").hidden = true;
    $("an-text").value = "";
    noteForm.hidden = false;
    if (noteDialog.showModal) noteDialog.showModal(); else noteDialog.setAttribute("open", "");
    $("an-text").focus();
  }
  if (noteForm) {
    noteForm.addEventListener("submit", function (e) {
      e.preventDefault();
      if (!noteFp || noteBusy) return;
      var text = $("an-text").value.trim();
      if (!text) { $("an-text").focus(); return; }
      var a = notesFor[noteFp];
      var submit = $("an-submit");
      noteBusy = true;
      submit.disabled = true;
      fetch("/api/settings/suppress/" + encodeURIComponent(a.i) + "/note", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run: run, expect: a.reason, expect_target: a.target, text: text })
      })
        .then(function (r) { return r.text().then(function (t) { return { ok: r.ok, text: t }; }); })
        .then(function (r) {
          var j = {};
          try { j = JSON.parse(r.text); } catch (e2) {}
          if (!r.ok) throw new Error(j.error || "The note couldn't be saved.");
          a.notes = (a.notes || 0) + 1;
          noteForm.hidden = true;
          noteResult("fixed", "Note added",
            "Kept with the accepted risk in Settings. The report shows it from the next analysis.");
          $("an-result").setAttribute("tabindex", "-1");
          $("an-result").focus();
        })
        .catch(function (err) { noteResult("error", "Not saved", err.message); $("an-text").focus(); })
        .then(function () { noteBusy = false; submit.disabled = false; });
    });
  }

  // A run loaded from the history: the page's own Run details (with its
  // Remove), hidden while the report's tab is expected; shown when the
  // frame says the tab or its Remove can't be seen (from then on), or
  // says nothing within 4 seconds of this page starting.
  var fallback = document.querySelector("[data-rd-fallback]");
  var tabSeen = false, tabDoubt = false;
  if (fallback) {
    setTimeout(function () { if (!tabSeen) fallback.hidden = false; }, 4000);
  }

  // ------------------------------------------------------- the messages
  window.addEventListener("message", function (e) {
    if (e.source !== frame.contentWindow) return;
    var m = e.data;
    if (!m || typeof m !== "object" || typeof m.type !== "string") return;
    if (m.type === "pathwarden:height") {
      var h = Number(m.height);
      if (!isFinite(h)) return;
      frame.style.height = Math.round(Math.min(MAX, Math.max(MIN, h))) + "px";
      frame.classList.add("sized");
      queueSync();
      return;
    }
    if (m.type === "pathwarden:scroll") {
      var y = Number(m.y);
      if (isFinite(y)) scrollFrameTo(y);
      return;
    }
    if (m.type === "pathwarden:place") {
      // An ID in the report (a tab, a rule, a finding), or none.
      if (typeof m.hash !== "string" || !/^[A-Za-z0-9_-]{0,128}$/.test(m.hash)) return;
      var url = location.pathname + location.search + (m.hash ? "#" + m.hash : "");
      if (url !== location.pathname + location.search + location.hash) {
        try { history.replaceState(history.state, "", url); } catch (e2) {}
      }
      return;
    }
    if (m.type === "pathwarden:explore-node") {
      // An object of the run's graph, by its number there.
      var node = Number(m.node);
      if (!isFinite(node) || node < 0 || node > 4294967295 || Math.floor(node) !== node) return;
      location.href = "/runs/" + encodeURIComponent(run) + "/explore?node=" + node;
      return;
    }
    if (m.type === "pathwarden:note") {
      // Only for a finding an accepted risk covers, as the server listed them.
      var fp = m.fingerprint;
      if (typeof fp !== "string" || fp.length > 64 || !FINGERPRINT.test(fp) || !own.call(notesFor, fp)) return;
      if (!noteDialog || !noteForm || anyDialogOpen() || noteBusy) return;
      openNote(fp);
      return;
    }
    if (m.type === "pathwarden:run-details") {
      // Whether the report's Run details tab can be seen, with this page's
      // nonce: this page's own copy goes when it can, and shows when it
      // can't.
      if (e.origin !== "null" && e.origin !== location.origin) return;
      if (Object.keys(m).length !== 3 || typeof m.nonce !== "string") return;
      var d = document.querySelector(".rd-delete[data-delete][data-rd]");
      var w = d ? d.getAttribute("data-rd") : "";
      if (!/^[0-9a-f]{32}$/.test(w) || m.nonce !== w) return;
      if (m.shown === true && !tabDoubt) { tabSeen = true; if (fallback) fallback.hidden = true; }
      else if (m.shown !== true) { tabDoubt = true; if (fallback) fallback.hidden = false; }
      return;
    }
    if (m.type === "pathwarden:run-action") {
      // The Run details tab: from the sandboxed report frame only, exactly
      // {type, action, nonce}, one of the actions it knows, with the nonce this
      // page gave the frame (only the panel the server put in has it).
      // Remove opens this page's own confirm dialog; nothing is removed
      // until the user confirms there.
      if (e.origin !== "null" && e.origin !== location.origin) return;
      var keys = Object.keys(m);
      if (keys.length !== 3 || typeof m.action !== "string" || typeof m.nonce !== "string") return;
      var del = document.querySelector(".rd-delete[data-delete][data-rd]");
      var want = del ? del.getAttribute("data-rd") : "";
      if (!/^[0-9a-f]{32}$/.test(want) || m.nonce !== want) return;
      if (m.action === "remove") {
        if (!anyDialogOpen()) del.click();
      } else if (m.action === "performance") {
        location.href = "/runs/" + encodeURIComponent(run) + "/performance";
      } else if (m.action === "settings-folders") {
        location.href = "/settings#settings-folders";
      } else if (m.action === "settings") {
        location.href = "/settings";
      } else if (m.action === "schedule") {
        location.href = "/automate/schedule?run=" + encodeURIComponent(run);
      } else if (m.action === "history") {
        location.href = "/automate/history";
      } else if (m.action === "mappings") {
        // What each OpenGraph pack means (Other sources).
        location.href = "/mappings";
      } else if (m.action === "collect") {
        // The domains the run left out, ticked on the Collect page.
        location.href = "/runs/" + encodeURIComponent(run) + "/collect";
      } else if (m.action === "add-data") {
        // Add other data: Analyze, with the run's kept collection.
        location.href = "/analyze?from=" + encodeURIComponent(run);
      } else if (m.action === "sign-in") {
        // Git's sign-in window, then a sync (app.js); the page loads again
        // at the report's Run details tab.
        if (typeof window.pwSignIn === "function") window.pwSignIn("#details", null);
      }
      return;
    }
    // An accepted finding of this run can be opened in Explore too.
    var acceptedHere = typeof m.fingerprint === "string" && m.fingerprint.length <= 64 &&
      FINGERPRINT.test(m.fingerprint) && own.call(notesFor, m.fingerprint);
    if (m.type === "pathwarden:explore" && acceptedHere) {
      location.href = "/runs/" + encodeURIComponent(run) + "/explore?finding=" + encodeURIComponent(m.fingerprint);
      return;
    }
    if (!known(m.fingerprint)) return;
    if (m.type === "pathwarden:accept") {
      // One dialog at a time; nothing is saved until the user confirms.
      if (!dialog || !form || anyDialogOpen() || busy) return;
      openAccept(m.fingerprint);
    } else if (m.type === "pathwarden:explore") {
      location.href = "/runs/" + encodeURIComponent(run) + "/explore?finding=" + encodeURIComponent(m.fingerprint);
    }
  });
})();
