// The run page's side of retesting. Each open finding's row in the embedded
// report has a Retest button; a click there sends this page one message,
// { type: "pathwarden:retest", fingerprint }. It is accepted only from the
// report's frame, only for a well-formed fingerprint of one of this run's
// open findings (listed by the server on the dialog), and it only opens the
// Retest dialog: nothing runs until the user confirms there. With the
// built-in collector the dialog re-reads the finding's objects; the
// password goes only into the body of the one POST and is cleared from the
// form right after. The result goes back to the frame as plain values.
(function () {
  "use strict";
  // Bidi controls shown, not obeyed, as the server's pages show them
  // (pathwarden_core::text::is_bidi_control).
  function visible(s) {
    return String(s == null ? "" : s).replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, function (c) {
      return "\\u{" + c.charCodeAt(0).toString(16) + "}";
    });
  }
  var dialog = document.getElementById("rt-dialog");
  if (!dialog) return;
  function $(id) { return document.getElementById(id); }

  var run = dialog.getAttribute("data-run");
  var builtin = dialog.getAttribute("data-builtin") === "1";
  var findings = {};
  try { findings = JSON.parse(dialog.getAttribute("data-findings")) || {}; } catch (e) { findings = {}; }
  var own = Object.prototype.hasOwnProperty;
  var form = $("rt-form");
  var current = null; // the fingerprint being retested
  var busy = false;
  // As the server checks them: PW-003-0123456789abcdef.
  var FINGERPRINT = /^PW-[A-Za-z0-9-]{1,61}$/;

  function credVisible() {
    var pw = form.querySelector('input[name="auth"][value="password"]');
    $("rt-cred").hidden = !(pw && pw.checked);
    if (pw && pw.checked) $("rt-ldaps").checked = true;
    // As the Windows account, Windows' own SMB client signs: no checkbox.
    $("rt-smb-signing").parentNode.hidden = !(pw && pw.checked);
  }
  if (form) credVisible();
  if (form) {
    form.querySelectorAll('input[name="auth"]').forEach(function (r) { r.addEventListener("change", credVisible); });
    if (dialog.getAttribute("data-windows") !== "1") {
      // The current Windows account is Windows only.
      var cur = form.querySelector('input[name="auth"][value="current"]');
      if (cur) { cur.disabled = true; cur.parentNode.classList.add("off"); }
    }
  }

  function showResult(kind, title, lines) {
    var box = $("rt-result");
    box.hidden = false;
    box.className = "rt-result " + kind;
    box.textContent = "";
    var h = document.createElement("strong");
    h.textContent = title;
    box.appendChild(h);
    if (lines && lines.length) {
      var ul = document.createElement("ul");
      lines.forEach(function (l) { var li = document.createElement("li"); li.textContent = l; ul.appendChild(li); });
      box.appendChild(ul);
    }
  }

  function open(fp) {
    var f = findings[fp];
    current = fp;
    $("rt-d-title").textContent = visible(f.title);
    $("rt-result").hidden = true;
    var targetable = builtin && f.t === 1;
    $("rt-targeted").hidden = !targetable;
    $("rt-submit").hidden = !targetable;
    var why = $("rt-why");
    if (!targetable) {
      why.hidden = false;
      why.textContent = !builtin
        ? "This version of Pathwarden can't collect, so it can't re-read single objects. Upload a new collection or collect again to retest."
        : f.why;
    } else {
      why.hidden = true;
      var n = Number(f.n), c = Number(f.c) || 0;
      var text = "Re-reads " + n + (n === 1 ? " object" : " objects") + " from Active Directory.";
      if (c > 0) {
        text += " Also reads sessions on " + (c === 1 ? "1 computer" : c + " computers") +
          " (needs a user and password).";
      }
      // A held finding: one line saying what this retest can check.
      if (typeof f.h === "string" && f.h) text = f.h + " " + text;
      $("rt-objects").textContent = text;
      if (f.domain && !$("rt-domain").value) $("rt-domain").value = f.domain;
      credVisible();
    }
    if (dialog.showModal) dialog.showModal(); else dialog.setAttribute("open", "");
  }

  // A finding's Retest button in the report.
  window.addEventListener("message", function (e) {
    var frame = $("report-frame");
    if (!frame || e.source !== frame.contentWindow) return;
    var m = e.data;
    if (!m || typeof m !== "object" || m.type !== "pathwarden:retest") return;
    var fp = m.fingerprint;
    if (typeof fp !== "string" || fp.length > 64 || !FINGERPRINT.test(fp) || !own.call(findings, fp)) return;
    // One at a time: a click while a dialog is open (or a retest is
    // running) is ignored.
    if (busy || Array.prototype.some.call(document.querySelectorAll("dialog"), function (d) { return d.open; })) return;
    open(fp);
  });

  // The result, back to the report's row (an opaque origin, hence "*": the
  // message holds only this result). Only while the frame still shows the
  // report: app.js marks data-live="0" when it navigated on its own (the
  // report's links open new tabs, so that should not happen). The frame's
  // address can't be read across origins, so this is the check we have.
  function tellReport(fp, j) {
    var frame = $("report-frame");
    if (!frame || !frame.contentWindow || frame.getAttribute("data-live") !== "1") return;
    frame.contentWindow.postMessage({
      type: "pathwarden:retest-result",
      fingerprint: fp,
      verdict: j.verdict,
      detail: typeof j.detail === "string" ? j.detail : "",
      at: Number(j.at)
    }, "*");
  }

  if (!form) return;
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!current || busy) return;
    var submit = $("rt-submit");
    var auth = form.querySelector('input[name="auth"]:checked');
    var body = {
      fingerprint: current,
      domain: $("rt-domain").value.trim(),
      server: $("rt-server").value.trim() || null,
      auth: auth ? auth.value : "current",
      user: $("rt-user").value.trim(),
      ldaps: $("rt-ldaps").checked,
      // Opt-outs, so a missing answer means the safe default.
      allow_ntlm: !$("rt-kerberos-only").checked,
      allow_unsigned_smb: !$("rt-smb-signing").checked
    };
    if (body.auth === "password") body.password = $("rt-password").value;
    $("rt-password").value = "";
    busy = true;
    submit.disabled = true;
    submit.classList.add("busy");
    var hosts = body.auth === "password" && Number((findings[current] || {}).c) > 0;
    showResult("working", hosts ? "Re-reading the objects and the computers on its path…" : "Re-reading the objects…", []);
    var fp = current;
    fetch("/api/runs/" + encodeURIComponent(run) + "/retest", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    })
      .then(function (r) { return r.text().then(function (t) { return { ok: r.ok, text: t }; }); })
      .then(function (r) {
        var j = {};
        try { j = JSON.parse(r.text); } catch (e2) {}
        if (!r.ok) throw new Error(j.error || "The retest failed.");
        var kind = j.verdict === "fixed" ? "fixed" : j.verdict === "still_open" ? "open" : "unknown";
        var title = j.verdict === "fixed" ? "Fixed" : j.label;
        // The details, then what was read (the server's sentences).
        var lines = (j.details || []).concat(j.lines || []);
        showResult(kind, title, lines);
        tellReport(fp, j);
      })
      .catch(function (err) {
        // No answer at all: say so, not the browser's words.
        var said = err instanceof TypeError ? "Pathwarden isn't answering. Is it still running?" : err.message;
        showResult("error", "Couldn't retest.", [said]);
      })
      .then(function () { busy = false; submit.disabled = false; submit.classList.remove("busy"); });
  });
})();
