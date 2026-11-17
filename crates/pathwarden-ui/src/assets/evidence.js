// Evidence packs and findings files: the run page's Download menu
// and its two dialogs, and Settings' signing key and pack check. The pages
// carry the markup; this fills it from the API and sends what is chosen.
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function icon(id) {
    return '<svg class="ic" aria-hidden="true"><use href="#' + id + '"/></svg>';
  }

  var tipN = 0;
  function tip(about, body) {
    var id = "ev-tip-" + (++tipN);
    return '<span class="tip"><button type="button" class="tip-btn" aria-label="About: ' + esc(about) +
      '" aria-describedby="' + id + '">' + icon("i-info") + '</button><span class="tip-text" role="tooltip" id="' +
      id + '">' + esc(body) + "</span></span>";
  }

  // US style, local time (PathwardenTime in app.js).
  function date(unix) { return window.PathwardenTime.local(unix, "date"); }
  function full(unix) { return window.PathwardenTime.local(unix); }

  // A history run ID (20261019T191300.000Z) as a time, or null.
  function runIdTime(id) {
    var m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})/.exec(id || "");
    if (!m) return null;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
  }

  function sentence(s) {
    s = String(s || "").trim();
    if (!s) return s;
    s = s.charAt(0).toUpperCase() + s.slice(1);
    return /[.!?]$/.test(s) ? s : s + ".";
  }

  function plural(n, one, many) { return n === 1 ? one : many; }

  function getJson(url, opts) {
    return fetch(url, Object.assign({ credentials: "same-origin" }, opts || {}))
      .then(function (r) {
        return r.text().then(function (t) {
          var j = {};
          try { j = JSON.parse(t); } catch (e) { j = { error: t || "Pathwarden didn't answer (" + r.status + "). Is it still running?" }; }
          if (!r.ok) throw new Error(j.error || "Pathwarden didn't answer (" + r.status + "). Is it still running?");
          return j;
        });
      });
  }

  function postJson(url, body) {
    return getJson(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  function download(href, name) {
    var a = document.createElement("a");
    a.href = href;
    a.download = name || "";
    a.hidden = true;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function closeMenus(el) {
    var d = el.closest("details");
    if (d) d.open = false;
  }

  // Copy buttons: the text of the element they name.
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest(".copy-btn[data-copy]");
    if (!b) return;
    var el = $(b.getAttribute("data-copy"));
    if (!el || !navigator.clipboard) return;
    navigator.clipboard.writeText(el.textContent).then(function () {
      b.classList.add("done");
      setTimeout(function () { b.classList.remove("done"); }, 1200);
    });
  });

  // ---------------------------------------------------------------- run page

  var ev = $("ev-dialog");
  if (ev) {
    var run = ev.getAttribute("data-run");
    var form = $("ev-form"), base = $("ev-base"), submit = $("ev-submit");
    var some = $("ev-some"), chips = $("ev-chips"), q = $("ev-q"), results = $("ev-results");
    var redact = $("ev-redact"), err = $("ev-error");
    var data = null, picked = [], findingsOf = {}, hasKey = false;

    var showError = function (m) { err.textContent = m || ""; err.hidden = !m; };

    var selected = function () {
      var r = form.querySelector('input[name="ev-sel"]:checked');
      return r ? r.value : "all";
    };

    var refresh = function () {
      if (!data) return;
      var opt = data.earlier[base.selectedIndex];
      var n = opt ? opt.open : 0;
      $("ev-all-count").textContent = n + " " + plural(n, "finding.", "findings.");
      $("ev-file").textContent = redact.checked ? data.file_redacted : data.file;
      $("ev-limit").querySelector("span").textContent = redact.checked
        ? "Holds no names and no report."
        : "Holds names and the full report. Share it like the report.";
      some.hidden = selected() !== "some";
      submit.disabled = !hasKey || (selected() === "some" && picked.length === 0);
      if (selected() === "some") loadFindings();
    };

    var renderKey = function () {
      var box = $("ev-key");
      if (data.key) {
        hasKey = true;
        box.className = "ev-key";
        box.innerHTML = icon("i-lock") + "<span>This computer's key</span><code>" + esc(data.key.fingerprint) +
          '</code><a href="/settings#evidence">Settings</a>';
      } else {
        hasKey = false;
        box.className = "ev-key none";
        box.innerHTML = icon("i-alert") + "<span>" +
          (data.key_error ? esc(sentence("The signing key can't be read: " + data.key_error)) : "No signing key yet.") + " " +
          tip("the signing key", "Kept on this computer, readable by your account only. Settings shows its fingerprint, which you publish so auditors can check your packs.") +
          '</span><button type="button" class="btn small-btn" id="ev-newkey">' + icon("i-plus") + " Create a key</button>";
        $("ev-newkey").addEventListener("click", function () {
          this.disabled = true;
          postJson("/api/evidence/key", { action: data.key_error ? "replace" : "create" })
            .then(function (k) { data.key = k; data.key_error = null; renderKey(); refresh(); })
            .catch(function (e) { showError(e.message); });
        });
      }
    };

    var renderChips = function () {
      chips.innerHTML = picked.map(function (p, i) {
        return '<li class="chip-item"><span class="chip-text">' + esc(p.value) + '</span><span class="chip-sub">' +
          esc(p.sub) + '</span><button type="button" class="fl-remove" data-i="' + i + '" aria-label="Remove ' +
          esc(p.value) + '">' + icon("i-x") + "</button></li>";
      }).join("");
      refresh();
    };

    chips.addEventListener("click", function (e) {
      var b = e.target.closest(".fl-remove");
      if (!b) return;
      picked.splice(+b.getAttribute("data-i"), 1);
      renderChips();
    });

    var loadFindings = function () {
      var id = base.value;
      if (findingsOf[id]) return;
      findingsOf[id] = [];
      getJson("/api/runs/" + encodeURIComponent(run) + "/evidence/findings?against=" + encodeURIComponent(id))
        .then(function (j) { findingsOf[id] = j.findings; search(); })
        .catch(function (e) { delete findingsOf[id]; showError(e.message); });
    };

    var options = [];
    var search = function () {
      var text = q.value.trim().toLowerCase();
      var list = findingsOf[base.value] || [];
      if (!text) { results.hidden = true; return; }
      var rules = {};
      list.forEach(function (f) { rules[f.rule] = (rules[f.rule] || 0) + 1; });
      options = [];
      Object.keys(rules).sort().forEach(function (r) {
        if (r.toLowerCase().indexOf(text) !== -1) {
          options.push({ kind: "rule", value: r, sub: "Every finding of this rule (" + rules[r] + ")" });
        }
      });
      list.forEach(function (f) {
        var hay = (f.title + " " + f.rule + " " + f.fp).toLowerCase();
        if (hay.indexOf(text) !== -1) options.push({ kind: "finding", value: f.fp, sub: f.title });
      });
      options = options.filter(function (o) {
        return !picked.some(function (p) { return p.kind === o.kind && p.value === o.value; });
      }).slice(0, 30);
      results.innerHTML = options.length
        ? options.map(function (o, i) {
          return '<li role="option" data-i="' + i + '"><span>' + esc(o.sub) + '</span><span class="r-fp">' + esc(o.value) + "</span></li>";
        }).join("")
        : '<li class="none">No open finding of that run matches.</li>';
      results.hidden = false;
    };
    q.addEventListener("input", search);
    results.addEventListener("click", function (e) {
      var li = e.target.closest("li[data-i]");
      if (!li) return;
      picked.push(options[+li.getAttribute("data-i")]);
      q.value = "";
      results.hidden = true;
      renderChips();
    });

    form.addEventListener("change", function (e) {
      if (e.target === base) { picked = []; renderChips(); return; }
      refresh();
    });

    var reset = function () {
      $("ev-make").hidden = false;
      $("ev-done").hidden = true;
      showError("");
    };
    ev.addEventListener("close", reset);

    document.addEventListener("click", function (e) {
      var b = e.target.closest && e.target.closest("[data-ev-open]");
      if (!b) return;
      closeMenus(b);
      reset();
      ev.showModal();
      if (data) return;
      getJson("/api/runs/" + encodeURIComponent(run) + "/evidence").then(function (j) {
        data = j;
        base.innerHTML = j.earlier.map(function (x) {
          var t = "Run of " + full(x.created_at) + (x.label ? " · " + x.label : "") + (x.previous ? " · the run before this one" : "");
          return '<option value="' + esc(x.id) + '">' + esc(t) + "</option>";
        }).join("");
        renderKey();
        refresh();
      }).catch(function (e) { showError(e.message); });
    });

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      showError("");
      var body = { against: base.value, findings: [], rules: [], redact: redact.checked };
      if (selected() === "some") {
        picked.forEach(function (p) { (p.kind === "rule" ? body.rules : body.findings).push(p.value); });
      }
      submit.disabled = true;
      var label = submit.innerHTML;
      submit.textContent = "Making the pack…";
      postJson("/api/runs/" + encodeURIComponent(run) + "/evidence", body).then(function (j) {
        submit.innerHTML = label;
        refresh();
        download(j.download, j.file);
        var res = $("ev-res");
        res.className = "ev-res " + (j.verified ? "good" : "bad");
        res.querySelector(".head").innerHTML = j.verified
          ? icon("i-check") + "<strong>Saved to Downloads.</strong>"
          : icon("i-x") + "<strong>Saved, but the check failed.</strong>";
        $("ev-r-file").textContent = j.file;
        $("ev-r-shows").textContent = j.shows + ", against the run of " + date(j.against) + ".";
        $("ev-r-checked").textContent = j.verified
          ? "Signature valid. " + j.files_ok + " of " + j.files_checked + " files match."
          : j.problems.map(sentence).join(" ");
        $("ev-r-fp").textContent = j.signed_by;
        $("ev-r-sha").textContent = j.sha256;
        $("ev-r-limit").querySelector("span").textContent = j.redacted
          ? "Holds no names and no report."
          : "Holds names and the full report. Share it like the report.";
        $("ev-make").hidden = true;
        $("ev-done").hidden = false;
      }).catch(function (e) {
        submit.innerHTML = label;
        refresh();
        showError(e.message);
      });
    });
  }

  var ff = $("ff-dialog");
  if (ff) {
    var ffRun = ff.getAttribute("data-run");
    var info = null;
    var ffUpdate = function () {
      var fmt = ff.querySelector('input[name="ff-fmt"]:checked').value;
      if (fmt !== "sarif" && fmt !== "defectdojo") return;
      var a = $("ff-download");
      a.href = "/runs/" + encodeURIComponent(ffRun) + "/findings-file?format=" + encodeURIComponent(fmt);
      if (!info) return;
      $("ff-file").textContent = info[fmt];
      a.download = info[fmt];
      var held = $("ff-held");
      held.hidden = !(fmt === "defectdojo" && info.held > 0);
      $("ff-held-text").textContent = info.held === 1
        ? "1 finding couldn't be checked in this run and isn't in the file. A reimport that closes old findings would close it."
        : info.held + " findings couldn't be checked in this run and aren't in the file. A reimport that closes old findings would close them.";
    };
    ff.addEventListener("change", ffUpdate);
    document.addEventListener("click", function (e) {
      var b = e.target.closest && e.target.closest("[data-ff-open]");
      if (!b) return;
      closeMenus(b);
      ff.showModal();
      if (info) return;
      getJson("/api/runs/" + encodeURIComponent(ffRun) + "/findings-file").then(function (j) {
        info = j;
        $("ff-lead").textContent = j.open === 1
          ? "1 open finding, with when it was first seen and what changed."
          : j.open + " open findings, with when each was first seen and what changed.";
        ffUpdate();
      }).catch(function (e) {
        var p = $("ff-error");
        p.textContent = e.message;
        p.hidden = false;
      });
    });
  }

  // ---------------------------------------------------------------- Settings

  var keySection = $("evidence");
  if (keySection && $("key-file")) {
    var status = $("key-status");
    var keyDone = function (p) {
      p.then(function () { location.hash = "evidence"; location.reload(); })
        .catch(function (e) { status.textContent = e.message; });
    };
    var keyFile = $("key-file");
    keySection.addEventListener("click", function (e) {
      var t = e.target.closest("button");
      if (!t) return;
      if (t.hasAttribute("data-key-create")) {
        t.disabled = true;
        keyDone(postJson("/api/evidence/key", { action: "create" }));
      } else if (t.hasAttribute("data-key-use")) {
        keyFile.value = "";
        keyFile.click();
      } else if (t.hasAttribute("data-key-replace")) {
        $("key-replace").showModal();
      }
    });
    keyFile.addEventListener("change", function () {
      var f = keyFile.files[0];
      if (!f) return;
      f.text().then(function (text) {
        keyDone(postJson("/api/evidence/key", { action: "use", text: text }));
      });
    });
    $("key-replace").addEventListener("close", function () {
      if (this.returnValue === "replace") keyDone(postJson("/api/evidence/key", { action: "replace" }));
    });
  }

  var vf = $("verify-form");
  if (vf) {
    var pack = $("vf-pack"), keyIn = $("vf-key"), fp = $("vf-fp"), out = $("vf-result");
    var keyText = "";
    var vfSubmit = $("vf-submit"), vfStatus = $("vf-status");
    $("vf-choose").addEventListener("click", function () { pack.click(); });
    pack.addEventListener("change", function () {
      var f = pack.files[0];
      var name = $("vf-name");
      name.textContent = f ? f.name : "No pack chosen.";
      name.classList.toggle("unset", !f);
      vfSubmit.disabled = !f;
      out.innerHTML = "";
    });
    $("vf-name").classList.add("unset");
    $("vf-keylink").addEventListener("click", function (e) { e.preventDefault(); keyIn.value = ""; keyIn.click(); });
    keyIn.addEventListener("change", function () {
      var f = keyIn.files[0];
      if (!f) return;
      f.text().then(function (t) { keyText = t; fp.value = f.name; fp.readOnly = true; });
    });
    fp.addEventListener("focus", function () {
      if (keyText) { keyText = ""; fp.value = ""; fp.readOnly = false; }
    });

    var dl = function (rows) {
      return "<dl>" + rows.map(function (r) { return "<dt>" + r[0] + "</dt><dd>" + r[1] + "</dd>"; }).join("") + "</dl>";
    };
    var showsLine = function (s) {
      var t = runIdTime(s.baseline_run_id);
      var against = t ? "the run of " + date(t) : "an earlier collection";
      return esc(s.counts + ", against " + against + ".");
    };
    var render = function (v) {
      var rows = [];
      if (v.signed_by) rows.push(["Signature", "Valid, made with <code>" + esc(v.signed_by) + "</code>."]);
      rows.push(["Files", esc(v.files_ok + " of " + v.files_checked + " match the manifest.")]);
      if (v.shows) {
        rows.push(["Created", esc(full(v.shows.created_at) + ", with Pathwarden " + v.shows.pathwarden + ".") +
          (v.shows.redacted ? " Names and the report left out." : "") + " " +
          tip("the creation time", "The signing computer's clock, not a trusted timestamp.")]);
        rows.push(["Shows", showsLine(v.shows)]);
      }
      if (v.outcome === "verified") {
        return '<div class="ev-res good" role="status"><p class="head">' + icon("i-check") +
          '<strong>Verified.</strong><span class="muted small">Every file is exactly as signed, by the expected key.</span></p>' + dl(rows) + "</div>";
      }
      if (v.outcome === "signer_not_checked") {
        // Nothing vouches for the key, so nothing the pack says is shown
        // as fact: only that its files match, and which key it names.
        var unchecked = [
          ["Files", esc(v.files_ok + " of " + v.files_checked + " match the manifest.")],
          ["Key", "<code>" + esc(v.signed_by) + "</code>, not compared with the sender's."]
        ];
        return '<div class="ev-res meh" role="status"><p class="head">' + icon("i-alert") +
          '<strong>Unchanged, signer not checked.</strong><span class="muted small">Give the fingerprint the sender published to check who made it.</span></p>' + dl(unchecked) + "</div>";
      }
      return '<div class="ev-res bad" role="status"><p class="head">' + icon("i-x") +
        '<strong>Not verified.</strong><span class="muted small">Don\'t rely on this pack.</span></p><ul>' +
        v.problems.map(function (p) { return "<li>" + esc(sentence(p)) + "</li>"; }).join("") + "</ul></div>";
    };

    vf.addEventListener("submit", function (e) {
      e.preventDefault();
      var f = pack.files[0];
      if (!f) return;
      var body = new FormData();
      body.append("pack", f, f.name);
      if (keyText) body.append("key", keyText);
      else body.append("fingerprint", fp.value.trim());
      vfSubmit.disabled = true;
      vfStatus.textContent = "Checking…";
      out.innerHTML = "";
      getJson("/api/evidence/verify", { method: "POST", body: body }).then(function (v) {
        vfStatus.textContent = "";
        out.innerHTML = render(v);
      }).catch(function (e) {
        vfStatus.textContent = e.message;
      }).then(function () { vfSubmit.disabled = false; });
    });
  }
})();
