// Pathwarden UI: Settings, Privilege Zones and Plugins. Everything from the
// server or the directory is put on the page with textContent, never as
// markup: object names come from Active Directory and anyone who can create
// an object chooses its name.
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }
  function all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function svg(id) {
    var s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("class", "ic");
    s.setAttribute("aria-hidden", "true");
    var u = document.createElementNS("http://www.w3.org/2000/svg", "use");
    u.setAttribute("href", "#" + id);
    s.appendChild(u);
    return s;
  }

  function toast(message) {
    var t = $("toast");
    if (!t) { alert(message); return; }
    t.textContent = message;
    t.classList.remove("kept"); // app.js may have left a note's look
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.hidden = true; }, 8000);
  }

  // JSON in, JSON out; rejects with the server's message.
  function api(method, url, body) {
    var opts = { method: method, credentials: "same-origin", headers: {} };
    // The page's environment and the pull counter it was loaded at: a save
    // from a page another tab's switch or a pull made out of date is
    // refused (409), with what to do.
    var env = document.body.getAttribute("data-env");
    if (env) opts.headers["X-Pathwarden-Env"] = env;
    var pulled = document.body.getAttribute("data-pulled");
    if (pulled) opts.headers["X-Pathwarden-Pulled"] = pulled;
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (text) {
        var j = null;
        try { j = text ? JSON.parse(text) : {}; } catch (e) {}
        if (!r.ok) {
          var err = new Error((j && j.error) || "Pathwarden didn't answer (" + r.status + "). Is it still running?");
          err.data = j || {};
          throw err;
        }
        // A save whose change goes to the run history after this answer.
        if (j && j.sharing) pollSharing(j.sharing);
        return j || {};
      });
    }, function () { throw new Error("Pathwarden is not answering. Is it still running?"); });
  }

  // "Oct 22, 2026" (PathwardenTime.date in app.js).
  function day(text) { return window.PathwardenTime.date(text); }
  // Bidi controls shown, not obeyed, as the server's pages show them
  // (pathwarden_core::text::is_bidi_control).
  function visible(s) {
    return String(s == null ? "" : s).replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, function (c) {
      return "\\u{" + c.charCodeAt(0).toString(16) + "}";
    });
  }

  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments, self = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(self, args); }, ms);
    };
  }

  // On narrow screens the rail is a scrolling tab bar: show this page's tab.
  var current = document.querySelector(".tablist-config a[aria-current=page]");
  var bar = document.querySelector(".tabs");
  if (current && bar && bar.scrollWidth > bar.clientWidth) {
    bar.scrollLeft = current.offsetLeft - bar.clientWidth / 2 + current.offsetWidth / 2;
  }

  // ---------------------------------------------------- confirm dialogs
  var dlg;
  function confirmBox(title, text, ok, danger) {
    if (!dlg) {
      dlg = el("dialog", "card");
      dlg.id = "confirm-box";
      var form = el("form");
      form.method = "dialog";
      form.appendChild(el("h2", "sub"));
      form.appendChild(el("p", "muted"));
      var actions = el("div", "dialog-actions");
      var cancel = el("button", "btn", "Cancel");
      cancel.value = "cancel";
      var go = el("button", "btn");
      go.value = "ok";
      actions.appendChild(cancel);
      actions.appendChild(go);
      form.appendChild(actions);
      dlg.appendChild(form);
      document.body.appendChild(dlg);
    }
    dlg.querySelector("h2").textContent = title;
    dlg.querySelector("p").textContent = text;
    var go2 = dlg.querySelector("button[value=ok]");
    go2.textContent = ok;
    go2.className = danger ? "btn danger solid" : "btn primary";
    return new Promise(function (resolve) {
      if (!dlg.showModal) { resolve(confirm(title + "\n\n" + text)); return; }
      dlg.returnValue = "";
      dlg.showModal();
      dlg.addEventListener("close", function onClose() {
        dlg.removeEventListener("close", onClose);
        resolve(dlg.returnValue === "ok");
      });
    });
  }

  // ---------------------------------------------------- after a save
  var saved = $("saved");
  function showSaved() {
    if (!saved) return;
    saved.hidden = false;
    clearTimeout(showSaved.timer);
    showSaved.timer = setTimeout(function () { saved.hidden = true; }, 15000);
  }
  if (saved) {
    $("saved-close").addEventListener("click", function () { saved.hidden = true; });
    if (location.hash === "#saved") {
      showSaved();
      try { history.replaceState(null, "", location.pathname); } catch (e) {}
    }
  }
  all("[data-rerun-path]").forEach(function (b) {
    b.addEventListener("click", function () {
      b.disabled = true;
      var data = new FormData();
      data.append("path", b.getAttribute("data-rerun-path"));
      // In the environment whose settings changed.
      if (b.getAttribute("data-rerun-env")) data.append("env", b.getAttribute("data-rerun-env"));
      // A deliberate re-run after a change: no "already analyzed" warning.
      data.append("force", "1");
      fetch("/api/analyze", { method: "POST", body: data, credentials: "same-origin" })
        .then(function (r) {
          return r.text().then(function (t) {
            var j = {};
            try { j = JSON.parse(t); } catch (e) {}
            if (r.status !== 202) throw new Error(j.error || "Couldn't start the analysis.");
            location.href = "/analyze?job=" + encodeURIComponent(j.job);
          });
        })
        .catch(function (e) { b.disabled = false; toast(e.message); });
    });
  });

  function status(section, text, ok) {
    var s = section.querySelector(".save-status");
    if (!s) return;
    s.textContent = text || "";
    s.className = "save-status small " + (ok === false ? "bad" : ok ? "good" : "muted");
  }

  // ---------------------------------------------------- unsaved changes
  // Each Settings section ([data-section]) saves on its own. A section whose
  // fields differ from what was last loaded or saved says "Unsaved changes";
  // saving another section names the ones still unsaved, and leaving the
  // page with any asks first.
  var UNSAVED = "Unsaved changes";
  var sections = all("[data-section]");
  function snapshot(sec) {
    var parts = all("input, select, textarea", sec)
      // [data-no-save]: controls that act on their own (the history's
      // passphrase), never part of the section's Save.
      .filter(function (i) { return i.type !== "search" && i.type !== "hidden" && !i.closest("[hidden], [data-no-save]"); })
      .map(function (i) {
        return (i.name || i.id) + "=" + (i.type === "checkbox" || i.type === "radio" ? i.checked : i.value);
      });
    all(".chip-item[data-value]", sec).forEach(function (c) { parts.push("chip=" + c.getAttribute("data-value")); });
    return parts.join("\n");
  }
  function sectionOf(node) { return node && node.closest ? node.closest("[data-section]") : null; }
  function isDirty(sec) { return sec.pwBase != null && snapshot(sec) !== sec.pwBase; }
  function checkDirty(sec) {
    var dirty = isDirty(sec);
    sec.classList.toggle("is-dirty", dirty);
    var s = sec.querySelector(".save-status");
    if (!s) return;
    if (dirty && (!s.textContent || s.textContent === "Saved")) {
      s.textContent = UNSAVED;
      s.className = "save-status small unsaved";
    } else if (!dirty && s.textContent === UNSAVED) {
      s.textContent = "";
      s.className = "save-status muted small";
    }
  }
  function markClean(sec) {
    if (!sec) return;
    sec.pwBase = snapshot(sec);
    checkDirty(sec);
  }
  function stillUnsaved(except) {
    return sections.filter(function (s) { return s !== except && isDirty(s); }).map(function (s) {
      var h = s.querySelector("h2");
      return h ? h.textContent.trim() : "another section";
    });
  }
  sections.forEach(function (sec) {
    var later = function () { setTimeout(function () { checkDirty(sec); }, 0); };
    ["input", "change", "click", "keyup"].forEach(function (t) { sec.addEventListener(t, later); });
  });
  // After every section's own setup below has run.
  setTimeout(function () { sections.forEach(markClean); }, 0);
  window.addEventListener("beforeunload", function (e) {
    // Reload on the repository's note: the user was told it drops them.
    if (window.Pathwarden && window.Pathwarden.leaving) return;
    if (!stillUnsaved(null).length) return;
    e.preventDefault();
    e.returnValue = "";
  });

  function saving(button, section, promise, onDone) {
    button.disabled = true;
    status(section, "Saving…");
    return promise.then(function (r) {
      button.disabled = false;
      var sec = sectionOf(section);
      markClean(sec);
      var others = stillUnsaved(sec);
      status(section, others.length ? "Saved. Still unsaved: " + others.join(", ") + "." : "Saved", true);
      showSaved();
      if (onDone) onDone(r);
    }, function (e) {
      button.disabled = false;
      status(section, e.message, false);
    });
  }

  // ---------------------------------------------------- object picker
  // <div class="picker" data-picker data-kinds="User,Group" [data-source="findings"]>
  function Picker(root, opts) {
    var input = root.querySelector("input[type=search]");
    var list = root.querySelector(".results");
    var addTyped = root.querySelector("[data-add-typed]");
    var searchable = input.hasAttribute("data-search");
    var source = root.getAttribute("data-source") || "objects";
    var active = -1;
    var items = [];
    var seq = 0;

    function kinds() {
      return opts.kinds ? opts.kinds() : (root.getAttribute("data-kinds") || "");
    }

    function hide() { list.hidden = true; active = -1; }

    function highlight(i) {
      active = i;
      all("li", list).forEach(function (li, j) {
        li.classList.toggle("active", j === i);
        li.setAttribute("aria-selected", j === i ? "true" : "false");
      });
    }

    function render(results, q) {
      list.textContent = "";
      items = results;
      if (!results.length) {
        list.appendChild(el("li", "none", source === "findings"
          ? "No finding matches " + q + "."
          : "Nothing named like " + q + " in the latest analysis. Press Add to use it as typed."));
      }
      results.forEach(function (r, i) {
        var li = el("li");
        li.setAttribute("role", "option");
        if (source === "findings") {
          var sev = el("span", "badge " + r.severity);
          sev.appendChild(el("span", "dot"));
          sev.appendChild(document.createTextNode(r.severity));
          li.appendChild(sev);
          var main = el("span", "r-main");
          main.appendChild(el("span", "r-name", r.title));
          main.appendChild(el("span", "r-sub", r.fingerprint + (r.suppressed ? " · already accepted" : "")));
          li.appendChild(main);
        } else {
          li.appendChild(el("span", "r-kind", r.kind));
          var m = el("span", "r-main");
          m.appendChild(el("span", "r-name", r.name));
          m.appendChild(el("span", "r-sub", r.dn || r.domain || r.id));
          li.appendChild(m);
          if (r.tier_zero) li.appendChild(el("span", "tag t0", "Tier Zero"));
        }
        li.addEventListener("mousedown", function (e) { e.preventDefault(); });
        li.addEventListener("click", function () { choose(i); });
        list.appendChild(li);
      });
      list.hidden = false;
      highlight(results.length ? 0 : -1);
    }

    function choose(i) {
      var r = items[i];
      if (!r) return;
      opts.onPick(r);
      input.value = "";
      hide();
      input.focus();
    }

    var search = debounce(function () {
      var q = input.value.trim();
      if (!q || !searchable) { hide(); return; }
      var mine = ++seq;
      var url = source === "findings"
        ? "/api/findings?q=" + encodeURIComponent(q)
        : "/api/objects?q=" + encodeURIComponent(q) + "&kinds=" + encodeURIComponent(kinds());
      api("GET", url).then(function (j) {
        if (mine === seq && input.value.trim() === q) render(j.results || [], q);
      }, function (e) { if (mine === seq) { list.textContent = ""; list.appendChild(el("li", "none", e.message)); list.hidden = false; } });
    }, 160);

    function typed() {
      var v = input.value.trim();
      if (!v || !opts.onTyped) return;
      opts.onTyped(v);
      input.value = "";
      hide();
    }

    input.addEventListener("input", search);
    input.addEventListener("focus", function () { if (items.length && input.value.trim()) list.hidden = false; });
    input.addEventListener("blur", function () { setTimeout(hide, 120); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown" && !list.hidden) { e.preventDefault(); highlight(Math.min(items.length - 1, active + 1)); }
      else if (e.key === "ArrowUp" && !list.hidden) { e.preventDefault(); highlight(Math.max(0, active - 1)); }
      else if (e.key === "Escape") { hide(); }
      else if (e.key === "Enter") {
        e.preventDefault();
        if (!list.hidden && active >= 0 && items[active]) choose(active); else typed();
      }
    });
    if (addTyped) addTyped.addEventListener("click", typed);
    this.refresh = search;
  }

  // ---------------------------------------------------- chips (Tier Zero)
  function chipList(ul) {
    function empty() {
      var e = ul.querySelector(".chip-empty");
      var has = ul.querySelector(".chip-item");
      // A list without data-empty says nothing when empty.
      if (!has && !e && ul.getAttribute("data-empty")) ul.appendChild(el("li", "chip-empty muted", ul.getAttribute("data-empty")));
      if (has && e) e.remove();
    }
    function bind(li) {
      li.querySelector("[data-remove]").addEventListener("click", function () { li.remove(); empty(); });
    }
    all(".chip-item", ul).forEach(bind);
    empty();
    return {
      add: function (value) {
        var exists = all(".chip-item", ul).some(function (li) {
          return li.getAttribute("data-value").toUpperCase() === value.toUpperCase();
        });
        if (exists) { toast(value + " is already in the list."); return; }
        var li = el("li", "chip-item");
        li.setAttribute("data-value", value);
        li.appendChild(el("span", "chip-text", value));
        var x = el("button", "fl-remove");
        x.type = "button";
        x.setAttribute("data-remove", "");
        x.setAttribute("aria-label", "Remove " + value);
        x.appendChild(svg("i-x"));
        li.appendChild(x);
        ul.appendChild(li);
        bind(li);
        empty();
      },
      values: function () { return all(".chip-item", ul).map(function (li) { return li.getAttribute("data-value"); }); }
    };
  }

  // ---------------------------------------------------- Settings
  // What a section showed when the page was loaded (or last saved).
  function loaded(section) {
    try { return JSON.parse(section.getAttribute("data-loaded")); } catch (e) { return null; }
  }
  var t0 = document.querySelector("[data-section=tier-zero]");
  if (t0) {
    var chips = chipList($("t0-list"));
    new Picker(t0.querySelector("[data-picker]"), {
      onPick: function (r) {
        if (r.tier_zero) toast(r.name + " is already Tier Zero; adding it changes nothing, but does no harm.");
        chips.add(r.name);
      },
      onTyped: function (v) { chips.add(v); }
    });
    var b0 = t0.querySelector("[data-save]");
    b0.addEventListener("click", function () {
      // What the page loaded: the server refuses the save if the file
      // changed since (the command line, another page).
      var items = chips.values();
      saving(b0, t0, api("POST", "/api/settings/tier-zero", { items: items, loaded: loaded(t0) }), function (r) {
        // As the file now holds it: what the next save compares with.
        if (r && r.loaded) t0.setAttribute("data-loaded", JSON.stringify(r.loaded));
      });
    });
  }

  // Tier Zero settings folders: a typed path, added with Add or
  // Enter; the server checks each when it saves.
  var sf = document.querySelector("[data-section=settings-folders]");
  if (sf) {
    var folders = chipList($("sf-list"));
    var sfInput = $("sf-q");
    var addFolder = function () {
      var v = sfInput.value.trim();
      if (!v) return;
      folders.add(v);
      sfInput.value = "";
    };
    sf.querySelector("[data-folder-field] [data-add-typed]").addEventListener("click", addFolder);
    sfInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); addFolder(); }
    });
    // A folder from the repository: used on this computer once chosen.
    all("[data-use-folder]", sf).forEach(function (b) {
      b.addEventListener("click", function () {
        var folder = b.getAttribute("data-use-folder");
        confirmBox("Use " + folder + " on this computer?",
          "Every analysis here, and the scheduled runs, will connect to it and read its settings files. Use it only if you know the folder.",
          "Use folder", false)
          .then(function (yes) {
            if (!yes) return null;
            b.disabled = true;
            return api("POST", "/api/settings/settings-folders/use", { folder: folder });
          })
          .then(function (r) {
          if (r === null) return;
          var li = b.closest(".chip-item");
          li.classList.remove("waiting");
          var tag = li.querySelector(".folder-waiting");
          if (tag) tag.remove();
          b.remove();
          toast(folder + " is used on this computer from the next analysis.");
        }, function (e) {
          b.disabled = false;
          toast(e.message);
        });
      });
    });
    var bsf = sf.querySelector("[data-save]");
    bsf.addEventListener("click", function () {
      saving(bsf, sf, api("POST", "/api/settings/settings-folders", { items: folders.values(), loaded: loaded(sf) }), function (r) {
        if (r && r.loaded) sf.setAttribute("data-loaded", JSON.stringify(r.loaded));
      });
    });
  }

  var rules = document.querySelector("[data-section=rules]");
  if (rules) {
    var count = $("rules-count");
    var boxes = all("input[name=rule]", rules);
    var picks = all("select[name=sev]", rules);
    var rows = all(".rule-row", rules);
    var showing = "all";
    var changed = function (row) {
      var sel = row.querySelector("select[name=sev]");
      var box = row.querySelector("input[name=rule]");
      return (sel && sel.value !== "") || (box && !box.checked);
    };
    var plural = function (n, one, many) { return n + " " + (n === 1 ? one : many); };
    var recount = function () {
      var on = boxes.filter(function (b) { return b.checked; }).length;
      var set = picks.filter(function (p) { return p.value !== ""; }).length;
      var text = on === boxes.length ? "All " + on + " on" : on + " of " + boxes.length + " on";
      if (set > 0) text += " · " + plural(set, "severity", "severities") + " set";
      count.textContent = text;
      var n = rows.filter(changed).length;
      $("rules-all-n").textContent = rows.length;
      $("rules-changed-n").textContent = n;
      // A class, not [hidden]: rows the filter hides still count for "Unsaved
      // changes" (snapshot() skips controls under [hidden]).
      rows.forEach(function (row) { row.classList.toggle("filtered-out", showing === "changed" && !changed(row)); });
      $("rules-none").hidden = !(showing === "changed" && n === 0);
      $("rules-reset-box").hidden = !(showing === "changed" && n > 0);
      $("rules-reset").textContent = n === 1 ? "Reset to default" : n === 2 ? "Reset both to default" : "Reset all " + n + " to default";
    };
    // A severity chosen here: the row shows it until it is saved.
    var mark = function (sel) {
      var row = sel.closest(".rule-row");
      sel.className = "input sev-pick" + (sel.value ? " is-set sev-" + sel.value : "");
      row.classList.toggle("sev-set", sel.value !== "");
      var who = row.querySelector(".rule-who");
      if (who) who.hidden = sel.value !== sel.getAttribute("data-saved");
    };
    picks.forEach(function (p) { p.addEventListener("change", function () { mark(p); recount(); }); });
    boxes.forEach(function (b) { b.addEventListener("change", recount); });
    all("button[data-show]", rules).forEach(function (b) {
      b.addEventListener("click", function () {
        showing = b.getAttribute("data-show");
        all("button[data-show]", rules).forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
        recount();
      });
    });
    $("rules-reset").addEventListener("click", function () {
      picks.forEach(function (p) { if (p.value !== "") { p.value = ""; mark(p); } });
      boxes.forEach(function (b) { b.checked = true; });
      recount();
    });
    // The default each drop-down names follows how attack paths are rated.
    var relabel = function () {
      var sev = rules.querySelector("input[name=severity]:checked");
      var key = sev && sev.value === "static" ? "data-default-static" : "data-default-exposure";
      picks.forEach(function (p) { if (p.options[0]) p.options[0].textContent = p.getAttribute(key); });
    };
    all("input[name=severity]", rules).forEach(function (r) { r.addEventListener("change", relabel); });
    recount();
    var br = rules.querySelector("[data-save]");
    br.addEventListener("click", function () {
      var num = function (id) { return Number($(id).value); };
      var sev = rules.querySelector("input[name=severity]:checked");
      var severities = {};
      picks.forEach(function (p) { severities[p.getAttribute("data-rule")] = p.value || "default"; });
      var body = {
        stale_days: num("stale_days"),
        password_age_days: num("password_age_days"),
        krbtgt_age_days: num("krbtgt_age_days"),
        sso_key_age_days: num("sso_key_age_days"),
        severity: sev ? sev.value : "exposure",
        disabled: boxes.filter(function (b) { return !b.checked; }).map(function (b) { return b.value; }),
        severities: severities
      };
      body.loaded = loaded(rules);
      saving(br, rules, api("POST", "/api/settings/rules", body), function (r) {
        if (r && r.loaded) rules.setAttribute("data-loaded", JSON.stringify(r.loaded));
        // Who set each severity, as the file now records it.
        if (r && r.set) {
          picks.forEach(function (p) {
            var row = p.closest(".rule-row");
            var text = r.set[p.getAttribute("data-rule")];
            p.setAttribute("data-saved", p.value);
            var who = row.querySelector(".rule-who");
            if (text && !who) {
              who = el("span", "rule-who");
              row.querySelector(".rule-title").appendChild(who);
            }
            if (who) { who.textContent = text || ""; who.hidden = !text; }
          });
        }
      });
    });
  }

  var risks = document.querySelector("[data-section=risks]");
  if (risks) {
    var form = $("risk-form");
    var editing = null;
    var target = function () { return form.querySelector("input[name=target]:checked").value; };
    var showTarget = function () {
      var t = target();
      all("[data-when]", form).forEach(function (f) { f.hidden = f.getAttribute("data-when") !== t; });
    };
    all("input[name=target]", form).forEach(function (r) { r.addEventListener("change", showTarget); });
    var open = function (risk) {
      editing = risk;
      $("risk-form-title").textContent = risk ? "Edit accepted risk" : "Accept a risk";
      form.querySelector("input[value=" + (risk && risk.rule ? "rule" : "fingerprint") + "]").checked = true;
      $("risk-fp").value = (risk && risk.fingerprint) || "";
      if (risk && risk.rule) $("risk-rule").value = risk.rule;
      $("risk-reason").value = (risk && risk.reason) || "";
      var shown = visible((risk && risk.reason) || "");
      var bidiNote = $("risk-reason-bidi");
      if (bidiNote) {
        bidiNote.hidden = shown === ((risk && risk.reason) || "");
        bidiNote.textContent = bidiNote.hidden ? "" :
          "This reason holds a character that changes the direction of text, so it may look reordered here. As saved: " + shown;
      }
      $("risk-expires").value = (risk && risk.expires) || "";
      // A day already over accepts nothing (the server says so too); an
      // entry that has expired keeps its date.
      var today = new Date().toISOString().slice(0, 10);
      var kept = risk && risk.expires;
      $("risk-expires").min = kept && kept < today ? kept : today;
      status(form, "");
      showTarget();
      form.hidden = false;
      markClean(risks);
      form.scrollIntoView({ block: "nearest", behavior: "smooth" });
      (risk && risk.rule ? $("risk-reason") : $("risk-fp")).focus();
    };
    $("add-risk").addEventListener("click", function () { open(null); });
    $("risk-cancel").addEventListener("click", function () { form.hidden = true; markClean(risks); });
    var fpPicker = form.querySelector("[data-picker=fp]");
    if (fpPicker) {
      new Picker(fpPicker, { onPick: function (f) { $("risk-fp").value = f.fingerprint; $("risk-reason").focus(); } });
    }
    all(".risk-row", risks).forEach(function (row) {
      var risk = JSON.parse(row.getAttribute("data-risk"));
      row.querySelector("[data-edit-risk]").addEventListener("click", function () { open(risk); });
      row.querySelector("[data-remove-risk]").addEventListener("click", function () {
        confirmBox("Remove this accepted risk?", "The finding counts as open again from the next analysis. Reason: " + visible(risk.reason), "Remove", true)
          .then(function (yes) {
            if (!yes) return;
            api("DELETE", "/api/settings/suppress/" + risk.index, { expect: risk.reason, expect_target: risk.fingerprint != null ? risk.fingerprint : risk.rule })
              .then(function () { location.href = location.pathname + "#saved"; location.reload(); }, function (e) { toast(e.message); });
          });
      });
    });
    // Add a note: one form, moved under the risk it is for.
    var noteForm = $("note-form");
    var noteText = $("note-text");
    var noteRow = null, noteButton = null;
    var closeNote = function () {
      noteForm.hidden = true;
      noteText.value = "";
      status(noteForm, "");
      if (noteButton) {
        noteButton.setAttribute("aria-expanded", "false");
        noteButton.focus();
      }
      noteRow = null;
      markClean(risks);
    };
    var addNote = function (row, n) {
      var fold = row.querySelector(".risk-notes");
      var list = fold.querySelector("ol");
      var li = el("li");
      var meta = el("span", "meta");
      var who = n.by ? visible(n.by) : (n.on ? "an unknown user" : "");
      meta.textContent = [day(n.at), who + (n.on ? " on " + visible(n.on) : "")].filter(Boolean).join(" · ");
      li.appendChild(meta);
      li.appendChild(el("span", "note-text", visible(n.text)));
      list.appendChild(li);
      var count = list.children.length;
      fold.querySelector("summary").textContent = count === 1 ? "1 note" : count + " notes";
      fold.hidden = false;
      fold.open = true;
    };
    all(".risk-row", risks).forEach(function (row) {
      var risk = JSON.parse(row.getAttribute("data-risk"));
      var b = row.querySelector("[data-note-risk]");
      b.addEventListener("click", function () {
        if (noteRow === row) { closeNote(); return; }
        if (noteButton) noteButton.setAttribute("aria-expanded", "false");
        noteRow = row;
        noteButton = b;
        noteForm.risk = risk;
        row.appendChild(noteForm);
        noteText.value = "";
        status(noteForm, "");
        noteForm.hidden = false;
        // An empty note is nothing unsaved yet.
        markClean(risks);
        b.setAttribute("aria-expanded", "true");
        noteText.focus();
      });
    });
    $("note-cancel").addEventListener("click", closeNote);
    noteForm.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { e.preventDefault(); closeNote(); }
    });
    noteForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var risk = noteForm.risk;
      var text = noteText.value.trim();
      if (!risk) return;
      if (!text) { noteText.focus(); return; }
      var row = noteRow;
      var go = noteForm.querySelector("button[type=submit]");
      go.disabled = true;
      status(noteForm, "Saving…");
      api("POST", "/api/settings/suppress/" + risk.index + "/note", {
        expect: risk.reason,
        expect_target: risk.fingerprint != null ? risk.fingerprint : risk.rule,
        text: text
      }).then(function (j) {
        go.disabled = false;
        addNote(row, j.note || { text: text });
        closeNote();
        toast("Note added. The next analysis's report shows it with the finding.");
      }, function (err) {
        go.disabled = false;
        status(noteForm, err.message, false);
        noteText.focus();
      });
    });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var t = target();
      var body = {
        index: editing ? editing.index : null,
        expect: editing ? editing.reason : null,
        expect_target: editing ? (editing.fingerprint != null ? editing.fingerprint : editing.rule) : null,
        risk: {
          fingerprint: t === "fingerprint" ? $("risk-fp").value : null,
          rule: t === "rule" ? $("risk-rule").value : null,
          reason: $("risk-reason").value,
          expires: $("risk-expires").value || null
        }
      };
      saving(form.querySelector("button[type=submit]"), form, api("POST", "/api/settings/suppress", body), function () {
        location.href = location.pathname + "#saved";
        location.reload();
      });
    });
  }

  var state = document.querySelector("[data-section=state]");
  if (state) {
    var backend = function () { return state.querySelector("input[name=backend]:checked").value; };
    var showBackend = function () {
      var b = backend();
      all("[data-when-backend]", state).forEach(function (f) { f.hidden = f.getAttribute("data-when-backend") !== b; });
      $("state-path-label").textContent = b === "git" ? "Working copy folder" : "Folder";
    };
    all("input[name=backend]", state).forEach(function (r) { r.addEventListener("change", showBackend); });
    showBackend();
    var bs = state.querySelector("[data-save]");
    // What the history keeps: the warning shows with "Full runs and
    // settings", and choosing it is confirmed before it is saved.
    function keep() {
      var k = state.querySelector("input[name=keep]:checked");
      return k ? k.value : null;
    }
    var keptAtLoad = keep();
    var warn = state.querySelector(".keep-warn");
    // Full runs and settings proposes encryption: the passphrase panel
    // opens, unless the history is encrypted already ("Don't encrypt"
    // closes it again).
    all("input[name=keep]", state).forEach(function (r) {
      r.addEventListener("change", function () {
        if (warn) warn.hidden = keep() !== "full";
        var enc = $("enc"), box = $("state-encrypt");
        if (keep() === "full" && enc && enc.getAttribute("data-on") !== "true" && box && !box.checked) {
          box.checked = true;
          box.dispatchEvent(new Event("change"));
        }
      });
    });
    function stateBody() {
      var push = $("state-push");
      // Pull every: a git repository's only (this computer's own setting).
      var every = $("state-refresh");
      var refresh = backend() === "git" && every && every.value.trim() !== "" ? Number(every.value) : null;
      return {
        backend: backend(),
        path: $("state-path").value || null,
        remote: $("state-remote").value || null,
        branch: $("state-branch").value || null,
        keep: keep(),
        push: push ? push.checked : null,
        refresh: refresh
      };
    }
    // Choosing full runs and settings is confirmed first, on Save and on the
    // passphrase panel's "Set passphrase and save" alike.
    // `encrypting`: from "Set passphrase and save".
    function confirmKeep(encrypting) {
      if (keep() !== "full" || keptAtLoad === "full") return Promise.resolve(true);
      var enc = $("enc");
      if (encrypting || (enc && enc.getAttribute("data-on") === "true")) {
        return confirmBox("Keep full runs and settings?",
          "Each run in full and the shared settings and accepted risks, with who recorded or accepted them, go into the history encrypted: only those with the passphrase can read them. Anyone who can push to it can still change or remove them.",
          "Keep full runs and settings");
      }
      return confirmBox("Keep full runs and settings, not encrypted?",
        "The history is not encrypted: anyone who can read this folder or repository sees each run in full and the shared settings and accepted risks, with who recorded or accepted them. Anyone who can push to it can change them for every machine.",
        "Keep them in plain text");
    }
    // The passphrase panel (enc.js) sends this form with the passphrase:
    // the server encrypts the history before anything is shared.
    window.pwConfirmKeep = confirmKeep;
    window.pwStateBody = stateBody;
    var confirmed = false;
    bs.addEventListener("click", function () {
      if (!confirmed && keep() === "full" && keptAtLoad !== "full") {
        confirmKeep().then(function (ok) { if (ok) { confirmed = true; bs.click(); confirmed = false; } });
        return;
      }
      var body = stateBody();
      // Saved with full runs and settings and no encryption: the panel was
      // closed with "Don't encrypt" (or unticked), the user's choice.
      var enc = $("enc");
      if (keep() === "full" && !(enc && enc.getAttribute("data-on") === "true")) body.share_plain = true;
      var found = document.getElementById("hs-found");
      if (found) found.innerHTML = "";
      saving(bs, state, api("POST", "/api/settings/state", body).catch(function (e) {
        // A history is there already: Connect to it, said beside Save.
        if (e.data && e.data.connect && window.pwShowFound && window.pwShowFound(e.data)) {
          var quiet = new Error("Not saved.");
          throw quiet;
        }
        throw e;
      }), function () {
        // The History storage page shows which history is in use.
        if (document.getElementById("in-use")) { location.href = location.pathname + "#saved"; location.reload(); }
      });
    });
  }

  // History storage: how many full runs the history keeps, and the
  // largest file a full run keeps.
  var fullRuns = document.querySelector("[data-section=full-runs]");
  if (fullRuns) {
    var fb = fullRuns.querySelector("[data-save]");
    var fileMb = $("full-run-file-mb");
    var held = $("full-run-file-held");
    // On GitHub: why a larger setting is held, while it is.
    if (fileMb && held) {
      fileMb.addEventListener("input", function () {
        var v = parseInt(fileMb.value, 10);
        held.hidden = !(v > parseInt(held.getAttribute("data-hold"), 10));
      });
    }
    fb.addEventListener("click", function () {
      var n = parseInt($("full-runs-kept").value, 10);
      var body = { kept: isNaN(n) ? 0 : n };
      if (fileMb) {
        var mb = parseInt(fileMb.value, 10);
        body.file_mb = isNaN(mb) ? 0 : mb;
      }
      saving(fb, fullRuns, api("POST", "/api/settings/full-runs", body));
    });
  }

  // ---------------------------------------------------- Zones list
  all("[data-delete-zone]").forEach(function (b) {
    b.addEventListener("click", function () {
      var name = b.getAttribute("data-name");
      confirmBox("Delete the zone " + name + "?", "It is removed from pathwarden.toml, and the next analysis no longer reports on it.", "Delete zone", true)
        .then(function (yes) {
          if (!yes) return;
          api("DELETE", "/api/zones/" + b.getAttribute("data-delete-zone"), { expect: name })
            .then(function () { location.href = "/zones#saved"; location.reload(); }, function (e) { toast(e.message); });
        });
    });
  });

  // ---------------------------------------------------- Zone wizard
  var wiz = $("zone-wizard");
  if (wiz) {
    var data = JSON.parse(wiz.getAttribute("data-zone"));
    var picks = [];
    data.groups.forEach(function (v) { picks.push({ value: v, as: "group", kind: "Group" }); });
    data.ous.forEach(function (v) { picks.push({ value: v, as: "ou", kind: "OU" }); });
    data.members.forEach(function (v) { picks.push({ value: v, as: "member", kind: null }); });
    var nameInput = $("zone-name");
    nameInput.value = data.name || "";
    var step = 1;
    var lastPreview = null;

    var modes = {
      member: "Just this object",
      group: "Group and everyone in it",
      ou: "OU and everything below it"
    };

    var goto = function (n) {
      if (n > 1 && !nameInput.value.trim()) { toast("Give the zone a name first."); nameInput.focus(); n = 1; }
      if (n > 2 && !picks.length) { toast("Add at least one object, group or OU."); n = 2; }
      step = n;
      all("[data-panel]", wiz).forEach(function (p) { p.hidden = Number(p.getAttribute("data-panel")) !== n; });
      window.Pathwarden.step($("wiz-steps"), n, false);
      if (n === 2) $("zp-q").focus();
      if (n === 3) review();
      window.scrollTo({ top: 0, behavior: "smooth" });
    };
    all("[data-goto]").forEach(function (b) { b.addEventListener("click", function () { goto(Number(b.getAttribute("data-goto"))); }); });
    all("[data-next]", wiz).forEach(function (b) { b.addEventListener("click", function () { goto(step + 1); }); });
    all("[data-prev]", wiz).forEach(function (b) { b.addEventListener("click", function () { goto(step - 1); }); });
    all("[data-example]", wiz).forEach(function (b) {
      b.addEventListener("click", function () { nameInput.value = b.getAttribute("data-example"); nameInput.focus(); });
    });
    nameInput.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); goto(2); } });

    var body = function () {
      var z = { name: nameInput.value.trim(), members: [], groups: [], ous: [] };
      picks.forEach(function (p) {
        (p.as === "group" ? z.groups : p.as === "ou" ? z.ous : z.members).push(p.value);
      });
      return z;
    };

    var pickList = $("picks");
    var renderPicks = function () {
      pickList.textContent = "";
      $("pick-count").textContent = picks.length;
      if (!picks.length) pickList.appendChild(el("li", "chip-empty muted", pickList.getAttribute("data-empty")));
      picks.forEach(function (p, i) {
        var li = el("li", "pick");
        var main = el("span", "r-main");
        main.appendChild(el("span", "r-name", p.value));
        main.appendChild(el("span", "r-sub", p.kind ? p.kind : "Typed in"));
        li.appendChild(main);
        var sel = el("select", "input mode");
        sel.setAttribute("aria-label", "How " + p.value + " is added");
        var allowed = p.kind === "Group" ? ["group", "member"]
          : (p.kind === "OU" || p.kind === "Container") ? ["ou", "member"]
          : p.kind ? ["member"] : ["member", "group", "ou"];
        allowed.forEach(function (m) {
          var o = el("option", null, modes[m]);
          o.value = m;
          if (m === p.as) o.selected = true;
          sel.appendChild(o);
        });
        if (allowed.length === 1) sel.disabled = true;
        sel.addEventListener("change", function () { p.as = sel.value; refreshPreview(); });
        li.appendChild(sel);
        var x = el("button", "fl-remove");
        x.type = "button";
        x.setAttribute("aria-label", "Remove " + p.value);
        x.appendChild(svg("i-x"));
        x.addEventListener("click", function () { picks.splice(i, 1); renderPicks(); refreshPreview(); });
        li.appendChild(x);
        pickList.appendChild(li);
      });
    };

    var add = function (value, as, kind) {
      var dup = picks.some(function (p) { return p.value.toUpperCase() === value.toUpperCase(); });
      if (dup) { toast(value + " is already in the zone."); return; }
      picks.push({ value: value, as: as, kind: kind });
      renderPicks();
      refreshPreview();
    };

    var kindFilter = function () {
      var r = wiz.querySelector("input[name=kind]:checked");
      return r ? r.value : "";
    };
    var zp = new Picker(wiz.querySelector("[data-picker=zp]"), {
      kinds: kindFilter,
      onPick: function (r) {
        if (r.tier_zero) toast(r.name + " is Tier Zero. Tier Zero is never part of a zone (it already sits above every zone), so it will be left out.");
        add(r.name, r.adds_as, r.kind);
      },
      onTyped: function (v) { add(v, /^(OU|CN)=/i.test(v) ? "ou" : "member", null); }
    });
    all("input[name=kind]", wiz).forEach(function (r) { r.addEventListener("change", function () { zp.refresh(); $("zp-q").focus(); }); });

    var pv = $("preview").querySelector(".pv-body");
    var drawPreview = function (target, j, big) {
      target.textContent = "";
      if (!j) {
        target.appendChild(el("p", "muted small", "Add members to see what the zone resolves to."));
        return;
      }
      var p = j.preview;
      var head = el("div", "pv-total");
      head.appendChild(el("span", "pv-num", p.total.toLocaleString()));
      head.appendChild(el("span", "muted", p.total === 1 ? "object in the zone" : "objects in the zone"));
      target.appendChild(head);
      target.appendChild(el("p", "muted small pv-env", "In " + j.environment + ", the latest analysis. Tier Zero objects are never counted."));
      if (p.kinds.length) {
        var kinds = el("ul", "pv-kinds");
        var max = p.kinds[0][1];
        p.kinds.forEach(function (k) {
          var li = el("li");
          li.appendChild(el("span", "k-name", k[0]));
          var bar = el("span", "k-bar");
          var fill = el("span");
          fill.style.width = Math.max(4, Math.round(100 * k[1] / max)) + "%";
          bar.appendChild(fill);
          li.appendChild(bar);
          li.appendChild(el("span", "k-n", k[1].toLocaleString()));
          kinds.appendChild(li);
        });
        target.appendChild(kinds);
      }
      var warn = function (text) {
        var w = el("p", "pv-warn");
        w.appendChild(svg("i-alert"));
        w.appendChild(el("span", null, text));
        target.appendChild(w);
      };
      // Worded in core (ZonePreview::warnings), as `pathwarden zones preview` prints them.
      (j.warnings || []).forEach(warn);
      if (p.sample.length) {
        target.appendChild(el("h3", "form-title", big ? "Some of what is in it" : "Sample"));
        var ul = el("ul", "pv-sample");
        p.sample.forEach(function (n) { ul.appendChild(el("li", null, n)); });
        if (p.total > p.sample.length) ul.appendChild(el("li", "muted", "and " + (p.total - p.sample.length).toLocaleString() + " more"));
        target.appendChild(ul);
      }
    };
    var refreshPreview = debounce(function () {
      if (!picks.length) { lastPreview = null; drawPreview(pv, null); return; }
      $("preview").classList.add("loading");
      api("POST", "/api/zones/preview", body()).then(function (j) {
        $("preview").classList.remove("loading");
        lastPreview = j;
        drawPreview(pv, j);
      }, function (e) {
        $("preview").classList.remove("loading");
        lastPreview = null;
        pv.textContent = "";
        pv.appendChild(el("p", "muted small", e.message));
      });
    }, 250);

    var review = function () {
      var r = $("review");
      r.textContent = "";
      var z = body();
      var dl = el("dl", "facts review-facts");
      var row = function (label, values) {
        if (!values.length) return;
        var d = el("div");
        d.appendChild(el("dt", null, label));
        var dd = el("dd");
        values.forEach(function (v) { dd.appendChild(el("code", null, v)); });
        d.appendChild(dd);
        dl.appendChild(d);
      };
      row("Name", [z.name]);
      row("Groups, with everyone in them", z.groups);
      row("OUs, with everything below them", z.ous);
      row("Objects", z.members);
      r.appendChild(dl);
      var box = el("div", "review-preview");
      r.appendChild(box);
      if (lastPreview) drawPreview(box, lastPreview, true);
      else box.appendChild(el("p", "muted small", "No preview: the preview needs one analysis. The zone is still saved and applies to the next analysis."));
    };

    wiz.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = $("zone-save");
      saving(btn, wiz.querySelector("[data-panel='3']"), api("POST", "/api/zones", {
        index: data.index,
        expect: data.index === null ? null : data.name,
        zone: body()
      }), function () { location.href = "/zones#saved"; });
    });

    renderPicks();
    refreshPreview();
    if (data.index !== null) goto(2); else nameInput.focus();
  }

  // ---------------------------------------------------- Plugins list
  all("[data-delete-plugin]").forEach(function (b) {
    b.addEventListener("click", function () {
      var name = b.getAttribute("data-name");
      confirmBox("Remove the plugin " + name + "?", "Scheduled runs stop sending it results. Nothing is deleted on the other side.", "Remove", true)
        .then(function (yes) {
          if (!yes) return;
          api("DELETE", "/api/plugins/" + b.getAttribute("data-delete-plugin"), { expect: name })
            .then(function () { location.href = "/automate/ticketing#saved"; location.reload(); }, function (e) { toast(e.message); });
        });
    });
  });
  all("[data-test-plugin]").forEach(function (b) {
    b.addEventListener("click", function () {
      var name = b.getAttribute("data-name");
      var custom = b.getAttribute("data-custom") === "true";
      var ask = custom
        ? confirmBox("Test " + name + "?", "Pathwarden asks the plugin for a dry run by adding dry_run = true to its settings. A script that ignores that setting would really send its alert or create its tickets. Run it only if yours honors dry_run.", "Run dry run", false)
        : Promise.resolve(true);
      ask.then(function (yes) {
        if (!yes) return;
        var row = b.closest(".plugrow");
        var out = row.querySelector(".test-out");
        out.hidden = false;
        out.className = "test-out running";
        row.querySelector(".test-title").textContent = "Running a dry run…";
        row.querySelector(".test-sub").textContent = "";
        row.querySelector(".test-log").textContent = "";
        b.disabled = true;
        api("POST", "/api/plugins/" + b.getAttribute("data-test-plugin") + "/test", { expect: name }).then(function (j) {
          b.disabled = false;
          out.className = "test-out " + (j.ok ? "ok" : "bad");
          row.querySelector(".test-title").textContent = j.ok ? "Dry run finished" : "The plugin reported a problem";
          // The run's time in local time, as everywhere (app.js).
          var ran = typeof j.run_at === "number" && window.PathwardenTime
            ? j.run_env + ", analyzed " + window.PathwardenTime.local(j.run_at)
            : j.run;
          row.querySelector(".test-sub").textContent = j.status + " · " + ran;
          row.querySelector(".test-log").textContent = j.output || "(no output)";
        }, function (e) {
          b.disabled = false;
          out.className = "test-out bad";
          row.querySelector(".test-title").textContent = "Couldn't run the plugin";
          row.querySelector(".test-log").textContent = e.message;
        });
      });
    });
  });

  // ---------------------------------------------------- Plugin form
  var pform = $("plugin-form");
  if (pform) {
    var meta = JSON.parse(pform.getAttribute("data-plugin"));
    var kvRow = function (k, v) {
      var d = el("div", "kv");
      var ki = el("input", "input mono");
      ki.setAttribute("data-k", "");
      ki.placeholder = "name";
      ki.setAttribute("aria-label", "Name");
      ki.autocomplete = "off";
      ki.spellcheck = false;
      ki.value = k || "";
      var vi = el("input", "input");
      vi.setAttribute("data-v", "");
      vi.placeholder = "value";
      vi.setAttribute("aria-label", "Value");
      vi.autocomplete = "off";
      vi.value = v || "";
      var x = el("button", "fl-remove");
      x.type = "button";
      x.setAttribute("data-remove-kv", "");
      x.setAttribute("aria-label", "Remove");
      x.appendChild(svg("i-x"));
      d.appendChild(ki); d.appendChild(vi); d.appendChild(x);
      return d;
    };
    pform.addEventListener("click", function (e) {
      var rm = e.target.closest("[data-remove-kv]");
      if (rm) { rm.closest(".kv").remove(); envCheck(); return; }
      var add = e.target.closest("[data-add-kv]");
      if (add) {
        var box = $(add.getAttribute("data-add-kv"));
        var r = kvRow();
        box.appendChild(r);
        r.querySelector("[data-k]").focus();
      }
    });
    var pairs = function (id) {
      return all(".kv", $(id)).map(function (r) {
        return [r.querySelector("[data-k]").value.trim(), r.querySelector("[data-v]").value];
      }).filter(function (p) { return p[0] || p[1].trim(); });
    };
    var radio = function (name) { var r = pform.querySelector("input[name=" + name + "]:checked"); return r ? r.value : ""; };
    var toggle = function (attr, value) {
      all("[" + attr + "]", pform).forEach(function (f) { f.hidden = f.getAttribute(attr) !== value; });
    };
    var authName = meta.kind === "jira" ? "j-auth" : "sn-auth";
    all("input[name=" + authName + "]", pform).forEach(function (r) { r.addEventListener("change", function () { toggle("data-when-auth", radio(authName)); envCheck(); }); });
    all("input[name=pl-how]", pform).forEach(function (r) { r.addEventListener("change", function () { toggle("data-when-how", radio("pl-how")); }); });
    if (meta.kind === "command") toggle("data-when-how", radio("pl-how")); else toggle("data-when-auth", radio(authName));

    // Whether the named variables are set (never their values).
    var envCheck = debounce(function () {
      var targets = [];
      all("input[data-env]", pform).forEach(function (i) {
        if (!i.closest("[hidden]")) targets.push({ name: i.value.trim(), out: i.parentNode.querySelector(".envstatus") });
      });
      var envs = $("pl-envs");
      if (envs) {
        envs.textContent = "";
        pairs("pl-settings").forEach(function (p) {
          if (/_env$/.test(p[0]) && p[1].trim()) {
            var s = el("span", "envchip");
            envs.appendChild(s);
            targets.push({ name: p[1].trim(), out: s, chip: true });
          }
        });
      }
      var names = targets.map(function (t) { return t.name; }).filter(Boolean);
      if (!names.length) return;
      api("GET", "/api/env?names=" + encodeURIComponent(names.join(","))).then(function (j) {
        targets.forEach(function (t) {
          if (!t.out) return;
          t.out.textContent = "";
          var known = Object.prototype.hasOwnProperty.call(j, t.name);
          var set = known && j[t.name];
          t.out.className = (t.chip ? "envchip " : "envstatus ") + (!known ? "bad" : set ? "set" : "unset");
          t.out.appendChild(el("span", "dot"));
          if (t.chip) t.out.appendChild(el("code", null, t.name));
          t.out.appendChild(document.createTextNode(!known ? " not a valid variable name" : set ? " set in this environment" : " not set in this environment"));
        });
      }, function () {});
    }, 250);
    pform.addEventListener("input", function (e) {
      if (e.target.matches("[data-env], #pl-settings input")) envCheck();
    });
    envCheck();

    pform.addEventListener("submit", function (e) {
      e.preventDefault();
      var b = { index: meta.index, expect: meta.index === null ? null : meta.expect, kind: meta.kind };
      if (meta.kind === "servicenow") {
        b.plugin = "servicenow";
        b.instance = $("sn-instance").value;
        b.table = $("sn-table").value;
        b.min_severity = $("sn-min").value;
        b.scope = $("sn-scope").value;
        b.auth = radio("sn-auth");
        b.username_env = $("sn-user-env").value;
        b.password_env = $("sn-pass-env").value;
        b.token_env = $("sn-token-env").value;
        b.fields = pairs("sn-fields");
      } else if (meta.kind === "jira") {
        b.plugin = "jira";
        b.instance = $("j-instance").value;
        b.deployment = $("j-deployment").value;
        b.project = $("j-project").value;
        b.issue_type = $("j-type").value;
        b.min_severity = $("j-min").value;
        b.scope = $("j-scope").value;
        b.auth = radio("j-auth");
        b.username_env = $("j-user-env").value;
        b.token_env = $("j-token-env").value;
        b.pat_env = $("j-pat-env").value;
        b.set_priority = $("j-priority").value === "true";
        b.on_closed_but_present = $("j-closed").value;
        b.close_transition = $("j-close-tr").value;
        b.reopen_transition = $("j-reopen-tr").value;
        b.close_resolution = $("j-resolution").value;
        b.fields = pairs("j-fields");
      } else {
        b.plugin = $("pl-name").value;
        b.command = radio("pl-how") === "command"
          ? [$("pl-program").value].concat($("pl-args").value.split(/\r?\n/)).map(function (s) { return s.trim(); }).filter(Boolean)
          : null;
        if (b.command && !b.command.length) b.command = [""];
        b.settings = pairs("pl-settings");
      }
      if (meta.kind !== "command") {
        b.max_create = $("pl-max-create").value;
        b.max_resolve_percent = $("pl-max-resolve").value;
      }
      saving(pform.querySelector("button[type=submit]"), pform, api("POST", "/api/plugins", b), function () {
        location.href = "/automate/ticketing#saved";
      });
    });
  }

  // ---------------------------------------------------- shared settings
  // A save on a computer that pushes goes to the repository after the page
  // has its answer; this says how it went (a section to settle, a push that
  // failed, the history in use).
  function pollSharing(id) {
    var tries = 0;
    (function poll() {
      api("GET", "/api/settings/sharing?id=" + encodeURIComponent(id)).then(function (r) {
        if (r.running && tries++ < 180) { setTimeout(poll, 1000); return; }
        if (r.note) {
          toast(r.note);
          var t = $("toast");
          if (t && r.problem) t.classList.add("kept");
        }
      }, function () {});
    })();
  }

  // Dismiss on the note about settings that differ: no dot on Settings
  // until something else differs; the note stays, on one line.
  all("[data-sync-dismiss]").forEach(function (b) {
    b.addEventListener("click", function () {
      b.disabled = true;
      // Either way the page is drawn again: dismissed, or what differs now.
      var again = function () {
        if (window.Pathwarden) window.Pathwarden.leaving = true;
        location.reload();
      };
      var at = b.getAttribute("data-merged-at");
      api("POST", "/api/settings/dismiss", {
        key: b.getAttribute("data-sync-dismiss"),
        merged_at: at ? Number(at) : null
      }).then(again, again);
    });
  });

  // "Use shared settings" / "Use local settings" for one section.
  all("[data-sync-action]").forEach(function (b) {
    b.addEventListener("click", function () {
      var holder = b.closest(".clash-row, .cmp-actions, .card-actions, .card") || document.body;
      all("[data-sync-action]").forEach(function (x) { x.disabled = true; });
      status(holder, b.getAttribute("data-sync-action") === "keep_local" ? "Sharing…" : "Taking the shared value…");
      api("POST", "/api/settings/sync", {
        action: b.getAttribute("data-sync-action"),
        section: b.getAttribute("data-sync-section")
      }).then(function (r) {
        status(holder, r.note || "Done", true);
        setTimeout(function () { location.reload(); }, 900);
      }, function (e) {
        all("[data-sync-action]").forEach(function (x) { x.disabled = false; });
        status(holder, e.message, false);
      });
    });
  });

  // The note after a pull applied the repository's settings.
  all("[data-close-note]").forEach(function (b) {
    b.addEventListener("click", function () { b.closest(".saved-note").remove(); });
  });
})();
