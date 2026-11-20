// Pathwarden UI: theme, local times, the demo button, uploads and progress,
// and deleting runs. No libraries; everything is served by the app.
(function () {
  "use strict";
  var root = document.documentElement;

  function $(id) { return document.getElementById(id); }
  // A request that got no answer at all (an HTTP error is an answer: its
  // own message is shown instead).
  var NOT_ANSWERING = "Pathwarden isn't answering. Is it still running?";

  // `keep`: stays until the user dismisses it (a note to read, not a
  // passing error).
  function toast(message, keep) {
    var t = $("toast");
    if (!t) { alert(message); return; }
    clearTimeout(toast.timer);
    // A kept note's Escape is for that note only, not the one replacing it.
    if (toast.onKey) {
      document.removeEventListener("keydown", toast.onKey);
      toast.onKey = null;
    }
    t.textContent = "";
    var text = document.createElement("span");
    text.textContent = message;
    t.appendChild(text);
    t.classList.toggle("kept", !!keep);
    if (keep) {
      var close = document.createElement("button");
      close.type = "button";
      close.className = "btn toast-close";
      close.textContent = "Dismiss";
      var onKey = function (e) {
        if (e.key !== "Escape") return;
        // Another page's script may have put its own toast in place.
        if (close.isConnected) dismiss();
        else { document.removeEventListener("keydown", onKey); toast.onKey = null; }
      };
      var dismiss = function () {
        t.hidden = true;
        document.removeEventListener("keydown", onKey);
        toast.onKey = null;
      };
      close.addEventListener("click", dismiss);
      document.addEventListener("keydown", onKey);
      toast.onKey = onKey;
      t.appendChild(close);
    } else {
      toast.timer = setTimeout(function () { t.hidden = true; }, 6000);
    }
    t.hidden = false;
    if (keep) t.querySelector(".toast-close").focus();
  }

  // A note the page before left (Delete, about the run history).
  try {
    var left = sessionStorage.getItem("pw-note");
    if (left) { sessionStorage.removeItem("pw-note"); toast(left, true); }
  } catch (e) {}

  // The rail's amber dot on Settings (pages::settings_item): settings that
  // differ from the shared ones, a crash not dismissed, or both.
  window.Pathwarden = window.Pathwarden || {};
  window.Pathwarden.settingsDot = function (differ, crash) {
    var link = document.querySelector('.tablist a[href="/settings"]');
    if (!link) return;
    var DIFFER = "Settings differ from the shared settings", CRASH = "Pathwarden stopped unexpectedly";
    var words = differ && crash ? DIFFER + "; " + CRASH.toLowerCase() : differ ? DIFFER : crash ? CRASH : "";
    link.toggleAttribute("data-differ", !!differ);
    link.toggleAttribute("data-crash", !!crash);
    var dot = link.querySelector(".nav-dot");
    var said = link.querySelector(".sr-only");
    if (!words) {
      if (dot) dot.remove();
      if (said) said.remove();
      link.removeAttribute("title");
      return;
    }
    if (!said) {
      said = document.createElement("span");
      said.className = "sr-only";
      link.appendChild(said);
    }
    if (!dot) {
      dot = document.createElement("span");
      dot.className = "nav-dot";
      dot.setAttribute("aria-hidden", "true");
      link.appendChild(dot);
    }
    said.textContent = ": " + words.toLowerCase();
    dot.title = words;
    link.title = words;
  };

  // Open log, Open crash report, Open logs folder: the app opens it (only a
  // file of the logs folder, by its name) in this computer's default app.
  window.Pathwarden.openLog = function (file) {
    return fetch("/api/logs/open", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(file ? { file: file } : {})
    }).then(function (r) {
      if (r.ok) return;
      return r.json().then(function (j) { throw new Error((j && j.error) || "Couldn't open the log."); },
        function () { throw new Error("Couldn't open the log."); });
    }, function () { throw new Error(NOT_ANSWERING); }).catch(function (e) { toast(e.message || "Couldn't open the log."); });
  };

  // Settings, the Logs card: Open logs folder, Open crash report, Dismiss.
  (function () {
    var card = $("logs");
    if (!card || !card.classList.contains("setting")) return;
    var folder = card.querySelector("[data-logs-open]");
    if (folder) folder.addEventListener("click", function () { window.Pathwarden.openLog(null); });
    var open = card.querySelector("[data-crash-open]");
    if (open) open.addEventListener("click", function () {
      window.Pathwarden.openLog(open.getAttribute("data-crash-open"));
    });
    var dismiss = card.querySelector("[data-crash-dismiss]");
    if (dismiss) dismiss.addEventListener("click", function () {
      dismiss.disabled = true;
      fetch("/api/logs/dismiss", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file: dismiss.getAttribute("data-crash-dismiss") || null })
      }).then(function (r) {
        if (!r.ok) throw new Error("Couldn't dismiss the crash report. Try again.");
        var line = card.querySelector("[data-crash]");
        if (line) line.remove();
        var jump = document.querySelector('.jump a[href="#logs"]');
        if (jump) {
          jump.removeAttribute("title");
          jump.querySelectorAll(".jump-dot, .sr-only").forEach(function (e) { e.remove(); });
        }
        var rail = document.querySelector('.tablist a[href="/settings"]');
        window.Pathwarden.settingsDot(!!(rail && rail.hasAttribute("data-differ")), false);
      }).catch(function (e) { dismiss.disabled = false; toast(e.message); });
    });
  })();

  // The wizards' shared step indicator (pages::stepper): steps before `n`
  // (and `n` itself when `done`) are ticked, `n` is current, and the phone
  // line says "Step n of N · label".
  window.Pathwarden = window.Pathwarden || {};
  window.Pathwarden.step = function (ol, n, done) {
    if (!ol) return;
    var items = ol.querySelectorAll("li[data-step]");
    var label = "";
    Array.prototype.forEach.call(items, function (li) {
      var k = Number(li.getAttribute("data-step"));
      var current = k === n && !done;
      li.classList.toggle("done", k < n || (done && k === n));
      if (current) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
      if (k === n) {
        var l = li.querySelector(".sp-l");
        label = l ? l.textContent : "";
      }
    });
    var mobile = document.getElementById(ol.id + "-mobile");
    if (mobile) mobile.textContent = "Step " + n + " of " + items.length + " · " + label;
  };

  function errorText(xhrOrResponseText, fallback) {
    try {
      var j = JSON.parse(xhrOrResponseText);
      if (j && j.error) return j.error;
    } catch (e) {}
    return fallback;
  }

  // ---------------------------------------------------------------- Theme
  // The report's frame. Only this script sets its address (the page leaves
  // it out), so every load the app did not start is the frame navigating on
  // its own: data-live="0" then tells retest.js not to send it results.
  var frame = $("report-frame");
  var appLoad = false;
  if (frame) {
    frame.addEventListener("load", function () {
      frame.setAttribute("data-live", appLoad ? "1" : "0");
      appLoad = false;
    });
  }
  function frameSrc(theme) {
    if (!frame) return;
    var base = frame.getAttribute("data-src");
    // Only this app's own report pages, never another address.
    if (!/^\/runs\/[A-Za-z0-9_-]+\/report\?/.test(base || "")) return;
    var want = theme === "light" ? base + "&theme=light" : base;
    // The report's place, which run.js keeps in this page's address: the
    // report opens there (a reload, Back, a shared link, a theme switch).
    if (PLACE.test(location.hash)) want += location.hash;
    if (frame.getAttribute("src") !== want) {
      // A new #hash alone moves the report without loading it again, but
      // the frame still fires load, so this counts as the app's too.
      appLoad = true;
      frame.setAttribute("src", want);
    }
  }
  var PLACE = /^#[A-Za-z0-9_-]{1,128}$/;

  // Sign in, on a run page: git with its sign-in window allowed,
  // then a sync; the page loads again at `hash`, saying how it went. From
  // the page's own Run details, or the report's tab (run.js asks).
  var signingIn = false;
  function signIn(hash, button) {
    if (signingIn) return;
    signingIn = true;
    if (button) button.disabled = true;
    fetch("/api/history/sign-in", { method: "POST", credentials: "same-origin" })
      .then(function (r) {
        return r.text().then(function (t) {
          var j = {};
          try { j = t ? JSON.parse(t) : {}; } catch (e) {}
          if (!r.ok) throw new Error(j.error || "Sign-in didn't finish. Try again.");
          return j;
        });
      }, function () { throw new Error(NOT_ANSWERING); })
      .then(function (j) {
        var q = new URLSearchParams(location.search);
        if (typeof j.token === "string" && /^[0-9a-f]{32}$/.test(j.token)) q.set("signin", j.token);
        else q.delete("signin");
        var u = location.pathname + "?" + q.toString() + hash;
        if (u.split("#")[0] !== location.pathname + location.search) { location.href = u; return; }
        try { history.replaceState(history.state, "", u); } catch (e) {}
        location.reload();
      })
      .catch(function (e) {
        signingIn = false;
        if (button) button.disabled = false;
        toast(e.message, true);
      });
  }
  window.pwSignIn = signIn;
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest("button[data-sign-in]");
    if (!b) return;
    e.preventDefault();
    signIn("#run-details", b);
  });
  // "Run details" in the run page's header: the report's tab (#details,
  // which the hashchange below passes on to the frame), brought into view;
  // or, when the report can't carry the tab, the page's own Run details
  // below it, opened. The frame keeps its place then.
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest("a[data-rd-open]");
    if (!a) return;
    var below = $("run-details");
    if (a.getAttribute("href") === "#run-details" && below) {
      e.preventDefault();
      var more = below.querySelector("details.rd-more");
      if (more) more.open = true;
      below.scrollIntoView({ block: "start" });
    } else if (frame) {
      setTimeout(function () { frame.scrollIntoView({ block: "start" }); }, 0);
    }
  });
  // A new place typed or pasted into this page's address moves the report
  // there too (run.js's own address updates fire no hashchange).
  window.addEventListener("hashchange", function () {
    if (PLACE.test(location.hash)) frameSrc(root.getAttribute("data-theme"));
  });
  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    var button = $("theme-toggle");
    if (button) {
      // The label names the theme it switches to, so it is not a pressed
      // toggle: no aria-pressed.
      var label = theme === "dark" ? "Light mode" : "Dark mode";
      button.querySelector(".tt-label").textContent = label;
      button.title = label;
      button.removeAttribute("aria-pressed");
      // The icon of the theme it switches to: a sun in dark mode.
      var use = button.querySelector("use");
      if (use) use.setAttribute("href", theme === "dark" ? "#i-sun" : "#i-theme");
    }
    frameSrc(theme);
  }
  setTheme(root.getAttribute("data-theme") || "dark");
  var toggle = $("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      setTheme(next);
      try { localStorage.setItem("pathwarden-theme", next); } catch (e) {}
    });
  }
  // Until the button is used, the theme follows the system's, also when it
  // changes while the page is open (theme.js picks it at load).
  try {
    var system = matchMedia("(prefers-color-scheme: light)");
    var follow = function (e) {
      var saved = null;
      try { saved = localStorage.getItem("pathwarden-theme"); } catch (x) {}
      if (saved !== "light" && saved !== "dark") setTheme(e.matches ? "light" : "dark");
    };
    if (system.addEventListener) system.addEventListener("change", follow);
    else if (system.addListener) system.addListener(follow);
  } catch (e) {}

  // ----------------------------------------------------------------- Stop
  // Forms that end something (Stop Pathwarden) ask first.
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!confirm(f.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // A form that removes something (an environment) stays disabled until
  // its name is typed; the server checks the same (env_remove::confirms).
  document.querySelectorAll("input[data-must-match]").forEach(function (input) {
    var form = input.form;
    var button = form && form.querySelector("[data-confirm-button]");
    if (!button) return;
    var names = [input.getAttribute("data-must-match"), input.getAttribute("data-or-match")]
      .filter(Boolean)
      .map(function (n) { return n.trim().toLowerCase(); });
    function check() {
      var typed = input.value.trim().toLowerCase();
      button.disabled = !typed || names.indexOf(typed) < 0;
    }
    input.addEventListener("input", check);
    check();
  });

  // ---------------------------------------------------------- Local times
  // The one place times are formatted, always US style (as
  // pathwarden_core::time writes them). The server writes every time as
  // <time datetime data-unix> with US-style UTC text (pages::time); here it
  // becomes local time, with the UTC value as the tooltip. data-fmt picks
  // the form: "full" (Oct 9, 2026, 9:29 PM, the default), "date" (Oct 9,
  // 2026), "day" (Oct 9) or "time" (9:29 PM). Other scripts use
  // window.PathwardenTime.
  var FORMS = {
    full: { dateStyle: "medium", timeStyle: "short" },
    fullsec: { dateStyle: "medium", timeStyle: "medium" },
    date: { dateStyle: "medium" },
    day: { month: "short", day: "numeric" },
    dayclock: { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" },
    dayclocksec: { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" },
    time: { hour: "numeric", minute: "2-digit" }
  };
  var formatters = {};
  function formatter(key, zone) {
    var k = key + (zone || "");
    if (!(k in formatters)) {
      var o = {};
      for (var p in FORMS[key]) o[p] = FORMS[key][p];
      if (zone) o.timeZone = zone;
      try { formatters[k] = new Intl.DateTimeFormat("en-US", o); } catch (e) { formatters[k] = null; }
    }
    return formatters[k];
  }
  function us(unix, form, zone) {
    var d = new Date(Number(unix) * 1000);
    if (isNaN(d.getTime())) return "";
    var key = Object.prototype.hasOwnProperty.call(FORMS, form) ? form : "full";
    var f = formatter(key, zone);
    // Newer browsers put a narrow no-break space before AM/PM.
    return (f ? f.format(d) : d.toLocaleString("en-US")).replace(/[  ]/g, " ");
  }
  function localTime(unix, form) { return us(unix, form); }
  // "Oct 9, 2026, 9:29 PM UTC".
  function utcTime(unix, form) {
    var s = us(unix, form, "UTC");
    return s && form !== "date" && form !== "day" ? s + " UTC" : s;
  }
  // "Oct 22, 2026": a YYYY-MM-DD date as typed (never moved by the time
  // zone), or the local day of an RFC 3339 time (as
  // pathwarden_core::time::day_of); anything else as written.
  function dateOnly(text) {
    if (typeof text !== "string" || !/^\d{4}-\d{2}-\d{2}/.test(text)) return text == null ? "" : String(text);
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
    var d = m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])) : new Date(text);
    if (isNaN(d.getTime())) return text;
    return us(d.getTime() / 1000, "date", m ? "UTC" : undefined);
  }
  // Local times in `root` (the page, or HTML a script just put in).
  function localize(root) {
    root.querySelectorAll("[data-unix]").forEach(function (t) {
      var unix = t.getAttribute("data-unix");
      var text = localTime(unix, t.getAttribute("data-fmt"));
      if (!text) return;
      if (t.tagName === "TIME") {
        t.setAttribute("datetime", new Date(Number(unix) * 1000).toISOString());
        t.title = utcTime(unix);
      }
      t.textContent = text;
    });
  }
  window.PathwardenTime = { local: localTime, utc: utcTime, date: dateOnly, apply: localize };
  localize(document);

  // -------------------------------------------------------------- Menus
  // A <details class="menu"> closes on a click elsewhere, or on Escape.
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.menu[open]").forEach(function (m) {
      if (!m.contains(e.target)) m.open = false;
    });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    document.querySelectorAll("details.menu[open]").forEach(function (m) {
      m.open = false;
      var s = m.querySelector("summary");
      if (s) s.focus();
    });
  });

  // On a narrow screen the rail is a strip that scrolls sideways: bring the
  // current page's entry into view.
  var currentNav = document.querySelector('.rail .tablist a[aria-current="page"]');
  if (currentNav && currentNav.parentNode.scrollWidth > currentNav.parentNode.clientWidth) {
    var strip = currentNav.parentNode;
    var a = currentNav.getBoundingClientRect(), s = strip.getBoundingClientRect();
    strip.scrollLeft += a.left - s.left - (strip.clientWidth - a.width) / 2;
  }

  // ----------------------------------------------------------------- Demo
  document.querySelectorAll("[data-demo]").forEach(function (b) {
    b.addEventListener("click", function () {
      b.disabled = true;
      fetch("/api/demo", { method: "POST", credentials: "same-origin" })
        .then(function (r) {
          return r.text().then(function (text) { return { ok: r.ok, text: text }; });
        })
        .then(function (r) {
          if (!r.ok) throw new Error(errorText(r.text, "Couldn't start the demo."));
          location.href = "/analyze?job=" + encodeURIComponent(JSON.parse(r.text).job);
        })
        .catch(function (e) { b.disabled = false; toast(e.message || "Couldn't start the demo."); });
    });
  });

  // ---------------------------------------- Accept the history as it is
  // Older copies refused after a restore made on purpose: the
  // dialog says what accepting does; accepting resets this computer's
  // records for the history and reloads, so the server's page says how
  // the history reads now.
  var acceptDialog = $("accept-history-dialog");
  document.querySelectorAll("[data-accept-history]").forEach(function (b) {
    var status = b.parentNode.querySelector(".save-status");
    function go() {
      b.disabled = true;
      if (status) { status.textContent = ""; status.className = "save-status small"; }
      // The page's environment: a page left open after a switch in
      // another tab is refused.
      fetch("/api/history/accept", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ env: b.getAttribute("data-accept-history") || "" })
      })
        .then(function (r) {
          if (r.ok) { location.reload(); return; }
          return r.text().then(function (t) { throw new Error(errorText(t, "Couldn't accept the history.")); });
        })
        .catch(function (e) {
          b.disabled = false;
          if (status) { status.textContent = e.message; status.className = "save-status small err"; }
          else toast(e.message);
        });
    }
    b.addEventListener("click", function () {
      if (acceptDialog && acceptDialog.showModal) {
        acceptDialog.returnValue = "";
        acceptDialog.showModal();
        acceptDialog.addEventListener("close", function onClose() {
          acceptDialog.removeEventListener("close", onClose);
          if (acceptDialog.returnValue === "accept") go();
        });
      } else if (confirm("Accept the history as it is? This computer's records of it are reset.")) {
        go();
      }
    });
  });

  // -------------------------------------------------------- Delete a run
  var dialog = $("confirm-delete");
  document.querySelectorAll("[data-delete]").forEach(function (b) {
    b.addEventListener("click", function () {
      var id = b.getAttribute("data-delete");
      // The dialog's own words: Delete, Remove from the history or Hide.
      var head = dialog && dialog.querySelector("h2");
      var ask = head ? head.textContent : "Delete this run? This can't be undone.";
      var goWords = ($("confirm-delete-go") || b).textContent || "";
      var verb = /hide/i.test(goWords) ? "hide" : /remove/i.test(goWords) ? "remove" : "delete";
      function go() {
        fetch("/api/runs/" + encodeURIComponent(id), { method: "DELETE", credentials: "same-origin" })
          .then(function (r) {
            if (r.status === 204 || r.status === 404) { location.href = "/runs"; return; }
            // Deleted, with something about the history to read: shown on
            // the Runs page it goes to.
            if (r.status === 200) {
              return r.json().then(function (j) {
                try { if (j && j.note) sessionStorage.setItem("pw-note", j.note); } catch (e) {}
                location.href = "/runs";
              });
            }
            return r.text().then(function (t) { throw new Error(errorText(t, "Couldn't " + verb + " the run.")); });
          })
          .catch(function (e) { toast(e.message); });
      }
      if (dialog && dialog.showModal) {
        dialog.returnValue = "";
        dialog.showModal();
        dialog.addEventListener("close", function onClose() {
          dialog.removeEventListener("close", onClose);
          if (dialog.returnValue === "delete") go();
        });
      } else if (confirm(ask)) {
        go();
      }
    });
  });

  // ------------------------------------------------------- Inline editors
  // A run's label (Runs list, run page) and an environment's name
  // (Environments): the button opens a small form in place; saving posts it
  // and reloads, so the server's page is the one truth.
  function inline(openSel, formSel, cancelSel, scopeSel) {
    document.querySelectorAll(openSel).forEach(function (b) {
      var scope = b.closest(scopeSel);
      var f = scope && scope.querySelector(formSel);
      if (!f) return;
      var shown = [];
      function close() {
        f.hidden = true;
        shown.forEach(function (el) { el.hidden = false; });
        shown = [];
        scope.classList.remove("editing");
        b.focus();
      }
      b.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        // Hide what the form replaces: the title and the button before it.
        for (var el = f.previousElementSibling; el; el = el.previousElementSibling) {
          if (!el.hidden) { el.hidden = true; shown.push(el); }
        }
        f.hidden = false;
        scope.classList.add("editing");
        var input = f.querySelector("input[type=text]");
        if (input) { input.focus(); input.select(); }
      });
      var cancel = f.querySelector(cancelSel);
      if (cancel) cancel.addEventListener("click", close);
      f.addEventListener("keydown", function (e) { if (e.key === "Escape") { e.preventDefault(); close(); } });
      var saving = false;
      f.addEventListener("submit", function (e) {
        e.preventDefault();
        if (saving) return;
        saving = true;
        var body = new URLSearchParams(new FormData(f));
        var saveFails = f.hasAttribute("data-rename-form") ? "Couldn't save the name." : "Couldn't save the label.";
        fetch(f.action, {
          method: "POST", credentials: "same-origin", body: body,
          headers: { "Accept": "application/json" }
        })
          .then(function (r) {
            if (r.ok) { location.reload(); return; }
            return r.text().then(function (t) { throw new Error(errorText(t, saveFails)); });
          })
          .catch(function (err) { saving = false; toast(err.message); });
      });
    });
  }
  inline("[data-label-edit]", "form[data-label-form]", "[data-label-cancel]", ".runrow, .rh-title");
  inline("[data-rename]", "form[data-rename-form]", "[data-rename-cancel]", ".er-name");

  // New environment: "Connect to a run history" takes its name and
  // domains from the history, on the next page.
  document.querySelectorAll("form[data-env-new]").forEach(function (form) {
    var name = form.querySelector("input[name=name]");
    var sync = function () {
      var o = form.querySelector("input[name=origin]:checked");
      var connect = o && o.value === "connect";
      form.querySelectorAll("[data-when-origin]").forEach(function (el) {
        el.hidden = (el.getAttribute("data-when-origin") === "connect") !== connect;
      });
      if (name) name.required = !connect;
    };
    form.querySelectorAll("input[name=origin]").forEach(function (r) { r.addEventListener("change", sync); });
    sync();
  });

  // ------------------------------------------------------ Where it goes
  // The Saving-to line, the question and the environment cards on Collect
  // and Analyze (env_where.rs renders them): "change" opens the cards, and
  // choice() says what to send with the run.
  window.PathwardenWhere = function (box, onChange) {
    var initial = box.innerHTML;
    var appliesBox = $("an-applies");
    var initialApplies = appliesBox ? appliesBox.innerHTML : "";
    // Each load gets a number; a response to an older one is dropped.
    var seq = 0;
    function changed() { if (onChange) onChange(); }
    // The answer shown so far (the block, the Found in these files box,
    // the settings line) dims and is marked busy for assistive technology
    // until the new one replaces it (ui.css).
    var foundBox = null;
    function busy(on, found) {
      if (found) foundBox = found;
      if (on) box.setAttribute("data-state", "loading");
      [box, foundBox, appliesBox].forEach(function (el) {
        if (!el) return;
        if (on) el.setAttribute("aria-busy", "true");
        else el.removeAttribute("aria-busy");
      });
    }
    function wire() {
      var open = box.querySelector("[data-ew-change]");
      var cards = box.querySelector("#ew-cards");
      if (open && cards) {
        open.addEventListener("click", function () {
          box.setAttribute("data-changed", "1");
          ["ew-line", "ew-hint"].forEach(function (id) {
            var el = box.querySelector("#" + id);
            if (el) el.hidden = true;
          });
          cards.hidden = false;
          var picked = cards.querySelector("input[name=ew-pick]:checked") || cards.querySelector("input[name=ew-pick]");
          if (picked) picked.focus();
          changed();
        });
      }
      box.querySelectorAll("input[name=ew-pick]").forEach(function (r) { r.addEventListener("change", changed); });
      box.querySelectorAll("input[name=ew-name]").forEach(function (n) {
        n.addEventListener("input", function () {
          var radio = n.closest("label").querySelector("input[name=ew-pick]");
          if (radio && !radio.checked) radio.checked = true;
          changed();
        });
      });
    }
    wire();
    return {
      // What the run carries: {env}, {new_env}, with env_auto when the page
      // chose by itself; {} to let the data decide; null while a choice is
      // needed.
      choice: function () {
        var state = box.getAttribute("data-state");
        var cards = box.querySelector("#ew-cards");
        var open = cards && !cards.hidden;
        if (state === "loading") return null;
        if (!open && (state === "unknown" || state === "current")) return {};
        var picked = box.querySelector("input[name=ew-pick]:checked");
        if (!picked) return open ? null : {};
        // Cards open: the user's pick; closed: the page's own choice.
        var auto = open ? "0" : "1";
        if (picked.value === "new") {
          var name = picked.closest("label").querySelector("input[name=ew-name]");
          var v = name ? name.value.trim() : "";
          return v ? { new_env: v, env_auto: auto } : null;
        }
        return { env: picked.value.replace(/^env:/, ""), env_auto: auto };
      },
      // Renders the block for the domains in `data` (FormData: domain,
      // path or domains fields); `found` gets the Found in these files box.
      load: function (data, found) {
        var mine = ++seq;
        busy(true, found);
        box.removeAttribute("data-changed");
        changed();
        return fetch("/api/analyze/where", { method: "POST", credentials: "same-origin", body: data })
          .then(function (r) {
            return r.text().then(function (t) {
              var j = null;
              try { j = JSON.parse(t); } catch (e) {}
              if (!r.ok || !j) throw new Error((j && j.error) || "Couldn't read the domains.");
              return j;
            });
          })
          .then(function (j) {
            if (mine !== seq) return j;
            busy(false);
            box.innerHTML = j.html || "";
            box.setAttribute("data-state", j.state || "unknown");
            localize(box);
            if (found) found.innerHTML = j.found || "";
            // The settings line follows where the run goes.
            if (appliesBox && j.applies) appliesBox.innerHTML = j.applies;
            var instead = $("label-instead");
            if (instead) instead.textContent = j.computed || "the domain name";
            wire();
            changed();
            return j;
          })
          .catch(function (e) {
            if (mine !== seq) return;
            busy(false);
            box.innerHTML = initial;
            box.setAttribute("data-state", "unknown");
            wire();
            changed();
            toast(e.message);
          });
      },
      // Marks the answer shown as stale before a load starts (the domains
      // are still being read here).
      busy: function (found) { busy(true, found); },
      reset: function (found) {
        seq++;
        busy(false, found);
        box.innerHTML = initial;
        if (appliesBox) appliesBox.innerHTML = initialApplies;
        box.setAttribute("data-state", "unknown");
        box.removeAttribute("data-changed");
        if (found) found.innerHTML = "";
        var instead = $("label-instead");
        if (instead) instead.textContent = "the domain name";
        wire();
        changed();
      }
    };
  };

  // The collector's domains files in a chosen .zip, read in the browser
  // (central directory, then each entry; deflate with DecompressionStream):
  // a Promise of Blobs, empty when they can't be read (a ZIP64 archive, an
  // old browser). Only these small files are read, never the rest, and an
  // entry larger than DOMAINS_MAX is skipped whatever its header says:
  // inflating stops there. (tests/js/app.test.mjs runs it with Node.)
  var DOMAINS_MAX = 8 * 1024 * 1024; // same limit as the server (env_where.rs)
  function zipDomains(file) {
    var u16 = function (v, o) { return v.getUint16(o, true); };
    var u32 = function (v, o) { return v.getUint32(o, true); };
    var tailLen = Math.min(file.size, 65557);
    return file.slice(file.size - tailLen).arrayBuffer().then(function (buf) {
      var v = new DataView(buf);
      var at = -1;
      for (var i = buf.byteLength - 22; i >= 0; i--) {
        if (u32(v, i) === 0x06054b50) { at = i; break; }
      }
      if (at < 0) return [];
      var cdSize = u32(v, at + 12), cdOff = u32(v, at + 16);
      if (cdOff === 0xffffffff || cdSize === 0xffffffff || cdOff + cdSize > file.size) return [];
      return file.slice(cdOff, cdOff + cdSize).arrayBuffer().then(function (cd) {
        var c = new DataView(cd), p = 0, wanted = [];
        while (p + 46 <= cd.byteLength && u32(c, p) === 0x02014b50 && wanted.length < 16) {
          var method = u16(c, p + 10), csize = u32(c, p + 20), usize = u32(c, p + 24);
          var nlen = u16(c, p + 28), elen = u16(c, p + 30), clen = u16(c, p + 32), off = u32(c, p + 42);
          var name = new TextDecoder().decode(new Uint8Array(cd, p + 46, nlen));
          if (/domains\.json$/i.test(name) && usize <= DOMAINS_MAX && (method === 0 || method === 8)) {
            wanted.push({ method: method, csize: csize, off: off });
          }
          p += 46 + nlen + elen + clen;
        }
        return Promise.all(wanted.map(function (w) {
          return file.slice(w.off, w.off + 30).arrayBuffer().then(function (h) {
            var hv = new DataView(h);
            if (u32(hv, 0) !== 0x04034b50) return null;
            var start = w.off + 30 + u16(hv, 26) + u16(hv, 28);
            var data = file.slice(start, start + w.csize);
            if (w.method === 0) return data.size <= DOMAINS_MAX ? data : null;
            if (typeof DecompressionStream === "undefined") return null;
            var reader = data.stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
            var parts = [], total = 0;
            var more = function () {
              return reader.read().then(function (r) {
                if (r.done) return new Blob(parts);
                total += r.value.length;
                if (total > DOMAINS_MAX) { reader.cancel().catch(function () {}); return null; }
                parts.push(r.value);
                return more();
              });
            };
            return more();
          }).catch(function () { return null; });
        }));
      });
    }).then(function (list) { return (list || []).filter(Boolean); })
      .catch(function () { return []; });
  }
  window.PathwardenZipDomains = zipDomains;

  // ---- PathwardenFiles
  // Collector files chosen in the browser, on Analyze and in the Collect
  // page's "Add other data": which are taken (.zip and
  // .json, each once), the files of a dropped folder, a row of the list,
  // and what each file is (the server reads its two ends,
  // /api/opengraph/sniff). (tests/js/app.test.mjs runs take and dropped.)
  var PathwardenFiles = (function () {
    var COLLECTOR = /\.(zip|json)$/i;
    var MAX_FOUND = 2000; // most files taken out of dropped folders
    var PEEK = 65536;

    function size(n) {
      if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GB";
      if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MB";
      return Math.max(1, Math.round(n / 1024)) + " KB";
    }

    // Adds `files` to `chosen` (each once, by name and size): the names of
    // those that aren't .zip or .json.
    function take(files, chosen) {
      var rejected = [];
      Array.prototype.forEach.call(files || [], function (f) {
        if (!COLLECTOR.test(f.name)) { rejected.push(f.name); return; }
        if (!chosen.some(function (c) { return c.name === f.name && c.size === f.size; })) chosen.push(f);
      });
      return rejected;
    }

    // What was dropped (a DataTransfer), as a Promise of Files: files as
    // they are, and the .zip and .json files in a dropped folder and its
    // folders. Read here, in the drop event: its items go stale after.
    function dropped(dt) {
      var items = dt && dt.items ? Array.prototype.slice.call(dt.items) : [];
      var entries = items.map(function (it) {
        return it.kind === "file" && it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
      });
      if (!entries.some(function (e) { return e && e.isDirectory; })) {
        return Promise.resolve(Array.prototype.slice.call((dt && dt.files) || []));
      }
      var plain = items.map(function (it, i) { return entries[i] ? null : (it.getAsFile ? it.getAsFile() : null); });
      var found = [];
      function file(entry) {
        return new Promise(function (done) {
          entry.file(function (f) { found.push(f); done(); }, function () { done(); });
        });
      }
      function children(dir) {
        var reader = dir.createReader(), all = [];
        return new Promise(function (done) {
          (function more() {
            reader.readEntries(function (batch) {
              if (!batch.length) { done(all); return; }
              all = all.concat(Array.prototype.slice.call(batch));
              more();
            }, function () { done(all); });
          })();
        });
      }
      function walk(entry, inFolder) {
        if (!entry || found.length >= MAX_FOUND) return Promise.resolve();
        if (entry.isDirectory) {
          return children(entry).then(function (list) {
            return list.reduce(function (p, c) { return p.then(function () { return walk(c, true); }); }, Promise.resolve());
          });
        }
        // In a folder, only collector files; a file dropped by itself is
        // taken (or refused) as chosen.
        if (inFolder && !COLLECTOR.test(entry.name)) return Promise.resolve();
        return file(entry);
      }
      return entries.reduce(function (p, e, i) {
        return p.then(function () {
          if (e) return walk(e, false);
          if (plain[i]) found.push(plain[i]);
        });
      }, Promise.resolve()).then(function () { return found; });
    }

    // A row of the list: the file's name, what it is (when known), its
    // size, and a button that removes it.
    function row(f, kind, remove) {
      var li = document.createElement("li");
      li.className = "card";
      var ic = document.createElement("span");
      ic.innerHTML = '<svg class="ic" aria-hidden="true"><use href="#i-file"/></svg>';
      li.appendChild(ic.firstChild);
      var name = document.createElement("span");
      name.className = "fl-name";
      name.textContent = f.name;
      li.appendChild(name);
      if (kind !== undefined) {
        var k = document.createElement("span");
        k.className = "fl-kind";
        k.textContent = kind || "";
        li.appendChild(k);
      }
      var s = document.createElement("span");
      s.className = "muted small";
      s.textContent = size(f.size);
      li.appendChild(s);
      var x = document.createElement("button");
      x.type = "button";
      x.className = "fl-remove";
      x.setAttribute("aria-label", "Remove " + f.name);
      x.innerHTML = '<svg class="ic" aria-hidden="true"><use href="#i-x"/></svg>';
      x.addEventListener("click", remove);
      li.appendChild(x);
      return li;
    }

    // What each file is ("AzureHound: Entra ID", "OpenGraph: TaskHound",
    // "SharpHound"), from its first and last 64 KiB: a Promise of the
    // words, in order ("" where it can't be told).
    function kinds(files) {
      var some = files.slice(0, 40);
      return Promise.all(some.map(function (f) {
        if (!/\.json$/i.test(f.name)) return { name: f.name, size: f.size, head: "", tail: "" };
        return Promise.all([f.slice(0, PEEK).text(), f.slice(Math.max(0, f.size - PEEK)).text()])
          .then(function (ends) { return { name: f.name, size: f.size, head: ends[0], tail: ends[1] }; });
      })).then(function (list) {
        return fetch("/api/opengraph/sniff", {
          method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json" }, body: JSON.stringify({ files: list })
        });
      }).then(function (r) { return r.ok ? r.json() : {}; })
        .then(function (d) {
          var k = Array.isArray(d.kinds) ? d.kinds : [];
          return files.map(function (f, i) { return typeof k[i] === "string" ? k[i] : ""; });
        }, function () { return files.map(function () { return ""; }); });
    }

    return { size: size, take: take, dropped: dropped, row: row, kinds: kinds };
  })();
  window.PathwardenFiles = PathwardenFiles;
  // ---- end PathwardenFiles

  // -------------------------------------------------------------- Analyze
  var form = $("analyze-form");
  var progress = $("progress");
  if (!form || !progress) return;

  var input = $("files");
  var drop = $("dropzone");
  var list = $("filelist");
  var path = $("path");
  var start = $("start");
  var hint = $("start-hint");
  var chosen = [];
  // Add files and analyze again: a run's kept collection goes
  // first, named by the run; its domains say where the new run goes.
  var fromList = $("from-list");
  var fromId = fromList ? fromList.getAttribute("data-from") || "" : "";
  var fromDomains = [];
  try { fromDomains = fromList ? JSON.parse(fromList.getAttribute("data-domains") || "[]") : []; } catch (e) {}

  var size = PathwardenFiles.size;

  function refresh() {
    list.innerHTML = "";
    chosen.forEach(function (f, i) {
      list.appendChild(PathwardenFiles.row(f, undefined, function () { chosen.splice(i, 1); refresh(); }));
    });
    list.hidden = chosen.length === 0;
    // The Detected sources panel (opengraph.js) looks at the chosen files.
    document.dispatchEvent(new CustomEvent("pw:files", { detail: chosen.slice() }));
    readDomains();
    updateStart();
  }

  function updateStart() {
    var ready = chosen.length > 0 || path.value.trim() !== "" || picked().length > 0;
    var placed = !where || where.choice() !== null;
    start.disabled = !ready || !placed;
    var loading = where && $("ew").getAttribute("data-state") === "loading";
    hint.textContent = !ready && fromId ? "Add files to analyze with the collection."
      : !ready ? "Choose files or enter a path to begin."
      : loading ? "Reading the domains…"
      : !placed ? "Choose an environment to begin."
      : (chosen.length ? chosen.length + (chosen.length === 1 ? " file" : " files") + ", " +
          size(chosen.reduce(function (a, f) { return a + f.size; }, 0))
        : picked().length > 1 ? picked().length + " files and folders" : "Ready.");
  }

  // Where the run goes, from the domains files in what was chosen (read
  // here from a .zip, or by the server for a path on this computer).
  var where = $("ew") ? window.PathwardenWhere($("ew"), function () { updateStart(); }) : null;
  var whereSeq = 0, whereTimer = null;
  function readDomains() {
    if (!where) return;
    clearTimeout(whereTimer);
    // Start waits until the domains of what is chosen now are read.
    if (chosen.length || path.value.trim() || picked().length || fromId) {
      where.busy($("ew-found"));
    }
    whereTimer = setTimeout(function () {
      var mine = ++whereSeq;
      var paths = picked().slice();
      if (path.value.trim()) paths.push(path.value.trim());
      if (!chosen.length && !paths.length && !fromId) { where.reset($("ew-found")); return; }
      Promise.all(chosen.map(function (f) {
        if (/\.zip$/i.test(f.name)) return zipDomains(f);
        if (/domains\.json$/i.test(f.name) && f.size <= DOMAINS_MAX) return [f];
        return [];
      })).then(function (lists) {
        if (mine !== whereSeq) return;
        var fd = new FormData();
        fromDomains.forEach(function (d) { if (typeof d === "string") fd.append("domain", d); });
        lists.forEach(function (l) { l.forEach(function (b) { fd.append("domains", b, "domains.json"); }); });
        paths.forEach(function (p) { fd.append("path", p); });
        if (chosen.length) fd.append("files", "1");
        where.load(fd, $("ew-found"));
      });
    }, 350);
  }

  // Files and folders picked or dropped in the desktop window (its
  // desktop.js sets window.pwPaths): analyzed where they are, by path.
  function picked() {
    var p = window.pwPaths ? window.pwPaths() : [];
    return Array.isArray(p) ? p : [];
  }

  function add(files) {
    var rejected = PathwardenFiles.take(files, chosen);
    if (rejected.length) toast("Only .zip and .json files can be analyzed: " + rejected.join(", "));
    refresh();
  }

  input.addEventListener("change", function () { add(input.files); input.value = ""; });
  path.addEventListener("input", refresh);
  ["dragenter", "dragover"].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (e) { if (e.dataTransfer) PathwardenFiles.dropped(e.dataTransfer).then(add); });
  // Dropping outside the zone must not open the file in the browser.
  window.addEventListener("dragover", function (e) { e.preventDefault(); });
  window.addEventListener("drop", function (e) { e.preventDefault(); });

  // Progress
  var order = ["upload", "reading", "graph", "rules", "earlier", "remediation", "report"];
  var steps = {};
  document.querySelectorAll("#steps li").forEach(function (li) { steps[li.getAttribute("data-step")] = li; });
  var startedAt = Date.now();
  var clock = null;

  function mark(current, uploading) {
    var reached = false;
    order.forEach(function (name) {
      var li = steps[name];
      if (!li) return;
      if (name === "upload" && !uploading && li.hidden) return;
      if (name === "earlier" && li.hidden) return;
      li.className = name === current ? "active" : reached ? "" : "done";
      if (name === current) reached = true;
    });
  }

  function tick() {
    var s = Math.floor((Date.now() - startedAt) / 1000);
    $("elapsed").textContent = Math.floor(s / 60) + ":" + ("0" + (s % 60)).slice(-2);
  }

  function showProgress(source, uploading) {
    lastSource = source || "";
    form.hidden = true;
    $("failed").hidden = true;
    progress.hidden = false;
    $("progress-source").textContent = source || "";
    steps.upload.hidden = !uploading;
    $("upbar").hidden = !uploading;
    if (!clock) { tick(); clock = setInterval(tick, 1000); }
  }

  var lastSource = "";
  function fail(message) {
    clearInterval(clock); clock = null;
    progress.hidden = true;
    $("duplicate").hidden = true;
    $("ask-env").hidden = true;
    $("failed").hidden = false;
    $("failed-message").textContent = message;
    // What was being analyzed, unless the message already says.
    var src = $("failed-source");
    src.hidden = !lastSource || message.indexOf(lastSource) !== -1;
    src.textContent = "Source: " + lastSource;
    $("failed").scrollIntoView({ block: "nearest" });
  }

  $("retry").addEventListener("click", function () {
    $("failed").hidden = true;
    form.hidden = false;
    history.replaceState(null, "", fromId ? "/analyze?from=" + encodeURIComponent(fromId) : "/analyze");
    refresh();
  });

  function poll(job) {
    fetch("/api/jobs/" + encodeURIComponent(job), { credentials: "same-origin" })
      .then(function (r) {
        return r.text().then(function (t) { return { ok: r.ok, text: t }; });
      })
      .then(function (r) {
        if (!r.ok) throw new Error(errorText(r.text, "Can't get this analysis's progress. Reload the page to check on it."));
        handle(JSON.parse(r.text), job);
      }, function () { throw new Error(NOT_ANSWERING); })
      .catch(function (e) { fail(e.message || "Can't get this analysis's progress. Reload the page to check on it."); });
  }

  // The checklist follows the real phase, but steps one item at a time and
  // keeps each on screen for a moment: a small collection is analyzed in a
  // fraction of a second, and the steps should still be seen ticking off.
  // Large analyses are never slowed down; the display only catches up.
  var STEP_MS = 420;
  // "earlier": the demo's earlier runs, shown only while they are built.
  var phases = ["reading", "graph", "rules", "earlier", "remediation", "report"];
  var shown = -1, target = 0, lastStep = 0, finishedUrl = null, pacer = null;

  function pace() {
    if (pacer) return;
    pacer = setInterval(function () {
      var limit = finishedUrl ? phases.length : target;
      if (shown < limit && Date.now() - lastStep >= STEP_MS) {
        shown++;
        if (phases[shown] === "earlier" && steps.earlier.hidden) shown++;
        lastStep = Date.now();
        mark(phases[shown] || null, false);
      }
      if (finishedUrl && shown >= phases.length) {
        clearInterval(pacer);
        setTimeout(function () { location.href = finishedUrl; }, 450);
      }
    }, 50);
  }

  // The demo's earlier runs recorded so far: the line shows once they are
  // being built, and is the step while they are.
  var earlierDone = 0;
  function earlier(j) {
    if (!j.earlier) return;
    steps.earlier.hidden = false;
    earlierDone = Math.max(earlierDone, j.earlier.done);
    $("earlier-n").textContent = earlierDone + " of " + j.earlier.total;
    var at = phases.indexOf("earlier");
    if (j.status === "running" && at > target) target = at;
  }

  function handle(j, job) {
    earlier(j);
    if (j.status === "running") {
      // Bytes of collector data read, while reading.
      $("read-pct").textContent = j.phase === "reading" && j.reading && j.reading.total
        ? Math.floor(100 * j.reading.read / j.reading.total) + "% · " + size(j.reading.read) + " of " + size(j.reading.total)
        : "";
      var at = phases.indexOf(j.phase);
      if (at > target) target = at;
      pace();
      setTimeout(function () { poll(job); }, 300);
    } else if (j.status === "done") {
      $("read-pct").textContent = "";
      finishedUrl = "/runs/" + encodeURIComponent(j.run);
      pace();
    } else if (j.status === "collecting") {
      // A collection (Collect wizard) shows its progress there.
      location.href = "/collect?job=" + encodeURIComponent(job);
    } else if (j.status === "stopped") {
      clearInterval(pacer);
      fail("Stopped before the analysis finished.");
    } else if (j.status === "duplicate") {
      clearInterval(pacer); pacer = null;
      duplicate(j, job);
    } else if (j.status === "ask") {
      clearInterval(pacer); pacer = null;
      ask(j, job);
    } else {
      clearInterval(pacer);
      fail(j.error || "The analysis failed. See Settings › Logs, then try again.");
    }
  }

  // Something's off with the environment (the data's domains match two
  // environments, or one only partly): nothing was saved; the user picks,
  // and the same files are analyzed into that one.
  var askWhere = $("ask-where") ? window.PathwardenWhere($("ask-where"), function () {
    var c = askWhere ? askWhere.choice() : null;
    $("ask-go").disabled = !c || (!c.env && !c.new_env);
  }) : null;
  function ask(j, job) {
    clearInterval(clock); clock = null;
    progress.hidden = true;
    var fd = new FormData();
    (j.domains || []).forEach(function (d) { fd.append("domain", d); });
    askWhere.load(fd, null);
    $("ask-env").hidden = false;
    $("ask-env").scrollIntoView({ block: "nearest" });
    // Discard: nothing is saved, and the waiting files are deleted.
    $("ask-discard").onclick = function () {
      fetch("/api/jobs/" + encodeURIComponent(job) + "/discard", { method: "POST", credentials: "same-origin" })
        .then(function () { location.href = "/analyze"; })
        .catch(function () { location.href = "/analyze"; });
    };
    $("ask-go").onclick = function () {
      var c = askWhere.choice();
      if (!c || (!c.env && !c.new_env)) return;
      $("ask-go").disabled = true;
      fetch("/api/jobs/" + encodeURIComponent(job) + "/place", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ env: c.env || null, new_env: c.new_env || null })
      })
        .then(function (r) { return r.text().then(function (t) { return { ok: r.status === 202, text: t }; }); })
        .then(function (r) {
          if (!r.ok) throw new Error(errorText(r.text, "Couldn't save the run. Reload the page and try again."));
          $("ask-env").hidden = true;
          shown = -1; target = 0; finishedUrl = null;
          startedAt = Date.now();
          showProgress(lastSource, false);
          mark("reading", false);
          poll(job);
        })
        .catch(function (e) { $("ask-go").disabled = false; toast(e.message); });
    };
  }

  // The same collection as an earlier run: nothing was saved; open that run,
  // or analyze anyway.
  function duplicate(j, job) {
    clearInterval(clock); clock = null;
    progress.hidden = true;
    var when = localTime(j.at);
    $("duplicate-message").textContent = "Same data as " + j.what + " from " + when +
      ". A new run would add nothing.";
    var open = $("duplicate-open");
    open.href = j.run ? "/runs/" + encodeURIComponent(j.run) : "/runs";
    open.onclick = function () {
      fetch("/api/jobs/" + encodeURIComponent(job) + "/discard", { method: "POST", credentials: "same-origin", keepalive: true });
    };
    $("duplicate-anyway").onclick = function () {
      $("duplicate-anyway").disabled = true;
      fetch("/api/jobs/" + encodeURIComponent(job) + "/anyway", { method: "POST", credentials: "same-origin" })
        .then(function (r) { return r.text().then(function (t) { return { ok: r.status === 202, text: t }; }); })
        .then(function (r) {
          $("duplicate-anyway").disabled = false;
          if (!r.ok) throw new Error(errorText(r.text, "Couldn't start the analysis."));
          $("duplicate").hidden = true;
          shown = -1; target = 0; finishedUrl = null;
          startedAt = Date.now();
          showProgress($("progress-source").textContent, false);
          mark("reading", false);
          poll(job);
        })
        .catch(function (e) { $("duplicate-anyway").disabled = false; toast(e.message); });
    };
    $("duplicate").hidden = false;
    $("duplicate").scrollIntoView({ block: "nearest" });
  }

  // Resuming a job (from Home, the demo button, or a reload).
  var existing = progress.getAttribute("data-job");
  if (existing) {
    var initial = {};
    try { initial = JSON.parse(progress.getAttribute("data-initial") || "{}"); } catch (e) {}
    if (initial.status === "done" && initial.run) {
      // Finished before this page was opened (a reload, or the link
      // again): its run at once, not the steps ticking off.
      location.replace("/runs/" + encodeURIComponent(initial.run));
    } else {
      if (initial.started_at) startedAt = initial.started_at * 1000;
      showProgress(initial.source, false);
      if (initial.status) handle(initial, existing); else poll(existing);
    }
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (start.disabled) return;
    var data = new FormData();
    // Coverage declared for uploaded OpenGraph files (opengraph.js).
    var coverage = window.pwCoverage ? window.pwCoverage() : "";
    if (coverage === false) return;
    if (coverage) data.append("coverage", coverage);
    // A run's kept collection, by the run.
    if (fromId) data.append("from", fromId);
    chosen.forEach(function (f) { data.append("files", f, f.name); });
    var paths = picked().slice();
    if (path.value.trim()) paths.push(path.value.trim());
    paths.forEach(function (p) { data.append("path", p); });
    // Where the run goes (env, new_env, env_auto), and its label.
    var placed = where ? where.choice() : {};
    if (placed === null) return;
    Object.keys(placed).forEach(function (k) { data.append(k, placed[k]); });
    var label = $("run-label");
    if (label && label.value.trim()) data.append("label", label.value.trim());
    var source = chosen.length === 1 ? chosen[0].name
      : chosen.length ? chosen.length + " files"
      : paths.length > 1 ? paths[0] + " and " + (paths.length - 1) + " more" : paths[0] || "";
    if (fromId) source = fromList.getAttribute("data-name") + (source ? ", with " + source : "");
    var uploading = chosen.length > 0;
    startedAt = Date.now();
    showProgress(source, uploading);
    mark(uploading ? "upload" : "reading", uploading);

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/analyze");
    xhr.upload.addEventListener("progress", function (ev) {
      if (!ev.lengthComputable) return;
      var p = Math.round(100 * ev.loaded / ev.total);
      $("upload-pct").textContent = p + "%";
      $("upbar-fill").style.width = p + "%";
    });
    xhr.addEventListener("load", function () {
      $("upbar").hidden = true;
      if (xhr.status !== 202) {
        fail(errorText(xhr.responseText, "The upload failed. Try again."));
        return;
      }
      var job = JSON.parse(xhr.responseText).job;
      mark("reading", uploading);
      try { history.replaceState(null, "", "/analyze?job=" + encodeURIComponent(job)); } catch (e2) {}
      poll(job);
    });
    xhr.addEventListener("error", function () { fail(NOT_ANSWERING); });
    xhr.send(data);
  });

  refresh();
})();

// Definitions behind (i) in the app's own panels (the report has its own):
// shown on hover and focus by the stylesheet; a tap keeps one open until
// the next tap elsewhere or Escape, nudged to stay inside its row or card,
// and inside the window.
// A copy of the tip code in pathwarden-core's report/report.js, which the
// report inlines (it is one file, and its script's hash identifies it to
// Retest): a change to one belongs in the other.
(function () {
  "use strict";
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
  ["mouseover", "focusin"].forEach(function (type) {
    document.addEventListener(type, function (e) {
      var tip = e.target.closest && e.target.closest(".tip");
      if (tip) place(tip);
    });
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

  // ------------------------------------------------- the history's news
  // The app pulls a git history while it is open (auto_pull.rs). Every 30
  // seconds, while the tab is shown, the page asks what the pulls since it
  // was loaded brought: the footer's status is refreshed in place, and a
  // page the change affects shows a note with Reload. The page never
  // reloads itself. The server's HTML is escaped there. In a function of
  // its own: its names never touch the rest of this file's.
  (function () {
  function $(id) { return document.getElementById(id); }
  var body = document.body;
  var since = Number(body.getAttribute("data-pulled"));
  if (body.classList.contains("app") && isFinite(since)) {
    var page = body.getAttribute("data-page") || "";
    var run = /^\/runs\/([A-Za-z0-9_-]+)$/.exec(location.pathname);
    if (run) page = "run";
    var shown = null;
    var closed = null;
    var editing = function () { return !!document.querySelector("[data-section].is-dirty"); };
    var fromHtml = function (html) {
      var t = document.createElement("template");
      t.innerHTML = html;
      return t.content;
    };
    var setFoot = function (html) {
      var foot = document.querySelector(".rail-foot");
      if (!foot) return;
      foot.querySelectorAll(".pull-foot, .pull-btn").forEach(function (a) { a.remove(); });
      if (html) foot.insertBefore(fromHtml(html), foot.firstChild);
    };
    // The amber dot on Settings in the rail while settings differ from the
    // shared ones, as the last sync left them (the page draws it first),
    // or while a crash isn't dismissed: one dot for either.
    var setDot = function (differ, crash) {
      window.Pathwarden.settingsDot(differ, crash);
    };
    var setNote = function (html) {
      if (!html || html === closed) return;
      if (html === shown) return;
      var old = $("repo-note");
      if (old) old.remove();
      shown = html;
      body.appendChild(fromHtml(html));
      var n = $("repo-note");
      var reload = n.querySelector("[data-repo-reload]");
      if (reload) reload.addEventListener("click", function () {
        window.Pathwarden.leaving = true;
        location.reload();
      });
      n.querySelector("[data-repo-close]").addEventListener("click", function () {
        closed = html;
        shown = null;
        n.remove();
      });
    };
    var ask = function () {
      if (document.hidden) return;
      var q = "/api/history/pulled?since=" + since + "&page=" + encodeURIComponent(page) +
        "&env=" + encodeURIComponent(body.getAttribute("data-env") || "");
      if (run) q += "&run=" + encodeURIComponent(run[1]);
      if (editing()) q += "&editing=true";
      fetch(q, { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          if (!j) return;
          setFoot(j.foot);
          if (typeof j.differ === "boolean") setDot(j.differ, j.crash === true);
          setNote(j.note);
        }, function () {});
    };
    setInterval(ask, 30000);
    // A tab shown again asks at once (and the app pulls if one is due).
    document.addEventListener("visibilitychange", function () { if (!document.hidden) ask(); });
  }
  })();

  // ---- A wait shows: a click or form that hasn't changed the page
  // after WAIT ms gets a thin bar along the top; while the server reads a
  // run into memory, a line says so. Quick ones show nothing.
  (function () {
    var WAIT = 300, timer = null, poll = null, bar = null, pill = null;
    function start() {
      if (timer || bar) return;
      timer = setTimeout(show, WAIT);
    }
    function show() {
      timer = null;
      bar = document.createElement("div");
      bar.className = "pw-load";
      bar.setAttribute("role", "progressbar");
      bar.setAttribute("aria-label", "Loading");
      document.body.appendChild(bar);
      requestAnimationFrame(function () { requestAnimationFrame(function () { if (bar) bar.classList.add("go"); }); });
      check();
      poll = setInterval(check, 700);
    }
    function check() {
      fetch("/api/busy", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          if (!bar) return;
          if (j && j.loading_run) {
            if (!pill) {
              pill = document.createElement("div");
              pill.className = "pw-pill";
              pill.setAttribute("role", "status");
              var i = document.createElement("i");
              i.setAttribute("aria-hidden", "true");
              pill.appendChild(i);
              pill.appendChild(document.createTextNode("Opening this run…"));
              document.body.appendChild(pill);
            }
          } else if (pill) {
            pill.remove();
            pill = null;
          }
        }, function () {});
    }
    function stop() {
      clearTimeout(timer); timer = null;
      clearInterval(poll); poll = null;
      if (bar) { bar.remove(); bar = null; }
      if (pill) { pill.remove(); pill = null; }
    }
    // On window, so the page's own handlers have had their say: a click or
    // submit they handled (defaultPrevented) isn't a navigation.
    window.addEventListener("click", function (e) {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      var a = e.target && e.target.closest && e.target.closest("a[href]");
      if (!a || a.hasAttribute("download") || (a.target && a.target !== "_self")) return;
      var url;
      try { url = new URL(a.href, location.href); } catch (err) { return; }
      if (url.origin !== location.origin || !/^https?:$/.test(url.protocol)) return;
      // Only the hash changes: no page to wait for.
      if (url.pathname === location.pathname && url.search === location.search && url.hash) return;
      start();
    });
    window.addEventListener("submit", function (e) {
      if (e.defaultPrevented) return;
      var f = e.target;
      if (f && f.target && f.target !== "_self") return;
      // A dialog's own form only closes the dialog: no page comes.
      var sub = e.submitter;
      if ((f && (f.getAttribute("method") || "").toLowerCase() === "dialog") ||
          (sub && (sub.getAttribute("formmethod") || "").toLowerCase() === "dialog")) return;
      start();
    });
    // Back from the browser's page cache: nothing is loading.
    window.addEventListener("pageshow", function (e) { if (e.persisted) stop(); });
    window.Pathwarden = window.Pathwarden || {};
    window.Pathwarden.busy = { start: start, stop: stop };
  })();
})();
