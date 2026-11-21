// Pathwarden UI: the History storage page's actions (import earlier runs,
// keep them local only, Pull now). The form for
// where the history is kept is config.js's.
(function () {
  "use strict";

  function post(url, body) {
    var opts = { method: "POST", credentials: "same-origin", headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (text) {
        var j = null;
        try { j = text ? JSON.parse(text) : {}; } catch (e) {}
        if (!r.ok) throw new Error((j && j.error) || "Pathwarden couldn't do that. Try again; if it keeps failing, see Settings › Logs.");
        return j || {};
      });
    }, function () { throw new Error("Pathwarden isn't answering. Is it still running?"); });
  }

  // Where this environment's history lives: on this computer (the form,
  // kept in the environment's folder), connect to a run history (the
  // Connect page), or a shared one (the whole form).
  var state = document.getElementById("state");
  var origins = state ? state.querySelectorAll("input[name=hs-origin]") : [];
  if (origins.length) {
    var pick = function () {
      var o = state.querySelector("input[name=hs-origin]:checked");
      var v = o ? o.value : "local";
      state.querySelectorAll("[data-when-origin]").forEach(function (el) {
        var w = el.getAttribute("data-when-origin");
        el.hidden = w === "connect" ? v !== "connect" : w === "form" ? v === "connect" : v !== "shared";
      });
      if (v === "local") {
        // This environment's folder: the default place.
        var local = state.querySelector("input[name=backend][value=local]");
        if (local && !local.checked) { local.checked = true; local.dispatchEvent(new Event("change", { bubbles: true })); }
        var path = document.getElementById("state-path");
        if (path && path.value) { path.value = ""; path.dispatchEvent(new Event("input", { bubbles: true })); }
      }
    };
    origins.forEach(function (r) { r.addEventListener("change", pick); });
    pick();
  }

  // Start a new run history where one is already: Connect to it.
  window.pwShowFound = function (data) {
    var box = document.getElementById("hs-found");
    if (!box || !data || !data.connect) return false;
    box.innerHTML = "";
    var note = document.createElement("div");
    note.className = "note tips";
    note.setAttribute("role", "alert");
    note.innerHTML = '<svg class="ic" aria-hidden="true"><use href="#i-info"/></svg>';
    var body = document.createElement("div");
    var p = document.createElement("p");
    var strong = document.createElement("strong");
    strong.textContent = data.lead || "";
    p.appendChild(strong);
    p.appendChild(document.createTextNode(" " + (data.rest || "")));
    body.appendChild(p);
    var actions = document.createElement("div");
    actions.className = "enc-actions";
    var a = document.createElement("a");
    a.className = "btn small-btn primary";
    a.href = data.connect;
    a.textContent = "Connect to it";
    actions.appendChild(a);
    body.appendChild(actions);
    note.appendChild(body);
    box.appendChild(note);
    return true;
  };

  var busy = {
    "import": "Importing…",
    "keep-local": "Saving…",
    "refresh": "Syncing…",
    "sign-in": "Signing in…"
  };

  // This page's address with `signin` set to a Sign in's `token` (or taken off),
  // opened at In use.
  function signedUrl(token) {
    var q = new URLSearchParams(location.search);
    q.delete("signin");
    if (typeof token === "string" && /^[0-9a-f]{32}$/.test(token)) q.set("signin", token);
    var s = q.toString();
    return location.pathname + (s ? "?" + s : "") + "#in-use";
  }
  // Opens `u`, loading the page again even when only its #hash differs.
  function go(u) {
    if (u.split("#")[0] !== location.pathname + location.search) { location.href = u; return; }
    try { history.replaceState(history.state, "", u); } catch (e) {}
    location.reload();
  }

  document.querySelectorAll("[data-history-action]").forEach(function (b) {
    b.addEventListener("click", function () {
      var action = b.getAttribute("data-history-action");
      var section = b.closest("section");
      var status = section && section.querySelector(".save-status");
      var body;
      if (action === "keep-local") {
        body = { ids: (b.getAttribute("data-ids") || "").split(",").filter(Boolean) };
      }
      section.querySelectorAll("[data-history-action]").forEach(function (x) { x.disabled = true; });
      if (status) { status.textContent = busy[action] || ""; status.className = "save-status muted small"; }
      post("/api/history/" + action, body).then(function (j) {
        // Sign in: the page again, saying how it went (the server's words
        // for one of a few known outcomes).
        if (action === "sign-in") {
          go(signedUrl(j.token));
          return;
        }
        // Something the user should read first (runs an earlier failed
        // push left, a push that failed): kept on the page, not reloaded
        // away.
        if (j.note && status) {
          section.querySelectorAll("[data-history-action]").forEach(function (x) { x.disabled = false; });
          status.textContent = j.note + " Reload to see it.";
          status.className = "save-status small";
          return;
        }
        // Reloaded without an earlier Sign in's words.
        go(signedUrl(null));
      }, function (e) {
        section.querySelectorAll("[data-history-action]").forEach(function (x) { x.disabled = false; });
        if (status) { status.textContent = e.message; status.className = "save-status small err"; }
      });
    });
  });
})();
