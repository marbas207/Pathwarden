// Pathwarden UI: Connect to a run history. Step 1 looks at the
// repository or folder, step 2 opens it with its passphrase, step 3
// connects. A passphrase is sent once, to the local API, and the field is
// cleared; it never comes back from the server.
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  function post(url, body) {
    var opts = { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) };
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (text) {
        var j = null;
        try { j = text ? JSON.parse(text) : {}; } catch (e) {}
        if (!r.ok) {
          var err = new Error((j && j.error) || "Pathwarden didn't answer (" + r.status + "). Is it still running?");
          err.data = j || {};
          throw err;
        }
        return j || {};
      });
    }, function () { throw new Error("Pathwarden is not answering. Is it still running?"); });
  }

  // ------------------------------------------------ Step 1: where it is
  var where = $("cx-where");
  if (where) {
    var kind = function () { var k = where.querySelector("input[name=cx-kind]:checked"); return k ? k.value : "git"; };
    var show = function () {
      var k = kind();
      where.querySelectorAll("[data-when-kind]").forEach(function (f) { f.hidden = f.getAttribute("data-when-kind") !== k; });
    };
    where.querySelectorAll("input[name=cx-kind]").forEach(function (r) { r.addEventListener("change", show); });
    show();
    var look = $("cx-look"), msg = $("cx-msg"), quiet = where.querySelector(".cx-quiet");
    var quietText = quiet ? quiet.textContent : "";
    var go = function () {
      var body = { kind: kind(), env: where.getAttribute("data-env") || null };
      if (body.kind === "git") {
        body.url = $("cx-url").value.trim();
        body.branch = $("cx-branch").value.trim() || null;
        if (!body.url) { $("cx-url").focus(); return; }
      } else {
        body.folder = $("cx-folder").value.trim();
        if (!body.folder) { $("cx-folder").focus(); return; }
      }
      look.disabled = true;
      msg.innerHTML = "";
      if (quiet) quiet.textContent = "Looking at it…";
      post("/api/connect/probe", body).then(function (j) {
        location.href = "/environments/connect?s=" + encodeURIComponent(j.token);
      }, function (e) {
        look.disabled = false;
        if (quiet) quiet.textContent = quietText;
        if (e.data && e.data.note) { msg.innerHTML = e.data.note; }
        else {
          var p = document.createElement("p");
          p.className = "field-error";
          p.setAttribute("role", "alert");
          p.textContent = e.message;
          msg.appendChild(p);
        }
      });
    };
    look.addEventListener("click", go);
    // Sign in, on a note that the repository wanted one: looking again
    // lets git open its sign-in window.
    msg.addEventListener("click", function (e) {
      var b = e.target.closest && e.target.closest("[data-cx-sign-in]");
      if (!b) return;
      b.disabled = true;
      go();
    });
    ["cx-url", "cx-branch", "cx-folder"].forEach(function (id) {
      var f = $(id);
      if (f) f.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); go(); } });
    });
  }

  // "Change": back to step 1, filled in from this look (by its token); the
  // page removes its clone.
  document.querySelectorAll("[data-cx-change]").forEach(function (b) {
    var to = b.getAttribute("data-cx-change") || "";
    // Only back to step 1 of this page, never another address.
    if (!/^\/environments\/connect\?from=[A-Za-z0-9_-]+$/.test(to)) return;
    b.addEventListener("click", function () { location.href = to; });
  });

  // ------------------------------------------------ Step 2: the passphrase
  var gate = $("cx-gate");
  if (gate) {
    var input = $("cx-pass"), err = $("cx-pass-err"), open = $("cx-open");
    var fail = function (text) {
      err.querySelector("span").textContent = text;
      err.hidden = false;
      input.classList.add("bad");
      input.setAttribute("aria-invalid", "true");
    };
    var send = function () {
      if (!input.value) { input.focus(); return; }
      var body = { s: gate.getAttribute("data-s"), passphrase: input.value, remember: $("cx-remember").checked };
      input.value = "";
      open.disabled = true;
      post("/api/connect/open", body).then(function () {
        location.reload();
      }, function (e) { open.disabled = false; fail(e.message); input.focus(); });
    };
    open.addEventListener("click", send);
    input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); send(); } });
    input.addEventListener("input", function () {
      if (input.value) { input.classList.remove("bad"); input.removeAttribute("aria-invalid"); }
    });
  }

  // ------------------------------------------------ Step 3: connect
  var card = $("cx-go-card");
  if (card) {
    var token = card.getAttribute("data-s");
    var btn = $("cx-go"), cancel = $("cx-cancel"), gmsg = $("cx-go-msg");
    var name = $("cx-name"), what = card.querySelector(".cx-what");
    if (name && what && what.getAttribute("data-new") === "true") {
      name.addEventListener("input", function () {
        what.textContent = "Adds the environment " + (name.value.trim() || "…") + " and loads its runs.";
      });
    }
    btn.addEventListener("click", function () {
      if (!name.value.trim()) { name.focus(); return; }
      var push = card.querySelector("input[name=cx-push]:checked");
      var every = $("cx-refresh");
      var body = {
        s: token,
        name: name.value.trim(),
        push: push ? push.value === "push" : false,
        refresh: every && every.value.trim() !== "" ? Number(every.value) : null
      };
      var keep = $("cx-remember");
      if (keep) body.remember = keep.checked;
      btn.disabled = true; cancel.disabled = true;
      gmsg.className = "save-status muted small";
      gmsg.textContent = "Connecting and syncing…";
      post("/api/connect/go", body).then(function (j) {
        location.href = j.redirect;
      }, function (e) {
        // The passphrase must be given first: the page asks for it.
        if (e.data && e.data.reload) { location.reload(); return; }
        btn.disabled = false; cancel.disabled = false;
        gmsg.className = "save-status small err";
        gmsg.textContent = e.message;
      });
    });
    cancel.addEventListener("click", function () {
      cancel.disabled = true;
      post("/api/connect/cancel", { s: token }).then(function (j) { location.href = j.redirect; }, function () { location.href = "/environments"; });
    });
  }
})();
