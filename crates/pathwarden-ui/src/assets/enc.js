// Pathwarden UI: the history's passphrase (History storage's encryption
// part, and the "This history is encrypted" card on Runs). A passphrase is
// sent once, to the local API, and the fields are cleared; it never comes
// back from the server.
(function () {
  "use strict";

  var MIN = 12;
  function $(id) { return document.getElementById(id); }

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
        if (!r.ok) {
          var err = new Error((j && j.error) || "Pathwarden couldn't do that. Try again; if it keeps failing, see Settings › Logs.");
          err.data = j || {};
          throw err;
        }
        return j || {};
      });
    }, function () { throw new Error("Pathwarden isn't answering. Is it still running?"); });
  }

  function say(el, text, bad) {
    if (!el) return;
    el.textContent = text;
    el.className = "enc-msg small" + (bad ? " err" : " ok");
  }

  // How strong a new passphrase looks: [width %, word, advice].
  function strength(p) {
    var n = p.length;
    var words = p.trim().split(/[\s\-_.,;:+]+/).filter(Boolean).length;
    var hint = "Five or more words are easy to type and hard to guess.";
    if (n < MIN) return [Math.round((n / MIN) * 25), "Too short.", "At least " + MIN + " characters."];
    if (words >= 5 || n >= 28) return [Math.min(100, 70 + n), "Strong.", hint];
    if (n >= 16 || words >= 3) return [55, "Fair.", "Longer is stronger. " + hint];
    return [35, "Weak.", "Longer is stronger. " + hint];
  }

  // Two new-passphrase fields (`prefix`-pass, -pass2) with their match
  // hint and strength bar; `ready()` says whether they can be sent.
  function pair(prefix, onChange) {
    var a = $(prefix + "-pass"), b = $(prefix + "-pass2");
    var match = $(prefix + "-match"), bar = $(prefix + "-strength");
    if (!a || !b) return null;
    var update = function () {
      var s = strength(a.value);
      bar.querySelector(".bar > span").style.width = s[0] + "%";
      bar.className = "enc-strength" + (s[1] === "Strong." ? " strong" : s[1] === "Too short." ? " short" : "");
      bar.lastElementChild.innerHTML = "";
      var w = document.createElement("strong");
      w.textContent = s[1];
      bar.lastElementChild.appendChild(w);
      bar.lastElementChild.appendChild(document.createTextNode(" " + s[2]));
      if (!b.value) { match.hidden = true; }
      else {
        match.hidden = false;
        var same = a.value === b.value;
        match.className = "hint enc-match" + (same ? "" : " no");
        match.querySelector("span").textContent = same ? "The two match." : "They don't match yet.";
      }
      if (onChange) onChange();
    };
    a.addEventListener("input", update);
    b.addEventListener("input", update);
    return {
      ready: function () { return a.value.length >= MIN && a.value === b.value; },
      value: function () { return a.value; },
      clear: function () { a.value = ""; b.value = ""; update(); }
    };
  }

  // ------------------------------------------------ History storage
  var enc = $("enc");
  if (enc) {
    var box = $("state-encrypt");
    var on = enc.getAttribute("data-on") === "true";
    var msg = $("enc-msg");
    // These controls act on their own: they are not part of the card's
    // Save, so they never mark it unsaved.
    ["input", "change"].forEach(function (t) {
      enc.addEventListener(t, function (e) { e.stopPropagation(); });
    });
    var cardSave = enc.closest("section") && enc.closest("section").querySelector(".card-actions");
    // The passphrase panel saves; the card's own Save would be a second way.
    var panelOpen = function (open) { if (cardSave) cardSave.hidden = open; };

    if (!on) {
      var wrap = $("enc-setup-wrap"), ack = $("enc-ack"), set = $("enc-set");
      var setMsg = set && set.parentNode.querySelector(".enc-msg");
      var fields = pair("enc", function () { set.disabled = !(fields && fields.ready() && ack.checked); });
      box.addEventListener("change", function () {
        wrap.hidden = !box.checked;
        panelOpen(box.checked);
        if (box.checked) $("enc-pass").focus();
        else { fields.clear(); $("enc-no").hidden = true; }
      });
      ack.addEventListener("change", function () { set.disabled = !(fields.ready() && ack.checked); });
      $("enc-skip").addEventListener("click", function (e) { e.preventDefault(); $("enc-no").hidden = false; });
      $("enc-no-back").addEventListener("click", function () { $("enc-no").hidden = true; });
      $("enc-no-save").addEventListener("click", function () {
        box.checked = false; wrap.hidden = true; $("enc-no").hidden = true; fields.clear();
        panelOpen(false);
      });
      set.addEventListener("click", function () {
        if (!fields.ready() || !ack.checked) return;
        // Full runs and settings is confirmed as on Save (config.js).
        var asked = window.pwConfirmKeep ? window.pwConfirmKeep(true) : Promise.resolve(true);
        asked.then(function (ok) {
          if (!ok) return;
          var p = fields.value();
          fields.clear();
          set.disabled = true;
          say(setMsg, "Encrypting the history…", false);
          // The card's form goes with the passphrase: the server saves it,
          // encrypts the history, and only then shares the settings, so
          // nothing reaches the repository in plain text.
          var body = { on: true, passphrase: p };
          if (window.pwStateBody) body.state = window.pwStateBody();
          post("/api/history/encryption", body).then(function (j) {
            if (j.note) { say(setMsg, j.note + " Reload the page to see the history as it is now.", false); return; }
            location.href = location.pathname + "#saved"; location.reload();
          }, function (e) {
            // A history is there already: Connect to it; nothing was encrypted.
            if (e.data && e.data.connect && window.pwShowFound && window.pwShowFound(e.data)) {
              say(setMsg, "Not saved. Nothing was encrypted.", true);
              set.disabled = false;
              return;
            }
            say(setMsg, e.message, true);
          });
        });
      });
    } else {
      var off = $("enc-off"), change = $("enc-change");
      // Either panel acts on its own: the card's Save hides meanwhile.
      var syncSave = function () { panelOpen(!off.hidden || !change.hidden); };
      box.addEventListener("change", function () {
        off.hidden = box.checked;
        if (!box.checked && change) change.hidden = true;
        syncSave();
      });
      $("enc-off-cancel").addEventListener("click", function () { box.checked = true; off.hidden = true; syncSave(); });
      $("enc-off-go").addEventListener("click", function () {
        var b = this, m = off.querySelector(".enc-msg");
        b.disabled = true;
        say(m, "Decrypting the history…", false);
        post("/api/history/encryption", { on: false }).then(function (j) {
          if (j.note) { say(m, j.note + " Reload the page to see the history as it is now.", false); return; }
          location.href = location.pathname + "#saved"; location.reload();
        }, function (e) { b.disabled = false; say(m, e.message, true); });
      });
      var go = $("enc-change-go");
      var cmsg = go.parentNode.querySelector(".enc-msg");
      var current = $("enc-current");
      var nf = pair("enc-new", function () { go.disabled = !(nf && nf.ready() && (!current || current.value)); });
      if (current) current.addEventListener("input", function () { go.disabled = !(nf.ready() && current.value); });
      $("enc-change-open").addEventListener("click", function () {
        change.hidden = !change.hidden;
        syncSave();
        if (!change.hidden) (current || $("enc-new-pass")).focus();
      });
      $("enc-change-cancel").addEventListener("click", function () {
        change.hidden = true; nf.clear(); if (current) current.value = "";
        syncSave();
      });
      go.addEventListener("click", function () {
        if (!nf.ready()) return;
        var body = { "new": nf.value(), current: current ? current.value : null };
        nf.clear(); if (current) current.value = "";
        go.disabled = true;
        say(cmsg, "Encrypting every file again…", false);
        post("/api/history/passphrase/change", body).then(function (j) {
          if (j.note) { say(cmsg, j.note + " Reload the page to see the history as it is now.", false); return; }
          location.href = location.pathname + "#saved"; location.reload();
        }, function (e) { say(cmsg, e.message, true); });
      });
      $("enc-check").addEventListener("click", function () {
        var b = this;
        b.disabled = true;
        say(msg, "Checking…", false);
        post("/api/history/passphrase/check").then(function (j) {
          b.disabled = false; say(msg, j.message, false);
        }, function (e) { b.disabled = false; say(msg, e.message, true); });
      });
    }
  }

  // ------------------------------------------------ Runs: the card
  var gate = $("enc-gate");
  if (gate) {
    var input = $("gate-pass"), err = $("gate-err"), open = $("gate-open");
    var fail = function (text) {
      err.querySelector("span").textContent = text;
      err.hidden = false;
      input.classList.add("bad");
      input.setAttribute("aria-invalid", "true");
    };
    var send = function () {
      if (!input.value) { input.focus(); return; }
      var body = { passphrase: input.value, remember: $("gate-remember").checked };
      input.value = "";
      open.disabled = true;
      post("/api/history/passphrase/open", body).then(function () {
        location.reload();
      }, function (e) { open.disabled = false; fail(e.message); input.focus(); });
    };
    open.addEventListener("click", send);
    input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); send(); } });
    input.addEventListener("input", function () {
      if (input.value) { input.classList.remove("bad"); input.removeAttribute("aria-invalid"); }
    });
  }
})();
