// Pathwarden UI: the Collect wizard (one step at a time, the connection
// check, the collection's progress) and the schedule page's Copy buttons.
//
// The password is read from its field only when a request needs it, sent in
// that request's body, and the field is cleared once collecting starts. It is
// never put in a URL, in storage, or in the page.
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  function toast(message) {
    var t = $("toast");
    if (!t) { alert(message); return; }
    t.textContent = message;
    t.classList.remove("kept"); // app.js may have left a note's look
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.hidden = true; }, 6000);
  }

  function parse(text) {
    try { return JSON.parse(text); } catch (e) { return {}; }
  }

  function post(url, body) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (r) {
      return r.text().then(function (t) { return { ok: r.ok, status: r.status, data: parse(t) }; });
    });
  }

  // ------------------------------------------------------- Copy buttons
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.className = "sr-only";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }
  document.querySelectorAll("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var pre = $(b.getAttribute("data-copy"));
      if (!pre) return;
      var label = b.querySelector("span");
      copyText(pre.textContent).then(function () {
        label.textContent = "Copied";
        b.classList.add("done");
        setTimeout(function () { label.textContent = "Copy"; b.classList.remove("done"); }, 1800);
      }, function () { toast("Couldn't copy. Select the text and copy it instead."); });
    });
  });

  // ------------------------------------------------------------- Wizard
  var wiz = $("wizard");
  if (!wiz) return;

  var BUILTIN = wiz.getAttribute("data-builtin") === "1";
  var WINDOWS = wiz.getAttribute("data-windows") === "1";
  var LABELS = ["Where", "Who", "How deep", "Check", "Collect", "Results"];
  var step = 1;
  var checked = false; // the connection check passed for the current answers
  var checking = false;
  // What the check found about the DC: state "found" (with its name) or
  // "dns" (the lookup failed); empty until a check ends.
  var found = { state: "", server: "" };
  var ldapsAuto = false; // LDAPS was ticked by sync(), not by the user
  var job = null;
  // Who the check signed in as, for the confirmation before several
  // domains.
  var boundAs = "";

  var sections = {};
  document.querySelectorAll(".wiz-step").forEach(function (s) { sections[s.getAttribute("data-step")] = s; });
  var back = $("wiz-back");
  var next = $("wiz-next");
  var nav = $("wiz-nav");

  function radio(name) {
    var r = document.querySelector('input[name="' + name + '"]:checked');
    return r ? r.value : "";
  }
  function setRadio(name, value) {
    var r = document.querySelector('input[name="' + name + '"][value="' + value + '"]');
    if (r && !r.disabled) r.checked = true;
  }

  // Field errors
  function clearErrors() {
    document.querySelectorAll(".field-error[id]").forEach(function (p) { p.hidden = true; p.textContent = ""; });
    document.querySelectorAll("[aria-invalid]").forEach(function (el) { el.removeAttribute("aria-invalid"); });
  }
  function fieldError(field, message) {
    var p = $(field + "-error");
    var input = $(field);
    if (p) { p.textContent = message; p.hidden = false; }
    if (input) { input.setAttribute("aria-invalid", "true"); input.focus(); }
    if (!p) toast(message);
  }

  var HOST = /^(?!.*\.\.)[A-Za-z0-9_][A-Za-z0-9._-]*$/;

  // The answers and the step, kept for this tab (sessionStorage) so a
  // reload, or Back to the page, doesn't start over. Never the password.
  var SAVED = "pathwarden-collect";
  function save() {
    try {
      sessionStorage.setItem(SAVED, JSON.stringify({
        step: step,
        dcmode: radio("dcmode"),
        domain: $("domain").value,
        server: $("server").value,
        auth: radio("auth"),
        user: $("user").value,
        ldaps: $("ldaps").checked,
        ldaps_auto: ldapsAuto,
        skip_verify: $("skip-verify").checked,
        kerberos_only: $("kerberos-only").checked,
        smb_signing: $("smb-signing").checked,
        service_reads: $("service-reads").checked,
        task_reads: $("task-reads").checked,
        depth: radio("depth"),
        collector: radio("collector"),
        sharphound: $("sharphound").value,
        keep: $("keep").checked,
        // Before the list is in, the ticks kept so far.
        trusted: tdLoaded ? ticked() : tdKept,
        trusted_servers: tdDcKept()
      }));
    } catch (e) {}
  }
  function forget() {
    try { sessionStorage.removeItem(SAVED); } catch (e) {}
  }
  // The step to go back to, or 0 when nothing was kept.
  function restore() {
    var s = null;
    try { s = JSON.parse(sessionStorage.getItem(SAVED) || "null"); } catch (e) {}
    if (!s || typeof s !== "object") return 0;
    // An entry this page can't use (another version's, say) is dropped
    // rather than leave the wizard stuck.
    try { return apply(s); } catch (e) { forget(); return 0; }
  }
  function apply(s) {
    function text(id, v) { if (typeof v === "string" && $(id)) $(id).value = v.slice(0, 500); }
    function box(id, v) { if (typeof v === "boolean" && $(id)) $(id).checked = v; }
    ["dcmode", "auth", "depth", "collector"].forEach(function (name) {
      if (typeof s[name] === "string" && /^[a-z_-]+$/.test(s[name])) setRadio(name, s[name]);
    });
    text("domain", s.domain);
    text("server", s.server);
    text("user", s.user);
    text("sharphound", s.sharphound);
    box("ldaps", s.ldaps);
    // Ticked by sync() rather than the user: still untick it when LDAPS is
    // no longer needed.
    ldapsAuto = s.ldaps_auto === true && $("ldaps").checked;
    box("skip-verify", s.skip_verify);
    box("kerberos-only", s.kerberos_only);
    box("smb-signing", s.smb_signing);
    box("service-reads", s.service_reads);
    box("task-reads", s.task_reads);
    box("keep", s.keep);
    if (Array.isArray(s.trusted)) tdKept = s.trusted.filter(function (t) { return typeof t === "string"; }).slice(0, 50);
    if (s.trusted_servers && typeof s.trusted_servers === "object") {
      Object.keys(s.trusted_servers).slice(0, 50).forEach(function (k) {
        var v = s.trusted_servers[k];
        if (typeof v === "string") tdDc[k.toLowerCase()] = v.slice(0, 255);
      });
    }
    var n = Math.floor(Number(s.step)) || 1;
    // The check (step 4) runs again; a password has to be typed again.
    n = Math.max(1, Math.min(n, 3));
    if (radio("auth") === "password" && n > 2) n = 2;
    return n;
  }

  function answers() {
    var dcmode = radio("dcmode");
    var server = "";
    if (dcmode === "detected") server = document.querySelector("[data-dc]").getAttribute("data-dc");
    else if (dcmode === "choose") server = $("server").value.trim();
    return {
      domain: $("domain").value.trim(),
      server: server,
      auth: radio("auth") || "password",
      user: $("user").value.trim(),
      ldaps: $("ldaps").checked,
      skip_verify: $("ldaps").checked && $("skip-verify").checked,
      // Opt-outs, so a missing answer means the safe default.
      allow_ntlm: !$("kerberos-only").checked,
      allow_unsigned_smb: !$("smb-signing").checked,
      // Only a Full collection by the built-in collector reads them.
      service_reads: $("service-reads").checked,
      task_reads: $("task-reads").checked,
      depth: radio("depth") || "quick",
      collector: radio("collector") || "builtin",
      sharphound: $("sharphound").value.trim(),
      keep: $("keep").checked,
      trusted: ticked(),
      trusted_servers: tdServers()
    };
  }

  // ------------------------------------------------- Trusted domains
  // Step 1 lists the domain's trusted domains, from its last run: ticked
  // when the domain can probably be read with this sign-in, greyed with
  // the reason when it can't.
  var PICK = parse(wiz.getAttribute("data-pick") || "[]");
  if (!Array.isArray(PICK)) PICK = [];
  var tdKept = null; // ticked in the answers kept for this tab
  var tdLoaded = false; // the list shows the domain's trusted domains
  var tdFor = null, tdTimer = null, tdSeq = 0;
  // A trusted domain's domain controller as typed, by its lower-case name;
  // blank: found through DNS. Kept when the box is unticked and ticked
  // again; another first domain starts with none.
  var tdDc = {};
  function ticked() {
    return Array.prototype.map.call(document.querySelectorAll("#td-list input[type=checkbox]:checked:not(:disabled)"), function (i) { return i.value; });
  }
  // Each ticked domain shows its domain controller field; what is typed
  // is kept.
  function tdFields() {
    document.querySelectorAll("#td-list li").forEach(function (li) {
      var box = li.querySelector("input[type=checkbox]"), sub = li.querySelector(".td-dc");
      if (!box || !sub) return;
      sub.hidden = !box.checked || box.disabled;
      var dc = sub.querySelector("input");
      tdDc[box.value.toLowerCase()] = dc.value;
    });
  }
  // The typed domain controllers of the ticked domains, as
  // `--server DOMAIN=HOST` names them.
  function tdServers() {
    var out = {};
    document.querySelectorAll("#td-list li").forEach(function (li) {
      var box = li.querySelector("input[type=checkbox]"), dc = li.querySelector(".td-dc input");
      if (box && dc && box.checked && !box.disabled && dc.value.trim()) out[box.value] = dc.value.trim();
    });
    return out;
  }
  // What is typed, to keep for this tab: the filled ones, at most 50 (as
  // many as restore() takes back).
  function tdDcKept() {
    var out = {};
    Object.keys(tdDc).filter(function (k) { return tdDc[k]; }).slice(0, 50)
      .forEach(function (k) { out[k] = tdDc[k]; });
    return out;
  }
  function tdCount() {
    tdFields();
    var all = document.querySelectorAll("#td-list input[type=checkbox]").length;
    var n = ticked().length;
    $("td-count").textContent = n + " of " + all + " ticked";
    $("td-all").hidden = n === 0;
    // Said before the Check step signs in to them.
  }
  function alertIcon() {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "ic");
    svg.setAttribute("aria-hidden", "true");
    var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "#i-alert");
    svg.appendChild(use);
    return svg;
  }
  function renderTrusted(data, domain) {
    var box = $("trusted"), ul = $("td-list");
    ul.innerHTML = "";
    var doms = (data && Array.isArray(data.domains)) ? data.domains : [];
    // A link's picks tick only what the page would tick (the same rule as
    // --trusted): selective authentication stays the user's own tick. The
    // answers kept for this tab are the user's ticks, kept as they were.
    var fromLink = PICK.length > 0;
    var want = fromLink ? PICK : tdKept;
    PICK = []; tdKept = null; tdLoaded = true;
    doms.forEach(function (d) {
      if (!d || typeof d.name !== "string") return;
      var off = d.pick === "off";
      var li = document.createElement("li");
      if (off) li.className = "off";
      var label = document.createElement("label"); label.className = "toggle";
      var input = document.createElement("input"); input.type = "checkbox"; input.value = d.name;
      input.disabled = off;
      input.checked = !off && (want
        ? want.some(function (w) { return String(w).toLowerCase() === d.name.toLowerCase(); }) &&
          (!fromLink || d.pick === "on")
        : d.pick === "on");
      var body = document.createElement("span"); body.className = "t-body";
      var name = document.createElement("span"); name.className = "td-name";
      var strong = document.createElement("strong"); strong.textContent = d.name;
      var chip = document.createElement("span"); chip.className = "td-chip"; chip.textContent = d.chip || "";
      name.appendChild(strong); name.appendChild(chip);
      body.appendChild(name);
      if (d.why) {
        var why = document.createElement("span");
        why.className = "td-why" + (d.pick === "maybe" ? " maybe" : "");
        if (d.pick === "maybe") why.appendChild(alertIcon());
        why.appendChild(document.createTextNode(d.why));
        body.appendChild(why);
      }
      label.appendChild(input); label.appendChild(body);
      li.appendChild(label);
      if (!off) {
        // Optional: its domain controller, else one found through DNS.
        var id = "td-dc-" + ul.children.length;
        var sub = document.createElement("div"); sub.className = "sub-field td-dc";
        var lab = document.createElement("label"); lab.htmlFor = id; lab.textContent = "Domain controller ";
        var opt = document.createElement("span"); opt.className = "opt"; opt.textContent = "optional";
        lab.appendChild(opt);
        var dc = document.createElement("input"); dc.type = "text"; dc.id = id;
        dc.placeholder = "Find through DNS"; dc.spellcheck = false;
        dc.setAttribute("autocapitalize", "off"); dc.setAttribute("autocomplete", "off");
        dc.value = tdDc[d.name.toLowerCase()] || "";
        sub.appendChild(lab); sub.appendChild(dc);
        li.appendChild(sub);
      }
      ul.appendChild(li);
    });
    box.hidden = !ul.children.length;
    $("td-hint").textContent = data && data.from
      ? "From " + data.from + "'s last run. Ticked domains are collected in this run, one after another."
      : "";
    tdCount();
  }
  function loadTrusted(now) {
    var domain = $("domain").value.trim();
    if (domain === tdFor) return;
    clearTimeout(tdTimer);
    // Another domain: the ticks kept were for the one before.
    if (tdFor !== null) { tdKept = null; PICK = []; tdDc = {}; }
    tdLoaded = false;
    tdTimer = setTimeout(function () {
      tdFor = domain;
      var seq = ++tdSeq;
      if (!HOST.test(domain) || domain.indexOf(".") < 0) { renderTrusted(null, domain); return; }
      fetch("/api/collect/trusted?domain=" + encodeURIComponent(domain), { credentials: "same-origin" })
        .then(function (r) { return r.text(); })
        .then(function (t) { if (seq === tdSeq) renderTrusted(parse(t), domain); })
        .catch(function () { if (seq === tdSeq) renderTrusted(null, domain); });
    }, now ? 0 : 400);
  }
  $("td-all").addEventListener("click", function () {
    document.querySelectorAll("#td-list input[type=checkbox]:checked").forEach(function (i) { i.checked = false; });
    tdCount();
    if (checked) resetCheck();
    save();
  });

  // The answers plus the password, for the two requests that need it; and
  // where the run goes (step 5) with its label.
  function payload() {
    var a = answers();
    if (a.auth === "password") a.password = $("password").value;
    var placed = where ? where.choice() : null;
    if (placed) {
      if (placed.env) a.env = placed.env;
      if (placed.new_env) a.new_env = placed.new_env;
      a.env_auto = placed.env_auto === "1";
    }
    var label = $("run-label");
    if (label && label.value.trim()) a.label = label.value.trim();
    return a;
  }

  // Step 5: other collectors' files to analyze with the collection,
  // chosen and listed as on Analyze (app.js's PathwardenFiles), each with
  // what it is. Uploaded when Start collecting is pressed, just before
  // the collection starts.
  var also = [];      // the Files
  var alsoKind = [];  // what each is, in the same order ("" until known)
  var alsoSeq = 0;
  var Files = window.PathwardenFiles;
  function alsoShow() {
    var ul = $("also-list");
    ul.innerHTML = "";
    also.forEach(function (f, i) {
      ul.appendChild(Files.row(f, alsoKind[i] || "", function () {
        also.splice(i, 1);
        alsoKind.splice(i, 1);
        alsoShow();
      }));
    });
    ul.hidden = also.length === 0;
  }
  function alsoAdd(files) {
    var rejected = Files.take(files, also);
    if (rejected.length) toast("Only .zip and .json files can be analyzed: " + rejected.join(", "));
    alsoShow();
    var mine = ++alsoSeq, now = also.slice();
    Files.kinds(now).then(function (k) {
      if (mine !== alsoSeq) return;
      alsoKind = k;
      alsoShow();
    });
  }
  if ($("also-drop") && Files) {
    var alsoDrop = $("also-drop"), alsoInput = $("also-files");
    alsoInput.addEventListener("change", function () { alsoAdd(alsoInput.files); alsoInput.value = ""; });
    ["dragenter", "dragover"].forEach(function (ev) {
      alsoDrop.addEventListener(ev, function (e) { e.preventDefault(); alsoDrop.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      alsoDrop.addEventListener(ev, function (e) { e.preventDefault(); alsoDrop.classList.remove("over"); });
    });
    alsoDrop.addEventListener("drop", function (e) { if (e.dataTransfer) Files.dropped(e.dataTransfer).then(alsoAdd); });
    // Dropping outside the area must not open the file in the browser.
    window.addEventListener("dragover", function (e) { e.preventDefault(); });
    window.addEventListener("drop", function (e) { e.preventDefault(); });
  } else if ($("also")) {
    $("also").hidden = true;
  }
  // The chosen files, uploaded: a Promise of what Start collecting names
  // them by ("" for none).
  function alsoUpload() {
    if (!also.length) return Promise.resolve("");
    var fd = new FormData();
    also.forEach(function (f) { fd.append("files", f, f.name); });
    return fetch("/api/collect/also", { method: "POST", credentials: "same-origin", body: fd })
      .then(function (r) { return r.text().then(function (t) { return { ok: r.ok, data: parse(t) }; }); })
      .then(function (r) {
        if (!r.ok) throw new Error(r.data.error || "The added files couldn't be uploaded. Try again, or remove them.");
        return r.data.also || "";
      });
  }

  // Step 5: where the run goes, from the domain it collects
  // (env_where.rs); Start waits while something's off and nothing is
  // chosen.
  var where = $("ew") && window.PathwardenWhere
    ? window.PathwardenWhere($("ew"), function () { syncStart(); })
    : null;
  var whereFor = null;
  function syncStart() {
    var off = !!where && where.choice() === null;
    ["collect-start", "collect-resume", "collect-over"].forEach(function (id) {
      if ($(id)) $(id).disabled = off;
    });
    checkStopped();
  }

  // Step 5: a read of the domain that stopped and can be resumed,
  // in the environment chosen: offered with Resume (the main button) and
  // Start over instead of Start collecting.
  var stoppedFor = null, stoppedSeq = 0;
  function showStopped(text) {
    $("resume-note").hidden = !text;
    $("resume-text").textContent = text || "";
    $("collect-resume").hidden = !text;
    $("collect-over").hidden = !text;
    $("collect-start").hidden = !!text;
  }
  function checkStopped() {
    if (step !== 5 || job) return;
    var a = payload();
    delete a.password;
    delete a.label;
    var key = JSON.stringify(a);
    if (key === stoppedFor) return;
    stoppedFor = key;
    var seq = ++stoppedSeq;
    post("/api/collect/stopped", a).then(function (r) {
      if (seq === stoppedSeq) showStopped(r.ok && r.data.stopped ? r.data.stopped.text : "");
    }, function () {
      if (seq === stoppedSeq) showStopped("");
    });
  }
  function loadWhere() {
    if (!where) return;
    var domain = $("domain").value.trim();
    if (domain === whereFor) return;
    whereFor = domain;
    var fd = new FormData();
    fd.append("domain", domain);
    where.load(fd, null);
  }

  // Keeps every dependent control in line with the answers.
  function sync() {
    var a = answers();
    $("server-field").hidden = radio("dcmode") !== "choose";
    var pw = a.auth === "password";
    $("cred-fields").hidden = !pw;

    // LDAPS: required with a password and the built-in collector.
    var ldaps = $("ldaps");
    var mustLdaps = pw && a.collector === "builtin";
    // Ticked here only because a password needs it: unticked again when
    // it no longer does (a box the user ticked stays ticked).
    if (mustLdaps && !ldaps.checked) { ldaps.checked = true; ldapsAuto = true; }
    else if (!mustLdaps && ldapsAuto) { ldaps.checked = false; ldapsAuto = false; }
    ldaps.disabled = mustLdaps;
    $("ldaps-hint").textContent = pw
      ? "Required with a password. Needs a certificate this computer trusts."
      : "Optional: Windows already encrypts the connection.";
    $("skip-verify").disabled = !ldaps.checked;
    if (!ldaps.checked) $("skip-verify").checked = false;
    // Kerberos only and SMB signing turned off, or Kerberos only with the
    // certificate not checked: say what that means.
    $("ntlm-note").hidden = $("kerberos-only").checked;
    // As the Windows account, Windows' own SMB client signs: no toggle.
    $("smb-signing").closest("label").hidden = !pw;
    $("unsigned-note").hidden = !pw || $("smb-signing").checked;
    $("krb-cert-note").hidden = !(pw && $("kerberos-only").checked && $("skip-verify").checked);

    // Collector availability depends on the build, the platform, the depth
    // and how the user signs in.
    var bi = $("collector-builtin"), sh = $("collector-sharphound");
    var biWhy = !BUILTIN ? "Not included in this version of Pathwarden. Use SharpHound, or collect elsewhere and upload the file."
      : (a.depth === "full" && !pw) ? "For a Full collection it needs a user and password (step 2): it signs in to every computer with them."
      : (!pw && !WINDOWS) ? "Needs a user and password on this computer (step 2)." : "";
    var shWhy = !WINDOWS ? "Runs on Windows only."
      : pw ? "Runs as your Windows account only. Choose \"Use my Windows account\" in step 2 to use it." : "";
    setAvailable(bi, biWhy);
    setAvailable(sh, shWhy);
    var chosen = radio("collector");
    if (!chosen || document.querySelector('input[name="collector"]:checked').disabled) {
      var r = document.querySelector('input[name="collector"]:checked');
      if (r) r.checked = false;
      if (!biWhy) setRadio("collector", "builtin"); else if (!shWhy) setRadio("collector", "sharphound");
    }
    a = answers();
    $("sharphound-field").hidden = !(radio("collector") === "sharphound");
    // "Read service accounts" and "Read scheduled tasks": a Full
    // collection by the built-in collector.
    var svc = a.depth === "full" && a.collector === "builtin";
    $("service-reads-field").hidden = !svc;
    $("service-reads-note").hidden = !svc || $("service-reads").checked;
    $("task-reads-field").hidden = !svc;
    $("task-reads-note").hidden = !svc || $("task-reads").checked;
    $("sharphound-krb-note").hidden = radio("collector") !== "sharphound";
    $("means-quick").hidden = a.depth !== "quick";
    $("means-full").hidden = a.depth !== "full";
  }

  function setAvailable(label, why) {
    var input = label.querySelector("input");
    var w = label.querySelector(".c-why");
    input.disabled = !!why;
    label.classList.toggle("disabled", !!why);
    w.textContent = why;
    w.hidden = !why;
  }

  // Client-side checks per step (the server checks everything again).
  function validate(n) {
    clearErrors();
    var a = answers();
    if (n === 1) {
      if (!a.domain) return fieldError("domain", "Enter your domain's name, like scale.local."), false;
      if (!HOST.test(a.domain) || a.domain.indexOf(".") < 0)
        return fieldError("domain", "That doesn't look like a domain name. Use its full DNS name, like scale.local (not the short name, like SCALE)."), false;
      if (radio("dcmode") === "choose") {
        if (!a.server) return fieldError("server", "Enter the domain controller's full name, like dc01.scale.local."), false;
        if (!HOST.test(a.server)) return fieldError("server", "That doesn't look like a computer name. Use the domain controller's full name, like dc01.scale.local."), false;
      }
    }
    if (n === 2 && a.auth === "password") {
      if (!a.user) return fieldError("user", "Enter the user name."), false;
      if (!$("password").value) return fieldError("password", "Enter the password."), false;
    }
    if (n === 3) {
      var r = document.querySelector('input[name="collector"]:checked');
      if (!r || r.disabled) return fieldError("collector", "Choose a collector. If none is available here, analyze a file collected elsewhere on the Analyze page."), false;
      if (a.collector === "sharphound" && !a.sharphound)
        return fieldError("sharphound", "Enter where SharpHound.exe is, like C:\\Tools\\SharpHound.exe."), false;
    }
    if (n === 4 && !checked) {
      return false;
    }
    return true;
  }

  // Step 4's summary of the answers.
  function recap() {
    var a = answers();
    var dl = $("recap");
    dl.innerHTML = "";
    function row(k, v) {
      var d = document.createElement("div");
      var dt = document.createElement("dt"); dt.textContent = k;
      var dd = document.createElement("dd"); dd.textContent = v;
      d.appendChild(dt); d.appendChild(dd); dl.appendChild(d);
    }
    var sh = a.collector === "sharphound";
    // Only what the check has actually found: before it, the DC is still
    // to be looked up.
    var dc = a.server;
    if (sh) dc = a.server || "SharpHound finds one when it runs";
    else if (found.state === "found") dc = a.server ? found.server || a.server : (found.server || "A domain controller") + " (found through DNS)";
    else if (found.state === "dns") dc = a.server ? a.server + " (not found in DNS)" : "Not found through DNS";
    else if (!a.server) dc = "Find through DNS (not looked up yet)";
    row("Domain", a.domain);
    row("Domain controller", dc);
    if (a.trusted.length) row("Trusted domains", a.trusted.join(", "));
    var me = document.querySelector("[data-account]").getAttribute("data-account");
    row("Sign in as", a.auth === "password" ? a.user : "Your Windows account" + (me ? " (" + me + ")" : ""));
    row("Connection", a.ldaps ? (a.skip_verify ? "LDAPS, certificate not checked" : "LDAPS") : "LDAP, signed and encrypted by Windows");
    row("Depth", a.depth === "full" ? "Full: directory, sessions and local groups" : "Quick: directory only");
    row("Collector", sh ? "SharpHound" : "Built-in");
    row("Computers", sh ? "Not enforced: SharpHound signs in its own way"
      : (a.allow_ntlm ? "NTLM allowed" : "Kerberos only") + ", " +
        (a.auth !== "password" ? "SMB signing left to Windows"
          : a.allow_unsigned_smb ? "SMB signing not required" : "SMB signing required"));
    $("check-label").textContent = sh ? "Check SharpHound" : "Check the connection";
    $("check-intro").textContent = sh
      ? "Pathwarden makes sure SharpHound is where you said. SharpHound contacts the domain itself when it runs."
      : "Pathwarden signs in and reads a little, without collecting anything yet.";
    var nt = a.trusted.length;
    $("ready-summary").textContent = (a.depth === "full" ? "A Full collection" : "A Quick collection") +
      " of " + a.domain + (nt ? " and " + nt + (nt === 1 ? " trusted domain" : " trusted domains") : "") +
      " with " + (sh ? "SharpHound" : "the built-in collector") +
      (a.depth === "full" ? ". It contacts every computer and can take a while."
        : nt ? ". It usually takes a few minutes per domain." : ". It usually takes a few minutes.");
  }

  function showCheck(which) {
    ["idle", "busy", "ok", "bad"].forEach(function (k) { $("check-" + k).hidden = k !== which; });
  }

  function resetCheck() {
    checked = false;
    found = { state: "", server: "" };
    showCheck("idle");
    refreshNav();
  }

  function list(ul, items) {
    ul.innerHTML = "";
    (items || []).forEach(function (t) {
      var li = document.createElement("li");
      li.textContent = t;
      ul.appendChild(li);
    });
    ul.hidden = !items || !items.length;
  }

  var fixStep = 1;
  function runCheck() {
    if (checking) return;
    checking = true;
    showCheck("busy");
    refreshNav();
    post("/api/collect/test", payload()).then(function (r) {
      checking = false;
      if (r.ok) {
        checked = true;
        found = { state: r.data.server ? "found" : "", server: r.data.server || "" };
        boundAs = typeof r.data.bound_as === "string" ? r.data.bound_as : "";
        list($("check-lines"), r.data.lines);
        list($("check-warnings"), r.data.warnings);
        list($("check-unchecked"), r.data.not_checked);
        $("check-unchecked-box").hidden = !(r.data.not_checked || []).length;
        showCheck("ok");
      } else {
        checked = false;
        found = { state: r.data.dns ? "dns" : "", server: "" };
        $("check-error").textContent = r.data.error || "The check failed. Try again.";
        var detail = $("check-detail");
        detail.textContent = r.data.detail ? "Details: " + r.data.detail : "";
        detail.hidden = !r.data.detail;
        fixStep = r.data.step || 1;
        $("check-fix").title = "Go back to step " + fixStep + " (" + LABELS[fixStep - 1] + ")";
        $("check-fix").setAttribute("data-field", r.data.field || "");
        showCheck("bad");
      }
      if (step === 4) recap();
      refreshNav();
    }, function () {
      checking = false;
      checked = false;
      $("check-error").textContent = "Pathwarden isn't answering. Is it still running?";
      $("check-detail").hidden = true;
      showCheck("bad");
      refreshNav();
    });
  }
  $("check-run").addEventListener("click", runCheck);
  $("check-again").addEventListener("click", runCheck);
  $("check-fix").addEventListener("click", function () {
    var field = $("check-fix").getAttribute("data-field");
    go(fixStep);
    if (field) fieldError(field, $("check-error").textContent);
  });

  function refreshNav() {
    back.hidden = step === 1 || step >= 5;
    next.hidden = step >= 5;
    next.disabled = step === 4 && (!checked || checking);
    nav.hidden = step >= 5 && job !== null;
    if (step === 5 && job === null) back.hidden = false;
  }

  function progressTo(n, done) {
    window.Pathwarden.step($("wiz-progress"), n, done);
  }

  function go(n, quiet) {
    step = n;
    if (job === null) save();
    Object.keys(sections).forEach(function (k) { sections[k].hidden = Number(k) !== n; });
    progressTo(n, false);
    if (n === 4) recap();
    if (n === 5) { recap(); loadWhere(); checkStopped(); }
    refreshNav();
    if (!quiet) {
      var h = sections[n] && sections[n].querySelector("h2");
      if (h) h.focus({ preventScroll: true });
      window.scrollTo({ top: 0 });
    }
    if (n === 4 && !checked && !checking) runCheck();
  }

  next.addEventListener("click", function () {
    if (!validate(step)) return;
    go(step + 1);
  });
  back.addEventListener("click", function () {
    clearErrors();
    go(Math.max(1, step - 1));
  });

  // Any change to the answers needs a new check.
  // Saved after sync(), so what it ticks is kept too; never while a
  // collection runs (go() keeps nothing then either).
  function keepAnswers(e) {
    if (job === null && e.target && e.target.id !== "password" && !e.target.closest("#ew, .run-label, #also")) save();
  }
  $("wiz-form").addEventListener("input", function (e) {
    if (e.target && e.target.id === "domain") loadTrusted(false);
    if (e.target && e.target.closest("#td-list")) tdCount();
    if (!(e.target && (e.target.id === "keep" || e.target.closest("#ew, .run-label, #also")))) {
      if (checked || !$("check-bad").hidden) resetCheck();
      sync();
    }
    keepAnswers(e);
  });
  $("wiz-form").addEventListener("change", function (e) {
    if (!(e.target && (e.target.id === "keep" || e.target.closest("#ew, .run-label, #also")))) {
      if (e.target && e.target.id === "ldaps") ldapsAuto = false; // the user's choice now
      if (checked) resetCheck();
      sync();
    }
    keepAnswers(e);
  });
  $("wiz-form").addEventListener("submit", function (e) { e.preventDefault(); });
  // Enter in a text field moves on instead of submitting.
  $("wiz-form").addEventListener("keydown", function (e) {
    if (e.key === "Enter" && e.target.tagName === "INPUT" && e.target.type !== "checkbox" && e.target.type !== "radio") {
      e.preventDefault();
      if (step < 4) next.click();
    }
  });

  // --------------------------------------------------------- Collecting
  var order = ["collect", "reading", "graph", "rules", "remediation", "report"];
  var stepsLi = {};
  document.querySelectorAll("#run-steps li").forEach(function (li) { stepsLi[li.getAttribute("data-step")] = li; });
  var startedAt = Date.now();
  var clock = null;

  function mark(current) {
    var reached = false;
    order.forEach(function (name) {
      var li = stepsLi[name];
      li.className = name === current ? "active" : reached ? "" : "done";
      if (name === current) reached = true;
    });
  }

  function tick() {
    var s = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    $("run-elapsed").textContent = (h ? h + ":" + ("0" + m).slice(-2) : m) + ":" + ("0" + (s % 60)).slice(-2);
  }

  function view(which) {
    $("collect-ready").hidden = which !== "ready";
    $("collect-run").hidden = which !== "run";
    $("collect-stopped").hidden = which !== "stopped";
    $("collect-failed").hidden = which !== "failed";
    if (which !== "run") { clearInterval(clock); clock = null; }
  }

  function showRun() {
    if (step !== 5) go(5, true);
    view("run");
    if (!clock) { tick(); clock = setInterval(tick, 1000); }
  }

  // How much to show while collecting: summary (step and bar), details
  // (+ objects by type) or log (+ every collector line). Remembered here.
  var verb = "details";
  try { verb = localStorage.getItem("pw-collect-verbosity") || verb; } catch (e) {}
  function setVerb(v) {
    if (["summary", "details", "log"].indexOf(v) < 0) v = "details";
    verb = v;
    try { localStorage.setItem("pw-collect-verbosity", v); } catch (e) {}
    document.querySelectorAll("#verb [data-verb]").forEach(function (b) {
      b.setAttribute("aria-checked", b.getAttribute("data-verb") === v ? "true" : "false");
    });
    if (lastJob) render(lastJob);
  }
  document.querySelectorAll("#verb [data-verb]").forEach(function (b) {
    b.addEventListener("click", function () { setVerb(b.getAttribute("data-verb")); });
  });
  $("verb").addEventListener("keydown", function (e) {
    var keys = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    if (!keys[e.key]) return;
    e.preventDefault();
    var all = ["summary", "details", "log"];
    var next = all[(all.indexOf(verb) + keys[e.key] + all.length) % all.length];
    setVerb(next);
    document.querySelector('#verb [data-verb="' + next + '"]').focus();
  });

  // The whole log, gathered across polls (the server keeps the last lines).
  var logLines = [], logSeen = 0, logLost = 0;
  function gather(c) {
    var total = c.log_total || 0, lines = c.log || [];
    var fresh = Math.min(total - logSeen, lines.length);
    if (total - logSeen > lines.length) logLost += total - logSeen - lines.length;
    if (fresh > 0) logLines = logLines.concat(lines.slice(lines.length - fresh));
    if (logLines.length > 20000) { logLost += logLines.length - 20000; logLines = logLines.slice(-20000); }
    logSeen = Math.max(logSeen, total);
  }
  $("run-log-copy").addEventListener("click", function () {
    var b = $("run-log-copy"), label = b.querySelector("span");
    var text = (logLost ? earlierLines(logLost) + "\n" : "") + logLines.join("\n");
    copyText(text).then(function () {
      label.textContent = "Copied"; b.classList.add("done");
      setTimeout(function () { label.textContent = "Copy log"; b.classList.remove("done"); }, 1800);
    }, function () { toast("Couldn't copy. Select the text and copy it instead."); });
  });

  function num(n) { return Number(n || 0).toLocaleString(); }
  function size(n) {
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + u[i];
  }
  function units(st) {
    if (!st.done && st.total == null) return "";
    var bytes = st.unit === "bytes";
    var done = bytes ? size(st.done) : num(st.done);
    var out = st.total != null
      ? done + " of " + (bytes ? "" : "about ") + (bytes ? size(Math.max(st.total, st.done)) : num(Math.max(st.total, st.done))) + (bytes ? "" : " " + st.unit)
      : done + (bytes ? "" : " " + st.unit);
    if (st.rate >= 1) out += " \u00b7 " + (bytes ? size(st.rate) : num(Math.round(st.rate))) + "/s";
    return out;
  }
  function eta(st, collecting) {
    if (!collecting || st.finished) return "Collected";
    if (st.eta_secs == null) return "Estimating time left\u2026";
    if (st.eta_secs === 0) return "Almost done";
    return "About " + aboutMin(st.eta_secs) + " left";
  }
  // Time left as the header gives it ("8 min", "1 h 20 min").
  function aboutMin(s) {
    var m = Math.max(1, Math.round(s / 60));
    if (m < 60) return m + " min";
    return Math.floor(m / 60) + " h" + (m % 60 ? " " + (m % 60) + " min" : "");
  }
  function earlierLines(n) {
    return "(" + n.toLocaleString() + (n === 1 ? " earlier line" : " earlier lines") + " not shown)";
  }

  var lastJob = null;

  // ---- progressView: what the progress view says, worked out from
  // the job alone (no page here: tests/js/collect.test.mjs runs it).
  var progressView = (function () {
    function num(n) { return Number(n || 0).toLocaleString(); }
    var NAMES = { users: "Users", groups: "Groups", computers: "Computers", domains: "Domains", ous: "OUs",
      gpos: "GPOs", containers: "Containers", certtemplates: "Certificate templates", enterprisecas: "Enterprise CAs",
      rootcas: "Root CAs", aiacas: "AIA CAs", ntauthstores: "NTAuth stores", issuancepolicies: "Issuance policies",
      other: "Other entries" };
    var ORDER = ["users", "computers", "groups", "ous", "gpos", "containers", "domains"];
    // The kinds of the one quiet counts line; the rest behind All counts.
    var LINE = [["users", "users"], ["computers", "computers"], ["groups", "groups"], ["gpos", "GPOs"]];

    // "8 min", "1 h 20 min": the whole collection's time left, roughly.
    function roughly(s) {
      var m = Math.max(1, Math.round(s / 60));
      if (m < 60) return m + " min";
      return Math.floor(m / 60) + " h" + (m % 60 ? " " + (m % 60) + " min" : "");
    }
    function sentence(s) {
      s = String(s || "").trim();
      return s && !/[.!?]$/.test(s) ? s + "." : s;
    }
    function names(ds) { return ds.map(function (d) { return d.name; }); }

    function counts(c, st, collecting) {
      // Objects by type: what was written, else what has been read so far.
      // Read counts are raw directory entries: containers and other entries
      // mostly drop out in processing, so they wait for the written counts.
      var written = Object.keys(c.objects || {}).length > 0;
      var objects = written ? c.objects : (st && st.objects) || {};
      var expected = (st && st.expected) || {};
      var kinds = Object.keys(objects).concat(Object.keys(expected).filter(function (k) { return !(k in objects); }));
      if (!written) kinds = kinds.filter(function (k) { return k !== "other" && k !== "containers"; });
      kinds.sort(function (a, b) {
        var ia = ORDER.indexOf(a), ib = ORDER.indexOf(b);
        ia = ia < 0 ? (a === "other" ? 99 : 50) : ia; ib = ib < 0 ? (b === "other" ? 99 : 50) : ib;
        return ia - ib || (a < b ? -1 : 1);
      });
      function of(k) {
        return collecting && expected[k] != null ? "of ~" + num(Math.max(expected[k], objects[k] || 0)) : "";
      }
      var tiles = kinds.map(function (k) { return { dt: NAMES[k] || k, dd: num(objects[k]), of: of(k) }; });
      var line = LINE.filter(function (l) { return kinds.indexOf(l[0]) >= 0; }).map(function (l) {
        return { n: num(objects[l[0]]), word: l[1], title: of(l[0]) };
      });
      if (!line.length) line = tiles.slice(0, 4).map(function (t) { return { n: t.dd, word: t.dt, title: t.of }; });
      if (!kinds.length && collecting && st && st.done) {
        // A collector that only counts objects (SharpHound): the totals.
        var chips = [["Objects processed", num(st.done), "objects"]];
        if (st.total != null) chips.push(["Expected", "~" + num(Math.max(st.total, st.done)), "expected"]);
        if (st.rate >= 1) chips.push(["Per second", num(Math.round(st.rate)), "per second"]);
        return {
          tiles: chips.map(function (x) { return { dt: x[0], dd: x[1], of: "" }; }),
          line: chips.map(function (x) { return { n: x[1], word: x[2], title: "" }; }),
          more: false, readSoFar: false
        };
      }
      return { tiles: tiles, line: line, more: tiles.length > line.length, readSoFar: !written && collecting && tiles.length > 0 };
    }

    // "CONTOSO.COM: text" and "text" alike, in order: [{text, domains}].
    function notes(items) {
      var order = [], by = {};
      (Array.isArray(items) ? items : []).forEach(function (t) {
        if (typeof t !== "string" || !t) return;
        var m = /^([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+): ([\s\S]+)$/.exec(t);
        var text = m ? m[2] : t;
        if (!Object.prototype.hasOwnProperty.call(by, text)) { by[text] = { text: text, domains: [] }; order.push(text); }
        if (m && by[text].domains.indexOf(m[1]) < 0) by[text].domains.push(m[1]);
      });
      return order.map(function (t) { return by[t]; });
    }

    // `now`: Unix seconds.
    return function (j, now) {
      var c = j.collect || {}, st = c.status || null;
      var collecting = j.status === "collecting";
      var doms = c.domains || [];
      var multi = doms.length > 1;
      var by = { done: [], failed: [], waiting: [] }, active = null;
      doms.forEach(function (d) {
        if (d.state === "active" && !active) active = d;
        else (by[d.state] || by.waiting).push(d);
      });
      var finished = by.done.length + by.failed.length;
      var title = !collecting ? "Analyzing"
        : multi ? "Collecting " + doms.length + " domains"
        : c.domain ? "Collecting " + c.domain : "Collecting";
      var sub = "";
      if (multi && collecting) {
        sub = Math.max(1, Math.min(doms.length, finished + (active ? 1 : 0))) + " of " + doms.length;
        // Time left in all, once a domain has finished: the time each has
        // taken so far, for each one left; the current one's own estimate.
        var elapsed = j.started_at ? Math.max(0, now - j.started_at) : 0;
        if (finished > 0 && elapsed > 0) {
          var frac = active && st ? Math.min(1, Math.max(0, (st.percent || 0) / 100)) : 0;
          var per = elapsed / (finished + frac);
          var left = by.waiting.length * per +
            (active ? (st && st.eta_secs != null ? st.eta_secs : per * (1 - frac)) : 0);
          if (left > 0) sub += " · about " + roughly(left) + " left";
        }
      }
      function rows(ds, keep) {
        return ds.map(function (d) { return { name: d.name, text: keep ? d.text || "" : "" }; });
      }
      var groups = { done: null, skipped: null, waiting: null };
      if (multi) {
        if (by.done.length) groups.done = {
          head: by.done.length + " done", text: names(by.done).join(", "), rows: rows(by.done, true), more: true
        };
        if (by.failed.length) groups.skipped = {
          head: by.failed.length + " skipped",
          text: by.failed.length === 1 ? by.failed[0].name + ": " + sentence(by.failed[0].text) : names(by.failed).join(", "),
          rows: rows(by.failed, true), more: by.failed.length > 1
        };
        var w = names(by.waiting);
        if (w.length) groups.waiting = {
          head: w.length + " waiting",
          text: w.length > 3 ? w.slice(0, 3).join(", ") + " and " + (w.length - 3) + " more" : w.join(", "),
          rows: rows(by.waiting, false), more: w.length > 3
        };
      }
      var step = collecting && st
        ? ["Step " + st.step + " of " + st.steps].concat(st.detail ? [st.detail] : []).join(" · ") : "";
      return {
        collecting: collecting, multi: multi, title: title, sub: sub,
        // One domain: the title has its name; the panel says only the phase.
        panelName: multi && active ? active.name : "",
        phase: collecting ? (st ? st.phase : c.phase || "Starting") : "Collected",
        step: step, groups: groups, counts: counts(c, st, collecting),
        // The checklist is one line while collecting; it opens out after.
        stepsFolded: collecting,
        // Collected: the checklist says the step, and the panel goes.
        panel: collecting,
        // The collector's warnings, seen at the check already: folded into
        // one line, each message once with the domains it was about.
        notes: notes(c.warnings),
        // Other collectors' files read with it: their names, "" for
        // none (the row is hidden).
        also: (Array.isArray(c.also) ? c.also : []).filter(function (n) {
          return typeof n === "string" && n;
        }).join(", ")
      };
    };
  })();
  // ---- end progressView

  // A folded row of domains (done, skipped, waiting) and its own rows.
  function group(k, g) {
    var li = $("run-" + k);
    li.hidden = !g;
    if (!g) return;
    $("run-" + k + "-n").textContent = g.head;
    var nm = $("run-" + k + "-names");
    nm.textContent = g.text;
    nm.title = g.text;
    var show = li.querySelector(".dg-show"), ol = $("run-" + k + "-list");
    show.hidden = !g.more;
    ol.hidden = !g.more || show.getAttribute("aria-expanded") !== "true";
    ol.innerHTML = "";
    g.rows.forEach(function (r) {
      var row = document.createElement("li");
      var dn = document.createElement("span"); dn.className = "dn"; dn.textContent = r.name;
      row.appendChild(dn);
      if (r.text) { var ds = document.createElement("span"); ds.className = "ds"; ds.textContent = r.text; row.appendChild(ds); }
      ol.appendChild(row);
    });
  }
  document.querySelectorAll("#run-doms .dg-show").forEach(function (b) {
    b.addEventListener("click", function () {
      var open = b.getAttribute("aria-expanded") !== "true";
      b.setAttribute("aria-expanded", open ? "true" : "false");
      b.textContent = open ? "Hide" : "Show";
      var said = b.getAttribute("aria-label");
      if (said) b.setAttribute("aria-label", said.replace(/^(Show|Hide)/, open ? "Hide" : "Show"));
      $(b.getAttribute("aria-controls")).hidden = !open;
    });
  });
  var allCounts = false, notesOpen = false, outputOpen = false;
  $("run-notes-show").addEventListener("click", function () {
    notesOpen = !notesOpen;
    if (lastJob) render(lastJob);
  });
  $("run-output").addEventListener("click", function () {
    outputOpen = !outputOpen;
    if (lastJob) render(lastJob);
  });
  // The notes, one item a message, its domains under it.
  function showNotes(p) {
    var ul = $("run-warnings");
    ul.innerHTML = "";
    p.notes.forEach(function (g) {
      var li = document.createElement("li");
      li.appendChild(document.createTextNode(g.text));
      if (g.domains.length) {
        var d = document.createElement("span"); d.className = "nr-doms"; d.textContent = g.domains.join(", ");
        li.appendChild(d);
      }
      ul.appendChild(li);
    });
    var n = p.notes.length;
    $("run-notes-what").hidden = !n;
    $("run-notes-n").textContent = n + (n === 1 ? " warning" : " warnings");
    $("run-notes-show").textContent = notesOpen ? "Hide" : "Show";
    $("run-notes-show").setAttribute("aria-label", notesOpen ? "Hide warnings" : "Show warnings");
    $("run-notes-show").setAttribute("aria-expanded", notesOpen ? "true" : "false");
    ul.hidden = !n || !notesOpen;
    // Collected, the output is a link here (the panel's switch is gone).
    $("run-output").hidden = p.panel;
    $("run-output").textContent = outputOpen ? "Hide collector log" : "Collector log";
    $("run-output").setAttribute("aria-expanded", outputOpen ? "true" : "false");
    $("run-notes").hidden = !n && p.panel;
  }
  $("run-counts-all").addEventListener("click", function () {
    allCounts = !allCounts;
    $("run-counts-all").setAttribute("aria-expanded", allCounts ? "true" : "false");
    if (lastJob) render(lastJob);
  });

  function render(j) {
    lastJob = j;
    var c = j.collect || {};
    var st = c.status || null;
    var collecting = j.status === "collecting";
    if (j.started_at) startedAt = j.started_at * 1000;
    var p = progressView(j, Date.now() / 1000);
    $("run-title").textContent = p.title;
    $("run-phase").textContent = p.sub;
    // While collecting the panel's circle turns; analyzing, the header's.
    $("run-spinner").hidden = collecting;
    group("done", p.groups.done);
    group("skipped", p.groups.skipped);
    group("waiting", p.groups.waiting);
    // The panel: the current domain's phase, bar, numbers and counts.
    $("cp-st").className = "st " + (collecting ? "active" : "done");
    $("cp-dom").hidden = !p.panelName;
    $("cp-dom").textContent = p.panelName;
    $("cp-phase").textContent = p.phase;
    $("cp-step").textContent = p.step;
    var pct = collecting ? (st ? st.percent : 0) : 100;
    $("cp-fill").style.width = pct + "%";
    $("cp-bar").setAttribute("aria-valuenow", String(Math.floor(pct)));
    $("cp-bar").classList.toggle("busy", collecting && !!st && st.step_percent == null);
    $("cp-pct").textContent = Math.floor(pct) + "%";
    $("cp-units").textContent = collecting && st ? units(st) : "";
    // A read in parts: its streams, the parts behind the (i).
    var parts = collecting && st && st.parts ? st.parts : null;
    $("cp-streams").hidden = $("cp-parts").hidden = !parts;
    if (parts) {
      $("cp-streams").textContent = (units(st) ? " · " : "") + num(parts.streams) + (parts.streams === 1 ? " connection" : " connections");
      $("cp-parts-text").textContent = "Split into " + num(parts.parts) + (parts.parts === 1 ? " part; " : " parts; ") + num(Math.min(parts.done, parts.parts)) + " done.";
    } else {
      $("cp-parts").classList.remove("open");
    }
    var left = st || !collecting ? eta(st || {}, collecting) : "";
    if (p.multi && collecting && / left$/.test(left)) left += " in this domain";
    $("cp-eta").textContent = left;
    // Counts: the main kinds in one line, every kind behind All counts.
    var k = p.counts, kindsP = $("run-kinds");
    kindsP.innerHTML = "";
    k.line.forEach(function (it) {
      var s = document.createElement("span");
      var b = document.createElement("strong"); b.textContent = it.n;
      s.appendChild(b); s.appendChild(document.createTextNode(" " + it.word));
      if (it.title) s.title = it.title;
      kindsP.appendChild(s);
    });
    $("run-counts-line").hidden = !k.line.length || verb === "summary";
    $("run-counts-all").hidden = !k.more;
    var counts = $("run-counts");
    counts.innerHTML = "";
    k.tiles.forEach(function (t) {
      var d = document.createElement("div");
      var dt = document.createElement("dt"); dt.textContent = t.dt;
      var dd = document.createElement("dd"); dd.textContent = t.dd;
      d.appendChild(dd); d.appendChild(dt);
      if (t.of) { var of = document.createElement("span"); of.className = "of"; of.textContent = t.of; dt.appendChild(of); }
      counts.appendChild(d);
    });
    counts.hidden = $("run-counts-line").hidden || !k.more || !allCounts;
    // Only for read counts by type, and only with every count open.
    $("run-counts-note").hidden = counts.hidden || !k.readSoFar;
    $("run-steps").classList.toggle("folded", p.stepsFolded);
    // Other collectors' files read with it.
    $("run-also").hidden = !p.also;
    $("run-also-names").textContent = p.also;
    $("run-cur").hidden = !p.panel;
    showNotes(p);
    // Output
    gather(c);
    var box = $("run-log-box"), log = $("run-log");
    box.hidden = p.panel ? verb !== "log" : !outputOpen;
    var atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 24;
    log.textContent = (logLost ? earlierLines(logLost) + "\n" : "") + logLines.join("\n");
    if (atBottom) log.scrollTop = log.scrollHeight;
    $("run-log-n").textContent = c.log_total ? "(" + num(c.log_total) + " lines)" : "";
    // Reading the collection during the analysis: bytes read.
    var rp = $("run-read-pct");
    if (rp) rp.textContent = j.status === "running" && j.phase === "reading" && j.reading && j.reading.total
      ? Math.floor(100 * j.reading.read / j.reading.total) + "%" : "";
    if (j.status === "collecting") {
      mark("collect");
    } else if (j.status === "running") {
      mark(j.phase);
      $("collect-cancel").hidden = true;
      $("run-note").textContent = "Collected. Analyzing now; you can leave this page, it keeps going.";
    }
  }

  function poll() {
    fetch("/api/jobs/" + encodeURIComponent(job), { credentials: "same-origin" })
      .then(function (r) { return r.text().then(function (t) { return { ok: r.ok, data: parse(t) }; }); })
      .then(function (r) {
        if (!r.ok) throw new Error(r.data.error || "Can't get this collection's progress. Reload the page.");
        handle(r.data);
      }, function () { throw new Error("Pathwarden isn't answering. Is it still running?"); })
      .catch(function (e) { failed(e.message || "Can't get this collection's progress. Reload the page."); });
  }

  function handle(j) {
    if (j.status === "collecting" || j.status === "running") {
      showRun();
      render(j);
      setTimeout(poll, j.status === "collecting" ? 700 : 500);
    } else if (j.status === "done") {
      render(j);
      mark(null);
      progressTo(6, false);
      location.href = "/runs/" + encodeURIComponent(j.run);
    } else if (j.status === "ask") {
      // Collected, but where the run goes needs a choice: Analyze asks.
      location.href = "/analyze?job=" + encodeURIComponent(job);
    } else if (j.status === "stopped") {
      go(5);
      view("stopped");
      // Stopped with something read: kept for 24 hours, to resume.
      var kept = !!(j.collect && j.collect.resumable);
      $("stopped-text").textContent = kept
        ? "The collection was stopped. What it read is kept for 24 hours, to resume."
        : "The collection was stopped. Nothing was kept.";
      $("stopped-resume").hidden = !kept;
      $("stopped-over").hidden = !kept;
      $("collect-restart").hidden = kept;
      askPassword($("collect-stopped"), kept);
      job = null;
      refreshNav();
      nav.hidden = true;
    } else {
      failed(j.error || "The collection failed. Open the log for details.", !!(j.collect && j.collect.resumable), j.log);
    }
  }

  // `resumable`: the read stopped and is kept to resume.
  // `log`: the collection's log, for Open log beside the error.
  function failed(message, resumable, log) {
    go(5);
    view("failed");
    var err = $("collect-error");
    err.textContent = "";
    err.className = log ? "err-line" : "";
    var said = document.createElement("span");
    said.textContent = message;
    err.appendChild(said);
    if (log && window.Pathwarden && window.Pathwarden.openLog) {
      var open = document.createElement("button");
      open.type = "button";
      open.className = "linkish";
      open.textContent = "Open log";
      open.addEventListener("click", function () { window.Pathwarden.openLog(log); });
      err.appendChild(open);
    }
    $("failed-resume").hidden = !resumable;
    $("failed-over").hidden = !resumable;
    $("collect-retry").hidden = !!resumable;
    askPassword($("collect-failed"), resumable);
    job = null;
    nav.hidden = true;
  }

  // The password, asked for again next to Resume and Start over: the page
  // forgot it when the collection started.
  function askPassword(box, resumable) {
    var f = box.querySelector(".again-pw");
    f.hidden = !resumable || answers().auth !== "password";
    var input = f.querySelector("input");
    input.value = "";
    input.removeAttribute("aria-invalid");
    var err = f.querySelector(".field-error");
    err.hidden = true;
  }

  // More than one domain: confirm first.
  function confirmDomains(go) {
    var a = answers();
    if (!a.trusted.length) { go(); return; }
    var all = [a.domain.toUpperCase()].concat(a.trusted.map(function (t) { return t.toUpperCase(); }));
    var n = all.length;
    var who = boundAs || (a.auth === "password" ? a.user : "your Windows account");
    $("doms-title").textContent = "Collect " + n + " domains?";
    $("doms-who").textContent = "One after another, signed in as " + who + ", then analyzed together as one run.";
    list($("doms-list"), all);
    $("doms-go").textContent = "Collect " + n + " domains";
    var dlg = $("doms-dialog");
    dlg.returnValue = "";
    dlg.onclose = function () { if (dlg.returnValue === "go") go(); };
    dlg.showModal();
  }

  // Start, or Resume / Start over a read that stopped.
  function begin(resume) {
    if (where && where.choice() === null) { toast("Choose where the run goes first."); return; }
    confirmDomains(function () { startCollecting(resume); });
  }
  $("collect-start").addEventListener("click", function () { begin(false); });
  $("collect-resume").addEventListener("click", function () { begin(true); });
  $("collect-over").addEventListener("click", function () { begin(false); });
  function startCollecting(resume) {
    var buttons = ["collect-start", "collect-resume", "collect-over"].map($);
    function enable(on) { buttons.forEach(function (b) { b.disabled = !on; }); }
    enable(false);
    var a = payload();
    a.resume = !!resume;
    alsoUpload().then(function (id) {
      if (id) a.also = id;
      return post("/api/collect/start", a);
    }, function (e) {
      enable(true);
      toast(e.message);
      return null;
    }).then(function (r) {
      if (!r) return;
      enable(true);
      if (!r.ok) {
        if (r.data.step && r.data.step < 5) {
          go(r.data.step);
          if (r.data.field) fieldError(r.data.field, r.data.error);
          else toast(r.data.error);
        } else {
          toast(r.data.error || "Couldn't start the collection. Try again.");
        }
        return;
      }
      // The password has done its job in this page, and the answers too.
      $("password").value = "";
      forget();
      stoppedFor = null;
      logLines = []; logSeen = 0; logLost = 0;
      job = r.data.job;
      startedAt = Date.now();
      try { history.replaceState(null, "", "/collect?job=" + encodeURIComponent(job)); } catch (e) {}
      showRun();
      mark("collect");
      refreshNav();
      poll();
    }, function () {
      enable(true);
      toast("Pathwarden isn't answering. Is it still running?");
    });
  }

  // Stopping asks first: a read that can't be resumed is lost.
  $("collect-cancel").addEventListener("click", function () {
    var dlg = $("stop-dialog");
    if (dlg && dlg.showModal) {
      dlg.returnValue = "";
      dlg.onclose = function () { if (dlg.returnValue === "stop") stopCollecting(); };
      dlg.showModal();
    } else if (confirm("Stop collecting? Anything that can be resumed is kept for 24 hours.")) {
      stopCollecting();
    }
  });
  function stopCollecting() {
    var b = $("collect-cancel");
    b.disabled = true;
    $("run-phase").textContent = "Stopping\u2026";
    post("/api/collect/" + encodeURIComponent(job) + "/cancel").then(function (r) {
      if (!r.ok) { b.disabled = false; toast(r.data.error || "Couldn't stop the collection. Try again."); }
    }, function () { b.disabled = false; toast("Pathwarden isn't answering. Is it still running?"); });
  }

  function restart(toStep) {
    try { history.replaceState(null, "", "/collect"); } catch (e) {}
    $("collect-cancel").hidden = false;
    $("collect-cancel").disabled = false;
    $("run-note").textContent = "You can leave this page; collecting continues.";
    view("ready");
    job = null;
    nav.hidden = false;
    checked = false;
    showCheck("idle");
    go(toStep);
  }
  $("collect-restart").addEventListener("click", function () { restart(1); });
  $("collect-retry").addEventListener("click", function () { restart(4); });
  // A read that stopped: resumed, or started over, with the same answers.
  // The password is gone from the page once a collection starts: asked
  // for again first.
  function again(resume, box) {
    var f = box.querySelector(".again-pw");
    if (!f.hidden) {
      var input = f.querySelector("input");
      if (!input.value) { fieldError(input.id, "Enter the password to continue."); return; }
      $("password").value = input.value;
      input.value = "";
    }
    var typeAgain = answers().auth === "password" && !$("password").value;
    restart(typeAgain ? 2 : 5);
    if (typeAgain) { fieldError("password", "Enter the password again to continue."); return; }
    begin(resume);
  }
  $("failed-resume").addEventListener("click", function () { again(true, $("collect-failed")); });
  $("failed-over").addEventListener("click", function () { again(false, $("collect-failed")); });
  $("stopped-resume").addEventListener("click", function () { again(true, $("collect-stopped")); });
  $("stopped-over").addEventListener("click", function () { again(false, $("collect-stopped")); });

  // Start: resume a collection, or the answers kept for this tab, or
  // step 1.
  setVerb(verb);
  var existing = wiz.getAttribute("data-job");
  // A link's picks win over the answers kept for this tab.
  var resumeAt = existing || PICK.length ? 0 : restore();
  sync();
  loadTrusted(true);
  if (existing) {
    job = existing;
    var initial = parse(wiz.getAttribute("data-initial") || "{}");
    handle(initial.status ? initial : { status: "collecting" });
  } else {
    go(resumeAt || 1, true);
  }
})();
