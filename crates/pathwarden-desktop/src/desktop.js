// Pathwarden window: what the native window adds to the app's pages.
// WebView2 runs this in every document it creates, before the page's own
// scripts and outside its CSP, so it does nothing unless it is the
// window's top-level app page.
//
// - Analyze: collector files and folders are picked with a native dialog,
//   or dropped on the window, one or more at a time. They are listed under
//   the drop area and analyzed where they are (app.js sends each as a
//   `path` field, through window.pwPaths), never uploaded through the
//   webview, which would hold them in memory.
// - Downloads (`<a download>`) go through a native Save dialog.
(function () {
  "use strict";
  if (window.top !== window || location.origin !== "https://pathwarden.localhost") return;

  function post(path, body) {
    return fetch(path, { method: "POST", body: body || "", credentials: "same-origin" })
      .then(function (r) { return r.status === 204 ? null : r.json(); })
      .catch(function () { return null; });
  }

  // The picked paths, in order, without repeats.
  var paths = [];
  var list = null, pathField = null;
  window.pwPaths = function () { return paths.slice(); };

  function icon(id) {
    var s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("class", "ic");
    s.setAttribute("aria-hidden", "true");
    var u = document.createElementNS("http://www.w3.org/2000/svg", "use");
    u.setAttribute("href", "#" + id);
    s.appendChild(u);
    return s;
  }

  function render() {
    if (!list) return;
    list.textContent = "";
    paths.forEach(function (p, i) {
      var file = /\.(zip|json)$/i.test(p);
      var li = document.createElement("li");
      li.className = "card";
      var name = document.createElement("span");
      name.className = "fl-name";
      name.textContent = p;
      var kind = document.createElement("span");
      kind.className = "muted small";
      kind.textContent = file ? "File" : "Folder";
      var x = document.createElement("button");
      x.type = "button";
      x.className = "fl-remove";
      x.setAttribute("aria-label", "Remove " + p);
      x.appendChild(icon("i-x"));
      x.addEventListener("click", function () { paths.splice(i, 1); render(); });
      li.appendChild(icon(file ? "i-file" : "i-folder"));
      li.appendChild(name);
      li.appendChild(kind);
      li.appendChild(x);
      list.appendChild(li);
    });
    list.hidden = paths.length === 0;
    // app.js recounts what is chosen and enables Start.
    if (pathField) pathField.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function add(more) {
    if (!list || !Array.isArray(more)) return;
    more.forEach(function (p) {
      if (typeof p === "string" && p && paths.indexOf(p) < 0) paths.push(p);
    });
    render();
  }

  // Files and folders dropped on the window (the window hands over their paths).
  window.__pathwardenDropped = add;

  // Downloads: the window saves them with a native dialog.
  document.addEventListener("click", function (e) {
    var a = e.target && e.target.closest ? e.target.closest("a[download]") : null;
    if (!a) return;
    var u = new URL(a.getAttribute("href"), location.href);
    if (u.origin !== location.origin) return;
    e.preventDefault();
    post("/__desktop/save", u.pathname + u.search);
  }, true);

  document.addEventListener("DOMContentLoaded", function () {
    var drop = document.getElementById("dropzone");
    pathField = document.getElementById("path");
    if (!drop || !pathField) { pathField = null; return; }
    var title = drop.querySelector(".dz-title");
    if (title) title.textContent = "Drop files or folders here, or click to choose files";
    var hint = drop.querySelector(".dz-hint");
    if (hint) hint.textContent = ".zip or .json, one or more. They are analyzed where they are, not uploaded.";
    list = document.createElement("ul");
    list.className = "filelist";
    list.id = "pathlist";
    list.hidden = true;
    var uploads = document.getElementById("filelist");
    (uploads || drop).insertAdjacentElement("afterend", list);
    drop.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      post("/__desktop/pick-file").then(function (r) { if (r) add(r.paths); });
    }, true);
    var folder = document.createElement("button");
    folder.type = "button";
    folder.className = "btn small";
    folder.textContent = "Choose folders";
    folder.addEventListener("click", function () {
      post("/__desktop/pick-folder").then(function (r) { if (r) add(r.paths); });
    });
    pathField.parentNode.appendChild(folder);
  });
})();
