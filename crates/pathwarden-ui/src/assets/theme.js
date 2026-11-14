// Applies the theme before the page paints: the one chosen with the theme
// button (the same choice the report remembers), else the system's. The rail's Crown W draws itself on the first page of a
// session only (`.cw-intro`, report.css); after that it just keeps its idle
// pulse, so moving between pages doesn't replay it.
(function () {
  var root = document.documentElement;
  var t = null;
  try { t = localStorage.getItem("pathwarden-theme"); } catch (e) {}
  if (t !== "light" && t !== "dark") {
    try { t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"; } catch (e) { t = null; }
  }
  if (t === "light" || t === "dark") root.setAttribute("data-theme", t);
  try {
    if (!sessionStorage.getItem("pathwarden-intro")) {
      sessionStorage.setItem("pathwarden-intro", "1");
      root.classList.add("cw-intro");
    }
  } catch (e) {}
})();
