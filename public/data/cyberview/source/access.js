// CyberView data access page (access.html, rendered by scripts/pages.mjs from config/data-access.json).
// Filters the list by kind, reason and country, and shows and copies a source's own request (data-request on its row).
// Nothing is sent and nothing is stored: the maintainer sends each request himself.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  function safe(fn) { try { fn(); } catch (e) { if (window.console) console.warn("access: " + (e && e.message)); } }
  var rows = Array.prototype.slice.call(document.querySelectorAll("#sources tr[data-why]"));
  var groups = Array.prototype.slice.call(document.querySelectorAll("#sources .acgroup"));
  var kinds = Array.prototype.slice.call(document.querySelectorAll("#sources .ackind"));

  // filter by reason and country
  safe(function () {
    var fWhy = $("fWhy"), fCountry = $("fCountry"), fKind = $("fKind"), count = $("fCount"), box = $("acFilters");
    if (!fWhy || !fCountry || !count) return;
    function apply() {
      var w = fWhy.value, c = fCountry.value, k = fKind ? fKind.value : "", shown = 0;
      rows.forEach(function (tr) { var on = (!w || tr.getAttribute("data-why") === w) && (!c || tr.getAttribute("data-country") === c) && (!k || tr.getAttribute("data-kind") === k); tr.hidden = !on; if (on) shown++; });
      groups.forEach(function (g) { g.hidden = !g.querySelector("tr[data-why]:not([hidden])"); });
      kinds.forEach(function (g) { g.hidden = !g.querySelector("tr[data-why]:not([hidden])"); });
      count.textContent = "Showing " + shown + " of " + rows.length + " sources.";
    }
    fWhy.addEventListener("change", apply);
    fCountry.addEventListener("change", apply);
    if (fKind) fKind.addEventListener("change", apply);
    if (box) box.hidden = false;
    apply();
  });

  // each source's own request, shown and copied (the template fill is only a fallback for a row without one)
  safe(function () {
    var pre = $("reqText"), msg = $("reqMsg");
    if (!pre || !msg) return;
    var tpl = pre.textContent;
    function fill(op, feed) { return tpl.split("[operator]").join(op).split("[feed]").join(feed); }
    function selectPre() { try { var r = document.createRange(); r.selectNodeContents(pre); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); } catch (e) {} }
    function copy(tr) {
      var op = String(tr.getAttribute("data-operator") || "").slice(0, 120), feed = String(tr.getAttribute("data-feed") || "").slice(0, 160);
      var own = String(tr.getAttribute("data-request") || "").slice(0, 2000);
      var text = own || fill(op, feed);
      pre.textContent = text;
      var done = function () { msg.textContent = "Copied the request for " + op + ". Paste it into an email or the operator's contact form; nothing has been sent."; };
      var manual = function () { selectPre(); msg.textContent = "The request for " + op + " is filled in above and selected: copy it with Ctrl+C (or Cmd+C)."; };
      try { if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, manual); else manual(); } catch (e) { manual(); }
      var panel = $("request"); if (panel && panel.scrollIntoView) panel.scrollIntoView({ block: "start", behavior: "smooth" });
    }
    rows.forEach(function (tr) {
      var b = tr.querySelector("button.copyreq"); if (!b) return;
      b.hidden = false;
      b.setAttribute("aria-label", "Copy request to " + (tr.getAttribute("data-operator") || "this operator"));
      b.addEventListener("click", function () { copy(tr); });
    });
  });
})();
