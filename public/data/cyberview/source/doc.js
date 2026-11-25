// Document pages (About, Privacy, Terms, Tools; laid out by scripts/pages.mjs docLayout): the page's own search and
// the "On this page" contents rail. Search hides the sections (and list items) that do not mention the words and marks
// each match; matches are <mark> nodes made with createElement, nothing is ever parsed as HTML.
(function () {
  "use strict";
  var q = document.getElementById("q"), form = document.getElementById("qform"), qc = document.getElementById("qcount");
  var secs = [].slice.call(document.querySelectorAll(".docbody > section"));
  var toc = document.querySelector(".doctoc"), links = {};
  if (toc) [].forEach.call(toc.querySelectorAll("a[href^='#']"), function (a) { links[a.getAttribute("href").slice(1)] = a; });

  function plural(n, w) { return n + " " + w + (n === 1 ? "" : "s"); }
  function items(sec) { return [].slice.call(sec.querySelectorAll(":scope > ul > li, :scope > ol > li, tbody > tr")); }
  function has(node, t) { return node.textContent.toLowerCase().indexOf(t) >= 0; }
  function unmark(root) {
    [].slice.call(root.querySelectorAll("mark.qm")).forEach(function (m) {
      var p = m.parentNode; p.replaceChild(document.createTextNode(m.textContent), m); p.normalize();
    });
  }
  function mark(root, t) {
    var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null), found = [], n;
    while ((n = w.nextNode())) if (n.nodeValue.toLowerCase().indexOf(t) >= 0) found.push(n);
    found.forEach(function (node) {
      var s = node.nodeValue, lo = s.toLowerCase(), i = 0, j, f = document.createDocumentFragment();
      while ((j = lo.indexOf(t, i)) >= 0) {
        if (j > i) f.appendChild(document.createTextNode(s.slice(i, j)));
        var m = document.createElement("mark"); m.className = "qm"; m.textContent = s.slice(j, j + t.length); f.appendChild(m);
        i = j + t.length;
      }
      if (i < s.length) f.appendChild(document.createTextNode(s.slice(i)));
      node.parentNode.replaceChild(f, node);
    });
  }

  function run() {
    var raw = (q && q.value || "").trim().slice(0, 80), t = raw.toLowerCase(), hit = 0;
    secs.forEach(function (s) { unmark(s); s.hidden = false; items(s).forEach(function (i) { i.hidden = false; }); });
    if (t) secs.forEach(function (s) {
      if (!has(s, t)) { s.hidden = true; return; }
      hit++;
      var head = s.querySelector("h2"), its = items(s);
      // a heading match shows the whole section; otherwise keep only the list items that match, if any do
      if (!(head && has(head, t)) && its.some(function (i) { return has(i, t); })) its.forEach(function (i) { i.hidden = !has(i, t); });
      mark(s, t);
    });
    Object.keys(links).forEach(function (id) { var s = document.getElementById(id); links[id].classList.toggle("off", !!(s && s.hidden)); });
    if (qc) {
      qc.hidden = !t;
      qc.textContent = !t ? "" : hit ? plural(hit, "section") + (hit === 1 ? " mentions" : " mention") + " “" + raw + "”." : "Nothing on this page mentions “" + raw + "”. Clear the search to read everything.";
    }
  }

  if (form) form.addEventListener("submit", function (e) { e.preventDefault(); run(); });
  if (q) {
    var timer = 0;
    q.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(run, 120); });
    q.addEventListener("keydown", function (e) { if (e.key === "Escape" && q.value) { q.value = ""; run(); } });
    document.addEventListener("keydown", function (e) {
      var tag = (e.target && e.target.tagName) || "";
      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(tag) && !(e.target && e.target.isContentEditable)) { e.preventDefault(); q.focus(); }
    });
  }

  // the contents rail follows the reader: the first section in view is the current one
  if (toc && "IntersectionObserver" in window && secs.length) {
    var seen = {};
    var io = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) { seen[en.target.id] = en.isIntersecting; });
      var cur = null;
      for (var i = 0; i < secs.length; i++) if (seen[secs[i].id] && !secs[i].hidden) { cur = secs[i].id; break; }
      if (!cur) return;
      Object.keys(links).forEach(function (id) {
        if (id === cur) links[id].setAttribute("aria-current", "location"); else links[id].removeAttribute("aria-current");
      });
      // keep the current link visible in the rail without moving the page (the rail scrolls sideways on narrow screens)
      var a = links[cur], ol = a && a.closest("ol");
      if (ol && ol.scrollWidth > ol.clientWidth) {
        var l = a.offsetLeft - ol.offsetLeft, r = l + a.offsetWidth;
        if (l < ol.scrollLeft || r > ol.scrollLeft + ol.clientWidth) ol.scrollLeft = Math.max(0, l - 24);
      }
    }, { rootMargin: "-20% 0px -55% 0px" });
    secs.forEach(function (s) { io.observe(s); });
  }
})();
