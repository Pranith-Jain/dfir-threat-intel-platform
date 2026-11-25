// CyberView library page. Reads data/orkl-index.json (one compact row per report and per actor, mirrored from ORKL)
// and lets you browse and search the catalogue. CyberView stores the title, source, year, language and the links to
// ORKL only, never the report text. All text is inserted as text, never as HTML; every link is rebuilt and host-checked.
(function () {
  "use strict";
  var PAGE = 60;
  var reports = [], actors = [], sources = [], langs = [];
  var shown = PAGE, actShown = PAGE, OPEN = "", paneTitle = "", actorFilter = "", actorCount = {}, tab = "reports";
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function safe(name, fn) { try { fn(); } catch (e) { if (window.console) console.warn("library: " + name + " could not be drawn", e); } }

  // Every link back to ORKL is rebuilt here from a validated id and checked against the ORKL hosts, never taken from data.
  // Reports: the PDF lives at archive.orkl.eu/<sha1>.pdf; the library page at orkl.eu/library/<id>. Named orklUrl so the
  // security check (scripts/security-check.mjs) accepts it as an href source.
  function orklUrl(kind, v) {
    var s = String(v == null ? "" : v), u = "";
    if (kind === "pdf") { if (/^[0-9a-f]{40}$/.test(s)) u = "https://archive.orkl.eu/" + s + ".pdf"; }
    else if (kind === "lib") { if (/^[0-9A-Za-z._-]{1,64}$/.test(s)) u = "https://orkl.eu/library/" + s; }
    if (!u) return "";
    try { var x = new URL(u); if (x.protocol !== "https:" || !/^(archive\.)?orkl\.eu$/.test(x.hostname)) return ""; return x.href; } catch (e) { return ""; }
  }

  var LANG = null; try { LANG = new Intl.DisplayNames(["en"], { type: "language" }); } catch (e) { LANG = null; }
  function langName(code) {
    if (!code || code === "none") return "Unknown language";
    if (LANG) { try { var n = LANG.of(code); if (n && n.toLowerCase() !== code.toLowerCase()) return n; } catch (e) {} }
    return code;
  }
  function srcName(i) { return sources[i] || ""; }

  function load() {
    fetch("data/orkl-index.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }).then(function (d) {
      sources = Array.isArray(d.sources) ? d.sources : [];
      langs = Array.isArray(d.langs) ? d.langs : [];
      reports = (Array.isArray(d.reports) ? d.reports : []).map(function (r) {
        r.a = Array.isArray(r.a) ? r.a : []; r.c = Array.isArray(r.c) ? r.c : [];
        r._s = ((r.t || "") + " " + r.a.join(" ")).toLowerCase();
        r.a.forEach(function (n) { actorCount[n] = (actorCount[n] || 0) + 1; });
        return r;
      });
      actors = (Array.isArray(d.actors) ? d.actors : []).map(function (a) {
        a.al = Array.isArray(a.al) ? a.al : [];
        a._s = ((a.n || "") + " " + a.al.join(" ")).toLowerCase();
        return a;
      });
      var rt = typeof d.reports_total === "number" ? d.reports_total : reports.length;
      var at = typeof d.actors_total === "number" ? d.actors_total : actors.length;
      $("summary").textContent = rt.toLocaleString("en") + " public threat-intelligence reports and " + at.toLocaleString("en") + " tracked threat actors, mirrored from ORKL. CyberView keeps the titles and links; each report is read on ORKL.";
      $("repN").textContent = rt.toLocaleString("en");
      $("actN").textContent = at.toLocaleString("en");
      safe("filters", fillFilters);
      readHash();
      render(); renderActors();
      // a link to one report (library.html#r=<sha1>) opens it straight away
      var want = OPEN; OPEN = "";
      if (want) { var hit = reports.filter(function (r) { return r.s === want; })[0]; if (hit) openReport(hit, true); }
    }).catch(function () { $("summary").textContent = "The library can't be loaded right now. Try again in a minute."; });
  }

  function fillFilters() {
    var usedSrc = {}; reports.forEach(function (r) { r.c.forEach(function (i) { usedSrc[i] = 1; }); });
    Object.keys(usedSrc).map(Number).sort(function (a, b) { return srcName(a).localeCompare(srcName(b)); }).forEach(function (i) {
      if (!srcName(i)) return; var o = el("option", null, srcName(i)); o.value = String(i); $("source").appendChild(o);
    });
    var usedYr = {}, undated = false; reports.forEach(function (r) { if (r.y) usedYr[r.y] = 1; else undated = true; });
    Object.keys(usedYr).sort().reverse().forEach(function (y) { var o = el("option", null, y); o.value = y; $("year").appendChild(o); });
    if (undated) { var ou = el("option", null, "Undated"); ou.value = "none"; $("year").appendChild(ou); }
    var usedLg = {}; reports.forEach(function (r) { usedLg[r.l] = 1; });
    Object.keys(usedLg).map(Number).sort(function (a, b) { return langName(langs[a]).localeCompare(langName(langs[b])); }).forEach(function (i) {
      var o = el("option", null, langName(langs[i])); o.value = String(i); $("lang").appendChild(o);
    });
  }

  function matches(r) {
    var q = $("q").value.trim().toLowerCase(), src = $("source").value, yr = $("year").value, lg = $("lang").value;
    if (actorFilter && r.a.indexOf(actorFilter) < 0) return false;
    if (src !== "" && r.c.indexOf(Number(src)) < 0) return false;
    if (yr === "none") { if (r.y) return false; } else if (yr && r.y !== yr) return false;
    if (lg !== "" && String(r.l) !== lg) return false;
    if (!q) return true;
    return r._s.indexOf(q) >= 0;
  }

  function render() {
    var list = reports.filter(matches), box = $("list");
    box.textContent = "";
    $("count").textContent = list.length.toLocaleString("en") + " report" + (list.length === 1 ? "" : "s") + (list.length > shown ? ", showing " + shown.toLocaleString("en") : "");
    if (!list.length) { box.appendChild(el("li", "empty", "Nothing matches. Clear a filter or try another word.")); }
    list.slice(0, shown).forEach(function (r) { box.appendChild(rowEl(r)); });
    $("more").hidden = list.length <= shown;
    $("clear").hidden = !(actorFilter || $("source").value || $("year").value || $("lang").value || $("q").value.trim());
    showActorChip();
  }
  function changed() {
    if (tab === "reports") { shown = PAGE; render(); var v = document.querySelector("#repGrid .vlist"); if (v) v.scrollTop = 0; }
    else { actShown = PAGE; renderActors(); var a = document.querySelector("#actView .vlist"); if (a) a.scrollTop = 0; }
    writeHash();
  }

  function rowEl(r) {
    var li = el("li", "row"); li.id = "rp-" + r.s;
    var b = el("button"); b.type = "button"; b.setAttribute("aria-controls", "pane");
    b.setAttribute("aria-expanded", r.s === OPEN ? "true" : "false"); if (r.s === OPEN) li.classList.add("on");
    b.appendChild(el("span", "date", r.y || "Undated"));
    b.appendChild(el("span", "ttl", r.t || "Untitled report"));
    var meta = el("span", "meta");
    r.c.slice(0, 2).forEach(function (i) { var s = srcName(i); if (s) meta.appendChild(el("span", null, s)); });
    var lc = langs[r.l]; if (lc && lc !== "none") meta.appendChild(el("span", null, langName(lc)));
    r.a.slice(0, 3).forEach(function (n) { meta.appendChild(el("span", "pill", n)); });
    b.appendChild(meta);
    b.addEventListener("click", function () { if (OPEN === r.s) closePane(); else openReport(r); });
    li.appendChild(b); return li;
  }

  // one report's catalogue record, as text, in the detail pane: the sources, year, language, the actors it names
  // (each a button that filters the list), and the rebuilt links to read it on ORKL. Never the report body.
  function details(box, r) {
    var m = el("p", "armeta");
    r.c.forEach(function (i) { var s = srcName(i); if (s) m.appendChild(el("span", "cat", s)); });
    m.appendChild(el("span", null, r.y || "Undated"));
    var lc = langs[r.l]; if (lc) m.appendChild(el("span", null, langName(lc)));
    box.appendChild(m);
    box.appendChild(el("p", "note", "Catalogued from ORKL. CyberView stores the title, source and links only — the report itself is read on ORKL."));
    if (r.a.length) {
      box.appendChild(el("h3", null, r.a.length === 1 ? "Threat actor named" : "Threat actors named"));
      var ap = el("p", "arcves");
      r.a.slice(0, 20).forEach(function (n) { var btn = el("button", "pill", n); btn.type = "button"; btn.addEventListener("click", function () { filterByActor(n); }); ap.appendChild(btn); });
      box.appendChild(ap);
    }
    box.appendChild(el("h3", null, "Read it on ORKL"));
    var ul = el("ul"), any = false;
    if (orklUrl("lib", r.i)) { var la = el("a", null, "ORKL library page"); la.href = orklUrl("lib", r.i); la.target = "_blank"; la.rel = "noopener noreferrer"; var li1 = el("li"); li1.appendChild(la); ul.appendChild(li1); any = true; }
    if (orklUrl("pdf", r.s)) { var pa = el("a", null, "Download the report (PDF)"); pa.href = orklUrl("pdf", r.s); pa.target = "_blank"; pa.rel = "noopener noreferrer"; var li2 = el("li"); li2.appendChild(pa); ul.appendChild(li2); any = true; }
    if (any) box.appendChild(ul); else box.appendChild(el("p", "note", "No ORKL link is available for this report."));
    var lp = el("p", "arlink"), lk = el("a", null, "Link to this report");
    lk.href = "library.html#r=" + encodeURIComponent(r.s); lp.appendChild(lk); box.appendChild(lp);
  }

  function narrow() { return window.innerWidth < 1240; }
  function paneSync() {
    var p = $("pane"), d = $("det"), has = d.childNodes.length > 0;
    p.classList.toggle("has", has); $("repGrid").classList.toggle("vopen", has);
    p.querySelector(".vdtitle").textContent = has ? paneTitle : "";
    document.documentElement.classList.toggle("vsheet", has && narrow());
  }
  function mark() {
    [].forEach.call($("list").querySelectorAll(".row"), function (li) { var on = li.id === "rp-" + OPEN; li.classList.toggle("on", on); li.firstChild.setAttribute("aria-expanded", on ? "true" : "false"); });
  }
  function openReport(r, fromLink) {
    OPEN = r.s; paneTitle = r.t || "Report"; mark();
    var d = $("det"); d.textContent = ""; details(d, r);
    paneSync(); $("pane").scrollTop = 0; writeHash();
    if (narrow()) $("pane").querySelector(".vdclose").focus({ preventScroll: true });
    if (fromLink) { var n = $("rp-" + r.s); if (n && !narrow()) try { n.scrollIntoView({ block: "nearest" }); } catch (x) {} }
  }
  function closePane() {
    var back = OPEN ? $("rp-" + OPEN) : null;
    OPEN = ""; paneTitle = ""; $("det").textContent = ""; mark(); paneSync(); writeHash();
    if (back) back.firstChild.focus({ preventScroll: true });
  }

  function showActorChip() {
    var c = $("actorChip");
    if (!actorFilter) { c.hidden = true; c.textContent = ""; return; }
    c.hidden = false; c.textContent = "Showing reports that name " + actorFilter + ". Clear the filters to see the rest.";
  }
  function filterByActor(name) {
    actorFilter = name; $("q").value = "";
    ["source", "year", "lang"].forEach(function (k) { $(k).value = ""; });
    if (OPEN) closePane();
    showTab("reports"); changed();
    var v = document.querySelector("#repGrid .vlist"); if (v) v.scrollTop = 0;
  }

  function actMatches(a) { var q = $("q").value.trim().toLowerCase(); return !q || a._s.indexOf(q) >= 0; }
  function renderActors() {
    var list = actors.filter(actMatches), box = $("actList");
    box.textContent = "";
    $("actCount").textContent = list.length.toLocaleString("en") + " threat actor" + (list.length === 1 ? "" : "s") + (list.length > actShown ? ", showing " + actShown.toLocaleString("en") : "");
    if (!list.length) { box.appendChild(el("li", "empty", "No actor matches that search.")); }
    list.slice(0, actShown).forEach(function (a) { box.appendChild(actorEl(a)); });
    $("actMore").hidden = list.length <= actShown;
  }
  function actorEl(a) {
    var li = el("li", "row");
    var b = el("button"); b.type = "button";
    var rc = actorCount[a.n] || 0;
    b.appendChild(el("span", "date", rc.toLocaleString("en")));
    b.appendChild(el("span", "ttl", a.n));
    var meta = el("span", "meta");
    meta.appendChild(el("span", null, rc + " report" + (rc === 1 ? "" : "s") + " in the library"));
    if (a.s) meta.appendChild(el("span", null, "tracked by " + a.s));
    a.al.slice(0, 5).forEach(function (al) { meta.appendChild(el("span", "pill", al)); });
    b.appendChild(meta);
    b.setAttribute("aria-label", a.n + ": show its " + rc + " report" + (rc === 1 ? "" : "s"));
    b.addEventListener("click", function () { filterByActor(a.n); });
    li.appendChild(b); return li;
  }

  function showTab(which) {
    tab = which === "actors" ? "actors" : "reports";
    var rep = tab === "reports";
    $("tabReports").setAttribute("aria-selected", rep ? "true" : "false");
    $("tabActors").setAttribute("aria-selected", rep ? "false" : "true");
    $("repGrid").hidden = !rep; $("actView").hidden = rep;
    if (rep) render(); else renderActors();
  }

  function writeHash() {
    var p = new URLSearchParams();
    if (tab === "actors") p.set("tab", "actors");
    if ($("q").value.trim()) p.set("q", $("q").value.trim());
    if (actorFilter) p.set("actor", actorFilter);
    if ($("source").value && srcName(Number($("source").value))) p.set("src", srcName(Number($("source").value)));
    if ($("year").value) p.set("year", $("year").value);
    if ($("lang").value && langs[Number($("lang").value)]) p.set("lang", langs[Number($("lang").value)]);
    if (OPEN) p.set("r", OPEN);
    var h = p.toString(); try { history.replaceState(null, "", h ? "#" + h : location.pathname + location.search); } catch (e) {}
  }
  function readHash() {
    var p = new URLSearchParams(location.hash.slice(1));
    if (p.get("q")) $("q").value = p.get("q");
    if (p.get("actor")) actorFilter = p.get("actor");
    if (p.get("src")) { for (var i = 0; i < sources.length; i++) { if (sources[i] === p.get("src")) { $("source").value = String(i); break; } } }
    if (p.get("year")) $("year").value = p.get("year");
    if (p.get("lang")) { for (var j = 0; j < langs.length; j++) { if (langs[j] === p.get("lang")) { $("lang").value = String(j); break; } } }
    if (p.get("tab") === "actors") showTab("actors");
    if (p.get("r")) OPEN = p.get("r");
  }

  ["filters", "qform"].forEach(function (f) { var n = $(f); if (n) n.addEventListener("submit", function (e) { e.preventDefault(); }); });
  var t; $("q").addEventListener("input", function () { clearTimeout(t); t = setTimeout(changed, 150); });
  ["source", "year", "lang"].forEach(function (k) { $(k).addEventListener("change", changed); });
  $("clear").addEventListener("click", function () { actorFilter = ""; $("q").value = ""; ["source", "year", "lang"].forEach(function (k) { $(k).value = ""; }); changed(); });
  $("tabReports").addEventListener("click", function () { showTab("reports"); writeHash(); });
  $("tabActors").addEventListener("click", function () { showTab("actors"); writeHash(); });
  $("pane").querySelector(".vdclose").addEventListener("click", closePane);
  $("more").addEventListener("click", function () { shown += PAGE; render(); });
  $("actMore").addEventListener("click", function () { actShown += PAGE; renderActors(); });
  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement || {}).tagName || "", typing = /^(INPUT|TEXTAREA|SELECT)$/.test(tag) || (document.activeElement && document.activeElement.isContentEditable);
    if (e.key === "Escape" && OPEN && !typing) { e.preventDefault(); closePane(); }
    else if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !typing) { e.preventDefault(); $("q").focus(); }
  });
  var rz; window.addEventListener("resize", function () { clearTimeout(rz); rz = setTimeout(paneSync, 120); });
  load();
})();
