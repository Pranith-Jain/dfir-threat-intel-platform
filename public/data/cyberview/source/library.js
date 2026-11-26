// CyberView library page. Reads data/orkl-index.json (one compact row per report and per actor, mirrored from ORKL)
// and lets you browse and search the catalogue in pages. The catalogue holds the title, source, year, language and the
// links to ORKL, never the report text. All text is inserted as text, never as HTML; every link is rebuilt and
// host-checked. A link to one record (library.html#r=<sha1> for a report, #tab=actors&ta=<ORKL id> for an actor)
// opens that record straight away, on the page of the list that holds it.
// CyberView AI (a Claude model) also reads some of the reports: a read report shows a plain-language summary and the facts it
// names (data/library/cards/<xx>.json), and an actor, or a group of reports on one subject, shows a reviewed story in which every
// sentence cites the reports it came from (data/library/stories/<key>.json; #story=<key> opens one). Everything fetched is
// cleaned here again (cleanCard, cleanStory, cleanStoryIndex) and only ever inserted as text.
(function () {
  "use strict";
  var PAGE = 50;
  var reports = [], actors = [], sources = [], langs = [];
  var repPage = 0, actPage = 0, OPEN = "", OPEN_ACT = "", paneTitle = "", actTitle = "", actorFilter = "", actorCount = {}, tab = "reports";
  var byName = {}, profiles = null;
  var AI_BY = "CyberView AI (a Claude model)";
  var FAIL = "This write-up can't be loaded right now.";
  var SHA1 = /^[0-9a-f]{40}$/, SKEY = /^[A-Za-z0-9-]{1,70}$/, CVE = /^CVE-\d{4}-\d{4,7}$/i;
  var SECHEAD = { who: "Who they are", targets: "Who they go after", methods: "How they work", operations: "Notable operations", takeaway: "What defenders should take from it" };
  var OPEN_STORY = "", shards = {}, storyCache = {}, storyIdx = null;
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function safe(name, fn) { try { fn(); } catch (e) { if (window.console) console.warn("library: " + name + " could not be drawn", e); } }
  function plural(n, w) { return n.toLocaleString("en") + " " + w + (n === 1 ? "" : "s"); }
  var DAYFMT = null; try { DAYFMT = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { DAYFMT = null; }
  function fmtDate(iso) { var t = Date.parse(iso); return isFinite(t) && DAYFMT ? DAYFMT.format(new Date(t)) : ""; }

  /* ---------- cleaning what the build published (length limits; the build cleaned it already, this is the second check) ---------- */
  function clip(v, n) { return String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, n); }
  function list(v, max) { return Array.isArray(v) ? v.slice(0, max) : []; }
  function isObj(x) { return !!x && typeof x === "object" && !Array.isArray(x); }
  function cleanCard(raw) {
    if (!isObj(raw)) return null;
    var sm = clip(raw.sm, 600); if (!sm) return null;
    var f = isObj(raw.f) ? raw.f : {}, out = { sm: sm, k: clip(raw.k, 40), p: raw.p === true, f: {} };
    function vals(k, withBy) {
      return list(f[k], 20).map(function (x) {
        if (isObj(x)) { var v = clip(x.v, 200); return v ? { v: v, by: clip(withBy ? x.by : "", 120) } : null; }
        var s = clip(x, 200); return s ? { v: s, by: "" } : null;
      }).filter(Boolean);
    }
    ["a", "s", "c", "t"].forEach(function (k) { out.f[k] = vals(k, k === "a"); });
    out.f.v = vals("v", false).filter(function (x) { return CVE.test(x.v); }).map(function (x) { return { v: x.v.toUpperCase(), by: "" }; });
    return out;
  }
  function cleanStory(raw, key) {
    if (!isObj(raw) || raw.key !== key || !SKEY.test(key)) return null;
    var src = list(raw.src, 80).map(function (x) {
      if (!isObj(x) || !SHA1.test(String(x.sha1))) return null;
      return { sha1: x.sha1, title: clip(x.title, 300) || "Untitled report", authors: list(x.authors, 5).map(function (a) { return clip(a, 120); }).filter(Boolean), year: /^\d{4}$/.test(String(x.year)) ? String(x.year) : "" };
    }).filter(Boolean);
    var inSrc = {}; src.forEach(function (x) { inSrc[x.sha1] = 1; });
    var sections = list(raw.sections, 8).map(function (sec) {
      if (!isObj(sec) || !Object.prototype.hasOwnProperty.call(SECHEAD, sec.h)) return null;
      var ss = list(sec.sentences, 40).map(function (sn) {
        if (!isObj(sn)) return null; var t = clip(sn.t, 400); if (!t) return null;
        var cites = list(sn.cites, 8).filter(function (c) { return c === "catalogue" || (typeof c === "string" && SHA1.test(c) && inSrc[c]); });
        return { t: t, cites: cites };
      }).filter(Boolean);
      return ss.length ? { h: sec.h, sentences: ss } : null;
    }).filter(Boolean);
    // the fixed reading order, whatever order the file has: who, targets, methods, operations, takeaway
    var ORDER = Object.keys(SECHEAD); sections.sort(function (a, b) { return ORDER.indexOf(a.h) - ORDER.indexOf(b.h); });
    if (!sections.length) return null;
    return { key: key, kind: raw.kind === "actor" ? "actor" : "subject", name: clip(raw.name, 120), headline: clip(raw.headline, 120), in_short: clip(raw.in_short, 240), sections: sections,
      reviewed_at: clip(raw.reviewed_at, 40), src: src, stale: raw.stale === true };
  }
  function cleanStoryIndex(raw) {
    var rows = isObj(raw) ? list(raw.stories, 500) : [];
    return rows.map(function (x) {
      if (!isObj(x) || !SKEY.test(String(x.key)) || !clip(x.headline, 120)) return null;
      return { key: x.key, kind: x.kind === "actor" ? "actor" : "subject", name: clip(x.name, 120), headline: clip(x.headline, 120), in_short: clip(x.in_short, 240), reviewed_at: clip(x.reviewed_at, 40) };
    }).filter(Boolean);
  }
  function getJson(url) { return fetch(url, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }); }
  function loadCard(sha) {
    if (!SHA1.test(sha)) return Promise.reject(new Error("bad id"));
    // a failed fetch is not cached: the entry is dropped so the next open tries again
    var sh = sha.slice(0, 2); if (!shards[sh]) shards[sh] = getJson("data/library/cards/" + sh + ".json").catch(function (e) { delete shards[sh]; throw e; });
    return shards[sh].then(function (o) { var c = isObj(o) && Object.prototype.hasOwnProperty.call(o, sha) ? cleanCard(o[sha]) : null; if (!c) throw new Error("no card"); return c; });
  }
  function loadStory(key) {
    if (!SKEY.test(key)) return Promise.reject(new Error("bad key"));
    if (!storyCache[key]) storyCache[key] = getJson("data/library/stories/" + key + ".json").then(function (o) { var s = cleanStory(o, key); if (!s) throw new Error("bad story"); return s; })
      .catch(function (e) { delete storyCache[key]; throw e; });
    return storyCache[key];
  }
  // the list of reviewed stories, newest review first; empty when there is none or it cannot be read
  function loadStoryIndex() {
    if (!storyIdx) storyIdx = getJson("data/library/stories.json").then(function (o) { return cleanStoryIndex(o).sort(function (a, b) { return b.reviewed_at.localeCompare(a.reviewed_at) || a.key.localeCompare(b.key); }); }).catch(function () { storyIdx = null; return []; });
    return storyIdx;
  }

  // Every link back to ORKL is rebuilt here from a validated id and checked against the ORKL hosts, never taken from data.
  // Reports: the PDF lives at archive.orkl.eu/<sha1>.pdf and the record at orkl.eu/libraryEntry/<id>; an actor's profile
  // is orkl.eu/taEntry/<id> (orkl.eu/library/<id> is a dead end on ORKL). Named orklUrl so the security check
  // (scripts/security-check.mjs) accepts it as an href source.
  function orklUrl(kind, v) {
    var s = String(v == null ? "" : v), u = "";
    if (kind === "pdf") { if (/^[0-9a-f]{40}$/.test(s)) u = "https://archive.orkl.eu/" + s + ".pdf"; }
    else if (kind === "lib") { if (/^[0-9A-Za-z-]{1,64}$/.test(s)) u = "https://orkl.eu/libraryEntry/" + s; }
    else if (kind === "ta") { if (/^[0-9A-Za-z-]{1,64}$/.test(s)) u = "https://orkl.eu/taEntry/" + s; }
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
  function actKey(a) { return a.i || ("n:" + a.n + "|" + a.s); }

  function load() {
    fetch("data/orkl-index.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }).then(function (d) {
      sources = Array.isArray(d.sources) ? d.sources : [];
      langs = Array.isArray(d.langs) ? d.langs : [];
      reports = (Array.isArray(d.reports) ? d.reports : []).filter(function (r) { return r && typeof r.s === "string"; }).map(function (r) {
        r.a = Array.isArray(r.a) ? r.a.filter(function (x) { return typeof x === "string"; }) : []; r.c = Array.isArray(r.c) ? r.c : [];
        r.k = r.k === 1 && SHA1.test(r.s) ? 1 : 0; r.st = typeof r.st === "string" && SKEY.test(r.st) ? r.st : "";
        r._s = ((r.t || "") + " " + r.a.join(" ")).toLowerCase();
        var seen = {}; r.a.forEach(function (n) { if (!seen[n]) { seen[n] = 1; actorCount[n] = (actorCount[n] || 0) + 1; } });
        return r;
      });
      actors = (Array.isArray(d.actors) ? d.actors : []).filter(function (a) { return a && typeof a.n === "string"; }).map(function (a) {
        a.al = Array.isArray(a.al) ? a.al.filter(function (x) { return typeof x === "string"; }) : [];
        a.tl = Array.isArray(a.tl) ? a.tl.filter(function (x) { return typeof x === "string"; }) : [];
        a.i = typeof a.i === "string" && /^[0-9A-Za-z-]{1,64}$/.test(a.i) ? a.i : "";
        a.s = typeof a.s === "string" ? a.s : "";
        a.st = typeof a.st === "string" && SKEY.test(a.st) ? a.st : "";
        a._s = ((a.n || "") + " " + a.al.join(" ") + " " + a.tl.join(" ")).toLowerCase();
        (byName[a.n] = byName[a.n] || []).push(a);
        return a;
      });
      var rt = typeof d.reports_total === "number" ? d.reports_total : reports.length;
      var at = typeof d.actors_total === "number" ? d.actors_total : actors.length;
      intro(rt, at, null);
      getJson("data/orkl.json").then(function (o) { intro(rt, at, isObj(o) ? { cards: Math.max(0, Math.floor(Number(o.cards_read)) || 0), stories: Math.max(0, Math.floor(Number(o.stories_published)) || 0) } : null); }).catch(function () {});
      safe("featured", drawFeatured);
      $("repN").textContent = rt.toLocaleString("en");
      $("actN").textContent = at.toLocaleString("en");
      safe("filters", fillFilters);
      applyHash();
      window.addEventListener("hashchange", applyHash);
    }).catch(function () { $("summary").textContent = "The library can't be loaded right now. Try again in a minute."; });
  }

  // the intro line: the catalogue counts, then what CyberView's AI has read and written, only once there is something to say
  function intro(rt, at, c) {
    var t = rt.toLocaleString("en") + " public threat-intelligence reports and " + at.toLocaleString("en") + " tracked threat actors, mirrored from ORKL. ";
    if (c && c.cards > 0 && c.stories > 0) t += "CyberView's AI has read " + c.cards.toLocaleString("en") + " of them and written " + plural(c.stories, "reviewed story").replace("storys", "stories") + "; every fact links to the report it came from.";
    else if (c && c.cards > 0) t += "CyberView's AI has read " + c.cards.toLocaleString("en") + " of them; every fact links to the report it came from.";
    else t += "CyberView has not summarised these reports yet.";
    $("summary").textContent = t;
  }
  // Featured reads: up to six of the most recently reviewed stories, above the section strip; hidden when there are none
  function drawFeatured() {
    loadStoryIndex().then(function (rows) {
      safe("featured", function () {
        var box = $("featList"); box.textContent = "";
        rows.slice(0, 6).forEach(function (s) {
          var li = el("li"), a = el("a", "fcard"); a.href = "#story=" + encodeURIComponent(s.key);
          a.appendChild(el("span", "fkind", s.kind === "actor" ? "Threat actor story" : "Story"));
          a.appendChild(el("span", "fh", s.headline));
          if (s.in_short) a.appendChild(el("span", "fs", s.in_short));
          li.appendChild(a); box.appendChild(li);
        });
        $("featured").hidden = !rows.length;
      });
    });
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
    var cats = {}; actors.forEach(function (a) { if (a.s) cats[a.s] = (cats[a.s] || 0) + 1; });
    Object.keys(cats).sort().forEach(function (c) { var o = el("option", null, c + " (" + cats[c].toLocaleString("en") + ")"); o.value = c; $("actSrc").appendChild(o); });
  }

  /* ---------- paging (the same Previous / Page n of N / Next as the Vulnerabilities list) ---------- */
  function paged(list, page) { var pages = Math.max(1, Math.ceil(list.length / PAGE)), p = Math.min(Math.max(0, page | 0), pages - 1); return { page: p, pages: pages, items: list.slice(p * PAGE, (p + 1) * PAGE) }; }
  function pager(prefix, pg, total) {
    $(prefix + "Pager").hidden = pg.pages <= 1;
    $(prefix + "Page").textContent = "Page " + (pg.page + 1) + " of " + pg.pages.toLocaleString("en") + " (" + PAGE + " per page)";
    $(prefix + "Prev").disabled = pg.page === 0; $(prefix + "Next").disabled = pg.page >= pg.pages - 1;
    return total;
  }
  function listTop(view) { var v = document.querySelector("#" + view + " .vlist"); if (v) v.scrollTop = 0; var c = v && v.querySelector(".count"); if (c && narrow()) try { c.scrollIntoView({ block: "nearest" }); } catch (e) {} }
  // bring a row into view inside its own scrolling list on a wide screen (the page itself stays put), or on the page on a phone
  function reveal(n) {
    if (!n) return; var v = n.closest(".vlist");
    if (v && !narrow() && v.scrollHeight > v.clientHeight + 4) { v.scrollTop += n.getBoundingClientRect().top - v.getBoundingClientRect().top - v.clientHeight / 3; return; }
    try { n.scrollIntoView({ block: "nearest" }); } catch (x) {}
  }

  /* ---------- reports ---------- */
  function matches(r) {
    var q = $("q").value.trim().toLowerCase(), src = $("source").value, yr = $("year").value, lg = $("lang").value;
    if (actorFilter && r.a.indexOf(actorFilter) < 0) return false;
    if (src !== "" && r.c.indexOf(Number(src)) < 0) return false;
    if (yr === "none") { if (r.y) return false; } else if (yr && r.y !== yr) return false;
    if (lg !== "" && String(r.l) !== lg) return false;
    if (!q) return true;
    return r._s.indexOf(q) >= 0;
  }
  function filtersOn() { return !!(actorFilter || $("source").value || $("year").value || $("lang").value || $("q").value.trim()); }
  function render() {
    var list = reports.filter(matches), box = $("list"), pg = paged(list, repPage); repPage = pg.page;
    box.textContent = "";
    $("count").textContent = plural(list.length, "report") + (pg.pages > 1 ? ", " + (pg.page * PAGE + 1).toLocaleString("en") + "–" + (pg.page * PAGE + pg.items.length).toLocaleString("en") + " shown" : "");
    if (!list.length) { box.appendChild(el("li", "empty", "Nothing matches. Clear a filter or try another word.")); }
    pg.items.forEach(function (r) { box.appendChild(rowEl(r)); });
    pager("rep", pg, list.length);
    $("clear").hidden = !filtersOn();
    showActorChip();
  }
  function changed() {
    if (tab === "reports") { repPage = 0; render(); listTop("repGrid"); }
    else { actPage = 0; renderActors(); listTop("actView"); }
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
    if (r.a.length > 3) meta.appendChild(el("span", null, "+" + (r.a.length - 3) + " more"));
    b.appendChild(meta);
    b.addEventListener("click", function () { if (OPEN === r.s) closePane(); else openReport(r); });
    li.appendChild(b); return li;
  }

  // one report's catalogue record, as text, in the detail pane: the sources, year, language, the actors it names
  // (each opens that actor's record), and the rebuilt links to read it on ORKL. Never the report body.
  function details(box, r) {
    var m = el("p", "armeta");
    r.c.forEach(function (i) { var s = srcName(i); if (s) m.appendChild(el("span", "cat", s)); });
    m.appendChild(el("span", null, r.y || "Undated"));
    var lc = langs[r.l]; if (lc) m.appendChild(el("span", null, langName(lc)));
    box.appendChild(m);
    safe("summary", function () { cardBlock(box, r); });
    box.appendChild(el("h3", null, "Read it on ORKL"));
    var ln = el("p", "reclinks"), any = false;
    if (orklUrl("lib", r.i)) { var la = el("a", null, "ORKL record"); la.href = orklUrl("lib", r.i); la.target = "_blank"; la.rel = "noopener noreferrer"; ln.appendChild(la); any = true; }
    if (orklUrl("pdf", r.s)) { var pa = el("a", null, "The report (PDF)"); pa.href = orklUrl("pdf", r.s); pa.target = "_blank"; pa.rel = "noopener noreferrer"; ln.appendChild(pa); any = true; }
    if (any) box.appendChild(ln); else box.appendChild(el("p", "note", "No ORKL link is available for this report."));
    if (r.a.length) {
      box.appendChild(el("h3", null, r.a.length === 1 ? "Threat actor named" : "Threat actors named (" + r.a.length + ")"));
      var ap = el("p", "arcves");
      r.a.forEach(function (n) {
        var btn = el("button", "pill", n); btn.type = "button"; btn.title = "Open " + n + "'s record";
        btn.addEventListener("click", function () { var a = (byName[n] || [])[0]; if (a) openActorRecord(a, true); else filterByActor(n); });
        ap.appendChild(btn);
      });
      box.appendChild(ap);
    }
    box.appendChild(el("p", "note", "Catalogued from ORKL: the title, source and links are mirrored from ORKL, and the report itself is read there."));
    var lp = el("p", "arlink"), lk = el("a", null, "Link to this report");
    lk.href = "library.html#r=" + encodeURIComponent(r.s); lp.appendChild(lk); box.appendChild(lp);
  }

  // what CyberView's AI read in one report: the summary and the facts it names, or the line saying it has not read it
  function cardBlock(box, r) {
    if (!r.k) { box.appendChild(el("p", "note", "CyberView has not summarised this report.")); }
    else {
      var host = el("div", "rcard"); box.appendChild(host);
      loadCard(r.s).then(function (c) { if (OPEN !== r.s) return; safe("summary", function () { drawCard(host, c, r); }); })
        .catch(function () { if (OPEN === r.s) host.appendChild(el("p", "note", FAIL)); });
    }
    if (r.st) {
      var sp = el("p", "storylink"); box.appendChild(sp);
      loadStoryIndex().then(function (rows) {
        var s = rows.filter(function (x) { return x.key === r.st; })[0]; if (!s || OPEN !== r.s) return;
        sp.appendChild(document.createTextNode("Part of the story: ")); var a = el("a", null, s.headline); a.href = "#story=" + encodeURIComponent(s.key); sp.appendChild(a);
      });
    }
  }
  // the same "Report an error" route a story has: an event-report issue naming the Library summary or story
  function errorLink(label, title) {
    var ep = el("p", "storyend note"), ea = el("a", "reporterr", "Report an error");
    ea.href = "https://github.com/xanderhutch/CyberView/issues/new?template=event-report.yml&title=" + encodeURIComponent("Error report: " + label) + "&event=" + encodeURIComponent(String(title).slice(0, 120) + " (" + label + ")");
    ea.target = "_blank"; ea.rel = "noopener noreferrer"; ep.appendChild(ea); return ep;
  }
  function drawCard(host, c, r) {
    host.appendChild(el("h3", null, "What this report says"));
    host.appendChild(el("p", "summary", c.sm));
    function group(label, items, titled) {
      if (!items.length) return;
      host.appendChild(el("h4", "fl", label));
      var p = el("p", "arcves"); items.forEach(function (x) { var pl = el("span", "pill", x.v); if (titled && x.by) pl.title = "Named by " + x.by; p.appendChild(pl); }); host.appendChild(p);
    }
    group("Who", c.f.a, true); group("Targets", c.f.s.concat(c.f.c)); group("Tools", c.f.t);
    if (c.f.v.length) {
      host.appendChild(el("h4", "fl", "CVEs"));
      c.f.v.forEach(function (x) {
        var row = el("div", "cvrow"); row.appendChild(el("span", "cvid", x.v)); var ln = el("p", "reclinks");
        var a1 = el("a", null, "CVE record"); a1.href = "https://www.cve.org/CVERecord?id=" + x.v; var a2 = el("a", null, "NVD record"); a2.href = "https://nvd.nist.gov/vuln/detail/" + x.v;
        [a1, a2].forEach(function (a) { a.target = "_blank"; a.rel = "noopener noreferrer"; ln.appendChild(a); });
        var a4 = el("a", null, "Am I affected? How to fix"); a4.href = "vulnerabilities.html#" + x.v; ln.appendChild(a4);
        row.appendChild(ln); host.appendChild(row);
      });
    }
    host.appendChild(el("p", "note aiby", "Summarised by " + AI_BY + "." + (c.p ? " Read from part of the report." : "")));
    host.appendChild(errorLink("Library summary " + r.s, r.t || "Untitled report"));
  }

  // one reviewed story: headline, in short, byline, sections of sentences each followed by numbered citations, the numbered sources, and the error link
  function storyView(box, s, actor) {
    var w = el("article", "story"), num = {}, order = [], byHash = {};
    s.src.forEach(function (x) { byHash[x.sha1] = x; });
    function numOf(sha) { if (!num[sha]) { order.push(sha); num[sha] = order.length; } return num[sha]; }
    s.sections.forEach(function (sec) { sec.sentences.forEach(function (sn) { sn.cites.forEach(function (c) { if (c !== "catalogue") numOf(c); }); }); });
    s.src.forEach(function (x) { numOf(x.sha1); });
    w.appendChild(el("h2", null, s.headline || s.name));
    if (s.in_short) w.appendChild(el("p", "inshort", s.in_short));
    var d = fmtDate(s.reviewed_at);
    w.appendChild(el("p", "byline", "Written by " + AI_BY + " · from " + plural(s.src.length, "report") + (d ? " · reviewed " + d : "")));
    if (s.stale) w.appendChild(el("p", "staleline", "New reports have arrived since this was reviewed."));
    s.sections.forEach(function (sec) {
      w.appendChild(el("h3", null, SECHEAD[sec.h]));
      var p = el("p", "prose");
      sec.sentences.forEach(function (sn) {
        p.appendChild(el("span", "s", sn.t));
        sn.cites.forEach(function (c) {
          if (c === "catalogue") {
            var u = actor ? orklUrl("ta", actor.i) : "";
            if (u) { var ca = el("a", "cite", "ORKL catalogue"); ca.href = orklUrl("ta", actor.i); ca.target = "_blank"; ca.rel = "noopener noreferrer"; p.appendChild(ca); } else p.appendChild(el("span", "cite", "ORKL catalogue"));
          } else {
            var n = num[c], a = el("a", "cite", "[" + n + "]"); a.href = "library.html#r=" + c; a.setAttribute("aria-label", "Source " + n + ": " + byHash[c].title); p.appendChild(a);
          }
        });
        p.appendChild(document.createTextNode(" "));
      });
      w.appendChild(p);
    });
    if (order.length) {
      w.appendChild(el("h3", null, "Sources"));
      var ol = el("ol", "srcs");
      order.forEach(function (sha) {
        var x = byHash[sha], li = el("li"), a = el("a", null, x.title); a.href = "library.html#r=" + sha; li.appendChild(a);
        var meta = [x.authors.join(", "), x.year].filter(Boolean).join(" · "); if (meta) li.appendChild(el("span", "note", " " + meta));
        ol.appendChild(li);
      });
      w.appendChild(ol);
    }
    w.appendChild(errorLink("Library story " + s.key, s.headline || s.name));
    box.appendChild(w);
  }
  // fetch a story into its own slot; a failure shows the one line there and nothing else on the page changes
  function storySlot(box, key, actor, stillOpen) {
    var slot = el("div", "storybox"); box.appendChild(slot);
    loadStory(key).then(function (s) { if (stillOpen()) safe("story", function () { storyView(slot, s, actor); if (!actor) { $("pane").querySelector(".vdtitle").textContent = paneTitle = s.headline || s.name; } }); })
      .catch(function () { if (stillOpen()) slot.appendChild(el("p", "note", FAIL)); });
  }
  function openStory(key) {
    OPEN = ""; OPEN_STORY = key; paneTitle = "Story"; mark();
    var d = $("det"); d.textContent = ""; safe("story", function () { storySlot(d, key, null, function () { return OPEN_STORY === key; }); });
    paneSync(); $("pane").scrollTop = 0; writeHash();
  }

  function narrow() { return window.innerWidth < 1240; }
  function paneSync() {
    var p = $("pane"), d = $("det"), hasR = d.childNodes.length > 0 && tab === "reports";
    p.classList.toggle("has", hasR); $("repGrid").classList.toggle("vopen", hasR);
    p.querySelector(".vdtitle").textContent = hasR ? paneTitle : "";
    var ap = $("actPane"), ad = $("actDet"), hasA = ad.childNodes.length > 0 && tab === "actors";
    ap.classList.toggle("has", hasA); $("actView").classList.toggle("vopen", hasA);
    ap.querySelector(".vdtitle").textContent = hasA ? actTitle : "";
    document.documentElement.classList.toggle("vsheet", (hasR || hasA) && narrow());
  }
  function mark() {
    [].forEach.call($("list").querySelectorAll(".row"), function (li) { var on = li.id === "rp-" + OPEN; li.classList.toggle("on", on); li.firstChild.setAttribute("aria-expanded", on ? "true" : "false"); });
    [].forEach.call($("actList").querySelectorAll(".row"), function (li) { var on = !!OPEN_ACT && li.getAttribute("data-k") === OPEN_ACT; li.classList.toggle("on", on); li.firstChild.setAttribute("aria-expanded", on ? "true" : "false"); });
  }
  function openReport(r, fromLink) {
    OPEN = r.s; OPEN_STORY = ""; paneTitle = r.t || "Report";
    if (fromLink) {
      if (tab !== "reports") showTab("reports");
      // go to the page of the list that holds it, clearing the filters if they hide it
      var list = reports.filter(matches), at = list.indexOf(r);
      if (at < 0) { actorFilter = ""; $("q").value = ""; ["source", "year", "lang"].forEach(function (k) { $(k).value = ""; }); list = reports.filter(matches); at = list.indexOf(r); }
      repPage = at < 0 ? 0 : Math.floor(at / PAGE); render();
    }
    mark();
    var d = $("det"); d.textContent = ""; details(d, r);
    paneSync(); $("pane").scrollTop = 0; writeHash();
    if (narrow()) $("pane").querySelector(".vdclose").focus({ preventScroll: true });
    if (fromLink) { var n = $("rp-" + r.s); if (n) { reveal(n); if (!narrow()) n.firstChild.focus({ preventScroll: true }); } }
  }
  function closePane() {
    var back = OPEN ? $("rp-" + OPEN) : null;
    OPEN = ""; OPEN_STORY = ""; paneTitle = ""; $("det").textContent = ""; mark(); paneSync(); writeHash();
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
    if (OPEN) { OPEN = ""; $("det").textContent = ""; }
    showTab("reports"); repPage = 0; render(); paneSync(); listTop("repGrid"); writeHash();
  }

  /* ---------- actor catalogue ---------- */
  function actMatches(a) {
    var q = $("q").value.trim().toLowerCase(), c = $("actSrc").value;
    if (c && a.s !== c) return false;
    if ($("actHas").checked && !actorCount[a.n]) return false;
    return !q || a._s.indexOf(q) >= 0;
  }
  function renderActors() {
    var list = actors.filter(actMatches), box = $("actList"), pg = paged(list, actPage); actPage = pg.page;
    box.textContent = "";
    $("actCount").textContent = plural(list.length, "threat actor") + (pg.pages > 1 ? ", " + (pg.page * PAGE + 1).toLocaleString("en") + "–" + (pg.page * PAGE + pg.items.length).toLocaleString("en") + " shown" : "");
    if (!list.length) { box.appendChild(el("li", "empty", "No actor matches. Clear a filter or try another name.")); }
    pg.items.forEach(function (a) { box.appendChild(actorEl(a)); });
    pager("act", pg, list.length);
  }
  function actorEl(a) {
    var li = el("li", "row"), k = actKey(a); li.setAttribute("data-k", k); li.id = "ta-" + k.replace(/[^\w-]/g, "_");
    if (k === OPEN_ACT) li.classList.add("on");
    var b = el("button"); b.type = "button"; b.setAttribute("aria-controls", "actPane"); b.setAttribute("aria-expanded", k === OPEN_ACT ? "true" : "false");
    var rc = actorCount[a.n] || 0;
    b.appendChild(el("span", "date", rc ? plural(rc, "report") : "No reports"));
    b.appendChild(el("span", "ttl", a.n));
    var meta = el("span", "meta");
    if (a.s) meta.appendChild(el("span", null, "tracked by " + a.s));
    if (a.tl.length) meta.appendChild(el("span", null, plural(a.tl.length, "tool")));
    a.al.slice(0, 4).forEach(function (al) { meta.appendChild(el("span", "pill", al)); });
    if (a.al.length > 4) meta.appendChild(el("span", null, "+" + (a.al.length - 4) + " aliases"));
    b.appendChild(meta);
    b.addEventListener("click", function () { if (OPEN_ACT === k) closeActor(); else openActorRecord(a); });
    li.appendChild(b); return li;
  }

  // CyberView's own actor profiles (data/actors.json: groups named in checked events), loaded once, matched on name
  // and aliases so an ORKL actor links to what CyberView has on file for it
  function loadProfiles() {
    if (profiles) return profiles;
    profiles = fetch("data/actors.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (j) {
      var m = {}; (Array.isArray(j && j.profiles) ? j.profiles : []).forEach(function (p) {
        if (!p || typeof p.id !== "string" || !/^[\w-]{1,80}$/.test(p.id) || typeof p.name !== "string") return;
        [p.name].concat(Array.isArray(p.aliases) ? p.aliases : []).forEach(function (n) { if (typeof n === "string" && n) m[n.toLowerCase()] = { id: p.id, name: p.name }; });
      });
      return m;
    }).catch(function () { return {}; });
    return profiles;
  }

  // one actor's record in the pane: catalogue, aliases, tools, the reports that name it (newest first, each opens),
  // its ORKL profile and, when CyberView has it on file, its profile on the Actors in events page
  function actorDetails(box, a) {
    var rc = actorCount[a.n] || 0;
    var m = el("p", "armeta");
    if (a.s) m.appendChild(el("span", "cat", a.s));
    m.appendChild(el("span", null, rc ? plural(rc, "report") + " in the library" : "No reports in the library name it"));
    box.appendChild(m);
    var ln = el("p", "reclinks");
    if (orklUrl("ta", a.i)) { var oa = el("a", null, "ORKL actor profile"); oa.href = orklUrl("ta", a.i); oa.target = "_blank"; oa.rel = "noopener noreferrer"; ln.appendChild(oa); }
    var cv = el("span"); ln.appendChild(cv); box.appendChild(ln);
    loadProfiles().then(function (map) {
      var hit = null; [a.n].concat(a.al).some(function (n) { hit = map[String(n).toLowerCase()] || null; return !!hit; });
      if (hit && OPEN_ACT === actKey(a)) { var ca = el("a", null, "On file in CyberView events: " + hit.name); ca.href = "actors.html#a=" + encodeURIComponent(hit.id); cv.appendChild(ca); }
    });
    var others = (byName[a.n] || []).filter(function (o) { return o !== a && o.s; });
    var storyHere = a.st ? (function () { var k = actKey(a); return function () { return OPEN_ACT === k; }; })() : null;
    if (others.length) {
      var op = el("p", "note", "Also tracked under this name by: ");
      others.forEach(function (o, i) { if (i) op.appendChild(document.createTextNode(", ")); var ob = el("button", "linkish", o.s); ob.type = "button"; ob.addEventListener("click", function () { openActorRecord(o); }); op.appendChild(ob); });
      box.appendChild(op);
    }
    if (a.st) safe("story", function () { storySlot(box, a.st, a, storyHere); });
    if (a.al.length) { box.appendChild(el("h3", null, "Aliases (" + a.al.length + ")")); var al = el("p", "arcves"); a.al.forEach(function (x) { al.appendChild(el("span", "pill", x)); }); box.appendChild(al); }
    if (a.tl.length) { box.appendChild(el("h3", null, "Tools (" + a.tl.length + ")")); var tl = el("p", "arcves"); a.tl.forEach(function (x) { tl.appendChild(el("span", "pill", x)); }); box.appendChild(tl); }
    if (rc) {
      var named = reports.filter(function (r) { return r.a.indexOf(a.n) >= 0; });
      box.appendChild(el("h3", null, "Reports that name it (" + named.length.toLocaleString("en") + ")"));
      var ul = el("ul", "recreps");
      named.slice(0, 12).forEach(function (r) {
        var li = el("li"), rb = el("button", "linkish", (r.y ? r.y + " · " : "") + (r.t || "Untitled report")); rb.type = "button";
        rb.addEventListener("click", function () { openReport(r, true); }); li.appendChild(rb); ul.appendChild(li);
      });
      box.appendChild(ul);
      if (named.length > 12) { var all = el("button", "btn ghost", "List all " + named.length.toLocaleString("en") + " reports"); all.type = "button"; all.addEventListener("click", function () { filterByActor(a.n); }); box.appendChild(all); }
    }
    box.appendChild(el("p", "note", "Catalogued from ORKL (" + (a.s || "source not stated") + "). Aliases and tools are the catalogue's, not CyberView findings."));
    var lp = el("p", "arlink"), lk = el("a", null, "Link to this actor");
    lk.href = "library.html#tab=actors&" + (a.i ? "ta=" + encodeURIComponent(a.i) : "an=" + encodeURIComponent(a.n)); lp.appendChild(lk); box.appendChild(lp);
  }
  function openActorRecord(a, fromLink) {
    var k = actKey(a); OPEN_ACT = k; actTitle = a.n;
    if (tab !== "actors") { showTab("actors"); fromLink = true; }
    if (fromLink) {
      var list = actors.filter(actMatches), at = list.indexOf(a);
      if (at < 0) { $("q").value = ""; $("actSrc").value = ""; $("actHas").checked = false; list = actors.filter(actMatches); at = list.indexOf(a); }
      actPage = at < 0 ? 0 : Math.floor(at / PAGE); renderActors();
    }
    mark();
    var d = $("actDet"); d.textContent = ""; actorDetails(d, a);
    paneSync(); $("actPane").scrollTop = 0; writeHash();
    if (narrow()) $("actPane").querySelector(".vdclose").focus({ preventScroll: true });
    if (fromLink) reveal($("ta-" + k.replace(/[^\w-]/g, "_")));
  }
  function closeActor() {
    var back = OPEN_ACT ? $("ta-" + OPEN_ACT.replace(/[^\w-]/g, "_")) : null;
    OPEN_ACT = ""; actTitle = ""; $("actDet").textContent = ""; mark(); paneSync(); writeHash();
    if (back) back.firstChild.focus({ preventScroll: true });
  }

  function showTab(which) {
    tab = which === "actors" ? "actors" : "reports";
    var rep = tab === "reports";
    $("tabReports").setAttribute("aria-current", rep ? "page" : "false");
    $("tabActors").setAttribute("aria-current", rep ? "false" : "page");
    $("repGrid").hidden = !rep; $("actView").hidden = rep;
    $("q").placeholder = rep ? "Report title, actor, alias" : "Actor name, alias or tool";
    if (rep) render(); else renderActors();
    paneSync();
  }

  function writeHash() {
    var p = new URLSearchParams();
    if (tab === "actors") p.set("tab", "actors");
    if ($("q").value.trim()) p.set("q", $("q").value.trim());
    if (tab === "reports") {
      if (actorFilter) p.set("actor", actorFilter);
      if ($("source").value && srcName(Number($("source").value))) p.set("src", srcName(Number($("source").value)));
      if ($("year").value) p.set("year", $("year").value);
      if ($("lang").value && langs[Number($("lang").value)]) p.set("lang", langs[Number($("lang").value)]);
      if (OPEN) p.set("r", OPEN);
      else if (OPEN_STORY) p.set("story", OPEN_STORY);
      else if (repPage) p.set("p", String(repPage + 1));
    } else {
      if ($("actSrc").value) p.set("cat", $("actSrc").value);
      if ($("actHas").checked) p.set("has", "1");
      var a = OPEN_ACT ? actors.filter(function (x) { return actKey(x) === OPEN_ACT; })[0] : null;
      if (a) { if (a.i) p.set("ta", a.i); else p.set("an", a.n); }
      else if (actPage) p.set("p", String(actPage + 1));
    }
    var h = p.toString(); try { history.replaceState(null, "", h ? "#" + h : location.pathname + location.search); } catch (e) {}
  }
  // the hash decides the view: on load, and whenever a link on this page (the section strip, "Link to this ...") changes it
  function applyHash() {
    var p = new URLSearchParams(location.hash.slice(1));
    $("q").value = p.get("q") || "";
    actorFilter = p.get("actor") || "";
    $("source").value = ""; if (p.get("src")) { for (var i = 0; i < sources.length; i++) { if (sources[i] === p.get("src")) { $("source").value = String(i); break; } } }
    $("year").value = p.get("year") || "";
    $("lang").value = ""; if (p.get("lang")) { for (var j = 0; j < langs.length; j++) { if (langs[j] === p.get("lang")) { $("lang").value = String(j); break; } } }
    $("actSrc").value = p.get("cat") || ""; $("actHas").checked = p.get("has") === "1";
    var pageN = Math.max(0, (parseInt(p.get("p"), 10) || 1) - 1);
    var r = p.get("r"), ta = p.get("ta"), an = p.get("an");
    var want = r ? reports.filter(function (x) { return x.s === r; })[0] : null;
    var wantA = ta ? actors.filter(function (x) { return x.i === ta; })[0] : an ? (byName[an] || [])[0] : null;
    var sk = p.get("story"); sk = sk && SKEY.test(sk) ? sk : "";
    var storyA = !want && !wantA && sk ? actors.filter(function (x) { return x.st === sk; })[0] : null;
    OPEN = ""; OPEN_STORY = ""; $("det").textContent = ""; OPEN_ACT = ""; $("actDet").textContent = "";
    if (want) { showTab("reports"); openReport(want, true); return; }
    if (wantA || storyA) { tab = "actors"; showTab("actors"); openActorRecord(wantA || storyA, true); return; }
    if (sk) { showTab("reports"); openStory(sk); return; }
    if (p.get("tab") === "actors") { actPage = pageN; showTab("actors"); } else { repPage = pageN; showTab("reports"); }
    mark(); paneSync();
  }

  ["filters", "qform", "actFilters"].forEach(function (f) { var n = $(f); if (n) n.addEventListener("submit", function (e) { e.preventDefault(); }); });
  var t; $("q").addEventListener("input", function () { clearTimeout(t); t = setTimeout(changed, 150); });
  ["source", "year", "lang", "actSrc", "actHas"].forEach(function (k) { $(k).addEventListener("change", changed); });
  $("clear").addEventListener("click", function () { actorFilter = ""; $("q").value = ""; ["source", "year", "lang"].forEach(function (k) { $(k).value = ""; }); changed(); });
  // the two library sections on this page switch in place; the others are their own pages
  $("tabReports").addEventListener("click", function (e) { e.preventDefault(); showTab("reports"); writeHash(); });
  $("tabActors").addEventListener("click", function (e) { e.preventDefault(); showTab("actors"); writeHash(); });
  $("pane").querySelector(".vdclose").addEventListener("click", closePane);
  $("actPane").querySelector(".vdclose").addEventListener("click", closeActor);
  $("repPrev").addEventListener("click", function () { repPage--; render(); listTop("repGrid"); writeHash(); });
  $("repNext").addEventListener("click", function () { repPage++; render(); listTop("repGrid"); writeHash(); });
  $("actPrev").addEventListener("click", function () { actPage--; renderActors(); listTop("actView"); writeHash(); });
  $("actNext").addEventListener("click", function () { actPage++; renderActors(); listTop("actView"); writeHash(); });
  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement || {}).tagName || "", typing = /^(INPUT|TEXTAREA|SELECT)$/.test(tag) || (document.activeElement && document.activeElement.isContentEditable);
    if (e.key === "Escape" && !typing && tab === "reports" && (OPEN || OPEN_STORY)) { e.preventDefault(); closePane(); }
    else if (e.key === "Escape" && !typing && tab === "actors" && OPEN_ACT) { e.preventDefault(); closeActor(); }
    else if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !typing) { e.preventDefault(); $("q").focus(); }
  });
  var rz; window.addEventListener("resize", function () { clearTimeout(rz); rz = setTimeout(paneSync, 120); });
  load();
})();
