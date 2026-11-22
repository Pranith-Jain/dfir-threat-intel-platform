// CyberView vulnerabilities page: one tool for "what is exploited and due, am I affected, how do I check and fix, what do I hunt for",
// plus "All CVEs": a lookup and browser over a static, compact copy of NVD served from data/cve/ (see cvedb-lib.js).
// Reads data/workbench.json (written by scripts/build.mjs). The visitor's software list is parsed, matched and stored
// only in this browser (localStorage "cwm.inv"); nothing is sent. Every record passes a clean function with length
// limits, and all text is inserted as text.
(function () {
  "use strict";
  var W = window.CVWorkbench, D = window.CVDB, OL = window.CVOT;
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function strs(a, k, n) { return (Array.isArray(a) ? a : []).map(function (x) { return str(x, n).trim(); }).filter(Boolean).slice(0, k); }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function isDay(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s || ""); }
  function isCve(s) { return /^CVE-\d{4}-\d{4,}$/.test(s || ""); }
  // every link target from data passes through here: https only, or the map's own permalinks
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/[^\s"'<>]+$/.test(u) || /^\.\/#e=[a-z0-9-]+$/.test(u) ? u : "about:blank"; }
  function blobUrl(b) { return b instanceof Blob ? URL.createObjectURL(b) : "about:blank"; }
  function link(href, text) { var a = el("a", null, text); a.href = safeUrl(href); if (/^https:/.test(href)) { a.target = "_blank"; a.rel = "noopener noreferrer"; } return a; }
  function fmtDay(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { month: "short", day: "numeric" }); } catch (e) { return d; } }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  var TODAY = new Date().toISOString().slice(0, 10);
  // each view draws inside safe(): one failure shows a note in that view and cannot blank the page
  function safe(panel, fn) {
    try { fn(); var old = document.querySelector("#wbp-" + panel + " > .fault"); if (old) old.remove(); }
    catch (e) {
      var p = $("wbp-" + panel); if (!p) return;
      var n = p.querySelector(":scope > .fault"); if (!n) { n = el("p", "caveat fault", "This part of the page could not be drawn. Reload the page; if it keeps happening, report it from the About page."); p.insertBefore(n, p.firstChild); }
    }
  }
  var FORMATS = { stix: "STIX", sigma: "Sigma rule", yara: "YARA rule", snort: "Snort rule", suricata: "Suricata rule", kql: "KQL query", spl: "Splunk query", csv: "CSV indicators", json: "JSON indicators", misp: "MISP event", openioc: "OpenIOC", text: "Indicator list", pdf: "PDF with indicators" };

  var cleanRange = W.cleanRange;
  function cleanHunt(h) {
    if (!h || typeof h !== "object" || !FORMATS[h.format]) return null;
    var u = str(h.url, 600); if (!/^https:\/\//.test(u)) return null;
    if (/csaf|cvrf|\bvex\b/i.test(u + " " + h.name)) return null;   // machine-readable advisories, not detection content
    var ev = str(h.event_id, 120);
    return { name: str(h.name, 100) || FORMATS[h.format], format: h.format, url: u, publisher: str(h.publisher, 80), about: str(h.about, 140), cve: isCve(h.cve) ? h.cve : "", event: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "", date: isDay(h.date) ? h.date : "" };
  }
  function cleanGuide(g) {
    if (!g || typeof g !== "object") return null;
    var a = g.advisory && typeof g.advisory === "object" ? { name: str(g.advisory.name, 100), url: str(g.advisory.url, 600) } : null;
    if (!a || !/^https:\/\//.test(a.url)) return null;
    return { advisory: a, depth: g.read_depth === "full" ? "full" : "summary", readAt: str(g.read_at, 10), check: strs(g.check, 6, 320), fixed: strs(g.fixed, 8, 160), workaround: strs(g.workaround, 5, 320), signs: strs(g.compromise_signs, 6, 320),
      exposure: { internet: 1, internal: 1, local: 1 }[g.exposure] ? g.exposure : "", exploit: g.exploit_public === true, hunt: (Array.isArray(g.hunt) ? g.hunt : []).map(cleanHunt).filter(Boolean).slice(0, 12) };
  }
  // exploitation analysis (the exploit analyst job, an AI model reading public sources): how the flaw is used and the
  // remediation path. Rendered as text only; links must be https pages. The build already refuses records that look like code.
  var SRC_KIND = { vendor: "Vendor", government: "Government", research: "Research", news: "News", database: "Database" };
  function cleanAnalysis(a) {
    if (!a || typeof a !== "object") return null;
    var r = a.remediation && typeof a.remediation === "object" ? a.remediation : {};
    var src = (Array.isArray(a.sources) ? a.sources : []).slice(0, 10).map(function (x) { var u = str(x && x.url, 600); return x && /^https:\/\//.test(u) && SRC_KIND[x.kind] ? { name: str(x.name, 100), url: u, kind: x.kind, full: x.read_depth === "full" } : null; }).filter(Boolean);
    var o = { at: str(a.analyzed_at, 30), status: str(a.exploitation_status, 240), how: str(a.how_exploited, 900), pre: strs(a.preconditions, 6, 260), path: strs(a.attack_path, 6, 280),
      exposure: { internet: "Internet-facing", internal: "Internal network", local: "Local access" }[a.exposure] || "", who: strs(a.who_is_exposed, 5, 260), detect: strs(a.detect, 6, 300),
      priority: { immediate: 1, urgent: 1, planned: 1 }[r.priority] ? r.priority : "", steps: strs(r.steps, 8, 320), fixed: strs(r.fixed_versions, 8, 160), work: strs(r.workarounds, 5, 320), verify: strs(r.verify, 5, 300), ir: strs(r.if_compromised, 6, 300),
      conf: { high: "High", medium: "Medium", low: "Low" }[a.confidence] || "", caveats: str(a.caveats, 500), sources: src };
    return o.how && o.steps.length && src.length >= 2 ? o : null;
  }
  // exploit watch: public GitHub repositories that name the CVE (a signal that exploit code may exist, not proof)
  function cleanRepo(r) {
    if (!r || typeof r !== "object") return { n: 0, top: [] };
    return { n: num(r.repos, 0, 1e5) || 0, top: (Array.isArray(r.top) ? r.top : []).slice(0, 3).map(function (x) { var u = str(x && x.url, 300); return /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(u) ? { name: str(x.name, 100), url: u, stars: num(x.stars, 0, 1e7) || 0 } : null; }).filter(Boolean) };
  }
  function cleanKev(k, guides, eventOf, an) {
    if (!k || typeof k !== "object" || !isCve(k.cve)) return null;
    var g = guides[k.cve] || null, ev = str(eventOf[k.cve], 120);
    return { cve: k.cve, kev: true, vendor: str(k.vendor, 80), product: str(k.product, 120), name: str(k.name, 200), added: isDay(k.added) ? k.added : "", due: isDay(k.due) ? k.due : "", ransomware: k.ransomware === true,
      desc: str(k.desc, 300), cvss: num(k.cvss, 0, 10), epss: num(k.epss, 0, 1), av: /^[NALP]$/.test(k.av || "") ? k.av : "", required: str(k.required, 700),
      refs: strs(k.refs, 4, 600).filter(function (u) { return /^https:\/\//.test(u); }), affected: (Array.isArray(k.affected) ? k.affected : []).slice(0, 60).map(cleanRange).filter(Boolean),
      guide: g, analysis: (an && an[k.cve]) || null, exposure: g ? g.exposure : "", exploit_public: !!(g && g.exploit), event: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "", severity: 3, repos: cleanRepo(k.repo).n, repoTop: cleanRepo(k.repo).top };
  }
  function cleanVuln(v, guides, an) {
    if (!v || typeof v !== "object" || !isCve(v.cve)) return null;
    var g = guides[v.cve] || null, prods = strs(v.products, 6, 60), ev = str(v.event_id, 120);
    return { cve: v.cve, kev: false, vendor: str(v.vendor, 80), product: prods.join(", "), name: str(v.title, 160), added: isDay(v.date) ? v.date : "", due: "", ransomware: false, desc: str(v.desc, 300),
      cvss: num(v.cvss, 0, 10), epss: num(v.epss, 0, 1), av: "", required: str(v.action, 300), refs: [], affected: prods.map(function (p) { return { vendor: str(v.vendor, 60), product: p, from: "", to: "", exact: "", nameOnly: true }; }),
      guide: g, analysis: (an && an[v.cve]) || null, exposure: g ? g.exposure : "", exploit_public: !!(g && g.exploit), event: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "", severity: v.severity === 3 ? 3 : 2, repos: cleanRepo(v.repo).n, repoTop: cleanRepo(v.repo).top };
  }

  var flaws = [], hunt = [], inv = [], rows = [], openCve = "", builtAt = "";
  function loadInv() {
    try { var a = JSON.parse(lsGet("cwm.inv") || "[]"); inv = (Array.isArray(a) ? a : []).slice(0, W.MAX_ITEMS).map(function (x) {
      return x && typeof x === "object" && str(x.name, 120) ? { name: str(x.name, 120).replace(/[<>]/g, ""), vendor: str(x.vendor, 80).replace(/[<>]/g, ""), version: /^[\w.+\-~:]{1,40}$/.test(x.version || "") ? x.version : "", count: Math.max(1, Math.round(+x.count) || 1) } : null; }).filter(Boolean); } catch (e) { inv = []; }
  }
  function saveInv() { return lsSet("cwm.inv", JSON.stringify(inv)); }

  /* shared with the downloadable scanner (workbench-lib.js matchFlaw), so both judge a software list the same way */
  function matchFlaw(f) { return inv.length ? W.matchFlaw(f, inv) : null; }
  function compute() {
    rows = flaws.map(function (f) { var m = matchFlaw(f), s = W.score(f, m, TODAY); return { f: f, m: m, score: s.total, points: s.points }; });
    // "clear" (you run it, but a fixed version) drops to the end: it needs no action
    rows.sort(function (a, b) { var ca = a.m && a.m.state === "clear" ? 1 : 0, cb = b.m && b.m.state === "clear" ? 1 : 0; return ca - cb || b.score - a.score || (a.f.added < b.f.added ? 1 : -1); });
  }
  function dueLeft(f) { return f.due ? Math.round((Date.parse(f.due + "T12:00:00Z") - Date.parse(TODAY + "T12:00:00Z")) / 864e5) : null; }
  function dueText(f) { var n = dueLeft(f); return n === null ? "" : n < 0 ? "Federal deadline passed " + (-n) + (n === -1 ? " day" : " days") + " ago" : n === 0 ? "Federal deadline today" : "Federal deadline in " + n + (n === 1 ? " day" : " days") + " (" + fmtDay(f.due) + ")"; }
  function visibleRows() {
    var q = W.norm($("wbQ").value), show = $("wbShow").value;
    return rows.filter(function (r) {
      if (q && W.norm(r.f.cve + " " + r.f.vendor + " " + r.f.product + " " + r.f.name).indexOf(q) < 0) return false;
      if (show === "mine") return r.m && (r.m.state === "affected" || r.m.state === "check");
      if (show === "due") { var n = dueLeft(r.f); return n !== null && n <= 7; }
      if (show === "guide") return !!r.f.guide;
      if (show === "ot") return !!(OT.data && OT.data.byCve[r.f.cve]);
      return true;
    });
  }
  var STATE = { affected: ["Affected", "bad"], check: ["Check version", "warn"], clear: ["Fixed version", "ok"] };
  function mineText(m) {
    if (!m || m.state === "none") return "";
    var parts = m.items.slice(0, 4).map(function (h) { return h.name + (h.version ? " " + h.version : " (no version)") + (h.count > 1 ? " ×" + h.count : ""); });
    return parts.join("; ") + (m.items.length > 4 ? "; and " + (m.items.length - 4) + " more" : "");
  }
  function list(parent, title, items, ordered) {
    if (!items.length) return; parent.appendChild(el("h4", null, title));
    var l = el(ordered ? "ol" : "ul"); items.forEach(function (x) { l.appendChild(el("li", null, x)); }); parent.appendChild(l);
  }
  var PRIO = { immediate: ["Fix immediately", "bad"], urgent: ["Fix urgently", "warn"], planned: ["Fix in the next planned cycle", "info"] };
  function analysisBox(a) {
    var box = el("section", "wbanal"); box.setAttribute("aria-label", "How it is exploited and how to fix it");
    var h = el("div", "wbanh"); h.appendChild(el("h4", null, "How it is exploited and how to fix it"));
    if (a.priority) h.appendChild(el("span", "badge " + PRIO[a.priority][1], PRIO[a.priority][0]));
    if (a.exposure) h.appendChild(el("span", "badge info", a.exposure));
    box.appendChild(h);
    if (a.status) box.appendChild(el("p", "wbanst", a.status));
    var cols = el("div", "wbancols"), left = el("div", "wbancol"), right = el("div", "wbancol fix");
    left.appendChild(el("h5", null, "The attack"));
    left.appendChild(el("p", null, a.how));
    list(left, "What an attacker needs", a.pre);
    list(left, "How an attack unfolds", a.path, true);
    list(left, "Who is exposed", a.who);
    list(left, "How to detect it", a.detect);
    right.appendChild(el("h5", null, "The remediation path"));
    list(right, "Do this, in order", a.steps, true);
    list(right, "Fixed in", a.fixed);
    list(right, "If you cannot patch yet", a.work);
    list(right, "Confirm the fix took", a.verify);
    list(right, "If you find signs of compromise", a.ir, true);
    cols.appendChild(left); cols.appendChild(right); box.appendChild(cols);
    var sl = el("p", "note"); sl.appendChild(document.createTextNode("Sources read: "));
    a.sources.forEach(function (s, i) { if (i) sl.appendChild(document.createTextNode(" · ")); sl.appendChild(link(s.url, s.name)); sl.appendChild(document.createTextNode(" (" + SRC_KIND[s.kind].toLowerCase() + (s.full ? "" : ", summary") + ")")); });
    box.appendChild(sl);
    box.appendChild(el("p", "note", "Written by CyberView AI (a Claude model), Opus, from the sources listed" + (a.at ? ", " + a.at.slice(0, 10) : "") + (a.conf ? "; confidence " + a.conf.toLowerCase() : "") + ". It explains how the flaw is used so you can defend against it and contains no exploit code. Confirm versions and steps against the vendor advisory before you act." + (a.caveats ? " Caveats: " + a.caveats : "")));
    return box;
  }
  function detail(r) {
    var f = r.f, g = f.guide, d = el("div", "wbdetail");
    if (f.desc) d.appendChild(el("p", null, f.desc));
    if (r.m && r.m.state !== "none") {
      var me = el("div", "wbme " + STATE[r.m.state][1]);
      me.appendChild(el("b", null, r.m.state === "affected" ? "You run an affected version" : r.m.state === "check" ? "You run this product: confirm the version" : "Your listed versions are outside the affected ranges"));
      me.appendChild(el("p", null, mineText(r.m)));
      if (r.m.fixed.length && r.m.state !== "clear") me.appendChild(el("p", null, "NVD lists it as fixed in: " + r.m.fixed.join(", ") + ". Confirm the right fixed release for your branch in the vendor advisory."));
      d.appendChild(me);
    }
    if (f.analysis) d.appendChild(analysisBox(f.analysis));
    var pts = el("div", "wbpts"); pts.appendChild(el("h4", null, "Why it ranks here: " + r.score + " of 100 patch queue points"));
    var pl = el("ul"); r.points.forEach(function (p) { var li = el("li"); li.appendChild(el("b", null, "+" + p[0])); li.appendChild(document.createTextNode(" " + p[1])); pl.appendChild(li); }); pts.appendChild(pl); d.appendChild(pts);
    if (g) {
      var gb = el("div", "wbguide");
      list(gb, "How to check if you are affected", g.check, true);
      list(gb, "Fixed in", g.fixed);
      list(gb, "If you cannot patch yet", g.workaround);
      list(gb, "Signs of compromise to look for", g.signs);
      if (g.hunt.length) { gb.appendChild(el("h4", null, "Detection resources")); var hl = el("ul"); g.hunt.forEach(function (h) { var li = el("li"); li.appendChild(link(h.url, h.name)); li.appendChild(el("span", "note", " " + FORMATS[h.format] + (h.publisher ? " · " + h.publisher : ""))); hl.appendChild(li); }); gb.appendChild(hl); }
      var src = el("p", "note", "Summarised by CyberView AI (a Claude model) from the advisory, " + (g.depth === "full" ? "read in full" : "from its summary page") + (g.readAt ? " on " + g.readAt : "") + ": "); src.appendChild(link(g.advisory.url, g.advisory.name)); gb.appendChild(src);
      d.appendChild(gb);
    } else {
      var fx = W.fixedIn(f);
      if (fx.length) list(d, "Fixed in (from NVD's version ranges)", fx);
      d.appendChild(el("p", "note", "Check and fix steps from the vendor advisory have not been written for this one yet. The advisory desk adds them for new exploited flaws within a day."));
    }
    if (f.repoTop.length) {
      d.appendChild(el("h4", null, "Public repositories naming this CVE (" + f.repos + ")"));
      var rl = el("ul"); f.repoTop.forEach(function (x) { var li = el("li"); li.appendChild(link(x.url, x.name)); li.appendChild(el("span", "note", " " + x.stars + " stars")); rl.appendChild(li); }); d.appendChild(rl);
      d.appendChild(el("p", "note", "Found by an automatic search of GitHub. A repository naming a CVE may hold a working exploit, a detector, notes or nothing useful, and some are traps: review before running anything."));
    }
    if (f.required) { d.appendChild(el("h4", null, f.kev ? "What CISA requires" : "What to do")); d.appendChild(el("p", null, f.required)); }
    d.appendChild(otJoin(f.cve));
    var vbx = el("div"); d.appendChild(vbx);
    loadVendor().then(function (m) { var b = vendorBox(m[f.cve] || null); if (b) vbx.appendChild(b); });
    var ln = el("p", "wblinks");
    f.refs.forEach(function (u) { var host = ""; try { host = new URL(u).host.replace(/^www\./, ""); } catch (e) {} ln.appendChild(link(u, "Advisory (" + (host || "link") + ")")); });
    ln.appendChild(link("https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(f.cve), "NVD record"));
    if (f.event) ln.appendChild(link("./#e=" + f.event, "On the map"));
    d.appendChild(ln);
    return d;
  }
  function renderQueue() { safe("queue", drawQueue); }
  function drawQueue() {
    var vis = visibleRows(), box = $("wbList"); box.textContent = "";
    $("wbNoInv").hidden = inv.length > 0;
    var mine = rows.filter(function (r) { return r.m && r.m.state === "affected"; }).length, chk = rows.filter(function (r) { return r.m && r.m.state === "check"; }).length;
    var over = rows.filter(function (r) { var n = dueLeft(r.f); return n !== null && n < 0; }).length;
    $("wbSummary").textContent = rows.length + " exploited or high-risk flaws ranked" + (inv.length ? " · " + mine + " affect versions you run" + (chk ? " · " + chk + " to check" : "") : "") + " · " + over + " past the federal deadline" + (builtAt ? " · data built " + builtAt.slice(0, 16).replace("T", " ") + " UTC" : "");
    $("wbnQueue").textContent = String(rows.length);
    $("wbCount").textContent = vis.length === rows.length ? "Highest priority first." : vis.length + " of " + rows.length + " shown.";
    if (!vis.length) { box.appendChild(el("li", "empty", "Nothing matches. Clear the search or the filter.")); return; }
    vis.slice(0, 150).forEach(function (r, i) {
      var f = r.f, li = el("li", "wbrow" + (r.m && r.m.state === "clear" ? " clear" : "")), open = openCve === f.cve;
      var b = el("button", "wbhead"); b.type = "button"; b.setAttribute("aria-expanded", open ? "true" : "false");
      var sc = el("span", "wbscore", String(r.score)); sc.title = "Patch queue rank: points out of 100 that order this list (not a CVSS score or the CyberView rating)"; b.appendChild(sc);
      var mid = el("span", "wbmid");
      var top = el("span", "wbtop"); top.appendChild(el("b", null, f.cve)); top.appendChild(document.createTextNode(" " + [f.vendor, f.product].filter(Boolean).join(" ")));
      mid.appendChild(top); mid.appendChild(el("span", "wbname", f.name));
      var chips = el("span", "wbchips");
      if (r.m && STATE[r.m.state]) chips.appendChild(el("span", "badge " + STATE[r.m.state][1], STATE[r.m.state][0] + (r.m.state !== "clear" ? ": " + mineText(r.m) : "")));
      if (f.kev) chips.appendChild(el("span", "badge bad", "Known exploited")); else chips.appendChild(el("span", "badge info", "Not on CISA's list"));
      if (f.ransomware) chips.appendChild(el("span", "badge bad", "Ransomware"));
      var dt = dueText(f); if (dt) chips.appendChild(el("span", "badge " + (dueLeft(f) < 0 ? "warn" : "info"), dt));
      if (f.epss !== null) chips.appendChild(el("span", "badge info", "EPSS " + Math.round(f.epss * 100) + "%"));
      if (f.guide) chips.appendChild(el("span", "badge ok", "Check and fix steps"));
      if (f.analysis) chips.appendChild(el("span", "badge ok", "Exploit and fix analysis"));
      if (OT.data && OT.data.byCve[f.cve]) chips.appendChild(el("span", "badge info", "Industrial advisory"));
      mid.appendChild(chips); b.appendChild(mid);
      b.appendChild(el("span", "wbrank", "#" + (i + 1)));
      b.addEventListener("click", function () { openCve = open ? "" : f.cve; renderQueue(); if (!open) { var n = document.getElementById("row-" + f.cve); if (n) n.querySelector("button").focus(); } });
      li.id = "row-" + f.cve; li.appendChild(b);
      if (open) li.appendChild(detail(r));
      box.appendChild(li);
    });
  }

  /* ---- my software ---- */
  function renderInv() { safe("inv", drawInv); }
  function drawInv() {
    $("wbnInv").textContent = inv.length ? String(inv.length) : "";
    var t = $("wbInvTable"); t.textContent = "";
    if (!inv.length) { $("wbInvHead").textContent = "Nothing loaded yet"; return; }
    var hit = {}; rows.forEach(function (r) { if (r.m) r.m.items.forEach(function (h) { var k = h.name + "|" + h.version; (hit[k] = hit[k] || []).push({ cve: r.f.cve, state: h.state }); }); });
    var order = { affected: 0, check: 1, clear: 2, none: 3 }, list = inv.map(function (it) { var h = hit[it.name + "|" + it.version] || []; var worst = h.reduce(function (w, x) { return order[x.state] < order[w] ? x.state : w; }, "none"); return { it: it, h: h, worst: worst }; })
      .sort(function (a, b) { return order[a.worst] - order[b.worst] || a.it.name.localeCompare(b.it.name); });
    var nAff = list.filter(function (x) { return x.worst === "affected"; }).length, noVer = inv.filter(function (x) { return !x.version; }).length;
    $("wbInvHead").textContent = inv.length + " products on your list · " + nAff + " with an affected version" + (noVer ? " · " + noVer + " without a version (matched by name only)" : "");
    var hr = el("tr"); ["Product", "Version", "Devices", "Exploited flaws"].forEach(function (h) { hr.appendChild(el("th", null, h)); }); var th = el("thead"); th.appendChild(hr); t.appendChild(th);
    var tb = el("tbody");
    list.slice(0, 400).forEach(function (x) {
      var tr = el("tr"); tr.appendChild(el("td", null, (x.it.vendor ? x.it.vendor + " " : "") + x.it.name)); tr.appendChild(el("td", "nowrap", x.it.version || "none given")); tr.appendChild(el("td", null, x.it.count));
      var td = el("td");
      if (!x.h.length) td.appendChild(el("span", "note", "none on file"));
      x.h.slice(0, 6).forEach(function (h) { var b = el("button", "badge " + STATE[h.state][1], h.cve + " · " + STATE[h.state][0]); b.type = "button"; b.addEventListener("click", function () { $("wbQ").value = h.cve; $("wbShow").value = "all"; openCve = h.cve; tab("queue"); renderQueue(); showOpen(); }); td.appendChild(b); });
      tr.appendChild(td); tb.appendChild(tr);
    });
    t.appendChild(tb);
    if (list.length > 400) $("wbInvHead").textContent += " · first 400 shown";
  }
  function addItems(name, text) {
    var r = W.parseInventory(name, text), before = inv.length;
    if (!r.items.length) { $("wbInvMsg").textContent = r.kind === "unreadable JSON" ? "That JSON file could not be read." : "No products found. Use one product per line with its version, or a table with a product column."; return; }
    var seen = {}; inv.forEach(function (x) { seen[W.norm(x.vendor + " " + x.name) + "|" + x.version] = x; });
    r.items.forEach(function (x) { var k = W.norm(x.vendor + " " + x.name) + "|" + x.version; if (seen[k]) seen[k].count = Math.max(seen[k].count, x.count); else if (inv.length < W.MAX_ITEMS) { inv.push(x); seen[k] = x; } });
    var saved = saveInv();
    $("wbInvMsg").textContent = "Read as " + r.kind + ": " + r.items.length + " products, " + (inv.length - before) + " new." + (saved ? "" : " This browser would not save the list, so it lasts until you close the page.") + (inv.length >= W.MAX_ITEMS ? " The list is full at " + W.MAX_ITEMS + "." : "");
    $("wbText").value = ""; compute(); renderInv(); renderQueue(); calLabel();
  }
  function readFile(f) {
    if (!f) return; if (f.size > 8e6) { $("wbInvMsg").textContent = "That file is over 8 MB. Export just the product, version and count columns."; return; }
    var fr = new FileReader(); fr.onload = function () { addItems(f.name, String(fr.result || "")); }; fr.onerror = function () { $("wbInvMsg").textContent = "The file could not be read."; }; fr.readAsText(f);
  }

  /* ---- hunt pack: what to look for in your logs, per exploited flaw and per reported campaign, most urgent first ---- */
  var huntShown = 12;
  function huntCards() {
    var fmt = $("wbFmt").value, mine = $("wbHuntMine").checked && inv.length, cards = [], used = {};
    var keep = function (list) { return list.filter(function (h) { return !fmt || h.format === fmt; }); };
    rows.slice().sort(function (a, b) { return b.score - a.score; }).forEach(function (r) {
      var f = r.f, g = f.guide, an = f.analysis;
      if (mine && !(r.m && (r.m.state === "affected" || r.m.state === "check"))) return;
      var seen = {}, files = keep(((g && g.hunt) || []).concat(hunt.filter(function (h) { return h.cve === f.cve || (f.event && h.event === f.event); }))).filter(function (h) { if (seen[h.url]) return false; seen[h.url] = 1; return true; });
      files.forEach(function (h) { used[h.url] = 1; });
      var signs = g ? g.signs : [], detect = an ? an.detect : [];
      if (fmt ? !files.length : !(signs.length || detect.length || files.length)) return;
      var why = [];
      if (f.kev) why.push("known exploited" + (f.added ? " since " + fmtDay(f.added) : ""));
      if (f.ransomware) why.push("used by ransomware");
      if (f.due) why.push("US federal patch deadline " + fmtDay(f.due));
      if (r.m && STATE[r.m.state]) why.push("your list: " + STATE[r.m.state][0].toLowerCase());
      cards.push({ kind: "flaw", f: f, r: r, title: f.cve + " · " + [f.vendor, f.product].filter(Boolean).join(" "), name: f.name, why: why, signs: signs, signsFrom: g ? g.advisory : null, detect: detect, files: files, date: f.added });
    });
    if (!mine) {
      var byEv = {};
      hunt.forEach(function (h) { if (!h.event || h.cve || used[h.url]) return; (byEv[h.event] = byEv[h.event] || { title: h.about, date: h.date, files: [] }).files.push(h); });
      Object.keys(byEv).forEach(function (k) { var e = byEv[k], files = keep(e.files); if (files.length) cards.push({ kind: "campaign", event: k, title: e.title || "Reported campaign", why: ["reported " + (e.date ? fmtDay(e.date) : "recently")], signs: [], detect: [], files: files, date: e.date }); });
    }
    return cards;
  }
  function huntList(h, items) { var ul = el("ul"); items.forEach(function (t) { ul.appendChild(el("li", null, t)); }); return ul; }
  function renderHunt() { safe("hunt", drawHunt); }
  function drawHunt() {
    var box = $("wbHunt"); box.textContent = "";
    $("wbHuntMine").disabled = !inv.length; $("wbHuntMineL").title = inv.length ? "" : "Load your software list first (Your software tab)";
    var cards = huntCards();
    $("wbnHunt").textContent = cards.length ? String(cards.length) : "";
    $("wbHuntCount").textContent = cards.length ? cards.length + " thing" + (cards.length === 1 ? "" : "s") + " to hunt for" + (cards.length > huntShown ? ", showing " + huntShown : "") : "";
    if (!cards.length) { box.appendChild(el("li", "empty", $("wbHuntMine").checked ? "Nothing to hunt for on your list: no exploited flaw matches your software." : $("wbFmt").value ? "No files in that format." : "Nothing to hunt for yet. Cards appear as vendors publish signs of compromise and the exploit analyst reads the advisories.")); $("wbHuntMore").hidden = true; return; }
    cards.slice(0, huntShown).forEach(function (c) {
      var li = el("li", "wbhcard" + (c.kind === "campaign" ? " camp" : ""));
      var top = el("div", "wbhtop");
      top.appendChild(el("span", "badge " + (c.kind === "campaign" ? "info" : c.f.ransomware ? "bad" : "warn"), c.kind === "campaign" ? "Campaign" : c.f.ransomware ? "Ransomware" : c.f.kev ? "Exploited" : "Flaw"));
      var t = el("div"); t.appendChild(el("h3", null, c.title)); if (c.name) t.appendChild(el("p", "note", c.name)); if (c.why.length) t.appendChild(el("p", "wbhwhy", "Why now: " + c.why.join(" · ")));
      top.appendChild(t); li.appendChild(top);
      if (c.signs.length) { var s1 = el("div", "wbhsec"); var h1 = el("h4", null, "What the vendor says to look for "); if (c.signsFrom) h1.appendChild(link(c.signsFrom.url, "(" + (c.signsFrom.name || "advisory") + ")")); s1.appendChild(h1); s1.appendChild(huntList(null, c.signs)); li.appendChild(s1); }
      if (c.detect.length) { var s2 = el("div", "wbhsec"); s2.appendChild(el("h4", null, "Where to look")); s2.appendChild(huntList(null, c.detect)); s2.appendChild(el("p", "note", "Written by CyberView AI (a Claude model) from the advisories it read; check against the vendor's own guidance.")); li.appendChild(s2); }
      if (c.files.length) { var s3 = el("div", "wbhsec"); s3.appendChild(el("h4", null, "Detection files from the publishers")); var ul = el("ul", "wbhfiles");
        c.files.forEach(function (h) { var x = el("li"); x.appendChild(el("span", "badge info", FORMATS[h.format])); x.appendChild(document.createTextNode(" ")); x.appendChild(link(h.url, h.name)); if (h.publisher) x.appendChild(el("span", "note", " · " + h.publisher)); ul.appendChild(x); });
        s3.appendChild(ul); li.appendChild(s3); }
      var act = el("p", "wbhact");
      if (c.kind === "flaw") { var b = el("button", "linkbtn", "Fix steps in the patch queue"); b.type = "button"; b.addEventListener("click", function () { $("wbQ").value = c.f.cve; openCve = c.f.cve; tab("queue"); renderQueue(); showOpen(); }); act.appendChild(b); if (c.f.event) { act.appendChild(document.createTextNode(" · ")); act.appendChild(link("./#e=" + c.f.event, "On the map")); } }
      else act.appendChild(link("./#e=" + c.event, "Read the report on the map"));
      li.appendChild(act); box.appendChild(li);
    });
    $("wbHuntMore").hidden = cards.length <= huntShown;
  }
  function toHuntPlan() {
    var cards = huntCards(), L = ["HUNT PLAN  " + TODAY, "From CyberView's workbench" + ($("wbHuntMine").checked && inv.length ? ", only flaws on our software list" : "") + ". Look for signs that someone got in before the fix was applied.", ""];
    cards.slice(0, 40).forEach(function (c, i) {
      L.push((i + 1) + ". " + c.title + (c.name ? "  (" + c.name + ")" : ""));
      if (c.why.length) L.push("   Why now: " + c.why.join("; "));
      if (c.signs.length) { L.push("   Vendor says look for:" + (c.signsFrom ? " (" + c.signsFrom.url + ")" : "")); c.signs.forEach(function (x) { L.push("   - " + x); }); }
      if (c.detect.length) { L.push("   Where to look (written by CyberView AI, a Claude model, from the advisories):"); c.detect.forEach(function (x) { L.push("   - " + x); }); }
      c.files.forEach(function (h) { L.push("   File: " + FORMATS[h.format] + " " + h.name + "  " + h.url); });
      L.push("");
    });
    return L.join("\n");
  }

  /* ---- exports ---- */
  function csvCell(v) { v = String(v == null ? "" : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }   // no spreadsheet formulas
  function toCsv() {
    var L = [["Rank", "Queue points", "CVE", "Vendor", "Product", "Flaw", "Known exploited", "Ransomware", "EPSS %", "CVSS", "CISA deadline", "Your status", "Your versions", "Fixed in", "Why", "Advisory", "NVD"]];
    visibleRows().forEach(function (r, i) { var f = r.f, g = f.guide;
      L.push([i + 1, r.score, f.cve, f.vendor, f.product, f.name, f.kev ? "yes" : "no", f.ransomware ? "yes" : "no", f.epss === null ? "" : Math.round(f.epss * 100), f.cvss === null ? "" : f.cvss, f.due,
        r.m && STATE[r.m.state] ? STATE[r.m.state][0] : inv.length ? "Not on your list" : "", mineText(r.m), (g && g.fixed.length ? g.fixed : (r.m && r.m.fixed.length ? r.m.fixed : W.fixedIn(f))).join("; "),
        r.points.map(function (p) { return "+" + p[0] + " " + p[1]; }).join("; "), (g && g.advisory.url) || f.refs[0] || "", "https://nvd.nist.gov/vuln/detail/" + f.cve]); });
    return L.map(function (row) { return row.map(csvCell).join(","); }).join("\r\n") + "\r\n";
  }
  function toChange() {
    var top = visibleRows().filter(function (r) { return !r.m || r.m.state !== "clear"; }).slice(0, 10), L = ["PATCH PRIORITIES  " + TODAY, "From CyberView's workbench" + (inv.length ? ", matched against our software list (" + inv.length + " products)" : " (general ranking; no software list loaded)"), ""];
    top.forEach(function (r, i) { var f = r.f, g = f.guide;
      L.push((i + 1) + ". " + f.cve + "  " + [f.vendor, f.product].filter(Boolean).join(" ") + "  [queue points " + r.score + "/100]");
      if (r.m && r.m.state !== "none") L.push("   We run: " + mineText(r.m) + " -> " + STATE[r.m.state][0]);
      L.push("   Why: " + r.points.map(function (p) { return p[1]; }).join("; "));
      var fx = g && g.fixed.length ? g.fixed : (r.m && r.m.fixed.length ? r.m.fixed : W.fixedIn(f)); if (fx.length) L.push("   Fixed in: " + fx.join("; "));
      if (dueText(f)) L.push("   " + dueText(f));
      L.push("   " + ((g && g.advisory.url) || f.refs[0] || "https://nvd.nist.gov/vuln/detail/" + f.cve)); L.push("");
    });
    L.push("Version ranges are from NIST NVD and can lag: confirm against the vendor advisory before closing an item.");
    return L.join("\n");
  }
  function flash(btn, t) { var old = btn.textContent; btn.textContent = t; setTimeout(function () { btn.textContent = old; }, 2200); }

  /* bring the opened flaw into view (on a phone it is otherwise below the fold) */
  function showOpen() { var n = openCve && document.getElementById("row-" + openCve); if (n) { try { n.scrollIntoView({ block: "start" }); } catch (e) { n.scrollIntoView(); } var b = n.querySelector("button"); if (b) b.focus({ preventScroll: true }); } }

  /* ---- patch deadlines: chart and calendar file (built here; nothing is sent) ---- */
  function openDeadlines() { return flaws.filter(function (f) { return f.kev && f.due && f.due >= TODAY; }); }
  function drawDeadlines() {
    var box = $("wbDlChart"); box.textContent = "";
    var up = [], over = [];
    flaws.forEach(function (f) { var n = f.kev ? dueLeft(f) : null; if (n === null) return; if (n >= 0) up.push({ f: f, n: n }); else if (n >= -14) over.push({ f: f, n: n }); });
    up.sort(function (a, b) { return a.n - b.n; }); over.sort(function (a, b) { return b.n - a.n; });
    $("kevCal").disabled = !openDeadlines().length;
    if (!up.length && !over.length) { box.appendChild(el("p", "note", "No known-exploited flaws with a deadline in the last two weeks or ahead.")); return; }
    var UP = up.slice(0, 8), OV = over.slice(0, 6), lo = Math.max(-14, Math.min(-3, OV.reduce(function (m, r) { return Math.min(m, r.n); }, 0))), hi = Math.min(28, Math.max(7, UP.reduce(function (m, r) { return Math.max(m, r.n); }, 0)));
    var zero = (-lo) / (hi - lo) * 100;
    function group(title, rows, total) {
      if (!rows.length) return;
      box.appendChild(el("h3", "wbdlh", title + " (" + total + ")"));
      var ul = el("ul", "wbdlist");
      rows.forEach(function (r) {
        var f = r.f, li = el("li"), b = el("button", "wbdlrow"); b.type = "button";
        var name = (f.vendor && f.product && f.product.toLowerCase().indexOf(f.vendor.toLowerCase()) < 0 ? f.vendor + " " + f.product : f.product || f.vendor) || f.name;
        var lab = el("span", "wbdllab"); lab.appendChild(el("b", null, name)); lab.appendChild(el("span", "note", f.cve + (f.ransomware ? " · used by ransomware" : "")));
        var track = el("span", "wbdltrack"), zl = el("span", "wbdlzero"); zl.style.left = zero + "%"; track.appendChild(zl);
        var bar = el("span", "wbdlbar" + (r.n < 0 ? " over" : "")), len = Math.min(Math.abs(r.n), r.n < 0 ? -lo : hi) / (hi - lo) * 100;
        bar.style.width = Math.max(r.n === 0 ? 0.8 : 1.2, len) + "%"; bar.style.left = (r.n < 0 ? zero - len : zero) + "%"; track.appendChild(bar);
        var txt = r.n === 0 ? "due today" : r.n < 0 ? (-r.n) + (r.n === -1 ? " day" : " days") + " overdue" : r.n + (r.n === 1 ? " day" : " days") + " left";
        b.setAttribute("aria-label", name + " " + f.cve + ": " + txt);
        b.appendChild(lab); b.appendChild(track); b.appendChild(el("span", "wbdltxt", txt));
        b.addEventListener("click", function () { goKnown(f.cve); });
        li.appendChild(b); ul.appendChild(li);
      });
      box.appendChild(ul);
      if (total > rows.length) box.appendChild(el("p", "note", "+" + (total - rows.length) + " more in the list below (use the Show filter: deadline within 7 days or passed)."));
    }
    group("Deadline ahead", UP, up.length); group("Deadline passed in the last two weeks", OV, over.length);
  }
  function renderDeadlines() { safe("queue", drawDeadlines); }
  function icsEsc(t) { return String(t || "").replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n"); }
  function icsFold(line) { var out = [], s = line; while (s.length > 73) { out.push(s.slice(0, 73)); s = " " + s.slice(73); } out.push(s); return out.join("\r\n"); }
  function plusDay(d) { return new Date(Date.parse(d + "T12:00:00Z") + 864e5).toISOString().slice(0, 10).replace(/-/g, ""); }
  function kevIcs(list) {
    var stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z"), L = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//CyberView//Patch deadlines//EN", "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:CyberView patch deadlines"];
    list.forEach(function (f) {
      var what = (f.vendor + " " + f.product).trim();
      L.push("BEGIN:VEVENT", "UID:" + f.cve.toLowerCase() + "-due@cyberview", "DTSTAMP:" + stamp, "DTSTART;VALUE=DATE:" + f.due.replace(/-/g, ""), "DTEND;VALUE=DATE:" + plusDay(f.due),
        "SUMMARY:" + icsEsc("Patch " + f.cve + " (" + what + "): CISA deadline"),
        "DESCRIPTION:" + icsEsc((f.desc ? f.desc + "\n\n" : "") + (f.ransomware ? "Known to be used in ransomware.\n" : "") + "Added to CISA's known-exploited list " + f.added + ". The deadline binds US federal agencies; treat it as an upper limit.\nNVD: https://nvd.nist.gov/vuln/detail/" + f.cve + "\nCyberView: " + location.origin + location.pathname + "#" + f.cve),
        "URL:https://nvd.nist.gov/vuln/detail/" + f.cve, "CATEGORIES:Security,Patch",
        "BEGIN:VALARM", "ACTION:DISPLAY", "DESCRIPTION:" + icsEsc("Patch " + f.cve + " due in 3 days"), "TRIGGER:-P3D", "END:VALARM", "END:VEVENT");
    });
    L.push("END:VCALENDAR");
    return L.map(icsFold).join("\r\n") + "\r\n";
  }
  function saveFile(name, mime, text) {
    var a = el("a"); a.href = blobUrl(new Blob([text], { type: mime })); var u = a.href; a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(u); }, 4000);
  }
  function calendar() {
    var pool = openDeadlines();
    if (inv.length) { var mineIds = {}; rows.forEach(function (r) { if (r.m && (r.m.state === "affected" || r.m.state === "check")) mineIds[r.f.cve] = 1; }); pool = pool.filter(function (f) { return mineIds[f.cve]; }); }
    var msg = $("wbDlMsg");
    if (!pool.length) { msg.textContent = inv.length ? "None of the open deadlines affect software on your list." : "There are no open deadlines."; return; }
    saveFile("cyberview-patch-deadlines.ics", "text/calendar;charset=utf-8", kevIcs(pool));
    msg.textContent = pool.length + " deadline" + (pool.length > 1 ? "s" : "") + " saved as a calendar file" + (inv.length ? " (software on your list only)" : "") + ". Open it to add them to your calendar; each has a reminder 3 days before.";
  }
  function calLabel() { $("kevCal").textContent = inv.length ? "My deadlines to calendar" : "Deadlines to calendar"; }

  /* ---- All CVEs: the CVE List as static lookup files (data/cve/, written by scripts/cve.mjs site), read on demand ---- */
  var CV = { idx: null, state: "idle", waiting: null, files: {}, ready: {}, sets: {}, pool: [], list: [], page: 0, open: "", kev: {}, events: null };
  var PAGE = 200, SEV = { C: ["Critical", "bad"], H: ["High", "bad"], M: ["Medium", "warn"], L: ["Low", "info"], N: ["None", "info"] };
  var CAVEAT = "What this is: every CVE published in the official CVE List (CVE Program), including CISA's enrichment: CVSS where the assigner gave none, the weakness (CWE), whether CISA has seen it exploited, and NVD's affected-version ranges where NVD has analysed the flaw (matched against your software list in this browser, never uploaded). Descriptions are trimmed, the first affected product is shown, and the list is rebuilt about every hour, so a very new change can be missing: the CVE record and NVD stay the authority. Exploit likelihood is FIRST EPSS, refreshed daily. \"Known exploited\" means listed in CISA's catalog (or seen exploited by CISA); it is also joined here from the catalog as CyberView holds it. A CVE is a database record, not an event on the map.";
  function fmtN(n) { try { return n.toLocaleString("en-US"); } catch (e) { return String(n); } }
  function fmtLong(d) { if (!d) return ""; try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { return d; } }
  function buildKev() { CV.kev = {}; flaws.forEach(function (f) { if (f.kev) CV.kev[f.cve] = f; }); }
  function cvStatus(msg) { var b = $("cvStatus"); b.hidden = !msg; b.textContent = msg || ""; $("cvMain").hidden = !!msg; }
  function getJson(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("http"); return r.json(); }); }
  /* vendor security advisories joined on CVE (data/psirt.json, scripts/psirt.mjs): loaded once; without it the page works as before */
  function loadVendor() {
    if (!CV.vendor) CV.vendor = getJson("data/psirt.json").then(function (j) { D.vendorIndex = D.cleanVendorIndex(j); return D.vendorIndex; }, function () { return {}; });
    return CV.vendor;
  }
  function vendorSays(r) { return (r && Array.isArray(r.adv) ? r.adv : []).filter(function (a) { return a.x; })[0] || null; }
  /** the vendor's own advisories for one CVE: link, the vendor's severity, fixed versions as stated, and its own exploited statement */
  function vendorBox(adv) {
    if (!Array.isArray(adv) || !adv.length) return null;
    var box = el("div", "wbvendor"); box.appendChild(el("h4", null, adv.length > 1 ? "The vendors' own advisories" : "The vendor's own advisory"));
    var ul = el("ul");
    adv.forEach(function (a) {
      var li = el("li"); li.appendChild(link(a.url, a.vendor + " " + a.id));
      if (a.sev) li.appendChild(el("span", "note", " · " + a.vendor + " rates it " + a.sev));
      if (a.x) { li.appendChild(document.createTextNode(" ")); li.appendChild(el("span", "badge bad", "Exploited (vendor)")); var q = el("p", "note", a.vendor + "'s statement: \u201c" + a.x + "\u201d"); li.appendChild(q); }
      if (a.fixed.length) li.appendChild(el("p", "note", "Fixed in, as " + a.vendor + " states it: " + a.fixed.join("; ")));
      ul.appendChild(li);
    });
    box.appendChild(ul);
    box.appendChild(el("p", "note", "Collected from the vendors' own advisories (CSAF, feeds and pages) by a script, not written by CyberView. A vendor's \u201cexploited\u201d statement raises the CyberView rating's Exploit Code Maturity to High, labelled as the vendor's statement."));
    return box;
  }
  function ensureIndex() {
    if (CV.waiting) return CV.waiting;
    CV.state = "loading";
    CV.waiting = Promise.all([getJson("data/cve/index.json"), loadVendor()]).then(function (a) { var j = a[0];
      var ix = D.cleanIndex(j); if (!ix) throw new Error("invalid");
      CV.idx = ix; CV.state = "ready"; initCvUi(); return ix;
    }).catch(function () {
      CV.state = "missing"; CV.waiting = null;
      cvStatus("The CVE list is not available right now. It is built when the site is deployed, so it can be missing just after a change. Known exploited flaws and My software work without it; try this view again in a little while.");
      return null;
    });
    return CV.waiting;
  }
  function initCvUi() {
    var ix = CV.idx, sel = $("cvYear"); sel.textContent = "";
    var o0 = el("option", null, "Published or changed in the last two weeks"); o0.value = "recent"; sel.appendChild(o0);
    ix.years.forEach(function (y) { var o = el("option", null, y.year + " · " + fmtN(y.count) + " CVEs"); o.value = String(y.year); sel.appendChild(o); });
    if (ix.total !== null) $("wbnAll").textContent = fmtN(ix.total);
    var age = ix.cvelist ? Math.round((Date.now() - Date.parse(ix.cvelist)) / 6e4) : null;
    $("cvSummary").textContent = (ix.total !== null ? fmtN(ix.total) + " CVEs on file, every one published since 1999" + (ix.rejected !== null ? " (" + fmtN(ix.rejected) + " of them rejected)" : "") + ". " : "") +
      (ix.kev !== null ? fmtN(ix.kev) + " are in CISA's known-exploited catalog" + (ix.ransomware ? " (" + fmtN(ix.ransomware) + " used by ransomware)" : "") + (ix.criticalNvd ? "; " + fmtN(ix.criticalNvd) + " are rated Critical by NVD's CVSS v3 scores" + (ix.critical !== null ? " (" + fmtN(ix.critical) + " when the vendor's own score is used first)" : "") : ix.critical !== null ? "; " + fmtN(ix.critical) + " are rated Critical (CVSS v3 or v4)" : "") + ". " :
        ix.exploited !== null ? fmtN(ix.exploited) + " are known or seen exploited. " : "") +
      (ix.withRanges ? fmtN(ix.withRanges) + " carry NVD affected-version ranges, so your software list can be matched by version. " : "") +
      (ix.ratingBands ? "CyberView rating (CVSS adjusted for exploitation): " + ["Critical", "High", "Medium"].map(function (b) { return fmtN(ix.ratingBands[b] || 0) + " " + b; }).join(", ") + ", " + fmtN((ix.ratingBands.Low || 0) + (ix.ratingBands.None || 0)) + " Low or None, " + fmtN(ix.ratingBands["Not scored"] || 0) + " not scored (no CVSS score). " : "") +
      (ix.decisions ? "CISA SSVC priority today: " + fmtN(ix.decisions.act || 0) + " Act, " + fmtN(ix.decisions.attend || 0) + " Attend, " + fmtN(ix.decisions["track*"] || 0) + " Track*, the rest Track. " : "") +
      (ix.audit && ix.audit.nvdTotal !== null ? "Checked against NVD and CISA every hour: NVD lists " + fmtN(ix.audit.nvdTotal) + " CVEs (" + fmtN(ix.audit.nvdRejected) + " rejected), CISA " + fmtN(ix.audit.cisaKev) + " known exploited; NVD's own scores rate " + fmtN(ix.audit.nvdCritical) + " Critical, ours use the assigner's score first. " : "") +
      (age !== null && isFinite(age) ? "Updated " + (age < 90 ? age + " minutes" : Math.round(age / 60) + " hours") + " ago." + (age > 360 ? " This is older than it should be; the hourly update may be failing." : "") : "");
    $("cvCaveat").textContent = CAVEAT;
    buildKev(); cvStatus("");
  }
  function getFile(file) {
    if (CV.files[file]) return CV.files[file];
    var pr = getJson("data/cve/" + file).then(function (d) { var c = D.parseFile(d); CV.ready[file] = c; return c; });
    CV.files[file] = pr; pr.catch(function () { delete CV.files[file]; });
    return pr;
  }
  function loadEvents() {
    if (!CV.events) CV.events = getJson("data/archive/search.json").then(function (d) {
      var f = d.fields || [], ci = f.indexOf("cves"), ii = f.indexOf("id"), ti = f.indexOf("title");
      return (d.rows || []).slice(0, 20000).map(function (r) { return { id: str(r[ii], 80), title: str(r[ti], 200), cves: Array.isArray(r[ci]) ? r[ci].filter(isCve) : [] }; });
    });
    return CV.events;
  }
  /* the CVSS base score the rating starts from (the assigner's or CISA's, else NVD's), named as CVSS so it is never read as the CyberView rating */
  function sevBadge(r) {
    var nvd = r.cvss === null && r.ncvss !== null, s = nvd ? r.ncvss : r.cvss, k = nvd ? r.nsev : r.sev;
    if (s === null) return el("span", "badge info", "No CVSS score");
    var b = el("span", "badge " + (SEV[k] ? SEV[k][1] : "info"), "CVSS " + s.toFixed(1) + (SEV[k] ? " " + SEV[k][0] : "") + (nvd ? " (NVD)" : "")); b.title = "CVSS base score from " + (nvd ? "NVD" : "the assigner or CISA") + ", before any adjustment"; return b;
  }
  function isKev(r) { return !!(r.kev || CV.kev[r.id]); }
  var DEC_CLASS = { act: "bad", attend: "warn", "track*": "info", track: "info" };
  function decBadge(rt) { var b = el("span", "badge " + (DEC_CLASS[rt.decision] || "info"), (rt.decision ? "Priority: " : "") + rt.label); b.title = rt.does; return b; }
  var onMapIds = null;   // CVEs a checked event covers, once the archive index has loaded
  /* match one All-CVEs row against the visitor's software list, in the browser, through the SAME matcher as the workbench
     (CVWorkbench.match over NVD's affected-version ranges on the row). When NVD has no ranges for the CVE yet, fall back to a
     name-only "check". Returns null when nothing matches or no list is loaded. nameOnly marks a product-only (not version) match. */
  function mineMatch(r) {
    if (!inv.length || r.rejected) return null;
    var ranges = Array.isArray(r.affected) ? r.affected : [];
    if (ranges.length) { var m = W.match({ vendor: r.vendor, product: r.product, affected: ranges }, inv); return m.state === "none" ? null : m; }
    if (!r.product) return null;
    var hits = inv.filter(function (it) { return W.nameHit((it.vendor ? it.vendor + " " : "") + it.name, r.vendor, r.product); });
    if (!hits.length) return null;
    return { state: "check", nameOnly: true, items: hits.slice(0, 20).map(function (it) { return { name: it.name, version: it.version, count: it.count, state: "check" }; }), fixed: [] };
  }
  function rateOpts() { return { mission: $("cvMission").value, exposed: $("cvExposed").value === "yes" ? true : $("cvExposed").value === "no" ? false : undefined }; }
  function onMap(r) { return !!(onMapIds && onMapIds[r.id]); }
  /* the CyberView rating, every step listed: CVSS base x CVSS v3.1 Exploit Code Maturity, CVSS Roundup, CVSS's bands */
  function scoreBox(r) {
    var sc = D.scored(r); if (!sc) return null;
    var box = el("div", "wbme cvscorebox " + sc.tone), head = el("div", "cvsh");
    var big = el("span", "cvbig", sc.score !== null ? sc.score.toFixed(1) : "-"); big.title = sc.score !== null ? "CyberView rating on the CVSS scale, 0.0 to 10.0" : "Not scored: no CVSS base score"; head.appendChild(big);
    var hl = el("div"); hl.appendChild(el("b", null, sc.score !== null ? "CyberView rating: " + sc.score.toFixed(1) + " " + sc.band : "CyberView rating: not scored"));
    hl.appendChild(el("p", "note", "The CVSS base score adjusted for exploitation evidence with CVSS's own Exploit Code Maturity metric (CVSS v3.1), on the same 0.0 to 10.0 scale with the same bands as CVSS. Never higher than the CVSS base score. How urgent it is for you: the priority below."));
    head.appendChild(hl); box.appendChild(head);
    if (sc.score === null) { box.appendChild(el("p", "cvline", sc.text)); return box; }
    var tb = el("div", "cvfactors");
    var step = function (label, value, why) { var row = el("div", "cvf"); row.appendChild(el("span", "cvfl", label)); row.appendChild(el("span", "cvfp", value)); if (why) row.appendChild(el("span", "cvfw", why)); tb.appendChild(row); };
    var b = sc.base;
    step("CVSS base score", b.score.toFixed(1) + " " + sc.baseBand, "From " + b.from + (b.ver ? ", CVSS v" + b.ver : "") + (b.vector ? " · " + b.vector : ""));
    step("Exploit Code Maturity (E)", "x " + sc.e.value.toFixed(2) + " " + sc.e.label, sc.eWhy.charAt(0).toUpperCase() + sc.eWhy.slice(1) + ". CVSS v3.1 values: High 1.00, Proof-of-Concept 0.94, Unproven 0.91.");
    step("CyberView rating", "= " + sc.score.toFixed(1) + " " + sc.band, "Rounded up to one decimal (CVSS Roundup). Bands as CVSS: Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0.");
    box.appendChild(tb);
    box.appendChild(el("p", "cvline", sc.text));
    sc.notes.forEach(function (n) { box.appendChild(el("p", "note", n)); });
    box.appendChild(el("p", "note", "Confidence " + sc.confidence.toLowerCase() + ": " + sc.confidenceWhy + ". Not in the rating, shown with the priority below: EPSS, ransomware use, CISA's dates and your own settings."));
    return box;
  }
  function rateBox(r) {
    var rt = D.rated(r), box = el("div", "wbme cvrate " + (DEC_CLASS[rt.decision] || "info"));
    box.appendChild(el("b", null, rt.decision ? "Priority: " + rt.label + " (CISA SSVC)" : rt.label));
    box.appendChild(el("p", null, rt.does));
    if (!rt.decision) return box;
    var fx = rt.fixBy || {}, ul = el("ul");
    var line = function (k, label) { var t = fx[k]; if (!t || (rt.fixFor && rt.fixFor !== k)) return; var li = el("li"); li.appendChild(el("b", null, label + ": ")); li.appendChild(document.createTextNode(t.text)); ul.appendChild(li); };
    line("exposed", "Fix by, internet-facing systems (CISA BOD 26-04)"); line("internal", "Fix by, internal systems (CISA BOD 26-04)");
    if (rt.deadline) { var li = el("li"); li.appendChild(el("b", null, "CISA catalog due date: ")); li.appendChild(document.createTextNode(fmtLong(rt.deadline) + (rt.overdue ? " (passed)" : ""))); ul.appendChild(li); }
    box.appendChild(ul);
    box.appendChild(el("h4", null, "How it was decided"));
    var il = el("ul"); rt.inputs.forEach(function (x) { var li = el("li"); li.appendChild(el("b", null, x.name + ": " + x.value)); li.appendChild(document.createTextNode(" · " + x.basis)); il.appendChild(li); }); box.appendChild(il);
    if (rt.signals.length) { box.appendChild(el("h4", null, "Supporting signals")); var sl = el("ul"); rt.signals.forEach(function (x) { sl.appendChild(el("li", null, x.text)); }); box.appendChild(sl); }
    var how = el("button", "linkbtn", "How CyberView rates vulnerabilities"); how.type = "button"; how.addEventListener("click", function () { var h = $("cvHow"); h.open = true; h.scrollIntoView({ block: "start" }); }); box.appendChild(how);
    return box;
  }
  function cvCard(r, open, rank) {
    var li = el("li", "wbrow cvrow" + (r.rejected ? " clear" : "")), b = el("button", "wbhead cvhead"); b.type = "button"; b.setAttribute("aria-expanded", open ? "true" : "false");
    // the square is the plain CVSS base score (the same one the rating starts from), captioned so it is never read as the rating
    var base = r.cvss !== null ? r.cvss : (r.ncvss != null ? r.ncvss : null), fromNvd = r.cvss === null && base !== null;
    var sc = el("span", "wbscore cvscore"); sc.appendChild(el("span", "cvnum", base !== null ? base.toFixed(1) : "-")); sc.appendChild(el("span", "cvcap", fromNvd ? "CVSS (NVD)" : "CVSS"));
    sc.title = base !== null ? "CVSS base score from " + (fromNvd ? "NVD" : "the assigner or CISA") + ", before the CyberView adjustment" : "No CVSS base score"; b.appendChild(sc);
    var mid = el("span", "wbmid"), top = el("span", "wbtop"); top.appendChild(el("b", null, r.id)); var who = [r.vendor, r.product].filter(Boolean).join(" "); if (who) top.appendChild(document.createTextNode(" " + who));
    mid.appendChild(top); mid.appendChild(el("span", "wbname", (r.title || r.desc || "No description.").slice(0, 200)));
    var chips = el("span", "wbchips"); if (!r.rejected) { chips.appendChild(decBadge(D.rated(r))); var scx = D.scored(r); if (scx) { var sbg = el("span", "badge " + scx.tone, scx.score !== null ? "CyberView " + scx.score.toFixed(1) + " " + scx.band : "CyberView: not scored"); sbg.title = scx.text; chips.appendChild(sbg); } } chips.appendChild(sevBadge(r));
    if (r.rejected) chips.appendChild(el("span", "badge warn", "Rejected"));
    if (isKev(r)) chips.appendChild(el("span", "badge bad", "Known exploited")); else if (r.expl === "active") chips.appendChild(el("span", "badge bad", "Exploited (CISA)"));
    else if (vendorSays(r)) { var vxb = el("span", "badge bad", "Exploited (vendor)"); vxb.title = vendorSays(r).vendor + "'s own advisory says it is exploited in the wild"; chips.appendChild(vxb); }
    if (r.ransom) chips.appendChild(el("span", "badge bad", "Ransomware"));
    if (r.epss !== null) chips.appendChild(el("span", "badge info", "EPSS " + (r.epss * 100).toFixed(r.epss < 0.01 ? 2 : 1) + "%"));
    var mm = mineMatch(r);
    if (mm) {
      if (mm.state === "affected") { var ab = el("span", "badge bad", "Your software: affected version"); ab.title = "A version on your software list falls inside NVD's affected-version range for this CVE"; chips.appendChild(ab); }
      else if (mm.state === "check") { var cb = el("span", "badge warn", mm.nameOnly ? "On your software list" : "Your software: check version"); cb.title = mm.nameOnly ? "You run this product; NVD has no version ranges for this CVE yet, so the version is not checked" : "You run this product; add the version to your list to confirm whether it is affected"; chips.appendChild(cb); }
      else if (mm.state === "clear") { var lb = el("span", "badge ok", "Your version is outside the range"); lb.title = "Every version you listed for this product is outside NVD's affected-version ranges"; chips.appendChild(lb); }
    }
    if (onMap(r)) chips.appendChild(el("span", "badge info", "On CyberView's map"));
    if (OT.data && OT.data.byCve[r.id]) chips.appendChild(el("span", "badge info", "Industrial advisory"));
    if (r.cwe) chips.appendChild(el("span", "badge info", r.cwe));
    if (r.pub) chips.appendChild(el("span", "badge info", r.pub));
    mid.appendChild(chips); b.appendChild(mid); b.appendChild(el("span", "wbrank", rank ? "#" + rank : ""));
    if (rank) b.addEventListener("click", function () { CV.open = open ? "" : r.id; renderAll(); var n = document.getElementById("cv-" + r.id); if (n) n.querySelector("button").focus({ preventScroll: true }); });
    li.id = rank ? "cv-" + r.id : "cvr-" + r.id; li.appendChild(b); if (open) li.appendChild(cvDetail(r));
    return li;
  }
  function cvDetail(r) {
    var d = el("div", "wbdetail"); if (r.desc) d.appendChild(el("p", null, r.desc));
    var sb = scoreBox(r); if (sb) d.appendChild(sb);
    d.appendChild(rateBox(r));
    var kv = el("ul");
    [["Affects", [r.vendor, r.product].filter(Boolean).join(" ")], ["Published", fmtLong(r.pub)], ["Last changed", r.upd && r.upd !== r.pub ? fmtLong(r.upd) : ""], ["Assigned by", r.cna],
      ["CVSS", r.cvss !== null ? r.cvss.toFixed(1) + (r.sev ? " " + SEV[r.sev][0].toLowerCase() : "") + (r.ver ? " (v" + r.ver + ")" : "") : ""],
      ["CVSS from NVD", r.ncvss !== null && (r.cvss === null || r.ncvss !== r.cvss) ? r.ncvss.toFixed(1) + (r.nsev ? " " + SEV[r.nsev][0].toLowerCase() : "") : ""], ["Weakness", r.cwe],
      ["CISA exploitation", r.expl ? D.EXPL[r.expl] : ""], ["Exploit likelihood (EPSS)", r.epss !== null ? (r.epss * 100).toFixed(2) + "% chance of exploitation in the next 30 days" + (r.pct !== null ? "; higher than " + (r.pct * 100).toFixed(1) + "% of CVEs" : "") : ""]]
      .forEach(function (p) { if (!p[1]) return; var li = el("li"); li.appendChild(el("b", null, p[0] + ": ")); li.appendChild(document.createTextNode(p[1])); kv.appendChild(li); });
    d.appendChild(kv);
    var mm2 = mineMatch(r);
    if (mm2) {
      var cls = mm2.state === "affected" ? "bad" : mm2.state === "clear" ? "ok" : "warn";
      var me2 = el("div", "wbme " + cls);
      me2.appendChild(el("b", null, mm2.state === "affected" ? "You run an affected version" : mm2.state === "clear" ? "Your listed versions are outside the affected ranges" : "You run this product: confirm the version"));
      var ml = el("ul");
      (mm2.items || []).slice(0, 12).forEach(function (it) { var li = el("li"); li.appendChild(document.createTextNode((it.name || "") + (it.version ? " " + it.version : " (no version)") + (it.count > 1 ? " × " + it.count : "") + (it.state === "affected" ? " — affected" : it.state === "clear" ? " — outside the range" : ""))); ml.appendChild(li); });
      if (ml.childNodes.length) me2.appendChild(ml);
      if (mm2.fixed && mm2.fixed.length) me2.appendChild(el("p", "note", "Fixed in, as NVD states it: " + mm2.fixed.join("; ")));
      me2.appendChild(el("p", "note", mm2.nameOnly ? "Matched by product name only: NVD has published no version ranges for this CVE yet, so the version could not be checked. Your software list stays in this browser and is never uploaded." : "Matched in your browser against NVD's affected-version ranges for this CVE. Your software list stays in this browser and is never uploaded."));
      d.appendChild(me2);
    }
    var vb = vendorBox(r.adv); if (vb) d.appendChild(vb);
    var k = CV.kev[r.id];
    if (k) {
      var me = el("div", "wbme bad"); me.appendChild(el("b", null, "On CISA's known-exploited list")); me.appendChild(el("p", null, "Added " + k.added + (k.due ? "; " + dueText(k).toLowerCase() : "") + (k.ransomware ? "; used by ransomware groups" : "") + "."));
      var gb = el("button", "linkbtn cvgo", "See it in Known exploited, with check and fix steps"); gb.type = "button"; gb.addEventListener("click", function () { goKnown(r.id); }); me.appendChild(gb); d.appendChild(me);
    }
    var ln = el("p", "wblinks"); ln.appendChild(link("https://www.cve.org/CVERecord?id=" + r.id, "CVE record")); ln.appendChild(link("https://nvd.nist.gov/vuln/detail/" + r.id, "NVD record"));
    if (r.kev) ln.appendChild(link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + r.id, "CISA catalog entry"));
    d.appendChild(otJoin(r.id));
    d.appendChild(ln);
    var ev = el("p", "note", "Checking the map and archive"); d.appendChild(ev);
    loadEvents().then(function (list) {
      var hit = list.filter(function (e) { return e.cves.indexOf(r.id) >= 0; }); ev.textContent = "";
      if (!hit.length) { ev.textContent = "Not on the map or in the archive: no checked report of this flaw yet."; return; }
      ev.appendChild(document.createTextNode("In the archive: "));
      hit.slice(0, 5).forEach(function (e, i) { if (i) ev.appendChild(document.createTextNode("; ")); var a = el("a", null, e.title.slice(0, 120)); a.href = "archive.html#q=" + encodeURIComponent(e.id); ev.appendChild(a); });
    }, function () { ev.textContent = ""; });
    return d;
  }
  /* one severity filter: the CyberView rating by band floor ("9", "7", "4"), or the CVSS base rating before adjustment ("b:Critical" ...), or "b:unscored" */
  function cvFilters() { D.rateOpts = rateOpts(); var sv = $("cvMin").value; return { minScore: /^\d/.test(sv) ? +sv : 0, baseSev: sv.slice(0, 2) === "b:" ? sv.slice(2) : "", decision: $("cvDec").value, rateOpts: D.rateOpts, q: $("wbQ").value, minEpss: +$("cvEpss").value || 0, cwe: $("cvCwe").value, vendor: $("cvVendor").value, status: $("cvStatusSel").value, exploited: $("cvKev").checked }; }
  function rebuildPool() {
    var out = [], seen = {};
    Object.keys(CV.sets).forEach(function (k) { if (CV.sets[k].state === "done") CV.sets[k].files.forEach(function (f) { (CV.ready[f] || []).forEach(function (r) { if (!seen[r.id]) { seen[r.id] = 1; out.push(r); } }); }); });
    CV.pool = out;
    var dl = $("cvVendors"), vl = $("cvVendorList"); dl.textContent = ""; vl.textContent = "";
    D.topVendors(out, 60).forEach(function (v) {
      var o = el("option"); o.value = v[0]; dl.appendChild(o);
      var b = el("button", "badge info", v[0] + " (" + fmtN(v[1]) + ")"); b.type = "button";
      b.addEventListener("click", function () { $("cvVendor").value = v[0]; CV.page = 0; renderAll(); });
      vl.appendChild(b);
    });
    $("cvVendorDir").hidden = !out.length;
  }
  function renderAll() { safe("all", drawAll); }
  function drawAll() {
    if (CV.state !== "ready") return;
    var names = Object.keys(CV.sets).filter(function (k) { return CV.sets[k].state === "done"; }).sort().reverse();
    $("cvLoaded").textContent = names.length ? "Loaded: " + names.map(function (k) { return k === "recent" ? "last two weeks" : k; }).join(", ") + " (" + fmtN(CV.pool.length) + " CVEs). Filters and search apply to these only." : "Nothing loaded yet. Choose a year (or the last two weeks) and load it to browse and filter, or look up one CVE above.";
    var box = $("cvList"); box.textContent = "";
    if (!CV.pool.length) { $("cvCount").textContent = ""; $("cvPager").hidden = true; return; }
    CV.list = D.filter(CV.pool, cvFilters(), CV.kev, $("cvSort").value);
    var pg = D.page(CV.list, CV.page, PAGE); CV.page = pg.page;
    $("cvCount").textContent = CV.list.length === CV.pool.length ? fmtN(CV.list.length) + " CVEs in what is loaded." : fmtN(CV.list.length) + " of " + fmtN(CV.pool.length) + " CVEs match.";
    if (!CV.list.length) box.appendChild(el("li", "empty", "Nothing matches. Clear the search or a filter, or load another year."));
    pg.items.forEach(function (r, i) { box.appendChild(cvCard(r, CV.open === r.id, pg.page * PAGE + i + 1)); });
    $("cvPager").hidden = pg.pages <= 1; $("cvPage").textContent = "Page " + (pg.page + 1) + " of " + pg.pages + " (" + PAGE + " per page)";
    $("cvPrev").disabled = pg.page === 0; $("cvNext").disabled = pg.page >= pg.pages - 1;
  }
  /* a year's lookup files are listed in the index (files_by_year); an older index without the list falls back to probing <year>/0.json, 1.json ... in groups until a whole group is missing */
  function loadSet(key) {
    if (CV.sets[key]) return;
    var set = CV.sets[key] = { state: "loading", files: [] }, prog = $("cvProg"), bar = $("cvBar"), fill = $("cvBarFill"), btn = $("cvLoadYear");
    var y = CV.idx.years.filter(function (x) { return String(x.year) === key; })[0], expect = y ? y.count : 0, got = 0;
    bar.hidden = false; fill.style.width = "0%"; btn.disabled = true; prog.textContent = "Loading " + (key === "recent" ? "the last two weeks" : key) + "...";
    function tick() { fill.style.width = expect ? Math.min(100, Math.round(got / expect * 100)) + "%" : "50%"; prog.textContent = "Loading " + (key === "recent" ? "the last two weeks" : key) + ": " + fmtN(got) + (expect ? " of about " + fmtN(expect) : "") + " CVEs"; }
    var work;
    if (key === "recent") work = getJson("data/cve/recent.json").then(function (d) { var rows = D.parseFile(d); CV.ready["recent.json"] = rows; set.files.push("recent.json"); got = rows.length; tick(); });
    else if (y && y.files) {
      var list = y.files.slice(), n = 0;
      var next = function () { if (n >= list.length) return Promise.resolve(); var batch = list.slice(n, n + 6); n += 6;
        return Promise.all(batch.map(function (k) { var f = key + "/" + k + ".json"; return getFile(f).then(function (rows) { set.files.push(f); got += rows.length; }, function () { return null; }); })).then(function () { tick(); return next(); }); };
      work = next().then(function () { if (!set.files.length) throw new Error("none"); });
    }
    else {
      var k = 0, GROUP = 4, MAX = 160;
      var step = function () {
        if (k >= MAX) return Promise.resolve();
        var batch = []; for (var i = 0; i < GROUP; i++) batch.push(key + "/" + (k + i) + ".json"); k += GROUP;
        return Promise.all(batch.map(function (f) { return getFile(f).then(function (rows) { return { f: f, n: rows.length }; }, function () { return null; }); })).then(function (rs) {
          var hits = rs.filter(Boolean); hits.forEach(function (h) { set.files.push(h.f); got += h.n; }); tick();
          if (!hits.length && k > 0) return;   // a whole group missing: past the last file
          return step();
        });
      };
      work = step().then(function () { if (!set.files.length) throw new Error("none"); });
    }
    work.then(function () { set.state = "done"; rebuildPool(); CV.page = 0; prog.textContent = (key === "recent" ? "The last two weeks" : key) + " loaded: " + fmtN(got) + " CVEs in memory."; }).catch(function () {
      delete CV.sets[key]; prog.textContent = "Part of the list could not be loaded. Try again in a moment.";
    }).then(function () { bar.hidden = true; btn.disabled = false; renderAll(); });
  }
  function loadYear() { loadSet($("cvYear").value); }
  function unloadYears() { CV.sets = {}; CV.pool = []; CV.page = 0; $("cvProg").textContent = "Unloaded."; rebuildPool(); renderAll(); }
  function lookup() {
    var out = $("cvResult"), msg = $("cvLookMsg"); out.textContent = ""; msg.textContent = "";
    var id = D.normId($("wbQ").value);
    if (!id) { msg.textContent = "Type a full CVE id in the search box, for example CVE-2024-3400."; return Promise.resolve(); }
    return ensureIndex().then(function (ix) {
      if (!ix) return;
      msg.textContent = "Looking up " + id + "...";
      return getFile(D.bucketFile(id)).then(function (rows) {
        var hit = rows.filter(function (r) { return r.id === id; })[0];
        msg.textContent = hit ? "" : id + " is not in the CVE List. It may be reserved but not yet published.";
        if (hit) { buildKev(); var ul = el("ol", "wblist cvlist"); ul.appendChild(cvCard(hit, true, 0)); out.appendChild(ul); }
      }, function () { msg.textContent = id + " is not in the CVE List, or the lookup files are not available right now."; });
    });
  }

  /* ---- Industrial (ICS/OT): CISA's and the vendors' own advisories (data/ics.json, scripts/ics.mjs, no AI model), loaded
     only when this view or a CVE's details need them. Mitigations stay in the advisory, linked; nothing is rewritten. ---- */
  var OT = { data: null, waiting: null, shown: 40, open: "" };
  var OT_EXPL = { kev: ["Known exploited", "bad"], active: ["Exploited", "bad"], poc: ["Public exploit", "warn"] };
  function otStatus(msg) { var b = $("otStatus"); b.hidden = !msg; b.textContent = msg || ""; $("otMain").hidden = !!msg; }
  function ensureOt() {
    if (OT.waiting) return OT.waiting;
    OT.waiting = fetch("data/ics.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("http"); return r.json(); }).then(function (d) {
      OT.data = OL.load(d); safe("ot", initOt); return OT.data;
    }).catch(function () {
      OT.waiting = null;
      otStatus("The industrial advisories are not available right now. They are built when the site is deployed, so they can be missing just after a change; the other views work without them. Try again in a little while.");
      return null;
    });
    return OT.waiting;
  }
  function otAge(at) { var m = at ? Math.round((Date.now() - Date.parse(at)) / 6e4) : NaN; return isFinite(m) ? (m < 90 ? m + " minutes" : Math.round(m / 60) + " hours") + " ago" : ""; }
  function initOt() {
    var d = OT.data, srcs = Object.keys(d.sources), n = d.list.length;
    $("wbnOt").textContent = String(n);
    var kev = d.list.filter(function (a) { return a.exploited === "kev"; }).length, act = d.list.filter(function (a) { return a.exploited === "active"; }).length, crit = d.list.filter(function (a) { return a.cvss !== null && a.cvss >= 9; }).length;
    var age = otAge(d.updatedAt), failed = srcs.filter(function (k) { return !d.sources[k].ok; }).map(function (k) { return d.sources[k].name; });
    $("otSummary").textContent = n + " industrial control system (ICS) and operational technology (OT) advisories first published in the last " + d.windowDays + " days, from CISA and the vendors' own machine-readable feeds. " +
      kev + " name a CVE on CISA's known-exploited list" + (act ? ", " + act + " more say exploitation was seen" : "") + "; " + crit + " have a CVSS base score of 9.0 or higher." + (age ? " Updated " + age + "." : "") +
      (failed.length ? " Not reachable on the last run, so their last copy is shown: " + failed.join(", ") + "." : "");
    var vs = $("otVendor"); while (vs.options.length > 1) vs.remove(1);
    OL.vendors(d.list, 120).forEach(function (v) { var o = el("option", null, v[0] + " (" + v[1] + ")"); o.value = v[0]; vs.appendChild(o); });
    var ss = $("otSrc"); while (ss.options.length > 1) ss.remove(1);
    srcs.forEach(function (k) { var s = d.sources[k], o = el("option", null, s.name + " (" + s.count + ")"); o.value = k; ss.appendChild(o); });
    $("otCaveat").textContent = "What this is: advisories as CISA and each vendor publish them (CISA's ICS and ICS medical advisories, Siemens ProductCERT, Schneider Electric, ABB and Phoenix Contact as CSAF documents; CERT@VDE, Moxa and Mitsubishi Electric from their RSS feeds), read every two hours. " +
      "CVSS is the highest base score the advisory gives; exploitation is what the advisory or CISA's known-exploited catalog says. RSS feeds carry less than CSAF documents: Mitsubishi Electric's names no CVEs and CERT@VDE's gives no scores, so open the advisory. " +
      "Rockwell Automation is not read directly (its site refuses automated readers) and Honeywell publishes no machine-readable feed; CISA republishes many of their advisories. The advisory itself stays the authority.";
    otStatus("");
  }
  function otFilters() { return { q: $("otQ").value, vendor: $("otVendor").value, source: $("otSrc").value, show: $("otShow").value, sort: $("otSort").value, lifeline: OT.data.lifeline, inv: inv, today: TODAY }; }
  function goCve(c) { try { history.replaceState(null, "", "#" + c); } catch (e) {} route("#" + c); }
  function goOt(a) {
    OT.open = a.source + ":" + a.id; $("otQ").value = a.id; $("otShow").value = ""; OT.shown = 40; tab("ot");
    ensureOt().then(function () { var n = document.getElementById("ot-" + OT.open.replace(/[^\w-]/g, "_")); if (n) { try { n.scrollIntoView({ block: "start" }); } catch (e) {} } });
  }
  function renderOt() { safe("ot", drawOt); }
  function drawOt() {
    if (!OT.data) return;
    var list = OL.filter(OT.data.list, otFilters()), box = $("otList"); box.textContent = "";
    $("otCount").textContent = list.length === OT.data.list.length ? list.length + " advisories, highest rank first." : list.length + " of " + OT.data.list.length + " advisories match.";
    if (!list.length) box.appendChild(el("li", "empty", "Nothing matches. Clear the search or a filter."));
    list.slice(0, OT.shown).forEach(function (x, i) {
      var a = x.a, key = a.source + ":" + a.id, open = OT.open === key, li = el("li", "wbrow" + (a.notAffected ? " clear" : ""));
      var b = el("button", "wbhead"); b.type = "button"; b.setAttribute("aria-expanded", open ? "true" : "false");
      var sc = el("span", "wbscore", String(x.score)); sc.title = "Rank points that order this list (not a CVSS score or the CyberView rating)"; b.appendChild(sc);
      var mid = el("span", "wbmid"), top = el("span", "wbtop"); top.appendChild(el("b", null, a.id)); if (a.vendor) top.appendChild(document.createTextNode(" " + a.vendor));
      mid.appendChild(top); mid.appendChild(el("span", "wbname", a.title));
      var chips = el("span", "wbchips");
      if (OT_EXPL[a.exploited]) chips.appendChild(el("span", "badge " + OT_EXPL[a.exploited][1], OT_EXPL[a.exploited][0]));
      if (a.notAffected) chips.appendChild(el("span", "badge ok", "Vendor: not affected"));
      if (a.cvss !== null) chips.appendChild(el("span", "badge " + (a.cvss >= 7 ? "bad" : a.cvss >= 4 ? "warn" : "info"), "CVSS " + a.cvss.toFixed(1)));
      if (x.mine) chips.appendChild(el("span", "badge warn", "Names your software"));
      var life = OL.lifelineHit(a, OT.data.lifeline); if (life) chips.appendChild(el("span", "badge info", life));
      if (OL.noFix(a)) chips.appendChild(el("span", "badge warn", "No vendor fix for some products"));
      if (a.cves.length) chips.appendChild(el("span", "badge info", a.cves.length + (a.cves.length === 1 ? " CVE" : " CVEs")));
      chips.appendChild(el("span", "badge info", a.sourceName));
      if (a.published || a.updated) chips.appendChild(el("span", "badge info", a.published || a.updated));
      mid.appendChild(chips); b.appendChild(mid); b.appendChild(el("span", "wbrank", "#" + (i + 1)));
      b.addEventListener("click", function () { OT.open = open ? "" : key; renderOt(); var n = document.getElementById("ot-" + key.replace(/[^\w-]/g, "_")); if (n) n.querySelector("button").focus({ preventScroll: true }); });
      li.id = "ot-" + key.replace(/[^\w-]/g, "_"); li.appendChild(b); if (open) li.appendChild(otDetail(x));
      box.appendChild(li);
    });
    $("otMore").hidden = list.length <= OT.shown;
  }
  function otDetail(x) {
    var a = x.a, d = el("div", "wbdetail");
    if (a.summary) d.appendChild(el("p", null, a.summary));
    if (a.notAffected) { var na = el("div", "wbme ok"); na.appendChild(el("b", null, "The vendor states its products are not affected")); na.appendChild(el("p", null, "This advisory lists the flaws and says which of the vendor's products they do not affect; there is nothing of this vendor's to patch for them.")); d.appendChild(na); }
    if (x.mine) { var me = el("div", "wbme warn"); me.appendChild(el("b", null, "Names a product on your software list")); me.appendChild(el("p", null, "Matched by product name only, in this browser. Check the affected versions in the advisory.")); d.appendChild(me); }
    var pts = el("div", "wbpts"); pts.appendChild(el("h4", null, "Why it ranks here: " + x.score + " rank points"));
    var pl = el("ul"); x.points.forEach(function (p) { var li = el("li"); li.appendChild(el("b", null, "+" + p[0])); li.appendChild(document.createTextNode(" " + p[1])); pl.appendChild(li); }); pts.appendChild(pl); d.appendChild(pts);
    var kv = el("ul");
    [["Vendor", a.vendor], ["Products", a.products.join("; ") + (a.productsTotal > a.products.length ? " and " + (a.productsTotal - a.products.length) + " more in the advisory" : "")],
      ["CVSS", a.cvss !== null ? a.cvss.toFixed(1) + (a.cvssVersion ? " (CVSS v" + a.cvssVersion + ")" : "") + ", the highest base score in the advisory" + (a.cvssVector ? " · " + a.cvssVector : "") : "Not given in the feed"],
      ["Exploitation", OL.EXPL[a.exploited] + (a.exploited === "kev" ? ": " + a.kevCves.join(", ") : a.exploitNote ? ": " + a.exploitNote : "")],
      ["Sectors (CISA)", a.sectors.join(", ")], ["Fix", OL.fixText(a)], ["Published", a.published], ["Last updated", a.updated && a.updated !== a.published ? a.updated : ""]]
      .forEach(function (p) { if (!p[1]) return; var li = el("li"); li.appendChild(el("b", null, p[0] + ": ")); li.appendChild(document.createTextNode(p[1])); kv.appendChild(li); });
    d.appendChild(kv);
    if (a.cves.length) {
      d.appendChild(el("h4", null, "CVEs in this advisory (" + a.cves.length + ")"));
      var cl = el("p", "wbchips");
      a.cves.forEach(function (c) { var b = el("button", "badge " + (a.kevCves.indexOf(c) >= 0 ? "bad" : "info"), c + (a.cveCvss[c] != null ? " · CVSS " + a.cveCvss[c].toFixed(1) : "") + (a.kevCves.indexOf(c) >= 0 ? " · known exploited" : "")); b.type = "button"; b.title = "Open " + c + " with its rating, priority and fix deadline"; b.addEventListener("click", function () { goCve(c); }); cl.appendChild(b); });
      d.appendChild(cl);
    }
    var ln = el("p", "wblinks"), host = ""; try { host = new URL(a.url || a.doc).host.replace(/^www\./, ""); } catch (e) {}
    ln.appendChild(link(a.url || a.doc, "Advisory with mitigations and fixes (" + (host || "link") + ")"));
    if (a.doc && a.doc !== a.url) ln.appendChild(link(a.doc, "CSAF document (machine-readable)"));
    d.appendChild(ln);
    d.appendChild(el("p", "note", "From " + a.sourceName + ", read as published. Mitigations and fixes are the publisher's own and are in the advisory; CyberView does not rewrite them."));
    return d;
  }
  /* beside a CVE elsewhere on the page: the industrial advisories that name it */
  function otJoin(cve) {
    var box = el("div", "wbme info otjoin"); box.hidden = true;
    ensureOt().then(function (d) {
      var list = d && d.byCve[cve]; if (!list || !list.length) return;
      box.hidden = false; box.appendChild(el("b", null, "Industrial (ICS/OT) advisor" + (list.length > 1 ? "ies" : "y") + " naming " + cve));
      var ul = el("ul");
      list.slice(0, 8).forEach(function (a) {
        var li = el("li"); li.appendChild(el("b", null, a.id + " "));
        li.appendChild(document.createTextNode((a.vendor ? a.vendor + ": " : "") + a.title + (a.cveCvss[cve] != null ? " · CVSS " + a.cveCvss[cve].toFixed(1) + " for this CVE" : "") + (a.notAffected ? " · the vendor states its products are not affected" : "") + " · "));
        li.appendChild(link(a.url || a.doc, "advisory")); li.appendChild(document.createTextNode(" · "));
        var b = el("button", "linkbtn", "open in Industrial"); b.type = "button"; b.addEventListener("click", function () { goOt(a); }); li.appendChild(b);
        ul.appendChild(li);
      });
      box.appendChild(ul);
      if (list.length > 8) box.appendChild(el("p", "note", (list.length - 8) + " more in the Industrial view."));
      box.appendChild(el("p", "note", "From CISA's and the vendors' own advisories; the mitigations and fixes are in the advisory."));
    }, function () {});
    return box;
  }
  var otT = 0;
  $("otQ").addEventListener("input", function () { clearTimeout(otT); otT = setTimeout(function () { OT.shown = 40; renderOt(); }, 140); });
  ["otShow", "otVendor", "otSrc", "otSort"].forEach(function (id) { $(id).addEventListener("change", function () { OT.shown = 40; renderOt(); }); });
  $("otMore").addEventListener("click", function () { OT.shown += 40; renderOt(); });

  /* ---- tabs, links and wiring ---- */
  var VIEWS = ["queue", "all", "inv", "hunt", "ot"], HASH = { known: "queue", queue: "queue", all: "all", inv: "inv", hunt: "hunt", ot: "ot", industrial: "ot", scanner: "inv" }, cur = "queue";
  function tab(t, keepHash) {
    cur = t;
    VIEWS.forEach(function (k) { $("wbt-" + k).setAttribute("aria-selected", k === t ? "true" : "false"); $("wbp-" + k).hidden = k !== t; });
    $("wbSearchBar").hidden = t !== "queue" && t !== "all";
    $("wbSearchHint").textContent = t === "all" ? "Filters the years you have loaded. To look up one CVE, type its id and press Enter. Nothing you type is sent anywhere." : "Filters the list below. Nothing you type is sent anywhere.";
    if (!keepHash) { try { history.replaceState(null, "", "#" + (t === "queue" ? "known" : t)); } catch (e) {} }
    if (t === "inv") renderInv(); if (t === "hunt") renderHunt();
    if (t === "all") ensureIndex().then(function () { renderAll(); });
    if (t === "queue") renderQueue();
    if (t === "ot") ensureOt().then(function () { renderOt(); });
  }
  /* open one flaw in the Known exploited view */
  function goKnown(cve) { $("wbQ").value = cve; $("wbShow").value = "all"; openCve = cve; tab("queue"); showOpen(); try { history.replaceState(null, "", "#" + cve); } catch (e) {} }
  function route(h) {
    h = String(h || "").replace(/^#/, "");
    if (isCve(h)) {
      if (flaws.some(function (f) { return f.cve === h; })) { openCve = h; $("wbQ").value = h; tab("queue", true); renderQueue(); showOpen(); return; }
      $("wbQ").value = h; tab("all", true); lookup(); return;
    }
    tab(HASH[h] || "queue", true);
    if (h === "scanner") { var sc = $("scanner"); if (sc) try { sc.scrollIntoView({ block: "start" }); } catch (e) {} }
  }
  VIEWS.forEach(function (k) { $("wbt-" + k).addEventListener("click", function () { tab(k); }); });
  $("wbGoInv").addEventListener("click", function () { tab("inv"); $("wbText").focus(); });
  var qt = 0; $("wbQ").addEventListener("input", function () { clearTimeout(qt); qt = setTimeout(function () { if (cur === "all") { CV.page = 0; renderAll(); } else renderQueue(); }, 140); });
  $("wbQ").addEventListener("keydown", function (ev) { if (ev.key === "Enter" && cur === "all") { ev.preventDefault(); lookup(); } });
  $("wbShow").addEventListener("change", function () { if ($("wbShow").value === "ot") ensureOt().then(renderQueue); else renderQueue(); });
  $("wbFmt").addEventListener("change", function () { huntShown = 12; renderHunt(); });
  $("wbHuntMine").addEventListener("change", function () { huntShown = 12; renderHunt(); });
  $("wbHuntMore").addEventListener("click", function () { huntShown += 12; renderHunt(); });
  $("wbHuntCopy").addEventListener("click", function () { var b = $("wbHuntCopy"); try { navigator.clipboard.writeText(toHuntPlan()).then(function () { flash(b, "Copied"); }, function () { flash(b, "Copy blocked"); }); } catch (e) { flash(b, "Copy blocked"); } });
  $("kevCal").addEventListener("click", function () { safe("queue", calendar); });
  $("cvLookup").addEventListener("click", lookup);
  $("cvLoadYear").addEventListener("click", loadYear);
  $("cvClearYears").addEventListener("click", unloadYears);
  ["cvEpss", "cvStatusSel", "cvSort", "cvKev", "cvDec", "cvMin"].forEach(function (id) { $(id).addEventListener("change", function () { CV.page = 0; renderAll(); }); });
  /* the visitor's rating settings stay in this browser, like the software list */
  try { var rs = JSON.parse(localStorage.getItem("cwm.rate") || "{}"); if (/^(low|medium|high)$/.test(rs.mission || "")) $("cvMission").value = rs.mission; if (/^(yes|no)$/.test(rs.exposed || "")) $("cvExposed").value = rs.exposed; } catch (e) {}
  ["cvMission", "cvExposed"].forEach(function (id) { $(id).addEventListener("change", function () { try { localStorage.setItem("cwm.rate", JSON.stringify({ mission: $("cvMission").value, exposed: $("cvExposed").value })); } catch (e) {} D.rateOpts = rateOpts(); CV.page = 0; renderAll(); }); });
  D.rateOpts = rateOpts();
  loadEvents().then(function (list) { onMapIds = {}; list.forEach(function (e) { e.cves.forEach(function (c) { onMapIds[c] = 1; }); }); D.rateOpts = rateOpts(); renderAll(); }, function () {});
  var ct = 0; ["cvVendor", "cvCwe"].forEach(function (id) { $(id).addEventListener("input", function () { clearTimeout(ct); ct = setTimeout(function () { CV.page = 0; renderAll(); }, 160); }); });
  $("cvPrev").addEventListener("click", function () { CV.page--; renderAll(); try { $("cvCount").scrollIntoView({ block: "start" }); } catch (e) {} });
  $("cvNext").addEventListener("click", function () { CV.page++; renderAll(); try { $("cvCount").scrollIntoView({ block: "start" }); } catch (e) {} });
  window.addEventListener("hashchange", function () { route(location.hash); });
  $("wbCsv").addEventListener("click", function () { var a = el("a"); a.href = blobUrl(new Blob([toCsv()], { type: "text/csv" })); var u = a.href; a.download = "cyberview-patch-queue-" + TODAY + ".csv"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(u); }, 4000); });
  $("wbCopy").addEventListener("click", function () { var b = $("wbCopy"); try { navigator.clipboard.writeText(toChange()).then(function () { flash(b, "Copied"); }, function () { flash(b, "Copy blocked"); }); } catch (e) { flash(b, "Copy blocked"); } });
  var drop = $("wbDrop"), file = $("wbFile");
  drop.addEventListener("click", function () { file.click(); });
  drop.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); file.click(); } });
  file.addEventListener("change", function () { readFile(file.files && file.files[0]); file.value = ""; });
  ["dragenter", "dragover"].forEach(function (n) { drop.addEventListener(n, function (ev) { ev.preventDefault(); drop.classList.add("over"); }); });
  ["dragleave", "drop"].forEach(function (n) { drop.addEventListener(n, function (ev) { ev.preventDefault(); drop.classList.remove("over"); }); });
  drop.addEventListener("drop", function (ev) { readFile(ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]); });
  $("wbAdd").addEventListener("click", function () { var t = $("wbText").value; if (!t.trim()) { $("wbInvMsg").textContent = "Type or paste at least one product first."; return; } addItems("pasted", t); });
  $("wbClear").addEventListener("click", function () { inv = []; saveInv(); try { localStorage.removeItem("cwm.inv"); } catch (e) {} $("wbInvMsg").textContent = "Your list is cleared from this browser."; compute(); renderInv(); renderQueue(); calLabel(); });

  loadInv();
  fetch("data/workbench.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
    builtAt = str(d && d.built_at, 30);
    var guides = {}, raw = d && d.guides && typeof d.guides === "object" ? d.guides : {};
    Object.keys(raw).slice(0, 2000).forEach(function (k) { if (isCve(k)) { var g = cleanGuide(raw[k]); if (g) guides[k] = g; } });
    var eventOf = d && d.event_of && typeof d.event_of === "object" ? d.event_of : {};
    var an = {}, ra = d && d.analyses && typeof d.analyses === "object" ? d.analyses : {};
    Object.keys(ra).slice(0, 2000).forEach(function (k) { if (isCve(k)) { var a = cleanAnalysis(ra[k]); if (a) an[k] = a; } });
    flaws = (Array.isArray(d && d.kev) ? d.kev : []).slice(0, 3000).map(function (k) { return cleanKev(k, guides, eventOf, an); }).filter(Boolean)
      .concat((Array.isArray(d && d.vulns) ? d.vulns : []).slice(0, 80).map(function (v) { return cleanVuln(v, guides, an); }).filter(Boolean));
    hunt = (Array.isArray(d && d.hunt) ? d.hunt : []).slice(0, 200).map(cleanHunt).filter(Boolean);
    var fm = {}; hunt.forEach(function (h) { fm[h.format] = 1; });
    Object.keys(fm).sort().forEach(function (k) { var o = el("option", null, FORMATS[k]); o.value = k; $("wbFmt").appendChild(o); });
    compute(); buildKev();
    renderQueue(); renderDeadlines(); renderInv(); renderHunt(); calLabel();
    route(location.hash);
  }).catch(function () {
    $("wbSummary").textContent = "The known-exploited data can't be loaded right now. Try again in a minute.";
    route(location.hash);   // All CVEs does not depend on it
  });
})();
