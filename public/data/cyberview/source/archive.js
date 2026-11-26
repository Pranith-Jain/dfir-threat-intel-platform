// CyberView archive page. Reads data/archive/search.json (one compact row per event) and loads a month's
// full records only when an event is opened. All text is inserted as text, never as HTML.
(function () {
  "use strict";
  var CAT = { incident: "Incident", vuln: "Patch / advisory", report: "Threat report", policy: "Law and policy", enforcement: "Law enforcement", investment: "Investment", outage: "Outage" };
  var PAGE = 50;
  var rows = [], page = 0, months = {}, OPEN = "", $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function safeUrl(u) { return /^https?:\/\//i.test(String(u || "")) ? String(u) : ""; }
  function safe(name, fn) { try { fn(); } catch (e) { if (window.console) console.warn("archive: " + name + " could not be drawn", e); } }
  function fmt(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { return d; } }

  function load() {
    fetch("data/archive/search.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }).then(function (d) {
      var f = d.fields || [];
      rows = (d.rows || []).map(function (r) { var o = {}; f.forEach(function (k, i) { o[k] = r[i]; }); return o; });
      var ms = {}; rows.forEach(function (r) { ms[String(r.date).slice(0, 7)] = 1; });
      Object.keys(ms).sort().reverse().forEach(function (m) {
        var o = el("option", null, new Date(m + "-15T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "long" })); o.value = m; $("month").appendChild(o);
      });
      var nClaims = rows.filter(function (r) { return r.status === "claimed"; }).length;
      $("summary").textContent = (rows.length - nClaims) + " checked events since " + (rows.length ? fmt(rows[rows.length - 1].date) : "the start") + (nClaims ? ", plus " + nClaims + " unverified claim" + (nClaims === 1 ? "" : "s") + " (hidden unless you include them)" : "") + ". The map shows today and the six days before; everything else lives here.";
      readHash(); recent(); render();
      safe("summary figures", kpis);
      $("recentAll").addEventListener("click", function () { recentAll = !recentAll; if (!recentAll && location.hash === "#recent") history.replaceState(null, "", location.pathname + location.search); recent(); });
      window.addEventListener("hashchange", function () { readHash(); page = 0; render(); });
      // a link to one event (archive.html#q=<id>) opens it straight away
      var q = $("q").value.trim(), hit = rows.filter(function (r) { return r.id === q; })[0];
      if (hit) openEvent(hit, true);
    }).catch(function () { $("summary").textContent = "The archive can't be loaded right now. Try again in a minute."; });
  }

  function matches(r) {
    var q = $("q").value.trim().toLowerCase(), m = $("month").value, c = $("cat").value, s = Number($("sev").value || 0);
    if (!$("claims").checked && r.status === "claimed") return false;
    if (m && String(r.date).slice(0, 7) !== m) return false;
    if (c && r.category !== c) return false;
    if (s && r.severity < s) return false;
    if (!q) return true;
    return [r.title, r.org, r.country, r.actor, (r.cves || []).join(" "), (r.tags || []).join(" "), r.id].join(" ").toLowerCase().indexOf(q) >= 0;
  }

  function render() {
    var list = rows.filter(matches), box = $("list");
    box.textContent = "";
    // pages, not "Show more" (owner, 2026-11-25): the same Previous / Page n of N / Next as the Vulnerabilities list
    var pages = Math.max(1, Math.ceil(list.length / PAGE)); page = Math.min(Math.max(0, page | 0), pages - 1);
    var items = list.slice(page * PAGE, (page + 1) * PAGE);
    $("count").textContent = list.length + " event" + (list.length === 1 ? "" : "s") + (pages > 1 ? ", " + (page * PAGE + 1) + "\u2013" + (page * PAGE + items.length) + " shown" : "");
    if (!list.length) { box.appendChild(el("li", "empty", "Nothing matches. Clear a filter or try another word.")); }
    items.forEach(function (r) { box.appendChild(rowEl(r)); });
    $("pager").hidden = pages <= 1; $("page").textContent = "Page " + (page + 1) + " of " + pages + " (" + PAGE + " per page)";
    $("prev").disabled = page === 0; $("next").disabled = page >= pages - 1;
    $("clear").hidden = !($("month").value || $("cat").value || $("sev").value || $("claims").checked || $("q").value.trim());
    safe("months", drawMonths);
  }
  function changed() { page = 0; render(); writeHash(); var v = document.querySelector(".argrid .vlist"); if (v) v.scrollTop = 0; }
  function turn(d) { page += d; render(); var v = document.querySelector(".argrid .vlist"); if (v) v.scrollTop = 0; }
  /* "Recently filed": events research added in the last 48 hours that happened earlier (more than 36 hours before they
     were filed). The map's "Just added" shows only new events; these are routed here instead, with both dates. */
  var FILED_H = 48, LATE_H = 36, RECENT_FEW = 5, recentAll = false;
  function filedLate(r) {
    var f = Date.parse(r.first_seen || ""), d = Date.parse(String(r.date || "") + "T23:59:59Z");
    return isFinite(f) && isFinite(d) && Date.now() - f < FILED_H * 3600e3 && f - d > LATE_H * 3600e3 && r.status !== "claimed";
  }
  function recent() {
    var sec = $("recent"); if (!sec) return;
    var list = rows.filter(filedLate).sort(function (a, b) { return Date.parse(b.first_seen) - Date.parse(a.first_seen); }).slice(0, 40);
    sec.hidden = !list.length; if (!list.length) return;
    $("recentHead").textContent = "Recently filed (" + list.length + ")";
    var ol = $("recentList"); ol.textContent = "";
    var all = recentAll || location.hash === "#recent", tb = $("recentAll");
    tb.hidden = list.length <= RECENT_FEW; tb.textContent = all ? "Show fewer" : "Show all " + list.length;
    list.slice(0, all ? list.length : RECENT_FEW).forEach(function (r) { var li = rowEl(r, true), meta = li.querySelector(".meta"), when = el("span", "pill filed", "Filed " + ago(r.first_seen) + ", happened " + fmt(r.date)); meta.insertBefore(when, meta.firstChild); ol.appendChild(li); });
  }
  /* the claims desk's check of a leak-site claim (scripts/claims-desk.mjs), on the event it names: label, summary, the
     confirming page (https, never a leak site or a claim tracker); an unknown decision shows nothing */
  var CLAIM_DEC = { confirmed_by_victim: 1, reported: 1, denied: 1, unconfirmed: 1, not_found: 1 };
  var LEAK_HOST = /(^|\.)(onion|ransomware\.live|ransomlook\.io|ransomwatch\.telemetry\.ltd|ransomfeed\.it|ransom-db\.com|ransomdb\.io|t\.me|x\.com|twitter\.com)$/;
  function str(v, n) { return typeof v === "string" ? v.slice(0, n).trim() : ""; }
  function cleanClaimCheck(c) {
    if (!c || typeof c !== "object" || !Object.prototype.hasOwnProperty.call(CLAIM_DEC, str(c.decision, 24))) return null;
    var group = str(c.group, 60), by = str(c.confirmed_by, 120), d = str(c.claimed_at, 10), u = str(c.url, 1000);
    if (!group || (c.decision === "confirmed_by_victim" && !by)) return null;
    try { var x = new URL(u); if (x.protocol !== "https:" || LEAK_HOST.test(x.hostname.toLowerCase())) u = ""; else u = x.href; } catch (e) { u = ""; }
    return { decision: c.decision, summary: str(c.summary, 300), group: group, claimed: /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : "", by: by, url: u, at: str(c.at, 30) };
  }
  function claimNode(c) {
    var g = c.group + "\u2019s leak-site claim" + (c.claimed ? " of " + fmt(c.claimed) : "");
    var t = { confirmed_by_victim: "confirmed by " + c.by + " \u2014 " + g, reported: "reported by publishers, not confirmed by the organisation \u2014 " + g,
      denied: "the organisation denies " + g, unconfirmed: "nothing beyond " + g + " was found; it will be checked again", not_found: "the organisation in " + g + " could not be identified" }[c.decision];
    var p = el("p", "note ccheck", "Checked by CyberView AI (a Claude model): " + t + (c.summary ? ". " + c.summary : ""));
    if (c.url) { p.appendChild(document.createTextNode(" ")); var a = el("a", null, "source"); a.href = safeUrl(c.url); a.target = "_blank"; a.rel = "noopener noreferrer"; p.appendChild(a); }
    if (c.at) { var w = ago(c.at); if (w) p.appendChild(document.createTextNode(" \u00b7 checked " + w)); }
    return p;
  }
  function ago(iso) {
    var m = Math.round((Date.now() - Date.parse(iso)) / 6e4); if (!isFinite(m)) return "";
    return m < 60 ? m + " min ago" : m < 1440 ? Math.round(m / 60) + " h ago" : Math.round(m / 1440) + " days ago";
  }
  function rowEl(r, inline) {
      var li = el("li", "row"); li.style.setProperty("--cc", "var(--c-" + r.category + ")");
      var b = el("button"); b.type = "button"; b.setAttribute("aria-expanded", "false");
      if (!inline) { li.id = "ev-" + String(r.id).replace(/[^\w-]/g, "_"); b.setAttribute("aria-controls", "arPane"); if (r.id === OPEN) { li.classList.add("on"); b.setAttribute("aria-expanded", "true"); } }
      b.appendChild(el("span", "date", fmt(r.date)));
      b.appendChild(el("span", "ttl", r.title));
      var meta = el("span", "meta");
      meta.appendChild(el("span", "cat", CAT[r.category] || r.category));
      meta.appendChild(el("span", null, ["", "Low", "Medium", "High"][r.severity] || ""));
      if (r.status === "claimed") meta.appendChild(el("span", "pill claimed", "Unverified claim"));
      if (r.org) meta.appendChild(el("span", null, r.org));
      if (r.country) meta.appendChild(el("span", null, r.country));
      (r.cves || []).slice(0, 3).forEach(function (c) { meta.appendChild(el("span", "pill", c)); });
      b.appendChild(meta);
      b.addEventListener("click", function () { if (inline) toggle(li, b, r); else if (OPEN === r.id) closePane(); else openEvent(r); });
      li.appendChild(b); return li;
  }

  function month(m) {
    if (!months[m]) months[m] = fetch("data/archive/" + m + ".json").then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
      var by = {}; (d.events || []).forEach(function (e) { by[e.id] = e; }); return by;
    });
    return months[m];
  }

  /* one event's full record, as text: used inline in "Recently filed" and in the detail pane beside the list */
  function details(box, e, r, full) {
    if (full) {
      box.appendChild(el("h2", "ardt", r.title));
      var m = el("p", "armeta"); m.style.setProperty("--cc", "var(--c-" + r.category + ")");
      m.appendChild(el("span", "cat", CAT[r.category] || r.category));
      [fmt(r.date), ["", "Low", "Medium", "High"][r.severity] ? ["", "Low", "Medium", "High"][r.severity] + " severity" : "", r.org, r.country].forEach(function (t) { if (t) m.appendChild(el("span", null, t)); });
      if (r.status === "claimed") m.appendChild(el("span", "pill claimed", "Unverified claim"));
      box.appendChild(m);
    }
    if (e.summary) box.appendChild(el("p", full ? "arsum" : null, e.summary));
    box.appendChild(el("p", "note", "Researched and written by CyberView AI (a Claude model) from the sources listed."));
    var cc = cleanClaimCheck(e.claim_check); if (cc) box.appendChild(claimNode(cc));
    if (e.action) { var p = el("p", full ? "aract" : null); p.appendChild(el("strong", null, "What to do: ")); p.appendChild(document.createTextNode(e.action)); box.appendChild(p); }
    if (e.actor) box.appendChild(el("p", null, "Actor: " + e.actor));
    // every CVE the record names (its CVE list and the text), each with its records: CVE.org, NVD, CISA's known-exploited
    // catalog when the record says CISA lists it, and CyberView's own check. Ids are validated before a link is built.
    var cves = [], seen = {}, kevd = {};
    function addCve(c) { c = String(c || "").toUpperCase(); if (/^CVE-\d{4}-\d{4,7}$/.test(c) && !seen[c]) { seen[c] = 1; cves.push(c); } }
    (r.cves || []).concat(e.cves || []).forEach(addCve);
    (Array.isArray(e.cve_meta) ? e.cve_meta : []).forEach(function (m) { if (m && typeof m === "object") { addCve(m.id); if (m.kev === true) kevd[String(m.id).toUpperCase()] = 1; } });
    [e.title, e.summary, e.impact, e.action].forEach(function (t) { (String(t || "").match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).forEach(addCve); });
    if (cves.length) {
      box.appendChild(el("h3", null, cves.length === 1 ? "Vulnerability named" : "Vulnerabilities named (" + cves.length + ")"));
      cves.slice(0, 12).forEach(function (c) {
        var row = el("div", "cvrow"); row.appendChild(el("b", null, c));
        var ln = el("p", "reclinks");
        var a1 = el("a", null, "CVE record"); a1.href = "https://www.cve.org/CVERecord?id=" + c; a1.target = "_blank"; a1.rel = "noopener noreferrer"; ln.appendChild(a1);
        var a2 = el("a", null, "NVD record"); a2.href = "https://nvd.nist.gov/vuln/detail/" + c; a2.target = "_blank"; a2.rel = "noopener noreferrer"; ln.appendChild(a2);
        if (kevd[c]) { var a3 = el("a", null, "CISA known-exploited entry"); a3.href = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + c; a3.target = "_blank"; a3.rel = "noopener noreferrer"; ln.appendChild(a3); }
        var a4 = el("a", null, "Am I affected? How to fix"); a4.href = "vulnerabilities.html#" + c; ln.appendChild(a4);
        row.appendChild(ln); box.appendChild(row);
      });
    }
    var src = (e.sources || []).filter(function (s) { return s && safeUrl(s.url); });
    if (src.length) {
      box.appendChild(el("h3", null, "Sources"));
      var ul = el("ul"); src.slice(0, full ? 12 : 6).forEach(function (s) {
        var a = el("a", null, s.name || s.url.replace(/^https?:\/\//, "").split("/")[0]); a.href = safeUrl(s.url); a.target = "_blank"; a.rel = "noopener noreferrer";
        var item = el("li"); item.appendChild(a); ul.appendChild(item);
      }); box.appendChild(ul);
    }
    if (full && (r.tags || []).length) { var tp = el("p", "artags"); r.tags.slice(0, 10).forEach(function (t) { tp.appendChild(el("span", "pill", t)); }); box.appendChild(tp); }
    var lp = el("p", "arlink"), la = el("a", null, "Link to this event");
    la.href = "archive.html#q=" + encodeURIComponent(r.id); lp.appendChild(la); box.appendChild(lp);
  }
  function toggle(li, b, r) {
    var open = li.querySelector(".more-info");
    if (open) { open.remove(); b.setAttribute("aria-expanded", "false"); return; }
    var box = el("div", "more-info", "Loading"); li.appendChild(box); b.setAttribute("aria-expanded", "true");
    month(String(r.date).slice(0, 7)).then(function (by) {
      var e = by[r.id]; box.textContent = "";
      if (!e) { box.textContent = "Details are not available."; return; }
      details(box, e, r, false);
    }).catch(function () { box.textContent = "Details could not be loaded."; });
  }
  /* the detail pane: the third column on a wide screen, a sheet over the page on a narrower one */
  function narrow() { return window.innerWidth < 1240; }
  function paneSync() {
    var p = $("arPane"), d = $("arDet"), has = d.childNodes.length > 0;
    p.classList.toggle("has", has); $("arGrid").classList.toggle("vopen", has);
    p.querySelector(".vdtitle").textContent = has ? d.getAttribute("data-title") || "" : "";
    document.documentElement.classList.toggle("vsheet", has && narrow());
  }
  function mark() {
    [].forEach.call($("list").querySelectorAll(".row"), function (li) { var on = li.id === "ev-" + String(OPEN).replace(/[^\w-]/g, "_"); li.classList.toggle("on", on); li.firstChild.setAttribute("aria-expanded", on ? "true" : "false"); });
  }
  function openEvent(r, fromLink) {
    OPEN = r.id; mark();
    var d = $("arDet"); d.textContent = ""; d.setAttribute("data-title", r.title || ""); d.appendChild(el("p", "note", "Loading"));
    paneSync(); $("arPane").scrollTop = 0;
    if (narrow()) $("arPane").querySelector(".vdclose").focus({ preventScroll: true });
    month(String(r.date).slice(0, 7)).then(function (by) {
      if (OPEN !== r.id) return;
      var e = by[r.id]; d.textContent = "";
      if (!e) { d.appendChild(el("p", null, "Details are not available.")); return; }
      details(d, e, r, true);
    }).catch(function () { if (OPEN === r.id) { d.textContent = ""; d.appendChild(el("p", null, "Details could not be loaded.")); } });
    if (fromLink) { var n = document.getElementById("ev-" + String(r.id).replace(/[^\w-]/g, "_")); if (n && !narrow()) try { n.scrollIntoView({ block: "nearest" }); } catch (x) {} }
  }
  function closePane() {
    var back = OPEN ? document.getElementById("ev-" + String(OPEN).replace(/[^\w-]/g, "_")) : null;
    OPEN = ""; $("arDet").textContent = ""; mark(); paneSync();
    if (back) back.firstChild.focus({ preventScroll: true });
  }

  /* the archive at a glance: each figure filters the list when it can */
  function kpis() {
    var box = $("kpis"), ok = rows.filter(function (r) { return r.status !== "claimed"; }), n = ok.length; if (!n) return;
    var now = Date.now(), wk = ok.filter(function (r) { var f = Date.parse(r.first_seen || ""); return isFinite(f) && now - f < 7 * 864e5; }).length;
    var mNow = new Date().toISOString().slice(0, 7), dPrev = new Date(); dPrev.setUTCDate(1); dPrev.setUTCMonth(dPrev.getUTCMonth() - 1);
    var mPrev = dPrev.toISOString().slice(0, 7), inM = function (m) { return ok.filter(function (r) { return String(r.date).slice(0, 7) === m; }).length; };
    var hi = ok.filter(function (r) { return r.severity >= 3; }).length, inc = ok.filter(function (r) { return r.category === "incident"; }).length, cl = rows.length - n;
    var pct = function (x) { return Math.round((x / n) * 100) + "% of the archive"; };
    function kpi(lbl, val, sub, act, title) {
      var k = el(act ? "button" : "div", "kpi" + (act ? " go" : "")); k.setAttribute("role", "listitem");
      if (act) { k.type = "button"; k.title = title; k.addEventListener("click", act); }
      k.appendChild(el("div", "kl", lbl)); var v = el("div", "kv", val); k.appendChild(v); if (sub) k.appendChild(el("span", "kd flat", sub)); box.appendChild(k);
    }
    function only(f) { return function () { $("month").value = f.month || ""; $("cat").value = f.cat || ""; $("sev").value = f.sev || ""; if (f.claims != null) $("claims").checked = f.claims; changed(); }; }
    kpi("Checked events", n.toLocaleString("en"), "since " + fmt(ok[ok.length - 1].date));
    kpi("Filed in the last 7 days", wk.toLocaleString("en"), "by the day CyberView filed them");
    kpi("Happened this month", inM(mNow).toLocaleString("en"), "last month: " + inM(mPrev).toLocaleString("en"), only({ month: mNow }), "Show this month's events");
    kpi("High severity", hi.toLocaleString("en"), pct(hi), only({ sev: "3" }), "Show high-severity events");
    kpi("Incidents", inc.toLocaleString("en"), pct(inc), only({ cat: "incident" }), "Show incidents");
    kpi("Unverified claims", cl.toLocaleString("en"), "hidden unless you include them", cl ? only({ claims: true }) : null, "Include unverified claims");
    box.hidden = false;
  }
  /* events per month under the current filters (month aside); a bar picks that month */
  function drawMonths() {
    var box = $("monthBars"), sec = $("arMonths"), keep = $("month").value; if (!box) return;
    $("month").value = ""; var by = {}; rows.forEach(function (r) { if (matches(r)) { var m = String(r.date).slice(0, 7); by[m] = (by[m] || 0) + 1; } }); $("month").value = keep;
    var ms = [].map.call($("month").options, function (o) { return o.value; }).filter(Boolean).slice(0, 18), max = 1;
    ms.forEach(function (m) { max = Math.max(max, by[m] || 0); });
    box.textContent = ""; sec.hidden = !ms.length;
    ms.forEach(function (m) {
      var n = by[m] || 0, b = el("button", "arm" + (keep === m ? " on" : "")); b.type = "button";
      b.setAttribute("aria-pressed", keep === m ? "true" : "false");
      b.setAttribute("aria-label", new Date(m + "-15T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "long" }) + ": " + n + " event" + (n === 1 ? "" : "s"));
      b.appendChild(el("span", "l", new Date(m + "-15T12:00:00Z").toLocaleDateString(undefined, { year: "2-digit", month: "short" })));
      var t = el("span", "t"), i = el("i"); i.style.width = (n ? Math.max(3, (n / max) * 100) : 0) + "%"; t.appendChild(i); b.appendChild(t);
      b.appendChild(el("span", "n", n.toLocaleString("en")));
      b.addEventListener("click", function () { $("month").value = keep === m ? "" : m; changed(); });
      box.appendChild(b);
    });
  }

  function writeHash() {
    var p = new URLSearchParams();
    if ($("q").value.trim()) p.set("q", $("q").value.trim());
    ["month", "cat", "sev"].forEach(function (k) { if ($(k).value) p.set(k, $(k).value); });
    if ($("claims").checked) p.set("claims", "1");
    var h = p.toString(); try { history.replaceState(null, "", h ? "#" + h : location.pathname); } catch (e) {}
  }
  function readHash() {
    var p = new URLSearchParams(location.hash.slice(1));
    if (p.get("q")) $("q").value = p.get("q");
    ["month", "cat", "sev"].forEach(function (k) { if (p.get(k)) $(k).value = p.get(k); });
    $("claims").checked = p.get("claims") === "1";
  }

  ["filters", "qform"].forEach(function (f) { $(f).addEventListener("submit", function (e) { e.preventDefault(); }); });
  var t; $("q").addEventListener("input", function () { clearTimeout(t); t = setTimeout(changed, 150); });
  ["month", "cat", "sev", "claims"].forEach(function (k) { $(k).addEventListener("change", changed); });
  $("clear").addEventListener("click", function () { $("q").value = ""; ["month", "cat", "sev"].forEach(function (k) { $(k).value = ""; }); $("claims").checked = false; changed(); });
  $("arPane").querySelector(".vdclose").addEventListener("click", closePane);
  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement || {}).tagName || "", typing = /^(INPUT|TEXTAREA|SELECT)$/.test(tag) || (document.activeElement && document.activeElement.isContentEditable);
    if (e.key === "Escape" && OPEN && !typing) { e.preventDefault(); closePane(); }
    else if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !typing) { e.preventDefault(); $("q").focus(); }
  });
  var rz; window.addEventListener("resize", function () { clearTimeout(rz); rz = setTimeout(paneSync, 120); });
  $("prev").addEventListener("click", function () { turn(-1); });
  $("next").addEventListener("click", function () { turn(1); });
  load();
})();
