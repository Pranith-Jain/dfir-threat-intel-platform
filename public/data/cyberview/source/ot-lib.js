// CyberView Industrial (ICS/OT) advisories: cleaning, ranking and filtering for the Vulnerabilities page, kept apart from
// the page so unit tests can run them in Node. The records come from site/data/ics.json (scripts/ics.mjs, no AI model).
// Everything runs in the visitor's browser; the software list it can match against is never sent anywhere.
(function (root) {
  "use strict";
  var O = {};
  function str(v, n) { return typeof v === "string" ? v.replace(/[\u0000-\u001f]/g, " ").slice(0, n) : ""; }
  function strs(a, k, n) { return (Array.isArray(a) ? a : []).map(function (x) { return str(x, n).trim(); }).filter(Boolean).slice(0, k); }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function day(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s || "") ? s : ""; }
  function isCve(s) { return /^CVE-\d{4}-\d{4,}$/.test(s || ""); }
  function https(u) { u = str(u, 600); return /^https:\/\/[^\s"'<>]+$/.test(u) ? u : ""; }
  function norm(s) { return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim(); }
  O.norm = norm;

  var EXPL = { kev: "Known exploited (CISA KEV)", active: "Exploited, per the advisory", poc: "Public exploit code, per the advisory", none: "No known exploitation, per the advisory", "": "Exploitation not stated" };
  var REM = { vendor_fix: "vendor fix", mitigation: "mitigation", workaround: "workaround", none_available: "no fix available", no_fix_planned: "no fix planned" };
  O.EXPL = EXPL;
  O.REM = REM;

  /* one record from ics.json, every field checked and cut to length; null when it is not usable */
  O.clean = function (a, sources) {
    if (!a || typeof a !== "object") return null;
    var id = str(a.id, 40), src = str(a.source, 20);
    if (!/^[A-Z0-9][A-Z0-9._:-]{2,39}$/.test(id) || !/^[a-z]{2,20}$/.test(src)) return null;
    var cves = strs(a.cves, 60, 30).filter(isCve), cc = {};
    var raw = a.cve_cvss && typeof a.cve_cvss === "object" ? a.cve_cvss : {};
    cves.forEach(function (c) { var n = num(raw[c], 0, 10); if (n !== null) cc[c] = n; });
    var url = https(a.url), doc = https(a.doc);
    if (!url && !doc) return null;
    return {
      id: id, source: src, sourceName: str(sources && sources[src] && sources[src].name, 80) || src, vendor: str(a.vendor, 60), title: str(a.title, 200) || id,
      products: strs(a.products, 8, 100), productsTotal: num(a.products_total, 0, 9999) || 0, cves: cves, cveCvss: cc,
      cvss: num(a.cvss, 0, 10), cvssVersion: /^[34](\.\d)?$/.test(a.cvss_version || "") ? a.cvss_version : "", cvssVector: /^CVSS:[34]\.\d\/[A-Z:/]{1,150}$/.test(a.cvss_vector || "") ? a.cvss_vector : "",
      exploited: Object.prototype.hasOwnProperty.call(EXPL, a.exploited) ? a.exploited : "", exploitNote: str(a.exploit_note, 200), kevCves: strs(a.kev_cves, 60, 30).filter(function (c) { return cves.indexOf(c) >= 0; }),
      notAffected: a.not_affected === true, sectors: strs(a.sectors, 12, 60),
      remediation: strs(a.remediation, 5, 20).filter(function (r) { return Object.prototype.hasOwnProperty.call(REM, r); }),
      url: url, doc: doc, summary: str(a.summary, 280), published: day(a.published), updated: day(a.updated)
    };
  };

  /* the whole file: { sources, lifeline, list, byCve } */
  O.load = function (d) {
    var sources = {}, rs = d && d.sources && typeof d.sources === "object" ? d.sources : {};
    Object.keys(rs).slice(0, 20).forEach(function (k) { var s = rs[k]; if (!/^[a-z]{2,20}$/.test(k) || !s) return;
      sources[k] = { name: str(s.name, 80) || k, tier: s.tier === "gov" ? "gov" : "vendor", ok: s.ok === true, at: str(s.at, 25), count: num(s.count, 0, 99999) || 0, error: str(s.error, 160) }; });
    var list = (Array.isArray(d && d.advisories) ? d.advisories : []).slice(0, 4000).map(function (a) { return O.clean(a, sources); }).filter(Boolean);
    var byCve = {};
    list.forEach(function (a) { a.cves.forEach(function (c) { (byCve[c] = byCve[c] || []).push(a); }); });
    return { sources: sources, lifeline: strs(d && d.lifeline, 30, 60), list: list, byCve: byCve, updatedAt: str(d && d.updated_at, 25), windowDays: num(d && d.window_days, 1, 3650) || 365 };
  };

  O.isExploited = function (a) { return a.exploited === "kev" || a.exploited === "active"; };
  O.lifelineHit = function (a, lifeline) { var l = (lifeline || []).map(function (s) { return s.toLowerCase(); }); return a.sectors.filter(function (s) { return l.indexOf(s.toLowerCase()) >= 0; })[0] || ""; };
  O.fixText = function (a) {
    var r = a.remediation;
    if (!r.length) return "";
    if (r.length === 1) return { vendor_fix: "Vendor fix available", mitigation: "Mitigations only, no vendor fix", workaround: "Workarounds only, no vendor fix", none_available: "No fix available", no_fix_planned: "No fix planned" }[r[0]];
    var order = ["vendor_fix", "mitigation", "workaround", "no_fix_planned", "none_available"];
    return "The advisory gives, each for some of its products: " + order.filter(function (x) { return r.indexOf(x) >= 0; }).map(function (x) { return REM[x]; }).join(", ");
  };
  O.noFix = function (a) { return a.remediation.length > 0 && a.remediation.indexOf("vendor_fix") < 0; };

  /* the visitor's software list (browser only): does an item name this vendor's product? */
  O.mine = function (a, inv) {
    if (!inv || !inv.length || a.notAffected) return false;
    var v = norm(a.vendor), prods = a.products.map(norm).filter(function (p) { return p.length >= 3; });
    if (!prods.length) return false;
    return inv.some(function (x) {
      var n = norm(x.name), xv = norm(x.vendor); if (!n) return false;
      if (xv && v && xv !== v && v.indexOf(xv) < 0 && xv.indexOf(v) < 0) return false;
      return prods.some(function (p) { return n === p || (n.length >= 4 && p.indexOf(n) >= 0) || n.indexOf(p) >= 0; });
    });
  };

  /* the order of the Industrial list: points, every one listed on the row (never a CVSS score) */
  O.rank = function (a, o) {
    o = o || {};
    var pts = [];
    if (a.notAffected) return { total: 0, points: [[0, "the vendor states its products are not affected"]] };
    if (a.exploited === "kev") pts.push([40, "known exploited: a CVE it names is in CISA's KEV catalog"]);
    else if (a.exploited === "active") pts.push([30, "exploited, as the advisory states"]);
    else if (a.exploited === "poc") pts.push([10, "public exploit code, as the advisory states"]);
    if (a.cvss !== null) { if (a.cvss >= 9) pts.push([25, "CVSS " + a.cvss.toFixed(1) + " (Critical)"]); else if (a.cvss >= 7) pts.push([15, "CVSS " + a.cvss.toFixed(1) + " (High)"]); else if (a.cvss >= 4) pts.push([5, "CVSS " + a.cvss.toFixed(1) + " (Medium)"]); }
    var life = O.lifelineHit(a, o.lifeline); if (life) pts.push([10, "deployed in a lifeline sector (" + life + ")"]);
    if (O.noFix(a)) pts.push([5, "no vendor fix for at least one product"]);
    if (o.mine) pts.push([20, "names a product on your software list"]);
    if (o.today && a.published) { var age = (Date.parse(o.today + "T12:00:00Z") - Date.parse(a.published + "T12:00:00Z")) / 864e5; if (age >= 0 && age <= 14) pts.push([5, "published in the last 14 days"]); }
    var total = pts.reduce(function (s, p) { return s + p[0]; }, 0);
    return { total: Math.min(100, total), points: pts };
  };

  /* filter and sort; f: { q, vendor, source, show, sort, lifeline, inv, today } */
  O.filter = function (list, f) {
    f = f || {};
    var q = norm(f.q), out = [];
    list.forEach(function (a) {
      var mine = O.mine(a, f.inv);
      if (q && norm([a.id, a.vendor, a.title, a.products.join(" "), a.cves.join(" "), a.sectors.join(" ")].join(" ")).indexOf(q) < 0) return;
      if (f.vendor && norm(a.vendor) !== norm(f.vendor)) return;
      if (f.source && a.source !== f.source) return;
      var s = f.show || "";
      if (s === "exploited" && !(O.isExploited(a) || a.exploited === "poc")) return;
      if (s === "critical" && !(a.cvss !== null && a.cvss >= 9)) return;
      if (s === "lifeline" && !O.lifelineHit(a, f.lifeline)) return;
      if (s === "nofix" && !O.noFix(a)) return;
      if (s === "mine" && !mine) return;
      if (s && s !== "notaffected" && a.notAffected) return;
      if (s === "notaffected" && !a.notAffected) return;
      var r = O.rank(a, { lifeline: f.lifeline, mine: mine, today: f.today });
      out.push({ a: a, score: r.total, points: r.points, mine: mine });
    });
    var by = f.sort || "rank";
    out.sort(function (x, y) {
      var dx = x.a.updated || x.a.published, dy = y.a.updated || y.a.published;
      if (by === "new") return dx < dy ? 1 : dx > dy ? -1 : 0;
      if (by === "cvss") return (y.a.cvss === null ? -1 : y.a.cvss) - (x.a.cvss === null ? -1 : x.a.cvss) || (dx < dy ? 1 : -1);
      return y.score - x.score || (dx < dy ? 1 : dx > dy ? -1 : 0);
    });
    return out;
  };

  /* the most common vendors, for the vendor filter */
  O.vendors = function (list, n) {
    var c = {}; list.forEach(function (a) { if (a.vendor) c[a.vendor] = (c[a.vendor] || 0) + 1; });
    return Object.keys(c).map(function (k) { return [k, c[k]]; }).sort(function (x, y) { return y[1] - x[1] || (x[0] < y[0] ? -1 : 1); }).slice(0, n || 80);
  };

  root.CVOT = O;
})(typeof window !== "undefined" ? window : this);
