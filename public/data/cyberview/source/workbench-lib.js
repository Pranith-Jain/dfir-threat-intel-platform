// CyberView workbench: the matching and scoring rules, kept apart from the page so unit tests can run them in Node.
// Everything here runs in the visitor's browser; an inventory is never sent anywhere.
(function (root) {
  "use strict";
  var L = {};
  var MAX_ITEMS = 5000;
  function txt(v, n) { return String(v == null ? "" : v).replace(/[\u0000-\u001f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n || 120); }
  function norm(s) { return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim(); }
  function isVer(s) { return /^v?\d+([.\-_+~:]\w+)*$/i.test(s) && /\d/.test(s) && s.length <= 40; }
  L.norm = norm;

  /* ---- versions ---- */
  // Compare dotted versions piece by piece: numbers as numbers, letters as text; a missing piece counts as 0 (7.2 == 7.2.0).
  function parts(v) { return String(v || "").toLowerCase().replace(/^v/, "").split(/[.\-_+~:]/).reduce(function (a, p) { return a.concat(p.match(/\d+|[a-z]+/g) || []); }, []); }
  L.cmp = function (a, b) {
    var x = parts(a), y = parts(b), n = Math.max(x.length, y.length);
    for (var i = 0; i < n; i++) {
      var p = x[i], q = y[i];
      if (p === undefined) p = "0"; if (q === undefined) q = "0";
      var pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
      if (pn && qn) { var d = parseInt(p, 10) - parseInt(q, 10); if (d) return d < 0 ? -1 : 1; }
      else if (pn !== qn) return pn ? 1 : -1;          // 7.2.1 is later than 7.2.rc
      else if (p !== q) return p < q ? -1 : 1;
    }
    return 0;
  };
  // Is version v inside one affected range? Returns true, false, or null when the range cannot be judged.
  L.inRange = function (v, r) {
    if (!v) return null;
    if (r.exact) return L.cmp(v, r.exact) === 0;
    if (!r.from && !r.to) return true;                 // every version is listed as vulnerable
    if (r.from) { var c = L.cmp(v, r.from); if (c < 0 || (c === 0 && !r.from_incl)) return false; }
    if (r.to) { var d = L.cmp(v, r.to); if (d > 0 || (d === 0 && !r.to_incl)) return false; }
    return true;
  };

  /* ---- names ---- */
  var GENERIC = { server: 1, client: 1, manager: 1, core: 1, enterprise: 1, security: 1, cloud: 1, connect: 1, gateway: 1, office: 1, desktop: 1, agent: 1, platform: 1, suite: 1, center: 1, service: 1, services: 1, firmware: 1, software: 1, edge: 1, access: 1, one: 1, pro: 1 };
  // Does an inventory name refer to this vendor/product? Every word of the product must be in the name;
  // a short or generic product word ("server", "edge") also needs the vendor in the name.
  L.nameHit = function (name, vendor, product) {
    var n = " " + norm(name) + " ", pv = norm(product), vv = norm(vendor);
    if (!pv || n.length < 4) return false;
    var words = pv.split(" "), all = words.every(function (w) { return n.indexOf(" " + w + " ") >= 0; });
    if (!all && n.replace(/ /g, "").indexOf(pv.replace(/ /g, "")) < 0) return false;
    if (!all && pv.replace(/ /g, "").length < 5) return false;
    var hasVendor = !!vv && vv.split(" ").some(function (w) { return w.length > 2 && n.indexOf(" " + w + " ") >= 0; });
    var weak = pv.replace(/ /g, "").length < 5 || words.every(function (w) { return GENERIC[w] || /^\d+$/.test(w); });
    return weak ? hasVendor : true;
  };

  /* ---- inventory import ---- */
  function csvRows(text) {
    var rows = [], row = [], cur = "", q = false, sep = (text.split("\n")[0].match(/\t/g) || []).length > (text.split("\n")[0].match(/,/g) || []).length ? "\t" : (text.split("\n")[0].indexOf(";") >= 0 && text.split("\n")[0].indexOf(",") < 0 ? ";" : ",");
    for (var i = 0; i < text.length; i++) {
      var c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
      else if (c === '"') q = true;
      else if (c === sep) { row.push(cur); cur = ""; }
      else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cur); cur = ""; if (row.some(function (x) { return x.trim(); })) rows.push(row); row = []; if (rows.length > MAX_ITEMS + 1) break; }
      else cur += c;
    }
    row.push(cur); if (row.some(function (x) { return x.trim(); })) rows.push(row);
    return rows;
  }
  function col(head, re) { for (var i = 0; i < head.length; i++) if (re.test(head[i])) return i; return -1; }
  function add(out, name, version, vendor, count) {
    name = txt(name, 120); version = txt(version, 40).replace(/^v(?=\d)/i, ""); vendor = txt(vendor, 80);
    if (name.length < 2 || /^(name|product|software|n\/a|unknown|null|none)$/i.test(name)) return;
    if (version && !isVer(version)) { var m = version.match(/\d+(\.\w+)+/); version = m ? m[0] : ""; }
    out.push({ name: name, vendor: vendor, version: version, count: Math.max(1, Math.min(1e6, Math.round(+count) || 1)) });
  }
  // Accepts: CycloneDX JSON (components), SPDX JSON (packages), CSV or TSV with a header (name/product/software,
  // version, vendor/publisher, count/devices), or plain lines such as "FortiOS 7.2.4" or "Google Chrome, 126.0.6478.61".
  L.parseInventory = function (fileName, text) {
    var out = [], kind = "list";
    text = String(text || "").slice(0, 8e6).replace(/^﻿/, "");
    var t = text.trim();
    if (t[0] === "{" || t[0] === "[") {
      try {
        var j = JSON.parse(t);
        var walk = function (cs) { (Array.isArray(cs) ? cs : []).forEach(function (c) { if (!c || typeof c !== "object" || out.length >= MAX_ITEMS) return; add(out, c.name, c.version, c.publisher || (c.supplier && c.supplier.name) || c.group, 1); walk(c.components); }); };
        if (j && Array.isArray(j.components)) { kind = "CycloneDX"; walk(j.components); }
        else if (j && Array.isArray(j.packages)) { kind = "SPDX"; j.packages.slice(0, MAX_ITEMS).forEach(function (p) { if (p) add(out, p.name, p.versionInfo, String(p.supplier || "").replace(/^(Organization|Person):\s*/i, "").replace(/NOASSERTION/i, ""), 1); }); }
        else if (Array.isArray(j)) { kind = "JSON list"; j.slice(0, MAX_ITEMS).forEach(function (p) { if (p && typeof p === "object") add(out, p.name || p.product || p.software || p.displayName, p.version || p.displayVersion, p.vendor || p.publisher, p.count || p.devices); else if (typeof p === "string") line(p); }); }
      } catch (e) { kind = "unreadable JSON"; }
    } else {
      var rows = csvRows(text), head = (rows[0] || []).map(function (h) { return norm(h); });
      var ni = col(head, /^(name|product|product name|software|software name|application|app|display ?name|title|package|component)$/), vi = col(head, /version/), pi = col(head, /^(vendor|publisher|manufacturer|supplier|company)$/), ci = col(head, /^(count|devices|device count|installs|install count|installations|hosts|quantity|qty|endpoints)$/);
      if (rows.length > 1 && ni >= 0) { kind = "table"; rows.slice(1, MAX_ITEMS + 1).forEach(function (r) { add(out, r[ni], vi >= 0 ? r[vi] : "", pi >= 0 ? r[pi] : "", ci >= 0 ? r[ci] : 1); }); }
      else text.split(/\r?\n/).slice(0, MAX_ITEMS).forEach(line);
    }
    function line(s) {
      s = txt(s, 200).replace(/^[-*•]\s*/, ""); if (!s || s[0] === "#") return;
      var p = s.split(/\s*[,;|\t]\s*/), name = p[0], version = "", count = 1;
      var w = name.split(" "), last = w[w.length - 1];
      if (w.length > 1 && isVer(last)) { version = last; name = w.slice(0, -1).join(" "); }
      // further fields: a dotted value is the version, a bare whole number after a version is the device count
      p.slice(1, 4).forEach(function (x) { if (!version && isVer(x)) version = x; else if (/^\d{1,7}$/.test(x)) count = x; });
      add(out, name, version, "", count);
    }
    // merge repeats of the same product and version
    var m = {}, list = [];
    out.forEach(function (x) { var k = norm(x.vendor + " " + x.name) + "|" + x.version; if (m[k]) m[k].count += x.count; else { m[k] = x; list.push(x); } });
    return { kind: kind, items: list.slice(0, MAX_ITEMS) };
  };

  /* ---- matching one flaw against the inventory ---- */
  // flaw: { vendor, product, affected: [ranges] }  ->  { state, items, fixed }
  //   affected  a version you run is inside a vulnerable range
  //   check     you run the product but the version is missing, or NVD has no ranges for it yet
  //   clear     you run the product and every version you listed is outside the ranges
  //   none      nothing in your list matches
  L.match = function (flaw, inv) {
    var ranges = Array.isArray(flaw.affected) ? flaw.affected : [], hit = [], fixed = {};
    (inv || []).forEach(function (it) {
      var full = (it.vendor ? it.vendor + " " : "") + it.name, mine = ranges.filter(function (r) { return L.nameHit(full, r.vendor, r.product); });
      var byName = mine.length > 0 || L.nameHit(full, flaw.vendor, flaw.product);
      if (!byName) return;
      var st = "check";
      if (it.version && mine.length) {
        var res = mine.map(function (r) { return L.inRange(it.version, r); });
        st = res.indexOf(true) >= 0 ? "affected" : res.every(function (x) { return x === false; }) ? "clear" : "check";
      }
      mine.forEach(function (r) { if (r.to && !r.to_incl && (!it.version || L.inRange(it.version, r) !== false)) fixed[r.to] = 1; });
      hit.push({ name: it.name, version: it.version, count: it.count, state: st });
    });
    if (!hit.length) return { state: "none", items: [], fixed: [] };
    var state = hit.some(function (h) { return h.state === "affected"; }) ? "affected" : hit.some(function (h) { return h.state === "check"; }) ? "check" : "clear";
    return { state: state, items: hit.slice(0, 20), fixed: Object.keys(fixed).sort(L.cmp).slice(-4) };
  };
  /* one affected range from data, checked (shared by the Vulnerabilities page and the downloadable scanner) */
  L.cleanRange = function (r) {
    var str = function (x, n) { return typeof x === "string" ? x.slice(0, n) : ""; };
    if (!r || typeof r !== "object" || !str(r.product, 60)) return null;
    var v = function (x) { x = str(x, 40); return /^[\w.+\-~:]+$/.test(x) ? x : ""; };
    return { vendor: str(r.vendor, 60), product: str(r.product, 60), from: v(r.from), from_incl: r.from_incl === true, to: v(r.to), to_incl: r.to_incl === true, exact: v(r.exact) };
  };
  /* one flaw against a software list, as the page and the scanner both judge it: version ranges first; a name-only range
     (flaws not yet in NVD's range data, marked nameOnly) can only say "you run this product" */
  L.matchFlaw = function (f, inv) {
    if (!inv || !inv.length) return null;
    var all = Array.isArray(f.affected) ? f.affected : [], real = all.filter(function (r) { return !r.nameOnly; });
    var m = L.match({ vendor: f.vendor, product: f.product, affected: real }, inv);
    if (m.state === "none" && real.length < all.length) {
      var hits = inv.filter(function (it) { return all.some(function (r) { return L.nameHit((it.vendor ? it.vendor + " " : "") + it.name, r.vendor, r.product); }); });
      if (hits.length) m = { state: "check", items: hits.slice(0, 20).map(function (it) { return { name: it.name, version: it.version, count: it.count, state: "check" }; }), fixed: [] };
    }
    return m;
  };
  // "fixed in" versions for a flaw when no inventory is loaded: the upper ends of its ranges
  L.fixedIn = function (flaw) {
    var f = {}; (flaw.affected || []).forEach(function (r) { if (r.to && !r.to_incl) f[(r.product || "") + " " + r.to] = 1; });
    return Object.keys(f).slice(0, 8);
  };

  /* ---- patch queue rank (points, 0 to 100) for the Known exploited view; every point is listed so the ranking can be checked.
     It only orders the queue: it is not the CyberView rating (cvedb-lib.js L.score, CVSS adjusted for exploitation) ---- */
  var EDGE = /vpn|firewall|gateway|fortios|fortigate|pan-os|globalprotect|ivanti|pulse|citrix|netscaler|adc\b|big-ip|sonicwall|sma\b|exchange|outlook web|sharepoint|confluence|jira|gitlab|jenkins|moveit|goanywhere|file transfer|web ?server|nginx|apache|tomcat|iis\b|router|access point|load balancer|proxy|remote (desktop|access|support)|screenconnect|connect secure|mail|zimbra|roundcube|wordpress|plugin|cms|vcenter|esxi|edge ?gateway|asa\b|firepower|ios xe|junos|check ?point|sophos|zyxel|d-link|tp-link|qnap|synology|nas\b/i;
  L.score = function (f, m, today) {
    var pts = [], add = function (n, why) { if (n > 0) pts.push([Math.round(n), why]); };
    if (f.kev) add(35, "Known exploited (CISA)"); else if (f.severity >= 3) add(15, "Rated high severity");
    if (f.ransomware) add(10, "Used by ransomware groups");
    if (typeof f.epss === "number") add(15 * f.epss, "EPSS " + Math.round(f.epss * 100) + "% chance of exploitation in 30 days");
    if (f.exploit_public) add(5, "Public exploit code");
    else if (f.repos > 0) add(3, f.repos + " public GitHub repositor" + (f.repos === 1 ? "y names" : "ies name") + " this CVE (possible exploit code)");
    if (f.exposure === "internet") add(10, "Internet-facing (from the advisory)");
    else if (!f.exposure && f.av !== "L" && f.av !== "P" && EDGE.test((f.vendor || "") + " " + (f.product || "") + " " + (f.name || ""))) add(10, "Likely internet-facing (by product keyword)");
    if (f.due) { var left = Math.round((Date.parse(f.due + "T12:00:00Z") - Date.parse(today + "T12:00:00Z")) / 864e5); if (left < 0) add(5, "Federal deadline passed"); else if (left <= 7) add(3, "Federal deadline within 7 days"); }
    if (m && m.state === "affected") add(20, "You run an affected version");
    else if (m && m.state === "check") add(10, "You run this product (version to check)");
    var total = Math.min(100, pts.reduce(function (s, p) { return s + p[0]; }, 0));
    return { total: total, points: pts };
  };
  L.MAX_ITEMS = MAX_ITEMS;

  if (typeof module !== "undefined" && module.exports) module.exports = L; else root.CVWorkbench = L;
})(typeof window !== "undefined" ? window : this);
