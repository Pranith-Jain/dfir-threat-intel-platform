// CyberView CVE helpers for the Vulnerabilities page: the pure rules (bucket file for an id, row cleaning, filtering, sorting,
// paging) kept apart from the page so unit tests can run them in Node. The data is the static lookup files written by
// scripts/cve.mjs `site` into data/cve/: <year>/<thousand>.json = { fields, rows: [[...]] }, index.json, recent.json.
// Nothing a visitor types is sent anywhere.
(function (root) {
  "use strict";
  var L = {};
  var ID_RE = /^CVE-\d{4}-\d{4,}$/;
  var SEV = { C: "Critical", H: "High", M: "Medium", L: "Low", N: "None" };
  var EXPL = { active: "Exploited (CISA)", poc: "Proof of concept public (CISA)", none: "No exploitation seen (CISA)" };
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function day(s) { return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ""; }
  /* one affected-version range from NVD (row field `aff`, written by scripts/cve.mjs) -> the shape the browser matcher uses
     (the same cleanRange as the Vulnerabilities page and the workbench: {vendor, product, from, from_incl, to, to_incl, exact}),
     so one matcher (CVWorkbench.match) serves known-exploited flaws and every other CVE alike. Null when malformed. */
  function cleanRange(r) {
    if (!r || typeof r !== "object" || !str(r.product, 60)) return null;
    var v = function (x) { x = str(x, 40); return /^[\w.+\-~:]+$/.test(x) ? x : ""; };
    return { vendor: str(r.vendor, 60), product: str(r.product, 60), from: v(r.from), from_incl: r.from_incl === true, to: v(r.to), to_incl: r.to_incl === true, exact: v(r.exact) };
  }
  L.cleanRange = cleanRange;
  L.SEV = SEV; L.EXPL = EXPL;
  L.isId = function (s) { return typeof s === "string" && s.length <= 24 && ID_RE.test(s); };
  L.normId = function (s) { var t = String(s || "").trim().toUpperCase().replace(/[‐-―−]/g, "-").replace(/\s+/g, ""); return L.isId(t) ? t : ""; };
  L.parseId = function (id) { return L.isId(id) ? { year: +id.slice(4, 8), seq: +id.slice(9) } : null; };
  /* the lookup file that holds an id: CVE-2024-3400 -> "2024/3.json" (thousands, as scripts/lib/cve.mjs bucket()) */
  L.bucketFile = function (id) { var p = L.parseId(id); return p ? p.year + "/" + Math.floor(p.seq / 1000) + ".json" : ""; };

  /* index.json: { built_at, total, rejected, exploited, critical, by_year: {"2024": n}, buckets, files_by_year: {"2024": [0, 1, 3 ...]}, sources: { cvelist, epss } }
     files is null for an older index without the list; the page then probes for the files */
  L.cleanIndex = function (x) {
    if (!x || typeof x !== "object") return null;
    var by = x.by_year && typeof x.by_year === "object" ? x.by_year : {}, years = [];
    var fy = x.files_by_year && typeof x.files_by_year === "object" ? x.files_by_year : {};
    Object.keys(by).slice(0, 120).forEach(function (k) { var n = num(by[k], 0, 1e7); if (/^\d{4}$/.test(k) && +k >= 1988 && +k <= 2100 && n !== null) {
      var f = Array.isArray(fy[k]) ? fy[k].slice(0, 2000).filter(function (v) { return typeof v === "number" && v >= 0 && v <= 99999 && Math.floor(v) === v; }) : null;
      years.push({ year: +k, count: n, files: f && f.length ? f : null }); } });
    years.sort(function (a, b) { return b.year - a.year; });
    var s = x.sources && typeof x.sources === "object" ? x.sources : {};
    var o = { builtAt: str(x.built_at, 30), total: num(x.total, 0, 1e8), rejected: num(x.rejected, 0, 1e8), exploited: num(x.exploited, 0, 1e8), critical: num(x.critical, 0, 1e8), criticalNvd: num(x.critical_nvd, 0, 1e8), ratingBands: x.rating_bands && typeof x.rating_bands === "object" ? { Critical: num(x.rating_bands.Critical, 0, 1e7), High: num(x.rating_bands.High, 0, 1e7), Medium: num(x.rating_bands.Medium, 0, 1e7), Low: num(x.rating_bands.Low, 0, 1e7), None: num(x.rating_bands.None, 0, 1e7), "Not scored": num(x.rating_bands["Not scored"], 0, 1e7) } : null, kev: num(x.kev, 0, 1e7), ransomware: num(x.ransomware, 0, 1e7), withRanges: num(x.with_ranges, 0, 1e8), decisions: x.decisions && typeof x.decisions === "object" ? { act: num(x.decisions.act, 0, 1e7), attend: num(x.decisions.attend, 0, 1e7), "track*": num(x.decisions["track*"], 0, 1e7), track: num(x.decisions.track, 0, 1e7) } : null,
      audit: x.audit && typeof x.audit === "object" && x.audit.nvd ? { at: str(x.audit.at, 30), nvdTotal: num(x.audit.nvd.total, 0, 1e8), nvdRejected: num(x.audit.nvd.rejected, 0, 1e8), nvdCritical: num(x.audit.nvd.critical_v3, 0, 1e8), cisaKev: num(x.audit.cisa_kev, 0, 1e7) } : null, years: years, cvelist: str(s.cvelist, 30), epss: str(s.epss, 30) };
    return o.total === null && !years.length ? null : o;
  };

  /* vendor security advisories joined on CVE (data/psirt.json, written by scripts/build.mjs from scripts/psirt.mjs's
     data/psirt/advisories.json): { cve: { "CVE-...": [[vendor, advisory id, url, severity as the vendor states it,
     the vendor's own exploited statement for this CVE or "", [fixed versions as stated]]] } } -> { id: [{ vendor, id, url,
     sev, x, fixed }] }. The page sets L.vendorIndex once it has loaded the file; cleanRow attaches a CVE's advisories as r.adv. */
  L.vendorIndex = {};
  L.cleanVendorIndex = function (x) {
    var m = {}, cv = x && x.cve && typeof x.cve === "object" ? x.cve : {}, n = 0;
    Object.keys(cv).forEach(function (k) {
      if (n >= 60000 || !L.isId(k) || !Array.isArray(cv[k])) return;
      var list = cv[k].slice(0, 4).map(function (a) {
        if (!Array.isArray(a)) return null;
        var url = str(a[2], 600);
        if (!/^https:\/\/[^\s"'<>]+$/.test(url)) return null;
        return { vendor: str(a[0], 40), id: str(a[1], 80), url: url, sev: str(a[3], 20), x: str(a[4], 400), fixed: (Array.isArray(a[5]) ? a[5] : []).slice(0, 2).map(function (f) { return str(f, 120); }).filter(Boolean) };
      }).filter(function (a) { return a && a.vendor && a.id; });
      if (list.length) { m[k] = list; n++; }
    });
    return m;
  };

  /* one lookup-file row (an array in the file's field order) -> a checked record, or null */
  L.cleanRow = function (fields, a) {
    if (!Array.isArray(a) || !Array.isArray(fields)) return null;
    var o = {}; fields.slice(0, 30).forEach(function (k, i) { o[k] = a[i]; });
    if (!L.isId(o.id)) return null;
    var c = {
      id: o.id, rejected: o.state === "R", pub: day(o.pub), upd: day(o.upd), cvss: num(o.cvss, 0, 10), sev: SEV[o.sev] ? o.sev : "", ver: /^[0-9.]{1,4}$/.test(o.ver || "") ? o.ver : "",
      cwe: /^CWE-\d{1,5}$/.test(o.cwe || "") ? o.cwe : "", vendor: str(o.vendor, 60), product: str(o.product, 80), title: str(o.title, 160), desc: str(o.desc, 600), cna: str(o.cna, 40),
      expl: EXPL[o.expl] ? o.expl : "", kev: /^\d{4}-\d{2}-\d{2}$|^yes$/.test(o.kev || "") ? o.kev : "", epss: num(o.epss, 0, 1), pct: num(o.pct, 0, 1),
      auto: o.auto === "yes" || o.auto === "no" ? o.auto : "", ti: o.ti === "total" || o.ti === "partial" ? o.ti : "", vec: /^[A-Za-z0-9.:\/()]{8,200}$/.test(o.vec || "") ? o.vec : "",
      due: day(o.due), ransom: o.ransom === true, ncvss: num(o.ncvss, 0, 10), nsev: SEV[o.nsev] ? o.nsev : "", nvec: /^[A-Za-z0-9.:\/()]{8,200}$/.test(o.nvec || "") ? o.nvec : "",
      n3: SEV[o.n3] ? o.n3 : "", n3c: o.n3c === true,
      // affected-version ranges from NVD; matched against a visitor's software list in the browser, nothing uploaded
      affected: Array.isArray(o.aff) ? o.aff.slice(0, 20).map(cleanRange).filter(Boolean) : []
    };
    c.hay = (c.id + " " + c.vendor + " " + c.product + " " + c.title + " " + c.desc + " " + c.cwe).toLowerCase();
    if (Object.prototype.hasOwnProperty.call(L.vendorIndex, c.id)) c.adv = L.vendorIndex[c.id];
    return c;
  };
  L.parseFile = function (d) {
    var f = Array.isArray(d && d.fields) ? d.fields : [];
    return (Array.isArray(d && d.rows) ? d.rows : []).slice(0, 6000).map(function (a) { return L.cleanRow(f, a); }).filter(Boolean);
  };

  /* filter: { q, sev, minEpss (0..1), cwe, vendor, status: "live" (default: not rejected) | "all" | "R", exploited } ; kev: object keyed by CVE id (CISA catalog as CyberView holds it) */
  L.isExploited = function (r, kev) { return !!(r.kev || r.expl === "active" || (kev && Object.prototype.hasOwnProperty.call(kev, r.id))); };
  L.matches = function (r, f, kev) {
    f = f || {};
    var q = String(f.q || "").trim().toLowerCase();
    if (q && r.hay.indexOf(q) < 0) return false;
    if (f.sev && r.sev !== f.sev) return false;
    if (f.minEpss && !(r.epss >= f.minEpss)) return false;
    if (f.cwe) { var c = String(f.cwe).trim().toUpperCase(); if (/^\d+$/.test(c)) c = "CWE-" + c; if (r.cwe !== c) return false; }
    if (f.vendor) { var v = String(f.vendor).trim().toLowerCase(); if ((r.vendor + " " + r.product).toLowerCase().indexOf(v) < 0) return false; }
    var st = f.status || "live";
    if (st === "live" ? r.rejected : st === "R" ? !r.rejected : false) return false;
    if (f.exploited && !L.isExploited(r, kev)) return false;
    if (f.minScore) { var sc = L.scored(r); if (!sc || sc.score === null || sc.score < f.minScore) return false; }
    if (f.baseSev) { var bs = L.scored(r); if (!bs || (f.baseSev === "unscored" ? bs.score !== null : bs.baseBand !== f.baseSev)) return false; }
    if (f.decision) { var d = L.rated(r, f.rateOpts); if (!d || (f.decision === "attend+" ? d.rank < 3 : d.decision !== f.decision)) return false; }
    return true;
  };
  /* sort keys, highest first: the CyberView rating (not scored last), the SSVC priority, EPSS */
  function ratingOf(r) { var s = L.scored(r); return s && s.score !== null ? s.score : -1; }
  function byRating(a, b) { return ratingOf(b) - ratingOf(a); }
  function byRank(a, b) { var x = L.rated(a), y = L.rated(b); return ((y && y.rank) || 0) - ((x && x.rank) || 0); }
  function byEpss(a, b) { return (b.epss === null ? -1 : b.epss) - (a.epss === null ? -1 : a.epss); }
  function seqOf(id) { var p = L.parseId(id); return p ? p.year * 1e9 + p.seq : 0; }
  var SORTS = {
    pub: function (a, b) { return a.pub < b.pub ? 1 : a.pub > b.pub ? -1 : seqOf(b.id) - seqOf(a.id); },
    old: function (a, b) { return a.pub < b.pub ? -1 : a.pub > b.pub ? 1 : seqOf(a.id) - seqOf(b.id); },
    upd: function (a, b) { return a.upd < b.upd ? 1 : a.upd > b.upd ? -1 : seqOf(b.id) - seqOf(a.id); },
    cvss: function (a, b) { return (b.cvss === null ? -1 : b.cvss) - (a.cvss === null ? -1 : a.cvss) || seqOf(b.id) - seqOf(a.id); },
    epss: function (a, b) { return (b.epss === null ? -1 : b.epss) - (a.epss === null ? -1 : a.epss) || seqOf(b.id) - seqOf(a.id); },
    id: function (a, b) { return seqOf(a.id) - seqOf(b.id); },
    score: function (a, b) { return byRating(a, b) || byRank(a, b) || byEpss(a, b) || seqOf(b.id) - seqOf(a.id); },
    priority: function (a, b) { return byRank(a, b) || byRating(a, b) || byEpss(a, b) || seqOf(b.id) - seqOf(a.id); }
  };
  /* the SSVC priority of a row for the visitor's current settings, computed once per settings; the CyberView rating depends on
     the record alone, so it is computed once */
  L.rateOpts = {};
  L.scored = function (r) { if (!r._sk) { r._score = L.score(r); r._sk = 1; } return r._score; };
  L.rated = function (r, opts) { opts = opts || L.rateOpts; var k = (opts.mission || "") + "|" + opts.exposed; if (!r._rk || r._rk !== k) { r._rate = L.rate(r, opts); r._rk = k; } return r._rate; };
  L.SORT_KEYS = Object.keys(SORTS);
  L.filter = function (list, f, kev, sort) { return (list || []).filter(function (r) { return L.matches(r, f, kev); }).sort(SORTS[sort] || SORTS.pub); };
  L.page = function (list, page, size) { var pages = Math.max(1, Math.ceil(list.length / size)), p = Math.min(Math.max(0, page | 0), pages - 1); return { page: p, pages: pages, items: list.slice(p * size, (p + 1) * size) }; };
  /* the n most common vendor names in a list, for the vendor suggestions */
  L.topVendors = function (list, n) {
    var m = {}; list.forEach(function (r) { if (r.vendor) m[r.vendor] = (m[r.vendor] || 0) + 1; });
    return Object.keys(m).sort(function (a, b) { return m[b] - m[a] || (a < b ? -1 : 1); }).slice(0, n).map(function (k) { return [k, m[k]]; });
  };


  /* ---- the rating: CISA's SSVC decision (Track, Track*, Attend, Act) from four inputs, each with where it came from ----
     Decision table: CISA SSVC coordinator tree 2.0.3, as published by CERT/CC (github.com/CERTCC/SSVC,
     data/csv/cisa/cisa_coordinator_2_0_3.csv). Order of the key: exploitation|automatable|technical impact|mission. */
  var T = "track", TS = "track*", AT = "attend", AC = "act";
  var DT = {
    "none|no|partial": [T, T, T], "none|no|total": [T, T, TS], "none|yes|partial": [T, T, AT], "none|yes|total": [T, T, AT],
    "poc|no|partial": [T, T, TS], "poc|no|total": [T, TS, AT], "poc|yes|partial": [T, T, AT], "poc|yes|total": [T, TS, AT],
    "active|no|partial": [T, T, AT], "active|no|total": [T, AT, AC], "active|yes|partial": [AT, AT, AC], "active|yes|total": [AT, AC, AC]
  };
  var MI = { low: 0, medium: 1, high: 2 };
  L.DECISIONS = {
    act: { label: "Act", rank: 4, does: "Fix now, out of your normal cycle; tell leadership." },
    attend: { label: "Attend", rank: 3, does: "Fix sooner than your normal cycle; senior staff should know." },
    "track*": { label: "Track*", rank: 2, does: "Fix in your normal cycle and watch closely for exploitation." },
    track: { label: "Track", rank: 1, does: "Fix in your normal patch cycle." }
  };
  L.ssvcDecision = function (exploitation, automatable, impact, mission) {
    var row = DT[exploitation + "|" + automatable + "|" + impact]; return row ? row[MI[mission] != null ? MI[mission] : 1] : null;
  };
  function vecHas(v, k) { return new RegExp("(^|/)" + k + "(/|$)").test(v || ""); }
  /* SSVC's Automatable (can steps 1-4 of the kill chain be automated?) estimated from CVSS: network attack, low complexity,
     no attack requirements, no privileges, no user interaction */
  L.automatableFromVector = function (v) {
    if (!v) return "";
    if (/^CVSS:4/.test(v)) return vecHas(v, "AV:N") && vecHas(v, "AC:L") && vecHas(v, "AT:N") && vecHas(v, "PR:N") && vecHas(v, "UI:N") ? "yes" : "no";
    if (/^CVSS:3/.test(v)) return vecHas(v, "AV:N") && vecHas(v, "AC:L") && vecHas(v, "PR:N") && vecHas(v, "UI:N") ? "yes" : "no";
    if (/AV:N/.test(v)) return /AC:L/.test(v) && /Au:N/.test(v) ? "yes" : "no";   // CVSS v2
    return "no";
  };
  /* SSVC's Technical Impact (total control or total disclosure, versus partial) estimated from CVSS: high confidentiality AND
     high integrity impact on the vulnerable system */
  L.impactFromVector = function (v) {
    if (!v) return "";
    if (/^CVSS:4/.test(v)) return vecHas(v, "VC:H") && vecHas(v, "VI:H") ? "total" : "partial";
    if (/^CVSS:3/.test(v)) return vecHas(v, "C:H") && vecHas(v, "I:H") ? "total" : "partial";
    return /C:C/.test(v) && /I:C/.test(v) ? "total" : "partial";   // CVSS v2: complete
  };
  /* CISA BOD 26-04 (issued 10 June 2026; supersedes BOD 22-01), Table 1: Remediation Timelines, in calendar days. Binding on US
     federal civilian agencies; CyberView shows it as the current government benchmark for everyone. Key:
     publicly exposed|in the KEV|automatable by adversary|technical impact. Transcribed from the directive page and confirmed by
     three independent readers (swarm/rating-20261119T1941). */
  var BOD = {
    "yes|yes|yes|total": "3t", "yes|yes|yes|partial": "3", "yes|yes|no|total": "3t", "yes|yes|no|partial": "14",
    "yes|no|yes|total": "3", "yes|no|yes|partial": "14", "yes|no|no|total": "14", "yes|no|no|partial": "60",
    "no|yes|yes|total": "3t", "no|yes|yes|partial": "14", "no|yes|no|total": "14", "no|yes|no|partial": "14",
    "no|no|yes|total": "60", "no|no|yes|partial": "60", "no|no|no|total": "upgrade", "no|no|no|partial": "upgrade"
  };
  L.BOD_SOURCE = "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk";
  /** -> { days: 3 | 14 | 60 | null, triage: bool, text } for one exposure answer */
  L.bodTimeline = function (exposed, kev, automatable, impact) {
    var v = BOD[(exposed ? "yes" : "no") + "|" + (kev ? "yes" : "no") + "|" + automatable + "|" + impact];
    if (!v) return null;
    if (v === "upgrade") return { days: null, triage: false, text: "at the next scheduled major upgrade or rebuild" };
    var t = v.slice(-1) === "t", d = parseInt(v, 10);
    return { days: d, triage: t, text: "within " + d + " days" + (t ? ", and check the system for compromise (forensic triage)" : "") };
  };
  L.WILD = /exploited in the wild|actively exploited|exploitation evidence (?:was )?(?:first )?observed|exploitation (?:was |has been )?(?:observed|detected|seen)|observed (?:being )?exploit|under active exploitation/i;
  L.POC = /proof[- ]of[- ]concept|public(?:ly available)? exploit|exploit has been (?:published|disclosed|made public)|exploit (?:code )?is (?:publicly )?available|PoC (?:is )?(?:publicly )?available/i;
  /** exploitation evidence for one CVE -> { value: "active" | "poc" | "none", basis, source }: CISA's KEV catalog, then CISA's
   *  SSVC assessment. The vendor's own advisory ("exploited in the wild", source "vendor") and the assigner's own record
   *  ("exploitation evidence was observed", "the exploit has been published") can say more; each is used, and labelled, only
   *  when it raises the answer. Shared by the SSVC priority and the CyberView rating. */
  L.exploitation = function (r) {
    var ex = "none", exB = "No exploitation reported to CISA", exS = "unassessed";
    if (r.kev) { ex = "active"; exB = "On CISA's Known Exploited Vulnerabilities catalog" + (r.kev !== "yes" ? " since " + r.kev : ""); exS = "cisa-kev"; }
    else if (r.expl === "active") { ex = "active"; exB = "CISA reports active exploitation (SSVC)"; exS = "cisa"; }
    else if (r.expl === "poc") { ex = "poc"; exB = "CISA: public proof of concept or exploit code (SSVC)"; exS = "cisa"; }
    else if (r.expl === "none") { exB = "CISA has seen no exploitation (SSVC)"; exS = "cisa"; }
    /* the vendor's own advisory says the flaw is exploited (scripts/psirt.mjs reads it from the vendor's CSAF, API, feed or
       page; only a statement that covers this CVE): High, labelled as the vendor's statement */
    var vx = (Array.isArray(r.adv) ? r.adv : []).filter(function (a) { return a && a.x; })[0];
    if (ex !== "active" && vx) { ex = "active"; exB = vx.vendor + "'s own advisory (" + vx.id + ") says it is exploited in the wild (the vendor's statement; CISA has not confirmed it)"; exS = "vendor"; }
    if (ex !== "active" && L.WILD.test(r.desc || "")) { ex = "active"; exB = "The CVE record's description reports exploitation in the wild (the assigner's statement; CISA has not confirmed it)"; exS = "description"; }
    else if (ex === "none" && L.POC.test(r.desc || "")) { ex = "poc"; exB = "The CVE record's description says exploit code is public (the assigner's statement)"; exS = "description"; }
    return { value: ex, basis: exB, source: exS };
  };
  /** One CVE -> { decision, label, does, inputs: [{name, value, basis, source}], signals: [...], deadline, overdue }.
   *  opts.mission: the visitor's mission and well-being impact for this kind of system (low, medium, high; default medium). */
  L.rate = function (r, opts) {
    opts = opts || {}; if (!r) return null;
    if (r.rejected) return { decision: null, label: "Rejected", does: "Not a vulnerability record: the CVE was withdrawn, merged into another or found not to be a flaw. Nothing to fix.", inputs: [], signals: [] };
    var today = opts.today || new Date().toISOString().slice(0, 10), inputs = [], signals = [];
    var exi = L.exploitation(r), ex = exi.value;
    inputs.push({ name: "Exploitation", value: ex === "poc" ? "public PoC" : ex, basis: exi.basis, source: exi.source });
    var vec = r.vec || r.nvec || "", au = r.auto, auB = "CISA's assessment (SSVC)", auS = "cisa";
    if (!au) { au = L.automatableFromVector(vec); auB = au ? "Estimated from the CVSS vector (" + (au === "yes" ? "network, low complexity, no privileges or user interaction" : "needs local access, privileges, user action or high complexity") + ")" : "Unknown: no CISA assessment or CVSS vector; assumed no"; auS = au ? "estimate" : "default"; au = au || "no"; }
    inputs.push({ name: "Automatable", value: au, basis: auB, source: auS });
    var ti = r.ti, tiB = "CISA's assessment (SSVC)", tiS = "cisa";
    if (!ti) { ti = L.impactFromVector(vec); tiB = ti ? "Estimated from the CVSS vector (" + (ti === "total" ? "high confidentiality and integrity impact" : "limited confidentiality or integrity impact") + ")" : "Unknown: no CISA assessment or CVSS vector; assumed partial"; tiS = ti ? "estimate" : "default"; ti = ti || "partial"; }
    inputs.push({ name: "Technical impact", value: ti, basis: tiB, source: tiS });
    var mi = MI[opts.mission] != null ? opts.mission : "medium";
    inputs.push({ name: "Mission and well-being", value: mi, basis: MI[opts.mission] != null ? "Your setting for this kind of system" : "Default for an organisation's ordinary systems; set yours", source: MI[opts.mission] != null ? "you" : "default" });
    var d = L.ssvcDecision(ex, au, ti, mi);
    var score = r.cvss != null ? r.cvss : (r.ncvss != null ? r.ncvss : null), scoreFrom = r.cvss != null ? "the assigner or CISA" : "NVD";
    /* CyberView's one addition to the CISA tree, following FIRST's EPSS guidance: a flaw nobody exploits yet but that EPSS puts in
       the top 5% for the next 30 days is watched closely (Track becomes Track*); EPSS never stands in for observed exploitation */
    if (d === T && r.pct != null && r.pct >= 0.95) { d = TS; signals.push({ text: "EPSS puts it in the top " + Math.max(0.1, Math.round((1 - r.pct) * 1000) / 10) + "% most likely to be exploited in the next 30 days, so Track becomes Track*", kind: "raise" }); }
    if (r.ransom) signals.push({ text: "Used in ransomware campaigns (CISA)", kind: "warn" });
    if (score != null) signals.push({ text: "CVSS " + score.toFixed(1) + (r.cvss != null ? (SEV[r.sev] ? " " + SEV[r.sev] : "") : (SEV[r.nsev] ? " " + SEV[r.nsev] : "")) + " from " + scoreFrom + ": how severe the flaw is in general, not how urgent it is for you", kind: "info" });
    if (r.cvss != null && r.ncvss != null && Math.abs(r.cvss - r.ncvss) >= 2) signals.push({ text: "NVD scores it " + r.ncvss.toFixed(1) + ", the assigner " + r.cvss.toFixed(1) + ": the sources disagree", kind: "info" });
    if (r.epss != null && !(r.pct >= 0.95)) signals.push({ text: "EPSS " + (r.epss * 100).toFixed(r.epss < 0.01 ? 2 : 1) + "% chance of exploitation in the next 30 days", kind: "info" });
    var out = { decision: d, label: L.DECISIONS[d].label, does: L.DECISIONS[d].does, rank: L.DECISIONS[d].rank, inputs: inputs, signals: signals, deadline: "", overdue: false,
      estimated: inputs.some(function (x) { return x.source === "estimate" || x.source === "default" && x.name !== "Mission and well-being"; }) };
    if (r.kev && r.due) { out.deadline = r.due; out.overdue = r.due < today; }
    /* BOD 26-04 Table 1 for both exposure answers; opts.exposed picks one when the visitor has said */
    out.fixBy = { exposed: L.bodTimeline(true, !!r.kev, au, ti), internal: L.bodTimeline(false, !!r.kev, au, ti) };
    out.fixFor = opts.exposed === true ? "exposed" : opts.exposed === false ? "internal" : "";
    /* policy floor: a flaw in CISA's KEV catalog is never rated below what BOD 26-04 demands of it (3 days: Act; 14 days: Attend),
       using the visitor's exposure answer, or internal when they have not said */
    if (r.kev) {
      var fl = out.fixBy[out.fixFor || "internal"], want = fl && fl.days === 3 ? AC : fl && fl.days === 14 ? AT : null;
      if (want && L.DECISIONS[want].rank > out.rank) {
        signals.unshift({ text: "In CISA's KEV catalog: BOD 26-04 requires a fix " + fl.text + (out.fixFor ? "" : " even on internal systems") + ", so the priority is raised from " + out.label + " to " + L.DECISIONS[want].label, kind: "raise" });
        out.decision = want; out.label = L.DECISIONS[want].label; out.does = L.DECISIONS[want].does; out.rank = L.DECISIONS[want].rank;
      }
    }
    return out;
  };

  /* ---- the CyberView rating: CVSS adjusted for exploitation evidence, on CVSS's own 0.0 to 10.0 scale ----
     The CVSS base score (the assigner's or CISA's first, else NVD's) multiplied by CVSS v3.1's Exploit Code Maturity (E)
     metric, set from the evidence CyberView holds, and rounded with CVSS's own Roundup. This is the CVSS v3.1 temporal
     equation (FIRST CVSS v3.1 specification, sections 3.1 and 7.2: Roundup(Base x E x RL x RC)) with Remediation Level and
     Report Confidence Not Defined (x 1), the adjustment often called CVSS-BT. CVSS v4's Exploit Maturity follows the same idea.
       Exploit Code Maturity High              x 1.00  exploited in the wild: CISA's KEV catalog, CISA reports active
                                                       exploitation, the vendor's own advisory says so (scripts/psirt.mjs),
                                                       or the CVE record states exploitation in the wild
       Exploit Code Maturity Proof-of-Concept  x 0.94  public exploit code (CISA, or the CVE record says so)
       Exploit Code Maturity Unproven          x 0.91  no exploitation or public exploit reported
     (Functional, x 0.97, is not used: CyberView holds no signal that tells it apart from a proof of concept.)
     Bands are CVSS's own: None 0.0 · Low 0.1-3.9 · Medium 4.0-6.9 · High 7.0-8.9 · Critical 9.0-10.0. The rating is never
     higher than the base score. No CVSS base score: "Not scored", never an invented number. EPSS, ransomware use, CISA's dates
     and the visitor's settings are not in it: they are shown beside it, and CISA's SSVC priority (L.rate) says how urgent. */
  L.E = { active: { label: "High", value: 1, why: "exploited in the wild" }, poc: { label: "Proof-of-Concept", value: 0.94, why: "public exploit code" }, none: { label: "Unproven", value: 0.91, why: "no exploitation or public exploit reported" } };
  L.BANDS = [[9, "Critical", "bad"], [7, "High", "bad"], [4, "Medium", "warn"], [0.1, "Low", "info"], [0, "None", "info"]];
  L.band = function (s) { if (typeof s !== "number" || !isFinite(s)) return null; var b = L.BANDS.filter(function (x) { return s >= x[0]; })[0] || L.BANDS[4]; return { band: b[1], tone: b[2] }; };
  /* CVSS v3.1 Appendix A Roundup: the smallest number, to one decimal place, equal to or higher than its input (with the
     specification's guard against floating point error) */
  L.roundup = function (x) { var i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  function verOf(v) { var m = /^CVSS:(\d\.\d)\//.exec(v || ""); return m ? m[1] : v ? "2.0" : ""; }
  /** the CVSS base score the rating starts from: { score, from, ver, vector } or null */
  L.baseOf = function (r) {
    if (!r) return null;
    if (r.cvss != null) return { score: r.cvss, from: "assigner or CISA", ver: r.ver || verOf(r.vec), vector: r.vec || "" };
    if (r.ncvss != null) return { score: r.ncvss, from: "NVD", ver: verOf(r.nvec), vector: r.nvec || "" };
    return null;
  };
  /** One CVE -> { score (0.0-10.0, or null when not scored), band, tone, base, baseBand, e, eWhy, notes, confidence, text } */
  L.score = function (r) {
    if (!r || r.rejected) return null;
    var ex = L.exploitation(r), base = L.baseOf(r), e = L.E[ex.value] || L.E.none;
    var eWhy = ex.value !== "none" ? ex.basis.replace(/^(On|The) /, function (m) { return m.toLowerCase(); }) :r.expl === "none" ? "CISA has seen no exploitation" : e.why;
    var conf = r.kev || r.expl ? "High" : "Medium";
    var confWhy = r.kev ? "the exploitation evidence is CISA's KEV catalog" : r.expl ? "CISA has assessed exploitation for this CVE" : ex.source === "vendor" ? "the exploitation evidence is the vendor's own advisory; CISA has not assessed it" : ex.source === "description" ? "the exploitation evidence is the assigner's own statement; CISA has not assessed it" : "CISA has not assessed exploitation, so Unproven means none reported to CyberView's sources, not proof that nobody exploits it";
    if (!base) return { score: null, band: "Not scored", tone: "info", base: null, baseBand: "", e: e, eWhy: eWhy, notes: [], confidence: "", confidenceWhy: "",
      text: "Not scored: neither the assigner, CISA nor NVD has published a CVSS base score, so there is nothing to adjust. CyberView never invents one; use the priority (CISA SSVC) and the signals shown with it." };
    var score = Math.min(base.score, L.roundup(base.score * e.value)), b = L.band(score), bb = L.band(base.score), notes = [];
    if (base.ver && !/^3/.test(base.ver)) notes.push("The base score is CVSS v" + base.ver + ": the CVSS v3.1 Exploit Code Maturity multiplier is applied to it and the result is banded on the v3.1 scale" + (/^4/.test(base.ver) ? " (CVSS v4 builds Exploit Maturity into its own score; this is the closest v3.1 equivalent)" : "") + ".");
    if (bb.band !== b.band) notes.push("One band below its CVSS base rating (" + bb.band + ") because " + (ex.value === "poc" ? "only a proof of concept is public and no exploitation in the wild is reported" : "no exploitation or public exploit is reported") + ". It returns to " + bb.band + " as soon as exploitation is reported.");
    return { score: score, band: b.band, tone: b.tone, base: base, baseBand: bb.band, e: e, eWhy: eWhy, notes: notes, confidence: conf, confidenceWhy: confWhy,
      text: "CVSS " + base.score.toFixed(1) + " (" + base.from + (base.ver ? ", v" + base.ver : "") + ") x " + e.value.toFixed(2) + " Exploit Code Maturity: " + e.label + " (" + eWhy + ") = " + score.toFixed(1) + " " + b.band };
  };
  if (typeof module !== "undefined" && module.exports) module.exports = L; else root.CVDB = L;
})(typeof window !== "undefined" ? window : this);
