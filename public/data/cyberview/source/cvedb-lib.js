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
    var o = { builtAt: str(x.built_at, 30), total: num(x.total, 0, 1e8), rejected: num(x.rejected, 0, 1e8), exploited: num(x.exploited, 0, 1e8), critical: num(x.critical, 0, 1e8), criticalNvd: num(x.critical_nvd, 0, 1e8), bands: x.bands && typeof x.bands === "object" ? { Critical: num(x.bands.Critical, 0, 1e7), High: num(x.bands.High, 0, 1e7), Elevated: num(x.bands.Elevated, 0, 1e7), Moderate: num(x.bands.Moderate, 0, 1e7), Low: num(x.bands.Low, 0, 1e7) } : null, kev: num(x.kev, 0, 1e7), ransomware: num(x.ransomware, 0, 1e7), decisions: x.decisions && typeof x.decisions === "object" ? { act: num(x.decisions.act, 0, 1e7), attend: num(x.decisions.attend, 0, 1e7), "track*": num(x.decisions["track*"], 0, 1e7), track: num(x.decisions.track, 0, 1e7) } : null,
      audit: x.audit && typeof x.audit === "object" && x.audit.nvd ? { at: str(x.audit.at, 30), nvdTotal: num(x.audit.nvd.total, 0, 1e8), nvdRejected: num(x.audit.nvd.rejected, 0, 1e8), nvdCritical: num(x.audit.nvd.critical_v3, 0, 1e8), cisaKev: num(x.audit.cisa_kev, 0, 1e7) } : null, years: years, cvelist: str(s.cvelist, 30), epss: str(s.epss, 30) };
    return o.total === null && !years.length ? null : o;
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
      n3: SEV[o.n3] ? o.n3 : "", n3c: o.n3c === true
    };
    c.hay = (c.id + " " + c.vendor + " " + c.product + " " + c.title + " " + c.desc + " " + c.cwe).toLowerCase();
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
    if (f.minScore) { var sc = L.scored(r, f.rateOpts); if (!sc || sc.score < f.minScore) return false; }
    if (f.decision) { var d = L.rated(r, f.rateOpts); if (!d || (f.decision === "attend+" ? d.rank < 3 : d.decision !== f.decision)) return false; }
    return true;
  };
  function seqOf(id) { var p = L.parseId(id); return p ? p.year * 1e9 + p.seq : 0; }
  var SORTS = {
    pub: function (a, b) { return a.pub < b.pub ? 1 : a.pub > b.pub ? -1 : seqOf(b.id) - seqOf(a.id); },
    old: function (a, b) { return a.pub < b.pub ? -1 : a.pub > b.pub ? 1 : seqOf(a.id) - seqOf(b.id); },
    upd: function (a, b) { return a.upd < b.upd ? 1 : a.upd > b.upd ? -1 : seqOf(b.id) - seqOf(a.id); },
    cvss: function (a, b) { return (b.cvss === null ? -1 : b.cvss) - (a.cvss === null ? -1 : a.cvss) || seqOf(b.id) - seqOf(a.id); },
    epss: function (a, b) { return (b.epss === null ? -1 : b.epss) - (a.epss === null ? -1 : a.epss) || seqOf(b.id) - seqOf(a.id); },
    id: function (a, b) { return seqOf(a.id) - seqOf(b.id); },
    score: function (a, b) { var x = L.scored(a), y = L.scored(b); return ((y && y.score) || 0) - ((x && x.score) || 0) || seqOf(b.id) - seqOf(a.id); },
    priority: function (a, b) { var x = L.rated(a), y = L.rated(b); return ((y && y.rank) || 0) - ((x && x.rank) || 0) || (b.epss === null ? -1 : b.epss) - (a.epss === null ? -1 : a.epss) || seqOf(b.id) - seqOf(a.id); }
  };
  /* the rating of a row for the visitor's current settings, computed once per settings */
  L.rateOpts = {};
  L.scored = function (r, opts) { opts = opts || L.rateOpts; var k = (opts.mission || "") + "|" + opts.exposed + "|" + (opts.mineKey || ""); if (!r._sk || r._sk !== k) { r._score = L.score(r, opts.mineFn ? Object.assign({}, opts, { mine: opts.mineFn(r), onMap: opts.mapFn && opts.mapFn(r) }) : opts); r._sk = k; } return r._score; };
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
  /** One CVE -> { decision, label, does, inputs: [{name, value, basis, source}], signals: [...], deadline, overdue }.
   *  opts.mission: the visitor's mission and well-being impact for this kind of system (low, medium, high; default medium). */
  L.rate = function (r, opts) {
    opts = opts || {}; if (!r) return null;
    if (r.rejected) return { decision: null, label: "Rejected", does: "Not a vulnerability record: the CVE was withdrawn, merged into another or found not to be a flaw. Nothing to fix.", inputs: [], signals: [] };
    var today = opts.today || new Date().toISOString().slice(0, 10), inputs = [], signals = [];
    var ex = "none", exB = "No exploitation reported to CISA", exS = "unassessed";
    if (r.kev) { ex = "active"; exB = "On CISA's Known Exploited Vulnerabilities catalog" + (r.kev !== "yes" ? " since " + r.kev : ""); exS = "cisa-kev"; }
    else if (r.expl === "active") { ex = "active"; exB = "CISA reports active exploitation (SSVC)"; exS = "cisa"; }
    else if (r.expl === "poc") { ex = "poc"; exB = "CISA: public proof of concept or exploit code (SSVC)"; exS = "cisa"; }
    else if (r.expl === "none") { exB = "CISA has seen no exploitation (SSVC)"; exS = "cisa"; }
    /* the assigner's own record can say more than CISA's assessment: "exploitation evidence was observed", "the exploit has been
       published". Used, and labelled, only when it raises the answer */
    if (ex !== "active" && L.WILD.test(r.desc || "")) { ex = "active"; exB = "The CVE record's description reports exploitation in the wild (the assigner's statement; CISA has not confirmed it)"; exS = "description"; }
    else if (ex === "none" && L.POC.test(r.desc || "")) { ex = "poc"; exB = "The CVE record's description says exploit code is public (the assigner's statement)"; exS = "description"; }
    inputs.push({ name: "Exploitation", value: ex === "poc" ? "public PoC" : ex, basis: exB, source: exS });
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

  /* ---- the CyberView rating: 0 to 100, every point listed ----
     A finer-grained companion to CISA's SSVC decision, built from every signal CyberView holds. Seven factors, each with a
     ceiling, so no single signal can carry a flaw to the top on its own:
       Exploitation evidence      up to 35  CISA KEV 35 · CISA saw exploitation 32 · the record reports it in the wild 28 ·
                                            public exploit code (CISA or the record) 15 · none seen 0
       Likelihood (FIRST EPSS)    up to 15  by percentile: top 1% 15 · top 5% 12 · top 10% 9 · top 25% 6 · top 50% 3
       Impact                     up to 20  technical impact total 10, partial 4 · plus CVSS base score / 10 x 10
       Attack surface             up to 10  automatable 5 · network reachable 2 · no privileges 2 · no user action 1
       Threat context             up to 10  used by ransomware 7 · on CyberView's map or in its archive 3
       Time pressure              up to 10  CISA deadline passed 4 or within 7 days 3 · added to KEV in the last 30 days 3 ·
                                            published in the last 14 days 3
       Your organisation          -15 to +15  internet-facing +5, internal only -5 · mission high +5, low -5 ·
                                            on your software list +5
     Bands: 80 and over Critical · 60 High · 40 Elevated · 20 Moderate · below 20 Low. Confidence says how much of the
     evidence exists for this CVE (CISA's assessment, a CVSS vector, EPSS, NVD's score). */
  L.BANDS = [[80, "Critical", "bad"], [60, "High", "bad"], [40, "Elevated", "warn"], [20, "Moderate", "info"], [0, "Low", "info"]];
  L.score = function (r, opts) {
    opts = opts || {}; if (!r || r.rejected) return null;
    var today = opts.today || new Date().toISOString().slice(0, 10), parts = [];
    var add = function (factor, pts, why) { if (pts) parts.push({ factor: factor, points: pts, why: why }); return pts; };
    var rt = L.rate(r, opts) || { inputs: [] }, ex = rt.inputs[0] || {}, au = (rt.inputs[1] || {}).value, ti = (rt.inputs[2] || {}).value;
    // 1 exploitation evidence (the strongest single item)
    if (r.kev) add("Exploitation", 35, "In CISA's Known Exploited Vulnerabilities catalog");
    else if (r.expl === "active") add("Exploitation", 32, "CISA reports active exploitation");
    else if (ex.source === "description" && ex.value === "active") add("Exploitation", 28, "The CVE record reports exploitation in the wild");
    else if (ex.value === "public PoC") add("Exploitation", 15, ex.source === "description" ? "The CVE record says exploit code is public" : "CISA: public proof of concept");
    // 2 likelihood
    if (r.pct != null) { var lp = r.pct >= 0.99 ? 15 : r.pct >= 0.95 ? 12 : r.pct >= 0.9 ? 9 : r.pct >= 0.75 ? 6 : r.pct >= 0.5 ? 3 : 0;
      add("Likelihood", lp, "EPSS " + (r.epss * 100).toFixed(r.epss < 0.01 ? 2 : 1) + "%, more likely than " + Math.floor(r.pct * 100) + "% of CVEs to be exploited in the next 30 days"); }
    // 3 impact
    add("Impact", ti === "total" ? 10 : 4, "Technical impact " + ti + " (" + ((rt.inputs[2] || {}).source === "cisa" ? "CISA" : "estimated from the CVSS vector") + ")");
    var sc = r.cvss != null ? r.cvss : r.ncvss;
    if (sc != null) add("Impact", Math.round(sc), "CVSS " + sc.toFixed(1) + " from " + (r.cvss != null ? "the assigner or CISA" : "NVD"));
    // 4 attack surface
    var v = r.vec || r.nvec || "";
    if (au === "yes") add("Attack surface", 5, "An attacker can automate exploitation (" + ((rt.inputs[1] || {}).source === "cisa" ? "CISA" : "estimated") + ")");
    if (/AV:N/.test(v)) add("Attack surface", 2, "Reachable over the network");
    if (/PR:N|Au:N/.test(v)) add("Attack surface", 2, "No privileges needed");
    if (/UI:N/.test(v)) add("Attack surface", 1, "No user action needed");
    // 5 threat context
    if (r.ransom) add("Threat context", 7, "Used in ransomware campaigns (CISA)");
    if (opts.onMap) add("Threat context", 3, "Covered by a checked report on CyberView");
    // 6 time pressure
    if (r.due) { if (r.due < today) add("Time pressure", 4, "CISA's remediation date passed on " + r.due); else if (r.due <= addDays(today, 7)) add("Time pressure", 3, "CISA's remediation date is " + r.due); }
    if (/^\d{4}-\d{2}-\d{2}$/.test(r.kev || "") && r.kev >= addDays(today, -30)) add("Time pressure", 3, "Added to CISA's catalog on " + r.kev);
    if (r.pub && r.pub >= addDays(today, -14)) add("Time pressure", 3, "Published on " + r.pub);
    // 7 your organisation
    if (opts.exposed === true) add("Your organisation", 5, "Your systems are internet-facing");
    if (opts.exposed === false) add("Your organisation", -5, "Your systems are internal only");
    if (opts.mission === "high") add("Your organisation", 5, "High mission impact for your organisation");
    if (opts.mission === "low") add("Your organisation", -5, "Low mission impact for your organisation");
    if (opts.mine) add("Your organisation", 5, "On your software list");
    var CAP = { "Exploitation": [0, 35], "Likelihood": [0, 15], "Impact": [0, 20], "Attack surface": [0, 10], "Threat context": [0, 10], "Time pressure": [0, 10], "Your organisation": [-15, 15] };
    var by = {}; parts.forEach(function (p) { by[p.factor] = (by[p.factor] || 0) + p.points; });
    var factors = Object.keys(CAP).map(function (k) { var raw = by[k] || 0, c = Math.max(CAP[k][0], Math.min(CAP[k][1], raw)); return { factor: k, points: c, max: CAP[k][1], capped: c !== raw, items: parts.filter(function (p) { return p.factor === k; }) }; });
    var total = Math.max(0, Math.min(100, factors.reduce(function (n, f) { return n + f.points; }, 0)));
    var band = L.BANDS.filter(function (b) { return total >= b[0]; })[0];
    var have = [!!(r.auto || r.ti || r.expl), !!(r.vec || r.nvec), r.epss != null, r.cvss != null || r.ncvss != null].filter(Boolean).length;
    return { score: total, band: band[1], tone: band[2], factors: factors, confidence: have >= 4 ? "High" : have >= 2 ? "Medium" : "Low",
      confidenceWhy: (r.auto || r.ti || r.expl ? "CISA assessed it" : "no CISA assessment") + "; " + (r.vec || r.nvec ? "CVSS vector known" : "no CVSS vector") + "; " + (r.epss != null ? "EPSS known" : "no EPSS") + "; " + (r.cvss != null || r.ncvss != null ? "scored" : "no CVSS score") };
  };
  function addDays(d, n) { var t = Date.parse(d + "T00:00:00Z") + n * 864e5; return new Date(t).toISOString().slice(0, 10); }
  if (typeof module !== "undefined" && module.exports) module.exports = L; else root.CVDB = L;
})(typeof window !== "undefined" ? window : this);
