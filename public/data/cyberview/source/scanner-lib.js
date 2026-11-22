// CyberView Scanner page tools, kept apart from the page so unit tests can run them in Node (tests/unit/scanner-view.test.mjs).
// Everything here runs in the visitor's browser: a report.json the visitor opens is read here and never sent anywhere, and
// a scope file is built here and handed back as a download. No network, no storage.
//
//   Report viewer: parse() reads the text of a scanner report.json (untrusted: every field is type-checked and length-limited
//   by cleanReport), counts() uses the same definitions as the scanner's summarize() (scanner/lib/report.mjs), rows() and
//   filterRows() drive the findings table, and diffClean()/diffReports() mirror scanner/lib/diff.mjs exactly (that module
//   imports Node code, so it cannot load here; the unit tests compare the two on the same reports).
//   Scope builder: parseTarget(), classify() and buildScope() mirror scanner/lib/scope.mjs checkScope (it imports node:net);
//   the unit tests run the built file through the scanner's own checkScope and its `check` command.
(function (root) {
  "use strict";
  var V = {};

  /* ---- small cleaners ---- */
  function str(v, n) { return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n) : ""; }
  function int(v, lo, hi) { return typeof v === "number" && v % 1 === 0 && v >= lo && v <= hi ? v : null; }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function arr(a, n) { return Array.isArray(a) ? a.slice(0, n) : []; }
  function obj(o) { return o && typeof o === "object" && !Array.isArray(o) ? o : {}; }
  function strs(a, k, n) { return arr(a, k).map(function (x) { return str(x, n).trim(); }).filter(Boolean); }
  function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  var ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?Z$/;
  var DAY = /^\d{4}-\d{2}-\d{2}$/;
  var CVE = /^CVE-\d{4}-\d{4,}$/;
  var HEX = /^[0-9a-f]{64}$/i;
  function iso(v) { return typeof v === "string" && ISO.test(v) ? v : ""; }
  function day(v) { return typeof v === "string" && DAY.test(v) ? v : ""; }
  function pick(v, list) { return list.indexOf(v) >= 0 ? v : ""; }
  V.BANDS = ["Critical", "High", "Medium", "Low", "None", "Not scored"];
  V.CONF = ["high", "medium", "low"];
  var SEV = ["high", "medium", "low", "info"];

  /* ---- the report viewer ---- */
  V.LIMITS = Object.freeze({ maxBytes: 64 * 1024 * 1024, hosts: 100000, ports: 65535, perHost: 2000, findings: 20000, seenOn: 2000, files: 8 });

  /** The text of a report.json -> { report } or { error }. Refuses anything that is not a CyberView Scanner report. */
  V.parse = function (text) {
    if (typeof text !== "string" || !text) return { error: "the file is empty" };
    if (text.length > V.LIMITS.maxBytes) return { error: "the file is larger than " + (V.LIMITS.maxBytes / 1048576) + " MB" };
    var j;
    try { j = JSON.parse(text); } catch (e) { return { error: "the file is not valid JSON (open a report.json written by the scanner)" }; }
    if (!j || typeof j !== "object" || !j.tool || j.tool.name !== "CyberView Scanner" || !Array.isArray(j.hosts) || !Array.isArray(j.findings)) return { error: "the file is not a CyberView Scanner report.json" };
    return { report: V.cleanReport(j), raw: j };
  };

  function cleanCert(c) {
    if (!c || typeof c !== "object") return null;
    return { subject: str(c.subject, 200), issuer: str(c.issuer, 200), valid_from: day(c.valid_from), valid_to: day(c.valid_to), expired: c.expired === true, not_yet_valid: c.not_yet_valid === true,
      days_left: int(c.days_left, -100000, 100000), self_signed: c.self_signed === true, key_type: str(c.key_type, 20), key_bits: int(c.key_bits, 0, 65536), sig_alg: str(c.sig_alg, 60),
      fingerprint256: str(c.fingerprint256, 95), san_dns: strs(c.san_dns, 20, 253), san_ip: strs(c.san_ip, 20, 45) };
  }
  function cleanHost(h) {
    var ports = arr(h.ports, V.LIMITS.ports).filter(function (p) { return p && int(p.port, 1, 65535) != null; }).map(function (p) { return { port: p.port, state: str(p.state, 12), banner: str(p.banner, 160) }; });
    var udp = arr(h.udp, 10).filter(function (u) { return u && int(u.port, 1, 65535) != null && u.state === "open"; }).map(function (u) { return { port: u.port, proto: str(u.proto, 10) }; });
    return {
      address: str(h.address, 45), names: strs(h.names, 20, 253), kind: str(h.kind, 20), public: h.public === true, up: h.up === true, source: str(h.source, 40),
      ports: ports, udp: udp,
      services: arr(h.services, V.LIMITS.perHost).filter(function (s) { return s && typeof s === "object" && int(s.port, 0, 65535) != null; }).map(function (s) {
        return { port: s.port, proto: str(s.proto, 12), vendor: str(s.vendor, 80), product: str(s.product, 120), label: str(s.label, 160), version: str(s.version, 40), shown_version: str(s.shown_version, 40),
          distro: str(s.distro, 40), source: str(s.source, 80), evidence: str(s.evidence, 240), guessed: s.guessed === true };
      }).filter(function (s) { return s.product || s.label; }),
      tls: arr(h.tls, V.LIMITS.perHost).filter(function (t) { return t && int(t.port, 1, 65535) != null; }).map(function (t) {
        return { port: t.port, protocol: str(t.protocol, 20), cipher: str(t.cipher_std || t.cipher, 80), cert: cleanCert(t.cert) };
      }),
      observations: arr(h.observations, V.LIMITS.perHost).filter(function (x) { return x && int(x.port, 0, 65535) != null && str(x.kind, 60); }).map(function (x) {
        return { port: x.port, kind: str(x.kind, 60), severity: pick(x.severity, SEV) || "info", text: str(x.text, 300) };
      }),
      observations_dropped: int(h.observations_dropped, 0, 1e7) || 0,
    };
  }
  function cleanFinding(f) {
    var r = obj(f.rating), pr = f.priority && typeof f.priority === "object" ? f.priority : null, pts = obj(f.points), fix = obj(f.fix), adv = f.fix && f.fix.advisory && typeof f.fix.advisory === "object" ? f.fix.advisory : null;
    var score = num(r.score, 0, 10), base = obj(r.base);
    return {
      cve: f.cve, rank: int(f.rank, 1, 1e6), title: str(f.title, 200), vendor: str(f.vendor, 80), product: str(f.product, 120), state: pick(f.state, ["affected", "check"]) || "check",
      kev: f.kev === true, kev_added: day(f.kev_added), cisa_due: day(f.cisa_due), overdue: f.overdue === true, ransomware: f.ransomware === true, epss: num(f.epss, 0, 1),
      rating: { score: score, band: score == null ? "Not scored" : (pick(r.band, V.BANDS) || "Not scored"), text: str(r.text, 600), from: str(r.from, 160), vector: str(base.vector, 120), notes: strs(r.notes, 6, 240) },
      priority: pr ? { decision: pick(pr.decision, ["act", "attend", "track*", "track"]), label: str(pr.label, 30), fix_by: str(pr.fix_by && pr.fix_by.text, 80), deadline: day(pr.deadline), does: str(pr.does, 200) } : null,
      points: { total: int(pts.total, -1000, 1000), list: arr(pts.list, 20).filter(function (p) { return p && int(p.points, -1000, 1000) != null && str(p.why, 200); }).map(function (p) { return { points: p.points, why: str(p.why, 200) }; }) },
      confidence: pick(f.confidence, V.CONF) || "low", confidence_why: str(f.confidence_why, 300),
      seen_on: arr(f.seen_on, V.LIMITS.seenOn).filter(function (s) { return s && str(s.host, 45) && int(s.port, 0, 65535) != null; }).map(function (s) {
        return { host: str(s.host, 45), names: strs(s.names, 10, 253), port: s.port, product: str(s.product, 160), version: str(s.version, 40), shown_version: str(s.shown_version, 40), state: pick(s.state, ["affected", "check"]) || "check",
          confidence: pick(s.confidence, V.CONF) || "low", confidence_why: str(s.confidence_why, 300), evidence: str(s.evidence, 240) };
      }),
      fix: { fixed_in: strs(fix.fixed_in, 8, 60), vendor_fixed: strs(fix.vendor_fixed, 8, 160), workaround: strs(fix.workaround, 5, 320), required: str(fix.cisa_required_action, 700),
        advisory: adv ? { name: str(adv.name, 100), url: str(adv.url, 600) } : null, references: strs(fix.references, 6, 600), analysis: !!(fix.analysis && typeof fix.analysis === "object") },
      hunt: arr(f.hunt, 12).filter(function (h) { return h && str(h.url, 600); }).map(function (h) { return { name: str(h.name, 100), format: str(h.format, 20), publisher: str(h.publisher, 80), url: str(h.url, 600) }; }),
      incidents: f.incidents && Array.isArray(f.incidents.cited) ? arr(f.incidents.cited, 10).filter(function (c) { return c && str(c.title, 160); }).map(function (c) { return { title: str(c.title, 160), date: day(c.date), link: str(c.link, 600) }; }) : [],
    };
  }

  /** A raw report object -> the fields the viewer shows, each type-checked and length-limited. */
  V.cleanReport = function (j) {
    var o = obj(j), tool = obj(o.tool), run = obj(o.run), sc = obj(o.scope), att = obj(sc.attestation), cov = obj(o.coverage), net = obj(run.network), data = obj(run.data);
    var sends = [], s = obj(net.sends);
    Object.keys(s).slice(0, 16).forEach(function (k) { if (/^[a-z0-9-]{1,24}$/.test(k) && str(s[k], 500)) sends.push({ what: k, text: str(s[k], 500) }); });
    var ports = arr(run.ports, 65535).filter(function (p) { return int(p, 1, 65535) != null; });
    var findings = arr(o.findings, V.LIMITS.findings).filter(function (f) { return f && CVE.test(f.cve || ""); }).map(cleanFinding);
    return {
      tool: { version: str(tool.version, 20) },
      run: { started_at: iso(run.started_at), finished_at: iso(run.finished_at), interrupted: run.interrupted === true, stop_reason: str(run.stop_reason, 200), ports: ports,
        udp: strs(run.udp, 3, 10).filter(function (k) { return own(UDP_PORT, k); }), paths: !!(run.paths && run.paths.enabled === true),
        connections: int(net.connections, 0, 1e8), sends: sends, data_mode: str(data.mode, 20), data_source: str(data.source, 200), workbench_built_at: iso(data.workbench_built_at) },
      scope: { owner: str(sc.owner, 160), contact: str(sc.contact, 160), sha256: HEX.test(sc.sha256 || "") ? sc.sha256 : "",
        attestation: { statement: str(att.statement, 400), agreed: att.agreed === true, name: str(att.name, 120), date: day(att.date), expires: day(att.expires), ref: str(att.authorization_ref, 200) },
        targets: strs(sc.targets, 1024, 260), exclude: strs(sc.exclude, 1024, 260), public_addresses: int(sc.public_addresses, 0, 1e6) || 0, public_confirmed: sc.public_confirmed === true,
        refused: arr(sc.refused, 200).filter(function (r) { return r && str(r.target, 300); }).map(function (r) { return { target: str(r.target, 300), why: str(r.why, 300) }; }) },
      coverage: { complete: cov.complete === true, interrupted: cov.interrupted === true, stop_reason: str(cov.stop_reason, 200),
        unreachable: strs(cov.hosts_unreachable, 5000, 45), filtered: int(cov.ports_filtered, 0, 1e9) || 0,
        not_checked: arr(cov.ports_not_checked, 5000).filter(function (x) { return x && str(x.address, 45); }).map(function (x) { return { address: str(x.address, 45), count: int(x.not_checked, 0, 65535) || 0 }; }),
        truncated: arr(cov.truncated_banners, 5000).filter(function (x) { return x && str(x.address, 45); }).map(function (x) { return { address: str(x.address, 45), count: int(x.count, 0, 65535) || 0 }; }),
        throttled: arr(cov.throttled, 5000).filter(function (x) { return x && str(x.address, 45); }).map(function (x) { return { address: str(x.address, 45), resets: int(x.resets, 0, 65535) || 0, recovered: int(x.recovered, 0, 65535) || 0 }; }) },
      hosts: arr(o.hosts, V.LIMITS.hosts).filter(function (h) { return h && typeof h === "object" && str(h.address, 45); }).map(cleanHost),
      findings: findings,
      named: arr(o.named, 50).filter(function (n) { return n && str(n.product, 160); }).map(function (n) { return { product: str(n.product, 160), version: str(n.version_seen, 40), count: int(n.cves_naming_it, 0, 1e6) || 0, exploited: int(n.exploited, 0, 1e6) || 0 }; }),
      notes: strs(o.notes, 12, 500),
    };
  };

  /** Headline counts with the scanner's own definitions (summarize() in scanner/lib/report.mjs): confident findings only. */
  V.counts = function (r) {
    var up = r.hosts.filter(function (h) { return h.up; }), strong = r.findings.filter(function (f) { return f.confidence !== "low"; });
    return {
      hosts_in_scope: r.hosts.length, hosts_up: up.length,
      open_ports: up.reduce(function (n, h) { return n + h.ports.filter(function (p) { return p.state === "open"; }).length; }, 0),
      services: up.reduce(function (n, h) { return n + h.services.length; }, 0),
      findings: r.findings.length, low_confidence: r.findings.length - strong.length,
      known_exploited: strong.filter(function (f) { return f.kev; }).length,
      critical: strong.filter(function (f) { return f.rating.band === "Critical"; }).length,
      act: strong.filter(function (f) { return f.priority && f.priority.decision === "act"; }).length,
      overdue: strong.filter(function (f) { return f.overdue; }).length,
      observations: up.reduce(function (n, h) { return n + h.observations.length; }, 0),
    };
  };

  /** One table row per finding and place it was seen. */
  V.rows = function (r) {
    var out = [];
    r.findings.forEach(function (f, i) {
      f.seen_on.forEach(function (s) { out.push({ f: f, s: s, rank: f.rank || i + 1 }); });
    });
    return out;
  };
  var BAND_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, None: 0, "Not scored": -1 };
  var CONF_RANK = { high: 3, medium: 2, low: 1 };
  /** Filters: host ("" any), band (minimum: "Critical" | "High" | "Medium" | ""), kev (true: known exploited only), confidence (minimum: "high" | "medium" | ""). */
  V.filterRows = function (rows, q) {
    q = q || {};
    return rows.filter(function (x) {
      if (q.host && x.s.host !== q.host) return false;
      if (q.band && own(BAND_RANK, q.band) && BAND_RANK[x.f.rating.band] < BAND_RANK[q.band]) return false;
      if (q.kev && !x.f.kev) return false;
      if (q.confidence && own(CONF_RANK, q.confidence) && CONF_RANK[x.s.confidence] < CONF_RANK[q.confidence]) return false;
      return true;
    });
  };

  /* ---- links: https only, to hosts the scanner itself emits ---- */
  // The scanner's links come from CyberView's own site (DEFAULT_SOURCE in scanner/lib/data.mjs) and from workbench.json
  // (vendor advisories, CISA's references, hunt files). The page adds the hosts found in the site's own data/workbench.json.
  V.BASE_HOSTS = ["xanderhutch.github.io", "www.cisa.gov", "nvd.nist.gov", "www.cve.org", "github.com"];
  /** Every https host named in a JSON value (the site's own workbench.json), capped. */
  V.hostsIn = function (value) {
    var out = {}, n = 0, stack = [value], seen = 0;
    while (stack.length && seen < 200000 && n < 2000) {
      var v = stack.pop(); seen++;
      if (typeof v === "string") { var m = /^https:\/\/([a-z0-9.-]{1,253})(?::443)?(?:[/?#]|$)/i.exec(v); if (m && !own(out, m[1].toLowerCase())) { out[m[1].toLowerCase()] = true; n++; } }
      else if (Array.isArray(v)) { for (var i = 0; i < v.length && i < 5000; i++) stack.push(v[i]); }
      else if (v && typeof v === "object") { var ks = Object.keys(v); for (var k = 0; k < ks.length && k < 5000; k++) stack.push(v[ks[k]]); }
    }
    return Object.keys(out);
  };
  /** An https URL on an allowed host, without credentials, or "". */
  V.safeUrl = function (u, allow) {
    var s = typeof u === "string" ? u : "";
    if (!s || s.length > 1000 || !/^https:\/\/[^\s"'<>`\\]+$/i.test(s)) return "";
    var x;
    try { x = new URL(s); } catch (e) { return ""; }
    if (x.protocol !== "https:" || x.username || x.password || (x.port && x.port !== "443")) return "";
    var host = x.hostname.toLowerCase();
    if (!allow || !own(allow, host)) return "";
    return x.href;
  };
  V.allowSet = function (hosts) { var o = Object.create(null); V.BASE_HOSTS.concat(hosts || []).forEach(function (h) { o[String(h).toLowerCase()] = true; }); return o; };

  /* ---- the diff: a mirror of scanner/lib/diff.mjs (same rules, same output) ---- */
  var UDP_PORT = { dns: 53, ntp: 123, snmp: 161 };
  function clipD(s, n) { return typeof s === "string" ? s.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n) : ""; }
  function intD(v, lo, hi) { return Number.isInteger(v) && v >= lo && v <= hi ? v : null; }
  var DL = { hosts: 100000, portsPerHost: 65535, perHost: 2000, findings: 20000, seenOn: 2000 };
  /** report.json -> the compared fields only (diff.mjs cleanReport). */
  V.diffClean = function (r) {
    var o = r && typeof r === "object" ? r : {};
    var run = o.run && typeof o.run === "object" ? o.run : {}, cov = o.coverage && typeof o.coverage === "object" ? o.coverage : {};
    var hosts = arr(o.hosts, DL.hosts).filter(function (h) { return h && typeof h === "object" && clipD(h.address, 45); }).map(function (h) {
      return {
        address: clipD(h.address, 45), names: arr(h.names, 20).map(function (n) { return clipD(n, 253).toLowerCase(); }).filter(Boolean), up: h.up === true,
        ports: arr(h.ports, DL.portsPerHost).concat(arr(h.udp, 10).filter(function (u) { return u && u.state === "open"; })).map(function (p) { return intD(p && p.port, 1, 65535); }).filter(function (p) { return p != null; }),
        services: arr(h.services, DL.perHost).filter(function (s) { return s && typeof s === "object" && intD(s.port, 0, 65535) != null; }).map(function (s) {
          return { port: s.port, product: clipD(s.label || [s.vendor, s.product].filter(function (x) { return typeof x === "string" && x; }).join(" ") || s.product, 120), version: clipD(s.shown_version, 40) };
        }).filter(function (s) { return s.product; }),
        tls: arr(h.tls, DL.perHost).filter(function (t) { return t && intD(t.port, 1, 65535) != null && t.cert && typeof t.cert === "object"; }).map(function (t) {
          return { port: t.port, fingerprint256: clipD(t.cert.fingerprint256, 95), issuer: clipD(t.cert.issuer, 200), subject: clipD(t.cert.subject, 200), valid_to: clipD(t.cert.valid_to, 10), spki_sha256: clipD(t.cert.spki_sha256, 95) };
        }),
        observations: arr(h.observations, DL.perHost).filter(function (x) { return x && intD(x.port, 0, 65535) != null && clipD(x.kind, 60); }).map(function (x) {
          return { port: x.port, kind: clipD(x.kind, 60), severity: clipD(x.severity, 10), text: clipD(x.text, 300) };
        }),
      };
    });
    var findings = arr(o.findings, DL.findings).filter(function (f) { return f && CVE.test(f.cve || ""); }).map(function (f) {
      return { cve: f.cve, title: clipD(f.title, 160), kev: f.kev === true,
        seen_on: arr(f.seen_on, DL.seenOn).filter(function (s) { return s && clipD(s.host, 45) && intD(s.port, 0, 65535) != null; }).map(function (s) {
          return { host: clipD(s.host, 45), port: s.port, product: clipD(s.product, 120), version: clipD(s.shown_version, 40), confidence: clipD(s.confidence, 10) };
        }) };
    });
    var udpPorts = arr(run.udp, 10).map(function (k) { return typeof k === "string" && own(UDP_PORT, k) ? UDP_PORT[k] : 0; }).filter(Boolean);
    var nc = {};
    arr(cov.ports_not_checked, DL.hosts).map(function (x) { return clipD(x && x.address, 45); }).filter(Boolean).forEach(function (a) { nc[a] = true; });
    return { started_at: clipD(run.started_at, 30), ports: arr(run.ports, 65535).filter(function (p) { return intD(p, 1, 65535) != null; }).concat(udpPorts), interrupted: run.interrupted === true,
      scope_sha256: clipD(o.scope && o.scope.sha256, 64), not_checked: nc, hosts: hosts, findings: findings, _clean: true };
  };
  function stateIn(rep, host, port) {
    var h = null; for (var i = 0; i < rep.hosts.length; i++) if (rep.hosts[i].address === host) { h = rep.hosts[i]; break; }
    if (!h) return "host-absent";
    if (h.ports.indexOf(port) >= 0) return "open";
    if (!h.up) return "host-down";
    if (port && rep.ports.length && rep.ports.indexOf(port) < 0) return "port-not-scanned";
    if (rep.interrupted || own(rep.not_checked, host)) return "not-checked";
    return "not-open";
  }
  var WHY = { "host-absent": "the host was not in this scan", "host-down": "the host did not answer in this scan", "port-not-scanned": "the port was not in this scan's port list",
    "not-checked": "a limit or an interruption left this host's ports partly unchecked", "not-open": "the port no longer answers (closed or filtered): not proof of a fix" };
  function assign(a, b) { var o = {}; Object.keys(a).forEach(function (k) { o[k] = a[k]; }); Object.keys(b || {}).forEach(function (k) { o[k] = b[k]; }); return o; }
  function mapOf() { return { keys: [], m: Object.create(null), set: function (k, v) { if (!(k in this.m)) this.keys.push(k); this.m[k] = v; }, get: function (k) { return this.m[k]; }, has: function (k) { return k in this.m; },
    each: function (fn) { var self = this; this.keys.forEach(function (k) { fn(self.m[k], k); }); }, values: function () { var self = this; return this.keys.map(function (k) { return self.m[k]; }); } }; }

  /** previous, current: report.json objects (raw or diffClean'd) -> the differences, each list capped at 500, with counts. */
  V.diffReports = function (previous, current) {
    var P = previous && previous._clean ? previous : V.diffClean(previous), C = current && current._clean ? current : V.diffClean(current);
    var hostsP = mapOf(), hostsC = mapOf();
    P.hosts.forEach(function (h) { hostsP.set(h.address, h); }); C.hosts.forEach(function (h) { hostsC.set(h.address, h); });
    var d = { previous: { started_at: P.started_at, scope_sha256: P.scope_sha256 }, current: { started_at: C.started_at, scope_sha256: C.scope_sha256 }, same_scope: !!P.scope_sha256 && P.scope_sha256 === C.scope_sha256,
      hosts: { new_up: [], no_longer_up: [] }, ports: { opened: [], no_longer_open: [], not_rechecked: [] },
      services: { new: [], gone: [], changed: [], not_rechecked: [] },
      findings: { new: [], fixed: [], gone: [], still_open: [], not_rechecked: [] },
      certificates: { changed: [], issuer_changed: [], key_changed: [] }, observations: { new: [], resolved: [], not_rechecked: [] } };
    C.hosts.forEach(function (h) { if (h.up && !(hostsP.get(h.address) || {}).up) d.hosts.new_up.push(h.address); });
    P.hosts.forEach(function (h) { if (h.up && !(hostsC.get(h.address) || {}).up) d.hosts.no_longer_up.push({ host: h.address, why: hostsC.has(h.address) ? WHY["host-down"] : WHY["host-absent"] }); });
    C.hosts.forEach(function (h) { var p = hostsP.get(h.address); h.ports.forEach(function (port) { if (!p || p.ports.indexOf(port) < 0) d.ports.opened.push({ host: h.address, port: port }); }); });
    P.hosts.forEach(function (h) { h.ports.forEach(function (port) { var st = stateIn(C, h.address, port); if (st === "open") return; (st === "not-open" ? d.ports.no_longer_open : d.ports.not_rechecked).push({ host: h.address, port: port, why: WHY[st] }); }); });
    // services: host|port|product, version compared
    function svcKey(host, s) { return host + "|" + s.port + "|" + s.product; }
    var svcP = mapOf(), svcC = mapOf();
    P.hosts.forEach(function (h) { h.services.forEach(function (s) { svcP.set(svcKey(h.address, s), assign({ host: h.address }, s)); }); });
    C.hosts.forEach(function (h) { h.services.forEach(function (s) { svcC.set(svcKey(h.address, s), assign({ host: h.address }, s)); }); });
    svcC.each(function (s, k) { var p = svcP.get(k); if (!p) d.services.new.push(s); else if (p.version !== s.version) d.services.changed.push({ host: s.host, port: s.port, product: s.product, before: p.version, after: s.version }); });
    svcP.each(function (s, k) { if (svcC.has(k)) return; var st = stateIn(C, s.host, s.port);
      (st === "open" || st === "not-open" ? d.services.gone : d.services.not_rechecked).push(assign(s, { why: st === "open" ? "the port answers, but this product was not identified on it" : WHY[st] })); });
    // findings, per place seen (cve|host|port)
    var fP = mapOf(), fC = mapOf();
    P.findings.forEach(function (f) { f.seen_on.forEach(function (s) { fP.set(f.cve + "|" + s.host + "|" + s.port, assign({ cve: f.cve, title: f.title, kev: f.kev }, s)); }); });
    C.findings.forEach(function (f) { f.seen_on.forEach(function (s) { fC.set(f.cve + "|" + s.host + "|" + s.port, assign({ cve: f.cve, title: f.title, kev: f.kev }, s)); }); });
    fC.each(function (x, k) { (fP.has(k) ? d.findings.still_open : d.findings.new).push(x); });
    fP.each(function (x, k) {
      if (fC.has(k)) return;
      var st = stateIn(C, x.host, x.port);
      if (st === "open") {
        var now = svcC.values().filter(function (s) { return s.host === x.host && s.port === x.port; }).map(function (s) { return s.product + " " + (s.version || "(no version)"); }).slice(0, 3);
        d.findings.fixed.push(assign(x, { why: "the service answered again and this CVE no longer matches" + (now.length ? "; now seen: " + now.join("; ") : "; no product identified on the port now") }));
      } else (st === "not-open" ? d.findings.gone : d.findings.not_rechecked).push(assign(x, { why: WHY[st] }));
    });
    // certificates, per host:port present in both
    C.hosts.forEach(function (h) {
      var p = hostsP.get(h.address); if (!p) return;
      h.tls.forEach(function (t) {
        var o = null; for (var i = 0; i < p.tls.length; i++) if (p.tls[i].port === t.port) { o = p.tls[i]; break; }
        if (!o || !o.fingerprint256 || !t.fingerprint256 || o.fingerprint256 === t.fingerprint256) return;
        var row = { host: h.address, port: t.port, before: { fingerprint256: o.fingerprint256, issuer: o.issuer, subject: o.subject, valid_to: o.valid_to }, after: { fingerprint256: t.fingerprint256, issuer: t.issuer, subject: t.subject, valid_to: t.valid_to },
          issuer_changed: !!o.issuer && !!t.issuer && o.issuer !== t.issuer, key_changed: o.spki_sha256 && t.spki_sha256 ? o.spki_sha256 !== t.spki_sha256 : null };
        d.certificates.changed.push(row);
        if (row.issuer_changed) d.certificates.issuer_changed.push({ host: row.host, port: row.port, before: o.issuer, after: t.issuer, note: "issuer changed: review it (a CA switch or renewal through another CA is common); not evidence of compromise" });
        if (row.key_changed) d.certificates.key_changed.push({ host: row.host, port: row.port });
      });
    });
    // observations: host|port|kind
    function oKey(host, x) { return host + "|" + x.port + "|" + x.kind; }
    var oP = mapOf(), oC = mapOf();
    P.hosts.forEach(function (h) { h.observations.forEach(function (x) { oP.set(oKey(h.address, x), assign({ host: h.address }, x)); }); });
    C.hosts.forEach(function (h) { h.observations.forEach(function (x) { oC.set(oKey(h.address, x), assign({ host: h.address }, x)); }); });
    oC.each(function (x, k) { if (!oP.has(k)) d.observations.new.push(x); });
    oP.each(function (x, k) { if (oC.has(k)) return; var st = stateIn(C, x.host, x.port); (st === "open" ? d.observations.resolved : d.observations.not_rechecked).push(st === "open" ? x : assign(x, { why: WHY[st] })); });
    // counts first, then cap every list
    var counts = {};
    Object.keys(d).forEach(function (sec) {
      var v = d[sec];
      if (!v || typeof v !== "object" || Array.isArray(v) || sec === "previous" || sec === "current") return;
      Object.keys(v).forEach(function (k) { if (Array.isArray(v[k])) { counts[sec + "." + k] = v[k].length; v[k] = v[k].slice(0, 500); } });
    });
    d.counts = counts;
    d.notes = ["Fixed means the same host and port answered again and the CVE no longer matched; gone means the port no longer answers; not rechecked means this scan did not reach it."]
      .concat(d.same_scope ? [] : ["The two reports come from different scope files (or the previous one has none): hosts outside either scope show as new or not rechecked."])
      .concat(["Compared with a previous report.json read from this machine; nothing was sent for the comparison."]);
    return d;
  };

  /* ---- the scope file: a mirror of scanner/lib/scope.mjs ---- */
  V.SCOPE_VERSION = 1;
  V.STATEMENT = "I own the systems listed in targets, or I hold written permission from their owner to scan them for known vulnerabilities, and this scan stays within that permission.";
  V.PUBLIC_FLAG = "--i-am-authorized-for-public-ranges";
  V.SCOPE_LIMITS = Object.freeze({ maxEntries: 1024, maxAddresses: 65536, minPrefix4: 16, minPrefix6: 120, minPublicPrefix4: 24, maxPublicAddresses: 1024, attestationDays: 365 });
  V.DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8000, 8008, 8080, 8443, 8888, 9443];
  V.PORT_PRESETS = { "default": null, web: [80, 443, 8000, 8008, 8080, 8443, 8888, 9443], remote: [22, 23, 3389, 5900] };
  var B = function (x) { return BigInt(x); };
  var V4 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
  /** 4, 6 or 0, like node:net isIP (zone ids such as %eth0 are not accepted here). */
  V.isIP = function (s) {
    s = String(s == null ? "" : s);
    if (V4.test(s)) return 4;
    if (s.indexOf(":") < 0 || !/^[0-9a-f:.]{2,45}$/i.test(s)) return 0;
    var m4 = /(?:^|:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (m4 && !V4.test(m4[1])) return 0;
    if (/:::/.test(s) || (s.match(/::/g) || []).length > 1) return 0;
    if (/^:[^:]/.test(s) || /[^:]:$/.test(s)) return 0;
    var groups = (m4 ? s.slice(0, s.length - m4[1].length) + "0:0" : s).split(":");
    var dbl = s.indexOf("::") >= 0, filled = groups.filter(function (g) { return g !== ""; });
    if (filled.some(function (g) { return !/^[0-9a-f]{1,4}$/i.test(g); })) return 0;
    if (dbl ? filled.length > 7 : groups.length !== 8) return 0;
    return 6;
  };
  function v4ToBig(s) { return s.split(".").reduce(function (a, p) { return (a << B(8)) + B(Number(p)); }, B(0)); }
  function bigToV4(n) { return [24, 16, 8, 0].map(function (k) { return String((n >> B(k)) & B(255)); }).join("."); }
  function v6ToBig(s) {
    var t = s.toLowerCase(), m4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(t);
    if (m4) { var n = v4ToBig(m4[1]); t = t.slice(0, -m4[1].length) + ((n >> B(16)) & B(0xffff)).toString(16) + ":" + (n & B(0xffff)).toString(16); }
    var sp = t.split("::"), head = sp[0], tail = sp[1], h = head ? head.split(":") : [], tl = tail !== undefined && tail ? tail.split(":") : [];
    var fill = []; if (tail !== undefined) for (var i = 0; i < 8 - h.length - tl.length; i++) fill.push("0");
    var parts = tail !== undefined ? h.concat(fill, tl) : h;
    return parts.reduce(function (a, p) { return (a << B(16)) + B(parseInt(p || "0", 16)); }, B(0));
  }
  function bigToV6(n) { var p = []; for (var i = 7; i >= 0; i--) p.push(((n >> B(i * 16)) & B(0xffff)).toString(16)); return new URL("http://[" + p.join(":") + "]/").hostname.slice(1, -1); }
  function toBig(ip) { var v = V.isIP(ip); return v === 4 ? { v: 4, n: v4ToBig(ip) } : v === 6 ? { v: 6, n: v6ToBig(ip) } : null; }
  function fromBig(v, n) { return v === 4 ? bigToV4(n) : bigToV6(n); }
  function inNet(n, base, bits, width) { return (n >> B(width - bits)) === (base >> B(width - bits)); }
  /** loopback, private, link-local, public; or a refused kind (unspecified, multicast, reserved, invalid). */
  V.classify = function (ip) {
    var b = toBig(ip); if (!b) return "invalid";
    var n = b.n;
    if (b.v === 4) {
      var at = function (s, bits) { return inNet(n, v4ToBig(s), bits, 32); };
      if (at("0.0.0.0", 8)) return "unspecified";
      if (at("127.0.0.0", 8)) return "loopback";
      if (at("10.0.0.0", 8) || at("172.16.0.0", 12) || at("192.168.0.0", 16)) return "private";
      if (at("169.254.0.0", 16)) return "link-local";
      if (at("224.0.0.0", 4)) return "multicast";
      if (at("240.0.0.0", 4)) return "reserved";
      return "public";
    }
    var at6 = function (s, bits) { return inNet(n, v6ToBig(s), bits, 128); };
    if (n === B(0)) return "unspecified";
    if (n === B(1)) return "loopback";
    if (at6("::ffff:0:0", 96)) return V.classify(bigToV4(n & B(0xffffffff)));
    if (at6("fc00::", 7)) return "private";
    if (at6("fe80::", 10)) return "link-local";
    if (at6("ff00::", 8)) return "multicast";
    return "public";
  };
  function isPrivateKind(k) { return k === "loopback" || k === "private" || k === "link-local"; }
  V.isPrivateKind = isPrivateKind;
  var REFUSED = { unspecified: "an unspecified address", multicast: "a multicast address", reserved: "a reserved or broadcast address", invalid: "not an address" };
  var LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
  var HOST_RE = new RegExp("^(?=.{1,253}$)" + LABEL + "(\\." + LABEL + ")*\\.?$", "i");
  /** One targets/exclude line -> { kind: ip | cidr | host, text, ... } or { error } (scope.mjs parseTarget). */
  V.parseTarget = function (raw) {
    var s = String(raw == null ? "" : raw).trim();
    if (!s) return { error: "empty entry" };
    if (s.length > 260) return { error: "entry too long" };
    var slash = s.indexOf("/");
    if (slash > 0) {
      var ip = s.slice(0, slash), bits = Number(s.slice(slash + 1)), b = toBig(ip);
      if (!b || !/^\d{1,3}$/.test(s.slice(slash + 1))) return { error: "\"" + s + "\" is not a CIDR range" };
      var width = b.v === 4 ? 32 : 128;
      if (bits > width) return { error: "\"" + s + "\": prefix longer than the address" };
      var base = (b.n >> B(width - bits)) << B(width - bits);
      return { kind: "cidr", v: b.v, base: base, bits: bits, size: B(1) << B(width - bits), text: fromBig(b.v, base) + "/" + bits };
    }
    var b2 = toBig(s);
    if (b2) return { kind: "ip", v: b2.v, n: b2.n, text: fromBig(b2.v, b2.n) };
    if (HOST_RE.test(s) && /[a-z]/i.test(s)) return { kind: "host", text: s.toLowerCase().replace(/\.$/, "") };
    return { error: "\"" + s + "\" is not an address, a CIDR range or a host name" };
  };
  /** "22,80,8000-8010" -> { ports } or { error } (scan.mjs parsePorts). */
  V.parsePorts = function (s) {
    var out = {}, n = 0, parts = String(s || "").split(",").map(function (x) { return x.trim(); }).filter(Boolean);
    for (var i = 0; i < parts.length; i++) {
      var m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(parts[i]);
      if (!m) return { error: "\"" + parts[i] + "\" is not a port or a port range" };
      var a = +m[1], b = m[2] ? +m[2] : a;
      if (a < 1 || b > 65535 || b < a) return { error: "\"" + parts[i] + "\" is outside 1-65535" };
      for (var p = a; p <= b; p++) { if (!out[p]) { out[p] = true; n++; } if (n > 1024) return { error: "at most 1024 ports in one scan" }; }
    }
    var list = Object.keys(out).map(Number).sort(function (x, y) { return x - y; });
    return list.length ? { ports: list } : { error: "no ports given" };
  };
  function lines(text) { return String(text || "").split(/[\r\n,]+/).map(function (x) { return x.trim(); }).filter(function (x) { return x && x.charAt(0) !== "#"; }); }
  V.lines = lines;

  /**
   * The form -> { ok, problems[], scope, text, needsPublic, publicCount, addressCount, hosts }.
   * form: { owner, contact, name, expires, ref, targets (text, one per line), exclude (text), ports ("default" | "web" | "remote" | "custom"), customPorts, agreed }
   * today: YYYY-MM-DD (UTC, as the scanner checks it). The same checks as scope.mjs checkScope; no file text without the attestation.
   */
  V.buildScope = function (form, today) {
    form = form || {};
    var problems = [], L = V.SCOPE_LIMITS;
    function s(v, n) { return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n) : ""; }
    var owner = s(form.owner, 160), contact = s(form.contact, 160), name = s(form.name, 120), expires = s(form.expires, 10), ref = s(form.ref, 200);
    if (owner.length < 2) problems.push("Owner: name the organisation or person that owns the targets.");
    if (name.length < 2) problems.push("Your name: the person who attests must be named.");
    if (!DAY.test(today || "")) problems.push("Today's date could not be read.");
    if (expires) { if (!DAY.test(expires)) problems.push("Valid until: use the date picker (YYYY-MM-DD)."); else if (expires < today) problems.push("Valid until: the date has passed; renew the authorization first."); }
    var list = lines(form.targets), exList = lines(form.exclude), seen = {};
    list = list.filter(function (x) { var k = x.toLowerCase(); if (seen[k]) return false; seen[k] = true; return true; });
    if (!list.length) problems.push("Targets: list at least one host, address or CIDR range; there is no default and nothing is scanned without it.");
    if (list.length > L.maxEntries) problems.push("Targets: " + list.length + " entries; at most " + L.maxEntries + ".");
    var targets = [], exclude = [], addressCount = B(0), publicCount = B(0), publicTargets = [];
    list.slice(0, L.maxEntries).forEach(function (raw) {
      var t = V.parseTarget(raw);
      if (t.error) { problems.push("Targets: " + t.error + "."); return; }
      if (t.kind !== "host") {
        var first = t.kind === "ip" ? fromBig(t.v, t.n) : fromBig(t.v, t.base), last = t.kind === "ip" ? first : fromBig(t.v, t.base + t.size - B(1));
        var k1 = V.classify(first), k2 = V.classify(last);
        if (REFUSED[k1] || REFUSED[k2]) { problems.push("Targets: \"" + t.text + "\" is or contains " + (REFUSED[k1] || REFUSED[k2]) + "; it cannot be scanned."); return; }
        if (t.kind === "cidr" && t.v === 4 && t.bits < L.minPrefix4) { problems.push("Targets: \"" + t.text + "\" is wider than a /" + L.minPrefix4 + "; split it into the ranges you actually own."); return; }
        if (t.kind === "cidr" && t.v === 6 && t.bits < L.minPrefix6) { problems.push("Targets: \"" + t.text + "\" is wider than a /" + L.minPrefix6 + "; list the IPv6 addresses you want checked."); return; }
        t.public = !isPrivateKind(k1) || !isPrivateKind(k2);
        if (t.public && t.kind === "cidr" && t.v === 4 && t.bits < L.minPublicPrefix4) { problems.push("Targets: \"" + t.text + "\" is a public range wider than a /" + L.minPublicPrefix4 + "; the scanner does not sweep public space that wide."); return; }
        var n = t.kind === "ip" ? B(1) : t.size;
        addressCount += n; if (t.public) { publicCount += n; publicTargets.push(t.text); }
      }
      targets.push(t);
    });
    exList.slice(0, L.maxEntries).forEach(function (raw) { var t = V.parseTarget(raw); if (t.error) problems.push("Exclude: " + t.error + "."); else exclude.push(t); });
    if (addressCount > B(L.maxAddresses)) problems.push("Targets: they expand to " + addressCount + " addresses; at most " + L.maxAddresses + " in one scan.");
    if (publicCount > B(L.maxPublicAddresses)) problems.push("Targets: they include " + publicCount + " public addresses; at most " + L.maxPublicAddresses + " in one scan.");
    var ports = null, preset = form.ports || "default";
    if (preset === "custom") { var pp = V.parsePorts(form.customPorts); if (pp.error) problems.push("Ports: " + pp.error + "."); else ports = pp.ports; }
    else if (own(V.PORT_PRESETS, preset)) ports = V.PORT_PRESETS[preset] ? V.PORT_PRESETS[preset].slice() : null;
    else problems.push("Ports: choose a preset.");
    if (form.agreed !== true) problems.push("Attestation: tick the box to attest that you own the targets or hold written permission to scan them. No scope file is made without it.");
    var out = { ok: problems.length === 0, problems: problems, needsPublic: publicCount > B(0), publicCount: Number(publicCount), addressCount: Number(addressCount),
      publicTargets: publicTargets, hosts: targets.filter(function (t) { return t.kind === "host"; }).map(function (t) { return t.text; }), scope: null, text: "" };
    if (!out.ok) return out;
    var scope = { cyberview_scope: V.SCOPE_VERSION, owner: owner, contact: contact,
      attestation: { statement: V.STATEMENT, agreed: true, name: name, date: today, expires: expires, authorization_ref: ref },
      targets: targets.map(function (t) { return t.text; }), exclude: exclude.map(function (t) { return t.text; }) };
    if (ports) scope.ports = ports;
    scope._help = "Built in the browser on CyberView's Scanner page. List only hosts, addresses and CIDR ranges you own or are authorized in writing to scan. Check it with: node scanner/cyberview-scan.mjs check --scope scope.json";
    out.scope = scope; out.text = JSON.stringify(scope, null, 2) + "\n";
    return out;
  };
  /** The commands to run with a built scope file. */
  V.commands = function (built, file) {
    var f = file || "scope.json", flag = built && built.needsPublic ? " " + V.PUBLIC_FLAG : "";
    return ["node scanner/cyberview-scan.mjs check --scope " + f + flag, "node scanner/cyberview-scan.mjs scan --scope " + f + " --online" + flag];
  };

  root.CVScanView = V;
})(typeof window !== "undefined" ? window : this);
