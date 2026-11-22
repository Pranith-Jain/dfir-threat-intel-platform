// CyberView Scanner page. Reads data/scanner.json (written by scripts/build.mjs through scripts/scanner-stats.mjs, no AI
// model): live counts read from the scanner's code, its opt-in flags and the hand-written list of recent features
// (config/scanner-page.json). Every record goes through clean*() first; all text is inserted as text. A missing number
// shows a dash.
// Two tools run in this page only (scanner-lib.js holds their pure parts): the report viewer reads report.json files the
// visitor opens (FileReader; never uploaded, sent or stored) and the scope builder hands back a scope.json as a download.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  // one failing panel must not blank the page: each renders inside safe() and says so if it breaks
  function safe(name, fn, box) { try { fn(); } catch (e) { if (box) { box.textContent = ""; box.appendChild(el("li", "note bad", "The " + name + " could not be shown.")); } } }
  function str(v, n) { return typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, n) : ""; }
  function num(v) { return typeof v === "number" && isFinite(v) && v >= 0 && v < 1e7 ? Math.round(v) : null; }
  function date(v) { return typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : ""; }
  function fmtN(n) { return n == null ? "—" : n.toLocaleString("en-US"); }
  function fmtD(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { return d; } }
  var AREAS = ["services", "edge", "cms", "apps", "rail"];
  var FLAG = /^--[a-z][a-z-]{1,40}$/;

  // ---------- clean: known fields only, with length limits ----------
  function cleanStats(s) {
    var o = { ok: false, version: "", products: null, rules: null, kevTotal: null, kevCovered: null, kevGap: null, railPaths: null, railEntries: null, perHost: null, areas: {}, optIns: [], recent: [], built: "" };
    if (!s || typeof s !== "object" || s.error) return o;
    o.ok = true;
    o.version = /^[\w.+-]{1,20}$/.test(s.version || "") ? s.version : "";
    o.products = num(s.products); o.rules = num(s.rules);
    o.kevTotal = num(s.kev_products); o.kevCovered = num(s.kev_covered); o.kevGap = num(s.kev_gap);
    if (o.kevTotal == null || o.kevCovered == null || o.kevCovered > o.kevTotal) { o.kevTotal = o.kevCovered = o.kevGap = null; }
    o.railPaths = num(s.rail_paths); o.railEntries = num(s.rail_entries); o.perHost = num(s.paths_per_host);
    var a = s.areas && typeof s.areas === "object" ? s.areas : {};
    AREAS.forEach(function (k) { o.areas[k] = num(a[k]); });
    o.optIns = (Array.isArray(s.opt_ins) ? s.opt_ins.slice(0, 12) : []).map(function (x) {
      return x && FLAG.test(x.flag || "") && str(x.what, 200) ? { flag: x.flag, what: str(x.what, 200) } : null;
    }).filter(Boolean);
    o.recent = (Array.isArray(s.recent) ? s.recent.slice(0, 20) : []).map(function (r) {
      if (!r || typeof r !== "object" || !str(r.title, 100) || !date(r.date)) return null;
      var pr = typeof r.pr === "number" && r.pr > 0 && r.pr < 100000 && Math.round(r.pr) === r.pr ? r.pr : null;
      return { title: str(r.title, 100), line: str(r.line, 300), date: r.date, pr: pr };
    }).filter(Boolean);
    o.built = typeof s.built_at === "string" && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(s.built_at) ? s.built_at : "";
    return o;
  }

  // ---------- render ----------
  function tiles(d) {
    $("nProducts").textContent = fmtN(d.products);
    $("nRules").textContent = fmtN(d.rules);
    if (d.kevTotal != null) {
      $("nKev").textContent = fmtN(d.kevCovered) + " of " + fmtN(d.kevTotal);
      $("nKevL").textContent = "known-exploited products it can name (" + fmtN(d.kevGap) + " not yet)";
    } else $("nKev").textContent = "—";
    $("nRail").textContent = fmtN(d.railPaths);
    $("nVersion").textContent = d.version || "—";
    var note = $("glanceNote");
    if (!d.ok) note.textContent = "The scanner's numbers could not be loaded; dashes stand for them.";
    else note.textContent = d.built ? "Counted at the site build of " + d.built.slice(0, 10) + " " + d.built.slice(11, 16) + " UTC." : "";
  }
  function areas(d) {
    Array.prototype.forEach.call(document.querySelectorAll("#areas .acount[data-n]"), function (b) {
      var k = b.getAttribute("data-n"), n = d.areas[k];
      var card = b.closest(".area");
      if (n != null) {
        b.textContent = k === "rail" ? fmtN(n) + " entries" + (d.railPaths != null ? ", " + fmtN(d.railPaths) + " paths" : "") + (d.perHost != null ? ", at most " + d.perHost + " per host" : "") + " · opt-in: --paths"
          : fmtN(n) + (k === "services" ? " built-in entries" : " detection rows");
        if (card) card.classList.remove("absent");
      } else if (d.ok) {
        b.textContent = "Not in this release yet";
        if (card) card.classList.add("absent");
      } else b.textContent = "—";
    });
  }
  function optIns(d) {
    var box = $("optins"); box.textContent = "";
    if (!d.optIns.length) { box.appendChild(el("li", "note", d.ok ? "None listed." : "Could not be loaded; see the guide.")); return; }
    d.optIns.forEach(function (x) { var li = el("li"); li.appendChild(el("code", null, x.flag)); li.appendChild(document.createTextNode(" " + x.what)); box.appendChild(li); });
  }
  function recent(d) {
    var box = $("recent"); box.textContent = "";
    if (!d.recent.length) { box.appendChild(el("li", "note", d.ok ? "Nothing listed yet." : "Could not be loaded.")); return; }
    d.recent.forEach(function (r) {
      var li = el("li", "rc");
      var t = el("time", "date", fmtD(r.date)); t.setAttribute("datetime", r.date); li.appendChild(t);
      var body = el("div", "rcb");
      var h = el("span", "rct", r.title); body.appendChild(h);
      if (r.pr) { var a = el("a", "rcpr", "#" + r.pr); a.href = "https://github.com/xanderhutch/CyberView/pull/" + r.pr; a.target = "_blank"; a.rel = "noopener noreferrer"; a.setAttribute("aria-label", "Pull request " + r.pr); body.appendChild(a); }
      if (r.line) body.appendChild(el("p", null, r.line));
      li.appendChild(body); box.appendChild(li);
    });
  }
  function render(d) {
    safe("numbers", function () { tiles(d); });
    safe("areas", function () { areas(d); });
    safe("opt-ins", function () { optIns(d); }, $("optins"));
    safe("recent list", function () { recent(d); }, $("recent"));
  }

  fetch("data/scanner.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(function (s) { render(cleanStats(s)); })
    .catch(function () { render(cleanStats(null)); });
})();

// ---------- the report viewer and the scope builder (browser only; nothing leaves this page) ----------
(function () {
  "use strict";
  var V = window.CVScanView;
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function add(parent, child) { parent.appendChild(child); return child; }
  // one failing section must not blank the rest: each renders inside safe() and says so if it breaks
  function safe(name, fn, box) { try { fn(); } catch (e) { if (box) add(box, el("p", "note bad", "The " + name + " could not be shown.")); } }
  if (!V || !$("viewer") || !$("scopeForm")) return;
  var ALLOW = V.allowSet([]);
  // links in a report: https, on a host the scanner itself emits (CyberView's site and the hosts in its workbench data), else text
  function safeUrl(u) { return V.safeUrl(u, ALLOW); }
  function blobUrl(b) { return URL.createObjectURL(b); }
  function link(text, url) {
    if (!safeUrl(url)) return el("span", "nolink", text);
    var a = el("a", null, text); a.href = safeUrl(url); a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
  }
  function cveLink(cve) { var a = el("a", "cve", cve); a.href = "vulnerabilities.html#" + cve; a.title = "This CVE on the Vulnerabilities page (today's data)"; return a; }
  function fmtN(n) { return n == null ? "—" : Number(n).toLocaleString("en-US"); }
  function when(s) { return s ? s.slice(0, 10) + " " + s.slice(11, 16) + " UTC" : "unknown time"; }
  function place(host, port) { return /:/.test(host) ? "[" + host + "]:" + port : host + ":" + port; }
  function dl(box, rows) {
    var d = add(box, el("dl", "kv"));
    rows.forEach(function (r) { if (r[1] == null || r[1] === "") return; add(d, el("dt", null, r[0])); var dd = add(d, el("dd")); if (r[1] instanceof Node) dd.appendChild(r[1]); else dd.textContent = String(r[1]); });
    return d;
  }
  function badge(text, cls) { return el("span", "badge " + (cls || "neutral"), text); }
  function section(box, title, id) { var s = add(box, el("section", "vsec")); if (id) s.id = id; add(s, el("h3", null, title)); return s; }
  var BAND_CLS = { Critical: "bad", High: "warn", Medium: "info", Low: "neutral", None: "neutral", "Not scored": "neutral" };

  /* ---------- reading the files ---------- */
  var reports = [], shown = 0;
  function fileName(f) { return String((f && f.name) || "report.json").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 80); }
  function readOne(f) {
    return new Promise(function (resolve) {
      var name = fileName(f);
      if (!f || typeof f.size !== "number") { resolve({ name: name, error: "not a file" }); return; }
      if (f.size > V.LIMITS.maxBytes) { resolve({ name: name, error: "the file is larger than " + (V.LIMITS.maxBytes / 1048576) + " MB" }); return; }
      var fr = new FileReader();
      fr.onload = function () {
        var p = V.parse(typeof fr.result === "string" ? fr.result : "");
        resolve(p.error ? { name: name, error: p.error } : { name: name, report: p.report, diff: V.diffClean(p.raw) });
      };
      fr.onerror = function () { resolve({ name: name, error: "the file could not be read" }); };
      fr.readAsText(f);
    });
  }
  function openFiles(list) {
    var files = Array.prototype.slice.call(list || [], 0, V.LIMITS.files), extra = ((list && list.length) || 0) - files.length;
    var msg = $("repMsg");
    if (!files.length) return;
    msg.textContent = "Reading " + files.length + " file(s) in this browser…";
    Promise.all(files.map(readOne)).then(function (res) {
      var ok = res.filter(function (r) { return r.report; }), bad = res.filter(function (r) { return r.error; });
      msg.textContent = "";
      if (ok.length) {
        reports = ok.sort(function (a, b) { var x = a.report.run.started_at, y = b.report.run.started_at; return x < y ? -1 : x > y ? 1 : 0; });
        shown = reports.length - 1; diffPick = { a: -1, b: -1 };
        add(msg, el("span", null, "Read " + ok.length + " report" + (ok.length > 1 ? "s" : "") + " in this browser. Nothing was uploaded, and nothing is kept after you leave the page."));
      }
      bad.forEach(function (r) { add(msg, el("span", "bad errline", r.name + ": " + r.error + ".")); });
      if (extra > 0) add(msg, el("span", "bad errline", extra + " more file(s) were not read: at most " + V.LIMITS.files + " at once."));
      if (ok.length) render();
    });
  }

  /* ---------- one report ---------- */
  function runHeader(box, r, name) {
    var s = section(box, "The run");
    var a = r.scope.attestation, cov = r.coverage;
    var covEl = el("span");
    add(covEl, badge(cov.complete ? "Complete" : "Incomplete", cov.complete ? "ok" : "warn"));
    covEl.appendChild(document.createTextNode(cov.complete ? " every host answered and every port was checked" : " some hosts or ports could not be checked: a clean result does not cover them (see Coverage gaps)"));
    var ports = r.run.ports.length > 24 ? r.run.ports.length + " TCP ports (" + r.run.ports[0] + "–" + r.run.ports[r.run.ports.length - 1] + ")" : r.run.ports.join(", ");
    var tg = r.scope.targets;
    dl(s, [
      ["File", name],
      ["Scope owner", r.scope.owner + (r.scope.contact ? " (" + r.scope.contact + ")" : "")],
      ["Attested by", a.name ? a.name + (a.date ? " on " + a.date : "") + (a.expires ? ", valid until " + a.expires : "") + (a.ref ? ", authorization " + a.ref : "") : "not recorded in this report"],
      ["Statement", a.statement ? "“" + a.statement + "”" : ""],
      ["When", r.run.started_at ? when(r.run.started_at) + (r.run.finished_at ? " to " + when(r.run.finished_at) : "") : "not recorded"],
      ["Targets", tg.length + " listed" + (tg.length ? ": " + tg.slice(0, 12).join(", ") + (tg.length > 12 ? " and " + (tg.length - 12) + " more" : "") : "")
        + (r.scope.exclude.length ? "; excluded: " + r.scope.exclude.slice(0, 12).join(", ") : "")
        + (r.scope.public_addresses ? "; " + r.scope.public_addresses + " public address(es)" + (r.scope.public_confirmed ? ", confirmed with " + V.PUBLIC_FLAG : "") : "")],
      ["Hosts", r.hosts.length + " in scope, " + r.hosts.filter(function (h) { return h.up; }).length + " answered"],
      ["Ports", ports + (r.run.udp.length ? "; UDP: " + r.run.udp.join(", ") : "")],
      ["Coverage", covEl],
      ["Data", ((r.run.data_mode ? r.run.data_mode + " " : "") + (r.run.data_source || "") + (r.run.workbench_built_at ? " (CyberView data built " + when(r.run.workbench_built_at) + ")" : "")).trim()],
      ["Scanner", r.tool.version ? "CyberView Scanner " + r.tool.version : ""],
    ]);
    if (r.run.sends.length) {
      var d = add(s, el("details", "sends"));
      add(d, el("summary", null, "What the scanner sent (" + (r.run.connections != null ? fmtN(r.run.connections) + " connections" : "as recorded") + ")"));
      var ul = add(d, el("ul", "plain"));
      r.run.sends.forEach(function (x) { var li = add(ul, el("li")); add(li, el("code", null, x.what)); li.appendChild(document.createTextNode(" " + x.text)); });
    }
  }
  function tiles(box, r) {
    var c = V.counts(r), s = section(box, "At a glance");
    var t = add(s, el("div", "tiles vtiles")); t.id = "repTiles";
    [["known_exploited", "known exploited (CISA)"], ["critical", "rated Critical"], ["act", "Act now (CISA's SSVC)"], ["overdue", "past CISA's deadline"]].forEach(function (x) {
      var d = add(t, el("div", "tile")); d.setAttribute("data-k", x[0]); add(d, el("span", "tn", fmtN(c[x[0]]))); add(d, el("span", "tl", x[1]));
    });
    add(s, el("p", "note", c.findings + " finding(s) on " + c.hosts_up + " host(s) that answered, " + c.open_ports + " open port(s), " + c.services + " service(s) identified, " + c.observations + " observation(s). "
      + "The four counts are confident findings only" + (c.low_confidence ? " (" + c.low_confidence + " low-confidence finding(s) are listed below but not counted)" : "") + ", with the same definitions as the scanner's summary.txt."));
  }
  function pointsList(f) {
    var box = el("div", "pts");
    if (f.rating.text) add(box, el("p", "rtext", f.rating.text));
    if (f.points.list.length) {
      add(box, el("p", "ptitle", "Patch-queue points: " + (f.points.total != null ? f.points.total : "")));
      var ul = add(box, el("ul", "plain ptl"));
      f.points.list.forEach(function (p) { add(ul, el("li", null, (p.points >= 0 ? "+" : "") + p.points + " " + p.why)); });
    }
    if (f.priority && f.priority.label) add(box, el("p", "ptitle", "CISA's SSVC: " + f.priority.label + (f.priority.fix_by ? ", fix " + f.priority.fix_by : "")));
    return box;
  }
  function fixCell(f) {
    var box = el("div", "fix");
    if (f.fix.fixed_in.length) add(box, el("p", null, "Fixed in " + f.fix.fixed_in.join(", ")));
    f.fix.vendor_fixed.forEach(function (x) { add(box, el("p", null, "Vendor: " + x)); });
    if (f.fix.advisory) { var p = add(box, el("p")); p.appendChild(document.createTextNode("Advisory: ")); p.appendChild(link(f.fix.advisory.name || "vendor advisory", f.fix.advisory.url)); }
    f.fix.workaround.slice(0, 2).forEach(function (x) { add(box, el("p", "muted", "Workaround: " + x)); });
    if (!f.fix.fixed_in.length && !f.fix.advisory && f.fix.required) add(box, el("p", null, "CISA: " + f.fix.required));
    if (f.hunt.length) {
      var hp = add(box, el("p", "muted")); hp.appendChild(document.createTextNode("Hunt: "));
      f.hunt.slice(0, 3).forEach(function (h, i) { if (i) hp.appendChild(document.createTextNode(", ")); hp.appendChild(link(h.name || h.format, h.url)); });
    }
    var a = add(add(box, el("p")), cveLink(f.cve)); a.textContent = "Check steps and today's rating";
    return box;
  }
  var filt = { host: "", band: "", kev: false, confidence: "" };
  function findings(box, r) {
    var s = section(box, "Findings", "repFindings");
    var rows = V.rows(r);
    if (!rows.length) { add(s, el("p", "note", "No findings in this report. A clean result is not proof that a host has no vulnerabilities: the scanner knows only the flaws CyberView's data covers.")); return; }
    var f = add(s, el("div", "filters vfilters"));
    var body, count;
    function sel(label, id, opts, val, on) {
      var l = add(f, el("label", null, label)), x = add(l, el("select")); x.id = id;
      opts.forEach(function (o) { var op = add(x, el("option", null, o[1])); op.value = o[0]; });
      x.value = val; x.addEventListener("change", function () { on(x.value); draw(); }); return x;
    }
    var hosts = []; rows.forEach(function (x) { if (hosts.indexOf(x.s.host) < 0) hosts.push(x.s.host); });
    if (filt.host && hosts.indexOf(filt.host) < 0) filt.host = "";
    sel("Host", "fHost", [["", "All hosts"]].concat(hosts.slice(0, 500).map(function (h) { return [h, h]; })), filt.host, function (v) { filt.host = v; });
    sel("Rating", "fBand", [["", "Any rating"], ["Critical", "Critical"], ["High", "High or above"], ["Medium", "Medium or above"]], filt.band, function (v) { filt.band = v; });
    sel("Confidence", "fConf", [["", "Any confidence"], ["high", "High only"], ["medium", "High or medium"]], filt.confidence, function (v) { filt.confidence = v; });
    var kl = add(f, el("label", "chk")), kc = add(kl, el("input")); kc.type = "checkbox"; kc.id = "fKev"; kc.checked = filt.kev; kl.appendChild(document.createTextNode(" Known exploited only"));
    kc.addEventListener("change", function () { filt.kev = kc.checked; draw(); });
    count = add(s, el("p", "count")); count.id = "repCount"; count.setAttribute("aria-live", "polite");
    var tb = add(add(s, el("div", "twrap")), el("table", "ftab")); tb.id = "repTable";
    var HEAD = ["#", "CVE", "Where", "Software seen", "CyberView rating, every point", "Confidence", "Fix"];
    var hr = add(add(tb, el("thead")), el("tr")); HEAD.forEach(function (h) { add(hr, el("th", null, h)); });
    body = add(tb, el("tbody"));
    add(s, el("p", "note", "Ratings and points are the scanner's own, worked out on the day of the scan with the same code as the Vulnerabilities page; the CVE link opens today's rating there. Fix guides and exploitation analyses on CyberView's pages are written by CyberView AI (a Claude model). A link shows only when it is https and on a host the scanner's data uses; otherwise its name is plain text."));
    function draw() {
      body.textContent = "";
      var list = V.filterRows(rows, filt);
      count.textContent = list.length + " of " + rows.length + " finding place(s) shown";
      list.slice(0, 2000).forEach(function (x) {
        var tr = add(body, el("tr")), fx = x.f, sx = x.s;
        tr.setAttribute("data-cve", fx.cve);
        function td(i, content) { var c = add(tr, el("td")); c.setAttribute("data-label", HEAD[i]); if (content instanceof Node) c.appendChild(content); else c.textContent = content == null ? "" : String(content); return c; }
        td(0, x.rank);
        add(td(1, cveLink(fx.cve)), el("span", "sub ftitle", fx.title));
        var c2 = td(2, place(sx.host, sx.port)); if (sx.names.length) add(c2, el("span", "sub", sx.names.slice(0, 3).join(", ")));
        var c3 = td(3, (sx.product || fx.product) + (sx.shown_version ? " " + sx.shown_version : " (no version stated)"));
        add(c3, el("span", "sub", sx.state === "affected" ? "version inside the affected range" : "product seen, version to check by hand"));
        if (sx.evidence) add(c3, el("span", "sub ev", sx.evidence));
        var c4 = td(4, badge(fx.rating.score != null ? fx.rating.score.toFixed(1) + " " + fx.rating.band : "Not scored", BAND_CLS[fx.rating.band] || "neutral"));
        var tags = add(c4, el("span", "tags"));
        if (fx.kev) add(tags, el("span", "pill", "Known exploited (CISA)"));
        if (fx.overdue) add(tags, el("span", "pill warnline", "Past CISA's deadline " + fx.cisa_due));
        if (fx.ransomware) add(tags, el("span", "pill", "Used in ransomware"));
        c4.appendChild(pointsList(fx));
        var c5 = td(5, sx.confidence); c5.className = "conf " + sx.confidence; if (sx.confidence_why) add(c5, el("span", "sub", sx.confidence_why));
        td(6, fixCell(fx));
      });
      if (list.length > 2000) add(add(body, el("tr")), el("td", "note", (list.length - 2000) + " more not shown; narrow the filters.")).colSpan = 7;
    }
    draw();
  }
  function hostsSec(box, r) {
    var s = section(box, "Hosts and services");
    if (!r.hosts.length) { add(s, el("p", "note", "No hosts in this report.")); return; }
    var ul = add(s, el("ul", "plain hostl")); ul.id = "repHosts";
    function svcText(list) { return list.map(function (x) { return (x.label || x.product) + (x.shown_version ? " " + x.shown_version : "") + (x.guessed ? " (inferred)" : ""); }).join("; "); }
    r.hosts.slice(0, 1000).forEach(function (h) {
      var li = add(ul, el("li", "hrow")), head = add(li, el("p", "hh"));
      add(head, el("strong", null, h.address));
      if (h.names.length) head.appendChild(document.createTextNode(" (" + h.names.slice(0, 5).join(", ") + ")"));
      head.appendChild(document.createTextNode(" "));
      add(head, badge(h.up ? "answered" : "no answer", h.up ? "ok" : "warn"));
      add(head, el("span", "sub", [h.kind, h.public ? "public" : "", h.source && h.source !== "scope" ? "found by " + h.source : ""].filter(Boolean).join(" · ")));
      if (!h.up) { add(li, el("p", "note", "Did not answer on any port: a coverage gap, not a clean result.")); return; }
      var open = h.ports.filter(function (p) { return p.state === "open"; }), pl = add(li, el("ul", "plain svc"));
      open.forEach(function (p) {
        var svcs = h.services.filter(function (x) { return x.port === p.port; }), row = add(pl, el("li"));
        add(row, el("code", null, p.port + "/tcp"));
        row.appendChild(document.createTextNode(" " + (svcs.length ? svcText(svcs) : "open, nothing identified")));
        svcs.slice(0, 3).forEach(function (x) { if (x.evidence) add(row, el("span", "sub ev", x.evidence)); });
      });
      h.udp.forEach(function (u) {
        var sv = h.services.filter(function (x) { return x.port === u.port; }), row = add(pl, el("li"));
        add(row, el("code", null, u.port + "/udp")); row.appendChild(document.createTextNode(" " + (sv.length ? svcText(sv) : u.proto || "open")));
      });
      if (!open.length && !h.udp.length) add(pl, el("li", "note", "Answered, but no port was open."));
    });
    if (r.hosts.length > 1000) add(s, el("p", "note", (r.hosts.length - 1000) + " more hosts not listed here."));
  }
  function certsSec(box, r) {
    var rows = []; r.hosts.forEach(function (h) { h.tls.forEach(function (t) { if (t.cert) rows.push({ h: h, t: t }); }); });
    if (!rows.length) return;
    var s = section(box, "Certificates");
    var tb = add(add(s, el("div", "twrap")), el("table", "ftab ctab")); tb.id = "repCerts";
    var HEAD = ["Where", "Subject", "Issuer", "Valid until", "Key and signature", "TLS"];
    var hr = add(add(tb, el("thead")), el("tr")); HEAD.forEach(function (x) { add(hr, el("th", null, x)); });
    var body = add(tb, el("tbody"));
    rows.slice(0, 2000).forEach(function (x) {
      var c = x.t.cert, tr = add(body, el("tr"));
      function td(i, v) { var d = add(tr, el("td")); d.setAttribute("data-label", HEAD[i]); d.textContent = v; return d; }
      td(0, place(x.h.address, x.t.port));
      var sj = td(1, c.subject || "—"); if (c.san_dns.length) add(sj, el("span", "sub", c.san_dns.slice(0, 6).join(", ")));
      td(2, (c.issuer || "—") + (c.self_signed ? " (self-signed)" : ""));
      var v = td(3, c.valid_to || "—");
      if (c.expired) add(v, el("span", "sub bad", "expired"));
      else if (c.not_yet_valid) add(v, el("span", "sub bad", "not yet valid"));
      else if (c.days_left != null) add(v, el("span", "sub" + (c.days_left < 30 ? " warnline" : ""), c.days_left + " days left at the scan"));
      td(4, [c.key_type, c.key_bits ? c.key_bits + " bits" : "", c.sig_alg].filter(Boolean).join(", ") || "—");
      td(5, [x.t.protocol, x.t.cipher].filter(Boolean).join(", ") || "—");
    });
  }
  var SEVR = { high: 0, medium: 1, low: 2, info: 3 };
  function obsSec(box, r) {
    var list = []; r.hosts.forEach(function (h) { h.observations.forEach(function (o) { list.push({ h: h, o: o }); }); });
    var dropped = r.hosts.reduce(function (n, h) { return n + h.observations_dropped; }, 0);
    if (!list.length && !dropped) return;
    var s = section(box, "Observations (not CVEs)");
    list.sort(function (a, b) { return SEVR[a.o.severity] - SEVR[b.o.severity]; });
    var ul = add(s, el("ul", "plain obs")); ul.id = "repObs";
    list.slice(0, 1000).forEach(function (x) {
      var li = add(ul, el("li")); add(li, badge(x.o.severity, x.o.severity === "high" ? "bad" : x.o.severity === "medium" ? "warn" : "neutral"));
      li.appendChild(document.createTextNode(" " + place(x.h.address, x.o.port) + " " + x.o.text)); add(li, el("span", "sub", x.o.kind));
    });
    if (list.length > 1000 || dropped) add(s, el("p", "note", (list.length > 1000 ? (list.length - 1000) + " more not listed. " : "") + (dropped ? dropped + " over the scanner's per-host cap were counted, not recorded." : "")));
  }
  function covSec(box, r) {
    var c = r.coverage, s = section(box, "Coverage gaps"), ul = add(s, el("ul", "plain gaps")), n = 0;
    ul.id = "repGaps";
    function gap(text) { add(ul, el("li", null, text)); n++; }
    var stop = c.stop_reason || r.run.stop_reason;
    if (c.interrupted || r.run.interrupted) gap("The scan stopped early" + (stop ? ": " + stop : "") + ". Hosts and ports after that point were not checked.");
    if (c.unreachable.length) gap(c.unreachable.length + " host(s) did not answer on any port: " + c.unreachable.slice(0, 20).join(", ") + (c.unreachable.length > 20 ? " and more" : "") + ". Not a clean result.");
    c.not_checked.slice(0, 50).forEach(function (x) { gap(x.address + ": " + x.count + " port(s) not checked (a limit or the time ran out)."); });
    c.truncated.slice(0, 50).forEach(function (x) { gap(x.address + ": " + x.count + " banner(s) cut off before a version (a tarpit or a throttled read)."); });
    c.throttled.slice(0, 50).forEach(function (x) { gap(x.address + ": " + x.resets + " connection reset(s), likely throttling; " + x.recovered + " service(s) found after backing off."); });
    if (c.filtered) gap(c.filtered + " port probe(s) filtered or dropped (no answer at all).");
    r.scope.refused.slice(0, 50).forEach(function (x) { gap("Not scanned: " + x.target + " (" + x.why + ")"); });
    if (!n) add(ul, el("li", null, c.complete ? "None: every host answered and every listed port was checked." : "None recorded in this report."));
  }
  function notesSec(box, r) {
    if (!r.notes.length && !r.named.length) return;
    var s = section(box, "Notes from the scanner");
    if (r.named.length) {
      add(s, el("p", null, "Also named in the CVE List (versions not checked; compare with the vendor's advisory):"));
      var nl = add(s, el("ul", "plain"));
      r.named.forEach(function (x) { add(nl, el("li", null, x.product + (x.version ? " " + x.version : "") + ": " + x.count + " CVE(s), " + x.exploited + " exploited")); });
    }
    var ul = add(s, el("ul", "plain notes")); r.notes.forEach(function (t) { add(ul, el("li", "note", t)); });
  }

  /* ---------- two or more reports: what changed (the same rules as the scanner's --compare) ---------- */
  var diffPick = { a: -1, b: -1 };
  function diffSec(box) {
    var s = section(box, "What changed between scans", "repDiff");
    if (diffPick.a < 0 || diffPick.a >= reports.length) diffPick.a = reports.length - 2;
    if (diffPick.b < 0 || diffPick.b >= reports.length) diffPick.b = reports.length - 1;
    var f = add(s, el("div", "filters vfilters"));
    function pick(label, key, id) {
      var l = add(f, el("label", null, label)), x = add(l, el("select")); x.id = id;
      reports.forEach(function (r, i) { var o = add(x, el("option", null, when(r.report.run.started_at) + " · " + r.name)); o.value = String(i); });
      x.value = String(diffPick[key]); x.addEventListener("change", function () { diffPick[key] = Number(x.value); render(); });
    }
    pick("Earlier scan", "a", "dA"); pick("Later scan", "b", "dB");
    if (diffPick.a === diffPick.b) { add(s, el("p", "note", "Choose two different reports.")); return; }
    var d = V.diffReports(reports[diffPick.a].diff, reports[diffPick.b].diff), c = d.counts;
    if (reports[diffPick.a].report.run.started_at > reports[diffPick.b].report.run.started_at) add(s, el("p", "note warnline", "The earlier scan you chose ran after the later one, so the comparison reads backwards."));
    var t = add(s, el("div", "tiles vtiles dtiles")); t.id = "dTiles";
    [["findings.new", "new findings"], ["findings.fixed", "fixed"], ["findings.still_open", "still open"], ["findings.gone", "gone with their port"], ["findings.not_rechecked", "not rechecked"]].forEach(function (x) {
      var dv = add(t, el("div", "tile")); dv.setAttribute("data-k", x[0]); add(dv, el("span", "tn", fmtN(c[x[0]]))); add(dv, el("span", "tl", x[1]));
    });
    function list(title, rows, fmt, id) {
      if (!rows.length) return;
      add(s, el("h4", null, title));
      var ul = add(s, el("ul", "plain dlist")); if (id) ul.id = id;
      rows.slice(0, 200).forEach(function (x) { add(ul, el("li", null, fmt(x))); });
      if (rows.length > 200) add(ul, el("li", "note", (rows.length - 200) + " more"));
    }
    function at(x) { return x.cve + " on " + place(x.host, x.port); }
    function fv(x) { return at(x) + " " + x.product + " " + (x.version || "(no version)") + (x.kev ? " (known exploited)" : ""); }
    function why(x) { return at(x) + ": " + x.why; }
    list("New findings", d.findings.new, fv, "dNew");
    list("Fixed", d.findings.fixed, why, "dFixed");
    list("Still open", d.findings.still_open, fv, "dOpen");
    list("Gone with their port (not proof of a fix)", d.findings.gone, why, "dGone");
    list("Not rechecked", d.findings.not_rechecked, why);
    list("Version changes", d.services.changed, function (x) { return place(x.host, x.port) + " " + x.product + " " + (x.before || "?") + " → " + (x.after || "?"); });
    list("New services", d.services.new, function (x) { return place(x.host, x.port) + " " + x.product + " " + (x.version || ""); });
    list("Hosts newly answering", d.hosts.new_up, function (x) { return x; });
    list("Hosts no longer answering", d.hosts.no_longer_up, function (x) { return x.host + ": " + x.why; });
    list("Ports newly open", d.ports.opened, function (x) { return place(x.host, x.port); });
    list("Ports no longer open", d.ports.no_longer_open, function (x) { return place(x.host, x.port) + ": " + x.why; });
    list("Certificate issuer changed (review it; not evidence of compromise)", d.certificates.issuer_changed, function (x) { return place(x.host, x.port) + " " + x.before + " → " + x.after; }, "dIssuer");
    list("Certificates replaced, same issuer", d.certificates.changed.filter(function (x) { return !x.issuer_changed; }), function (x) { return place(x.host, x.port) + " valid until " + (x.before.valid_to || "?") + " → " + (x.after.valid_to || "?") + (x.key_changed ? ", new key" : ""); });
    list("New observations", d.observations.new, function (x) { return place(x.host, x.port) + " " + x.text; });
    list("Resolved observations", d.observations.resolved, function (x) { return place(x.host, x.port) + " " + x.text; });
    var nl = add(s, el("ul", "plain notes")); d.notes.forEach(function (t2) { add(nl, el("li", "note", t2)); });
  }

  function render() {
    var out = $("repOut"); out.textContent = "";
    if (!reports.length) { out.hidden = true; return; }
    out.hidden = false;
    var bar = add(out, el("div", "repbar"));
    var clr = add(bar, el("button", "btn", "Close the report" + (reports.length > 1 ? "s" : ""))); clr.type = "button"; clr.id = "repClear";
    clr.addEventListener("click", function () { reports = []; $("repMsg").textContent = "Closed. Nothing was kept."; $("repFile").value = ""; render(); });
    if (reports.length > 1) {
      var l = add(bar, el("label", "field inl", "Report shown below")), x = add(l, el("select")); x.id = "repPick";
      reports.forEach(function (r, i) { var o = add(x, el("option", null, when(r.report.run.started_at) + " · " + r.name)); o.value = String(i); });
      x.value = String(shown); x.addEventListener("change", function () { shown = Number(x.value); render(); });
      safe("comparison", function () { diffSec(out); }, out);
    }
    var cur = reports[shown], r = cur.report, det = add(out, el("div", "repdet"));
    safe("run header", function () { runHeader(det, r, cur.name); }, det);
    safe("counts", function () { tiles(det, r); }, det);
    safe("findings", function () { findings(det, r); }, det);
    safe("hosts", function () { hostsSec(det, r); }, det);
    safe("certificates", function () { certsSec(det, r); }, det);
    safe("observations", function () { obsSec(det, r); }, det);
    safe("coverage gaps", function () { covSec(det, r); }, det);
    safe("notes", function () { notesSec(det, r); }, det);
  }

  var input = $("repFile"), drop = $("drop");
  input.addEventListener("change", function () { openFiles(input.files); });
  ["dragenter", "dragover"].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); }); });
  ["dragleave", "dragend"].forEach(function (ev) { drop.addEventListener(ev, function () { drop.classList.remove("over"); }); });
  drop.addEventListener("drop", function (e) { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer) openFiles(e.dataTransfer.files); });
  // the hosts the scanner's links use: CyberView's own workbench data (the same file the scanner reads); fetched from this site only
  fetch("data/workbench.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(function (w) { ALLOW = V.allowSet(V.hostsIn(w)); if (reports.length) render(); }).catch(function () {});

  /* ---------- the scope builder ---------- */
  var form = $("scopeForm"), sout = $("scopeOut"), lastUrl = "";
  function today() { return new Date().toISOString().slice(0, 10); }
  function values() {
    return { owner: $("scOwner").value, contact: $("scContact").value, name: $("scName").value, ref: $("scRef").value, expires: $("scExpires").value,
      targets: $("scTargets").value, exclude: $("scExclude").value, ports: $("scPorts").value, customPorts: $("scCustom").value, agreed: $("scAgree").checked === true };
  }
  function clearOut() { sout.textContent = ""; sout.hidden = true; if (lastUrl) { URL.revokeObjectURL(lastUrl); lastUrl = ""; } }
  function publicNote() {
    var box = $("scPublic"); box.textContent = "";
    var v = values(); v.agreed = true;
    var b = V.buildScope(v, today());
    if (!b.publicTargets.length) { box.hidden = true; return; }
    box.hidden = false;
    add(box, el("strong", null, "Public addresses: "));
    box.appendChild(document.createTextNode(b.publicTargets.slice(0, 10).join(", ") + (b.publicTargets.length > 10 ? " and more" : "") + " (" + b.publicCount + " address(es)). The scanner refuses them unless you also give "));
    add(box, el("code", null, V.PUBLIC_FLAG));
    box.appendChild(document.createTextNode(" on the command line; the commands this page shows include it. Use it only for addresses you own or hold written permission to test."));
  }
  function custom() { $("scCustomL").hidden = $("scPorts").value !== "custom"; }
  form.addEventListener("input", function () { clearOut(); safe("public check", publicNote); });
  form.addEventListener("change", custom);
  $("scStatement").textContent = V.STATEMENT;   // the scanner's exact wording (scanner/lib/scope.mjs STATEMENT; unit-tested)
  form.addEventListener("submit", function (e) {
    e.preventDefault(); clearOut();
    safe("scope file", function () {
      var b = V.buildScope(values(), today());
      sout.hidden = false;
      if (!b.ok) {
        var p = add(sout, el("div", "probs")); p.setAttribute("role", "alert"); p.id = "scProblems";
        add(p, el("p", null, "No scope file was made. Fix these first:"));
        var ul = add(p, el("ul")); b.problems.forEach(function (x) { add(ul, el("li", null, x)); });
        return;
      }
      var bar = add(sout, el("p", "heroacts"));
      var a = add(bar, el("a", "btn primary", "Download scope.json")); a.href = blobUrl(new Blob([b.text], { type: "application/json" })); a.download = "scope.json"; a.id = "scDownload";
      lastUrl = a.href;
      add(sout, el("p", "note", b.addressCount + " address(es)" + (b.hosts.length ? " plus " + b.hosts.length + " host name(s), resolved when the scan runs" : "") + (b.needsPublic ? "; " + b.publicCount + " of them public" : "")
        + ". Your browser saves the file; nothing was sent anywhere."));
      add(sout, el("h3", "subh", "Then run, from the CyberView repository's folder"));
      var ol = add(sout, el("ol", "steps")); ol.id = "scCmds";
      var labels = ["Check it (nothing is scanned)", "Scan, reading CyberView's public data (offline: --data with a downloaded copy instead of --online)"];
      V.commands(b).forEach(function (c, i) { var li = add(ol, el("li")); add(li, el("span", "sl", labels[i])); add(add(li, el("pre")), el("code", null, c)); });
      var d = add(sout, el("details", "sends")); add(d, el("summary", null, "Show the file"));
      add(add(d, el("pre", "scpre")), el("code", null, b.text)).id = "scPreview";
    }, sout);
  });
  custom();
})();
