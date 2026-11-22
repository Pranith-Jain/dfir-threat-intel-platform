// CyberView status page. Answers, in this order: is the site healthy right now, how the data flows from the feeds to the
// globe, where it comes from and what needs attention; everything else sits in collapsed details. Reads site/data/ops.json
// (routines, run logs, lead queue, collectors, improver; scripts/build.mjs), health.json and manifest.json (pipeline
// timestamps, grid sources, what the build left out, live commits) and efficiency.json (flow, sources, usage and output per
// routine, feeds, coverage, accuracy; scripts/efficiency.mjs). efficiency.json also holds the four targets for the improver,
// the guard and `swarm.mjs board`; the owner took them off this page (2026-11-20), so the page reads none of them. Every record goes through a clean*() function; every panel renders inside safe().
// Lateness is worked out here against the visitor's clock, so the page stays truthful between deploys.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var REPO = "https://github.com/xanderhutch/CyberView";
  var MODEL = { "claude-sonnet-5-5": "Sonnet 5.5", "claude-opus-5-5": "Opus 5.5", "claude-haiku-5-5": "Haiku 5.5" };
  var AI_BY = "CyberView AI (a Claude model)";
  var DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  var has = function (o, k) { return Object.prototype.hasOwnProperty.call(o, k); };
  function safe(fn) { try { fn(); } catch (e) { if (window.console) console.warn("status panel failed", e); } }
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/github\.com\//.test(u) ? u : "about:blank"; }
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function txt(v, n) { return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n || 200) : ""; }
  function nn(v) { return typeof v === "number" && isFinite(v) ? v : null; }
  function int0(v) { var x = nn(v); return x === null ? 0 : Math.max(0, Math.round(x)); }
  function isoOk(v) { return typeof v === "string" && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(v) && isFinite(Date.parse(v)) ? v : ""; }
  function arr(v, n) { return Array.isArray(v) ? v.slice(0, n) : []; }
  function obj(v) { return v && typeof v === "object" && !Array.isArray(v) ? v : null; }
  function pad(n) { return String(n).padStart(2, "0"); }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : (many || one + "s")); }
  function ago(iso) {
    var m = Math.round((Date.now() - Date.parse(iso)) / 6e4);
    if (!isFinite(m)) return "";
    if (m < 2) return "just now"; if (m < 60) return m + " min ago";
    var h = m / 60; if (h < 48) return (h < 10 ? h.toFixed(1) : Math.round(h)) + " h ago";
    return Math.round(h / 24) + " days ago";
  }
  function big(n) { return n === null ? "not logged" : n >= 1e9 ? (n / 1e9).toFixed(1) + " bn" : n >= 1e6 ? (n / 1e6).toFixed(1) + " M" : n >= 1e3 ? Math.round(n / 1e3) + " k" : String(Math.round(n)); }
  function badge(cls, text) { return el("span", "badge " + cls, text); }
  function link(href, text) { var a = el("a", null, text); a.href = safeUrl(href); a.target = "_blank"; a.rel = "noopener noreferrer"; return a; }
  // a link to one of the collapsed details on this page: opens it and scrolls to it
  function jump(id, text) { var a = el("a", null, text); a.href = "#" + id; a.dataset.open = id; return a; }
  document.addEventListener("click", function (ev) {
    var a = ev.target && ev.target.closest ? ev.target.closest("a[data-open]") : null; if (!a) return;
    var d = $(a.dataset.open); if (d && d.tagName === "DETAILS") { d.open = true; }
  });
  function openFromHash() { var d = location.hash.length > 1 ? document.getElementById(location.hash.slice(1)) : null; if (d && d.tagName === "DETAILS") d.open = true; }
  window.addEventListener("hashchange", openFromHash);

  // plain-language schedule for the cron shapes the routines use
  function when(cron) {
    var p = String(cron || "").split(/\s+/); if (p.length !== 5) return cron || "";
    var min = p[0], hr = p[1], dow = p[4];
    var days = dow === "*" ? "" : dow.split(",").map(function (d) { return DOW[+d] || d; }).join(" and ") + " ";
    if (hr === "*") return min.indexOf(",") > 0 ? "every 30 min" : "hourly at :" + pad(min);
    var every = hr.match(/^\*\/(\d+)$/); if (every) return "every " + every[1] + " h at :" + pad(min);
    return days + hr.split(",").map(function (h) { return pad(h) + ":" + pad(min); }).join(" and ");
  }

  /* ---------------- cleaning: every field the page shows, checked and cut to size; anything else is dropped ---------------- */

  /** One routine from ops.json (routines.json plus its last run). A retired routine names the job its duties moved to. */
  function cleanRoutine(r) {
    if (!obj(r) || typeof r.key !== "string") return null;
    var mi = typeof r.merged_into === "string" ? r.merged_into.replace(/[^a-z0-9 ,-]/gi, "").slice(0, 40).trim() : "";
    return { key: txt(r.key, 40), name: txt(r.name, 60) || txt(r.key, 40), does: txt(r.does, 400), tier: r.tier === "ai" ? "ai" : "automation",
      model: txt(r.model, 40), workflow: txt(r.workflow, 40), cron: txt(r.cron, 40), status_key: txt(r.status_key, 40), active: r.active === true,
      retired: !!r.retired && r.active !== true, merged_into: mi, last_at: isoOk(r.last_at), active_since: isoOk(r.active_since), max_age_hours: nn(r.max_age_hours) || 24 };
  }
  function cleanOps(o) {
    if (!obj(o)) return null;
    var L = obj(o.leads) || {}, P = obj(o.pipeline) || {}, S = obj(P.stories) || {}, I = obj(o.improve) || {};
    var col = function (c) { return obj(c) && typeof c.name === "string" ? { name: txt(c.name, 40), leads: nn(c.leads), used: nn(c.used), retired: txt(c.retired, 10), why: txt(c.why, 300) } : null; };
    return {
      built_at: isoOk(o.built_at),
      routines: arr(o.routines, 120).map(cleanRoutine).filter(Boolean),
      runs: arr(o.runs, 40).filter(obj).map(function (r) { return { at: isoOk(r.at), job: txt(r.job, 40), added: int0(r.added), updated: int0(r.updated), failed: int0(r.failed) }; }),
      leads: { last_24h: int0(L.last_24h), by_tier: obj(L.by_tier) || {}, failed: arr(L.failed_feeds, 30).map(function (f) { return txt(f, 160); }).filter(Boolean) },
      sources: arr(o.sources, 30).filter(function (x) { return obj(x) && typeof x.name === "string"; }).map(function (x) { return { name: txt(x.name, 30), ok: x.ok === true, error: txt(x.error, 90), at: isoOk(x.at) }; }),
      pipeline: { feeds: nn(P.feeds), leads_7d: nn(P.leads_7d), used_7d: nn(P.leads_used_7d), days: nn(P.days_covered), events_7d: nn(P.events_7d), median_hours: nn(P.median_hours),
        collectors: arr(P.collectors, 20).map(col).filter(Boolean), retired: arr(P.retired_collectors, 10).map(col).filter(Boolean),
        open: nn(S.open), corroborated: nn(S.corroborated) },
      improve: { at: isoOk(I.at), days: nn(I.days), events_added: nn(I.events_added), cost_usd: nn(I.cost_usd), cost_per_event: nn(I.cost_per_event),
        guard: obj(I.guard) ? { blocked: I.guard.blocked === true } : null,
        roles: Object.keys(obj(I.roles) || {}).slice(0, 30).map(function (k) { var r = obj(I.roles[k]) || {}; return { name: txt(k, 40), model: txt(r.model, 12), runs: int0(r.runs), ok_rate: nn(r.ok_rate), timeouts: int0(r.timeouts), cost_per_run: nn(r.cost_per_run), turns: nn(r.turns_per_run) }; }),
        changes: arr(I.changes, 10).filter(obj).map(function (c) { return { at: isoOk(c.at), key: txt(c.key, 80), from: txt(String(c.from), 20), to: txt(String(c.to), 20), reason: txt(c.reason, 300) }; }) }
    };
  }
  function cleanHealth(h) {
    if (!obj(h)) return null;
    var B = obj(h.backlog), GW = obj(h.grid_waiting), OQ = obj(h.outage_queue);
    return {
      built_at: isoOk(h.built_at), last_sweep_at: isoOk(h.last_sweep_at), last_collect_at: isoOk(h.last_collect_at), last_feeds_at: isoOk(h.last_feeds_at),
      grid: h.last_grid_at !== undefined, last_grid_at: isoOk(h.last_grid_at), grid_open: nn(h.grid_open) === null ? null : int0(h.grid_open), last_grid_research_at: isoOk(h.last_grid_research_at),
      grid_analysis: h.grid_analysis_at !== undefined, grid_analysis_at: isoOk(h.grid_analysis_at), grid_news: h.last_grid_news_at !== undefined, last_grid_news_at: isoOk(h.last_grid_news_at),
      grid_waiting: GW && nn(GW.count) !== null ? { count: int0(GW.count), oldest_min: int0(GW.oldest_min) } : null,
      outage_queue: OQ && nn(OQ.waiting) !== null ? { waiting: int0(OQ.waiting), checked_24h: int0(OQ.checked_24h), confirmed_24h: int0(OQ.confirmed_24h), cyber_leads_24h: int0(OQ.cyber_leads_24h), oldest_min: int0(OQ.oldest_min) } : null,
      last_outage_at: isoOk(h.last_outage_at),
      claims_queue: obj(h.claims_queue) && nn(h.claims_queue.waiting) !== null ? { waiting: int0(h.claims_queue.waiting), checked_24h: int0(h.claims_queue.checked_24h), confirmed_24h: int0(h.claims_queue.confirmed_24h),
        reported_24h: int0(h.claims_queue.reported_24h), denied_24h: int0(h.claims_queue.denied_24h) } : null,
      last_claims_at: isoOk(h.last_claims_at),
      grid_audit_flags: Array.isArray(h.grid_audit_flags) ? h.grid_audit_flags.filter(function (f) { return typeof f === "string" && /^[a-z0-9_]{1,40}$/.test(f); }).slice(0, 10) : null,
      grid_sources: obj(h.grid_sources),
      quality: cleanQuality(h.quality),
      backlog: B && nn(B.waiting) !== null ? { waiting: int0(B.waiting), incidents: int0(B.incidents), oldest_hours: nn(B.oldest_hours) || 0, oldest_incident_hours: nn(B.oldest_incident_hours) || 0 } : null,
      quarantined_count: int0(h.quarantined_count), quarantined: arr(h.quarantined, 5).map(function (q) { return txt(q, 160); }).filter(Boolean)
    };
  }
  /** The pipeline check's problems (health.json quality, from scripts/pipecheck.mjs): level, plain text, since when. */
  function cleanQuality(q) {
    if (!obj(q)) return null;
    var LV = { bad: "bad", warn: "warn", info: "info" };
    return { checked_at: isoOk(q.checked_at), problems: arr(q.problems, 30).filter(function (p) { return obj(p) && typeof p.id === "string" && /^[a-z0-9:_-]{1,60}$/.test(p.id) && typeof p.text === "string"; })
      .map(function (p) { return { id: p.id, level: has(LV, p.level) ? LV[p.level] : "info", text: txt(p.text, 300), since: isoOk(p.since), over: p.over === true }; }) };
  }
  // the badge for each kind of pipeline-check problem
  function qualityBadge(id) {
    return /^stage-/.test(id) ? "Late" : id === "status-keys" ? "Data lost" : id === "duplicates" ? "Duplicates" : id === "unreviewed" ? "Waiting" : id === "feeds-propose" || /^collector-/.test(id) ? "Not loading" : id === "broken-links" ? "Broken links" : "Check";
  }
  function countMap(o) { var out = {}; if (obj(o)) Object.keys(o).slice(0, 60).forEach(function (k) { var v = nn(o[k]); if (v !== null && /^[a-z0-9 -]{1,30}$/i.test(k)) out[k] = Math.max(0, Math.round(v)); }); return out; }
  var USAGE_STATE = ["logged", "partly logged", "not logged", "none (script)", "no runs"];
  var VERDICTS = ["useful", "noise", "nothing used yet", "silent"];
  /** Every field the page shows from efficiency.json, checked and cut to size; anything else is dropped. */
  function cleanEff(o) {
    if (!obj(o)) return null;
    if (typeof o.error === "string") return { error: txt(o.error, 240) };
    var cov = function (c) { c = obj(c) || {}; return { days: nn(c.days), events: int0(c.events), region: countMap(c.region), language: countMap(c.language), sector: countMap(c.sector), sector_basis: countMap(c.sector_basis) }; };
    var w = function (x) { x = obj(x) || {}; return { runs: int0(x.runs), tokens: int0(x.tokens), cost: nn(x.cost) }; };
    var LP = obj(o.loop), LB = LP && obj(LP.budget) || {}, lvl = function (x) { return x && ["ok", "tight", "stop"].indexOf(x.level) >= 0 ? x.level : ""; };
    var W = obj(o.windows) || {}, B = obj(W.budget), A = obj(o.accuracy) || {}, C = obj(o.coverage) || {}, CV = obj(o.covered) || {};
    var feed = function (f) {
      return { name: txt(f.name, 80), sources: arr(f.sources, 3).map(function (s) { return txt(s, 60); }).filter(Boolean), leads: int0(f.leads), used: int0(f.used), by_rule: int0(f.by_rule),
        yield: nn(f.yield), days_since_useful: nn(f.days_since_useful), ok: f.ok !== false, error: txt(f.error, 120), verdict: VERDICTS.indexOf(f.verdict) >= 0 ? f.verdict : "", retired: f.retired === true };
    };
    return {
      at: isoOk(o.at || o.built_at), note: txt(o.note, 300), days: nn(o.days) || 7, covered: { leads: nn(CV.leads), usage: nn(CV.usage), runs: nn(CV.runs) },
      windows: { estimate: W.estimate !== false, five: w(W.five_hour), week: w(W.week),
        budget: B ? { window_pct: nn(B.window_pct), week_pct: nn(B.week_pct), level: lvl(B), limited_until: isoOk(B.limited_until) } : null },
      loop: LP ? { cycles: int0(LP.cycles), idle: int0(LP.idle), idle_pct: nn(LP.idle_pct), ok: int0(LB.ok), tight: int0(LB.tight), stop: int0(LB.stop), unknown: int0(LB.unknown),
        leader: lvl(LP.leader_budget), last: lvl(LP.last_budget) } : null,
      routines: arr(o.routines, 80).filter(function (r) { return obj(r) && typeof r.key === "string"; }).map(function (r) {
        return { key: txt(r.key, 40), name: txt(r.name, 60) || txt(r.key, 40), runs: nn(r.runs), idle: nn(r.idle), idle_pct: nn(r.idle_pct), tokens: nn(r.tokens), idle_tokens: nn(r.idle_tokens), cost: nn(r.cost),
          added: int0(r.added), updated: int0(r.updated), reviewed: int0(r.reviewed), closed: int0(r.closed), filed: nn(r.filed), failures: int0(r.failures),
          usage: USAGE_STATE.indexOf(r.usage) >= 0 ? r.usage : "not logged", active: r.active !== false, retired: r.retired === true, last_run: isoOk(r.last_run) }; }),
      feeds: arr(o.feeds, 400).filter(function (f) { return obj(f) && typeof f.name === "string"; }).map(feed).filter(function (f) { return !f.retired; }),
      retired_feeds: arr(o.retired_feeds, 40).filter(function (f) { return obj(f) && typeof f.name === "string"; }).map(function (f) { return { name: txt(f.name, 80), leads: int0(f.leads), used: int0(f.used), at: txt(f.retired_at, 10), why: txt(f.why, 300) }; }),
      d7: cov(C.d7), d30: cov(C.d30), days_of_data: nn(C.days_of_data),
      accuracy: { days: nn(A.days) || 7, reviewed: int0(A.reviewed), corrected: int0(A.corrected), flagged: int0(A.flagged), corrected_pct: nn(A.corrected_pct),
        weeks: arr(A.weeks, 60).slice(-8).filter(function (x) { return obj(x) && /^\d{4}-\d{2}-\d{2}$/.test(x.week); }).map(function (x) { return { week: x.week, reviewed: int0(x.reviewed), corrected: int0(x.corrected), corrected_pct: nn(x.corrected_pct) }; }),
        categories: arr(A.categories, 12).filter(function (c) { return obj(c) && typeof c.name === "string"; }).map(function (c) { return { name: txt(c.name, 40), n: int0(c.n) }; }) },
      gaps: arr(o.gaps, 6).map(function (g) { return txt(g, 300); }).filter(Boolean),
      flow: cleanFlow(o.flow), sources: cleanSources(o.sources)
    };
  }
  /** The pipeline's stage counts (efficiency.json flow): last 24 hours and the report's 7 days, and what feeds it. */
  function cleanFlow(f) {
    if (!obj(f)) return null;
    if (typeof f.error === "string") return { error: txt(f.error, 240) };
    var S = obj(f.sources) || {}, T = obj(S.by_tier) || {};
    var win = function (w) {
      w = obj(w); if (!w) return null;
      return { hours: int0(w.hours), leads: int0(w.leads), stories: int0(w.stories), rule: int0(w.rule), researched: int0(w.researched), to_event: int0(w.to_event),
        reasons: arr(w.reasons, 3).filter(function (r) { return obj(r) && typeof r.reason === "string"; }).map(function (r) { return { reason: txt(r.reason, 120), n: int0(r.n) }; }),
        added: int0(w.added), updated: int0(w.updated), reviewed: int0(w.reviewed), passed: int0(w.passed), corrected: int0(w.corrected), flagged: int0(w.flagged) };
    };
    return { lead_days: nn(f.lead_days), d1: win(f.d1), d7: win(f.d7),
      sources: { feeds: int0(S.feeds), feeds_ok: nn(S.feeds_ok) === null ? null : int0(S.feeds_ok), gov: int0(T.gov), vendor: int0(T.vendor), news: int0(T.news), queries: int0(S.queries),
        collectors: int0(S.collectors), collectors_ok: int0(S.collectors_ok), languages: int0(S.languages), regions: int0(S.regions) } };
  }
  /** Where the week's events came from (efficiency.json sources): by tier and collector family, and the top publishers. */
  function cleanSources(s) {
    if (!obj(s)) return null;
    if (typeof s.error === "string") return { error: txt(s.error, 240) };
    return { events: int0(s.events), tier: countMap(s.tier), family: countMap(s.family),
      publishers: arr(s.publishers, 10).filter(function (p) { return obj(p) && typeof p.host === "string" && /^[a-z0-9.-]{1,100}$/i.test(p.host); })
        .map(function (p) { return { host: p.host.toLowerCase(), name: txt(p.name, 60) || p.host, events: int0(p.events) }; }) };
  }

  /* ---------------- shared pieces ---------------- */

  // routine state against the visitor's clock
  function state(r) {
    if (r.retired) return { cls: "neutral", text: "Retired — duties moved to " + (r.merged_into || "another job") };
    if (!r.active) return { cls: "wait", text: "Paused" };
    if (r.workflow === "flow" && !r.status_key) return { cls: "info", text: "Runs in the research loop" };
    if (!r.status_key) return { cls: "info", text: "See GitHub runs", link: /^[a-z0-9-]+\.yml$/.test(r.workflow) ? REPO + "/actions/workflows/" + r.workflow : "" };
    if (!r.last_at) {
      var since = r.active_since ? (Date.now() - Date.parse(r.active_since)) / 36e5 : Infinity;
      return since <= r.max_age_hours ? { cls: "info", text: "Waiting for first run" } : { cls: "bad", text: "No run recorded" };
    }
    var h = (Date.now() - Date.parse(r.last_at)) / 36e5;
    if (h <= r.max_age_hours) return { cls: "ok", text: "On time" };
    if (h <= 2 * r.max_age_hours) return { cls: "warn", text: "Late" };
    return { cls: "bad", text: "Stopped" };
  }
  // one table cell with a label for the phone layout (shown above or beside the value; hidden on wide screens)
  function cell(tr, label, value, cls) {
    var td = el("td", cls || null); td.appendChild(el("span", "lab", label));
    var v = el("span", "val"); if (value && value.nodeType) v.appendChild(value); else v.textContent = value == null ? "" : String(value);
    td.appendChild(v); tr.appendChild(td); return v;
  }
  function frag() { var f = el("span"); for (var i = 0; i < arguments.length; i++) { var a = arguments[i]; if (a == null || a === "") continue; f.appendChild(a.nodeType ? a : document.createTextNode(String(a))); } return f; }
  function yieldBar(pct) {
    var w = el("span", "ybar"); if (pct === null) { w.appendChild(el("span", "yval", "—")); return w; }
    var t = el("span", "ytrack"), f = el("span", "yfill"); f.style.width = Math.max(0, Math.min(100, pct)) + "%"; t.appendChild(f);
    w.appendChild(t); w.appendChild(el("span", "yval", pct + "%")); return w;
  }

  var COLLECTOR = { rss: "Agency, vendor and news RSS feeds", "bing-news": "Bing News standing searches", gdelt: "GDELT global news index", hibp: "Have I Been Pwned breach database",
    euvd: "ENISA EU Vulnerability Database (exploited)", nvd: "NIST NVD, new critical CVEs", "ransomware-live": "Leak-site listings (attackers' claims)", "hacker-news": "Hacker News discussion",
    "cloud-status": "Cloud providers' status pages", cvelist: "CVE List, new notable CVEs", "google-news": "Google News (retired)" };
  function feedLabel(name) {
    if (name.indexOf("rss:") === 0) return [name.slice(4), "RSS feed"];
    if (name.indexOf("feed:") === 0) return [name.slice(5), "RSS feed"];
    return [has(COLLECTOR, name) ? COLLECTOR[name] : name, "collector"];
  }
  var LANG = { en: "English", ja: "Japanese", ko: "Korean", de: "German", fr: "French", nl: "Dutch", es: "Spanish", pt: "Portuguese", it: "Italian", pl: "Polish", tr: "Turkish", ro: "Romanian",
    ru: "Russian", da: "Danish", vi: "Vietnamese", he: "Hebrew", id: "Indonesian", ar: "Arabic", zh: "Chinese", hu: "Hungarian", uk: "Ukrainian", sv: "Swedish", no: "Norwegian", fi: "Finnish",
    cs: "Czech", el: "Greek", th: "Thai", fa: "Persian" };
  function dimLabel(dim, k) {
    if (dim === "language") return has(LANG, k) ? LANG[k] : k === "not recorded" ? "Not recorded" : k;
    if (dim === "region" && k === "unplaced") return "No country";
    if (dim === "region" && k === "other") return "Other countries";
    var s = k.replace(/-/g, " "); return s.charAt(0).toUpperCase() + s.slice(1);
  }

  /* ---------------- A. health ---------------- */

  var checks = { ok: 0, bad: 0 };
  function renderHealth(h, m) {
    var ul = $("health"); ul.textContent = "";
    function row(ok, text) { var li = el("li"); li.appendChild(badge(ok ? "ok" : "warn", ok ? "OK" : "Check")); li.appendChild(document.createTextNode(" " + text)); li.dataset.ok = ok ? "1" : "0"; ul.appendChild(li); checks[ok ? "ok" : "bad"]++; }
    if (!h) { row(false, "The health record can't be loaded right now."); return; }
    var mins = function (iso) { return (Date.now() - Date.parse(iso)) / 6e4; };
    var lim = function (iso, max, label) { var v = mins(iso); row(isFinite(v) && v <= max, label + " " + (iso ? ago(iso) : "has not run yet") + (isFinite(v) && v > max ? " (expected within " + (max >= 120 ? Math.round(max / 60) + " h" : max + " min") + ")" : "")); };
    lim(h.built_at, 90, "Site data rebuilt");
    lim(h.last_sweep_at, 45, "Research run (every 15 minutes)");
    lim(h.last_collect_at, 120, "Feeds collected");
    lim(h.last_feeds_at, 360, "Vulnerability feeds synced");
    // power grid context layer: collection age, open incidents on the map, last cause research (context, not cyber events)
    if (h.grid) {
      var gv = mins(h.last_grid_at), gOk = isFinite(gv) && gv <= 120;
      row(gOk, "Power grid outages collected " + (h.last_grid_at ? ago(h.last_grid_at) : "not yet") + (h.last_grid_at && !gOk ? " (expected within 2 h)" : "") +
        (h.grid_open !== null ? "; " + plural(h.grid_open, "open incident") + " on the map" : "") +
        "; causes last checked " + (h.last_grid_research_at ? ago(h.last_grid_research_at) : "not yet") + " (context, not cyber events)");
      if (h.grid_analysis) lim(h.grid_analysis_at, 60, "Power grid analysis (no AI model) ran");
      if (h.grid_news) lim(h.last_grid_news_at, 60, "Power outages in the news collected");
      var gw = h.grid_waiting;
      if (gw) row(!(gw.count && gw.oldest_min > 120), "Grid outages waiting for a cause check: " + gw.count + (gw.count ? "; oldest " + (gw.oldest_min >= 120 ? Math.round(gw.oldest_min / 60) + " h" : gw.oldest_min + " min") : "") + (gw.count && gw.oldest_min > 120 ? " (expected within 2 h)" : ""));
      var gf = h.grid_audit_flags;
      if (gf) row(!gf.length, gf.length ? "Grid data audit (no AI model) flags: " + gf.map(function (f) { return f.replace(/_/g, " "); }).join(", ") : "Grid data audit (no AI model): no pipeline flags");
    }
    // the outage desk (scripts/outage-desk.mjs): outage reports nobody had checked, checked by CyberView AI in the research loop
    var oq = h.outage_queue;
    if (oq) row(!(oq.waiting && oq.oldest_min > 720), "Outage desk (" + AI_BY + "): " + plural(oq.waiting, "outage report") + " waiting for a check; " + oq.checked_24h + " checked in 24 h" +
      (oq.checked_24h ? " (" + oq.confirmed_24h + " confirmed" + (oq.cyber_leads_24h ? ", " + plural(oq.cyber_leads_24h, "cyber lead") + " passed to research" : "") + ")" : "") +
      "; last run " + (h.last_outage_at ? ago(h.last_outage_at) : "not yet") + (oq.waiting && oq.oldest_min > 720 ? " (the oldest report has waited over 12 h)" : ""));
    // the claims desk (scripts/claims-desk.mjs): leak-site claims, checked by CyberView AI in the research loop, most notable
    // first; a long queue of minor claims is normal, so the row asks only that the desk keeps running while claims wait
    var cq = h.claims_queue, cAge = h.last_claims_at ? (Date.now() - Date.parse(h.last_claims_at)) / 36e5 : Infinity;
    if (cq) row(!(cq.waiting && cAge > 6), "Claims desk (" + AI_BY + "): " + plural(cq.waiting, "leak-site claim") + " waiting for a check; " + cq.checked_24h + " checked in 24 h" +
      (cq.checked_24h ? " (" + cq.confirmed_24h + " confirmed by the organisation, " + cq.reported_24h + " reported, " + cq.denied_24h + " denied)" : "") +
      "; last run " + (h.last_claims_at ? ago(h.last_claims_at) : "not yet") + (cq.waiting && cAge > 6 ? " (expected every research cycle)" : ""));
    var bl = h.backlog;
    if (bl) row(bl.waiting <= 60 && !(bl.oldest_incident_hours > 2), "Research queue: " + plural(bl.waiting, "report") + " waiting for a decision" + (bl.incidents ? ", " + bl.incidents + " that read like incidents" : "") + (bl.waiting ? "; oldest " + bl.oldest_hours + " h" : "") + (bl.waiting > 60 ? " (expected under 60)" : ""));
    var q = h.quarantined_count;
    row(q === 0, q === 0 ? "Every record passed validation" : plural(q, "record") + " failed validation and " + (q === 1 ? "is" : "are") + " left out until fixed");
    if (m && obj(m.counts)) row(true, "Published: " + int0(m.counts.events_total) + " events on file, " + int0(m.counts.events_bundle) + " in the seven-day map, " + int0(m.counts.kev_total) + " known-exploited flaws" + (typeof m.commit === "string" && /^[0-9a-f]{7,40}$/.test(m.commit) ? " (build " + m.commit.slice(0, 7) + ")" : ""));
  }
  // which data commit (data branch) and code commit (main) the live site was built from (manifest.json, written by the
  // deploy); a deploy from before the data branch has no data_commit and shows code only
  function liveCommits(m) {
    if (!obj(m)) return;
    var sha = function (v) { return typeof v === "string" && /^[0-9a-f]{7,40}$/.test(v) ? v : ""; }, d = sha(m.data_commit), c = sha(m.commit);
    if (!d && !c) return;
    var at = [m.data_commit_at, m.built_at].filter(function (v) { return typeof v === "string" && isFinite(Date.parse(v)); })[0] || "";
    var p = $("liveCommits"); p.textContent = "Live: ";
    function lk(s, label) { var a = link(REPO + "/commit/" + s, s.slice(0, 7)); a.title = label + " " + s; return a; }
    if (d) { p.appendChild(document.createTextNode("data ")); p.appendChild(lk(d, "data branch commit")); if (at) p.appendChild(document.createTextNode(" (" + ago(at) + ")")); }
    else p.appendChild(document.createTextNode("data not recorded (built " + (at ? ago(at) : "at an unknown time") + ")"));
    if (c) { p.appendChild(document.createTextNode(", code ")); p.appendChild(lk(c, "main commit")); }
    p.dataset.data = d.slice(0, 7); p.dataset.code = c.slice(0, 7); p.hidden = false;
  }

  /* ---------------- B. how the data flows: one box per stage, left to right (stacked on phones) ---------------- */

  function fmt(n) { return n === null || n === undefined ? "—" : Number(n).toLocaleString("en"); }
  function pctOf(a, b) { return b ? Math.round(a / b * 100) : null; }
  function sentence(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ""; }
  // the stages, with every number from efficiency.json (flow) and manifest.json (the map); "—" when missing
  function flowStages(F, ops, m) {
    var a = F && F.d1, b = F && F.d7, S = F && F.sources, has1 = !!a, C = m && obj(m.counts) ? m.counts : null;
    var open = ops && ops.pipeline && ops.pipeline.open !== null ? ops.pipeline.open : null, decided = has1 ? a.rule + a.researched : 0;
    return [
      { key: "sources", name: "Sources", fig: S ? fmt(S.feeds) + " feeds" : "—", per: "", f7: "",
        sub: S ? "+ " + S.collectors_ok + " of " + S.collectors + " collectors, " + S.queries + " news searches" : "",
        what: S ? S.gov + " government or CERT, " + S.vendor + " vendor, " + S.news + " news feeds; " + S.languages + " languages, " + S.regions + " regions." : "Government, vendor and news feeds, news searches in many languages, and public databases.",
        share: S && S.feeds_ok !== null ? fmt(S.feeds_ok) + " of " + fmt(S.feeds) + " loading, every 30 min" : "Checked every 30 minutes" },
      { key: "leads", name: "Leads collected", fig: has1 ? fmt(a.leads) : "—", f7: b ? fmt(b.leads) : "",
        what: "New items the feeds, searches and databases filed. Scripts, no AI model.",
        share: has1 && a.leads ? "Grouped into " + fmt(a.stories) + " stories, " + (a.leads / Math.max(1, a.stories)).toFixed(1) + " leads each" : "" },
      { key: "stories", name: "Stories", fig: has1 ? fmt(a.stories) : "—", f7: b ? fmt(b.stories) : "",
        what: "Leads about the same thing grouped into one story by a script, so each is read once.",
        share: has1 ? "Decided in the same 24 h: " + fmt(a.rule) + " by rule, " + fmt(a.researched) + " by AI agents" + (open !== null ? "; " + fmt(open) + " waiting now" : "") : "" },
      { key: "rule", name: "Closed by rule", fig: has1 ? fmt(a.rule) : "—", f7: b ? fmt(b.rule) : "",
        what: "No AI model." + (has1 && a.reasons.length ? " Top reasons, 24 h:" : ""), reasons: has1 ? a.reasons : [],
        share: has1 && decided ? pctOf(a.rule, decided) + "% of the stories decided stop here" : "" },
      { key: "ai", name: "Researched by AI agents", fig: has1 ? fmt(a.researched) : "—", f7: b ? fmt(b.researched) : "",
        what: "Stories read from the original pages by CyberView AI (a Claude model).",
        share: has1 && a.researched ? fmt(a.to_event) + " (" + pctOf(a.to_event, a.researched) + "%) became or updated an event" : "" },
      { key: "published", name: "Published events", fig: has1 ? fmt(a.added + a.updated) : "—", f7: b ? fmt(b.added + b.updated) : "",
        sub: has1 ? fmt(a.added) + " new, " + fmt(a.updated) + " updated" : "",
        what: "Checked events written up from the pages read, then validated and published by scripts.",
        share: has1 ? fmt(a.reviewed) + " second-reviewed in the same 24 h" : "" },
      { key: "review", name: "Second review", fig: has1 ? fmt(a.reviewed) : "—", f7: b ? fmt(b.reviewed) : "",
        sub: has1 ? fmt(a.passed) + " passed, " + fmt(a.corrected) + " corrected, " + fmt(a.flagged) + " flagged" : "",
        what: "A different AI agent checks every new or changed event against its sources.",
        share: has1 && a.reviewed ? pctOf(a.passed, a.reviewed) + "% passed unchanged" : "" },
      { key: "map", name: "On the map", fig: C ? fmt(int0(C.events_bundle)) : "—", f7: "",
        sub: C ? "of " + fmt(int0(C.events_total)) + " events on file" : "",
        what: "Checked events of the last seven days, drawn on the globe.", share: "" }
    ];
  }
  function renderFlow(e, ops, m) {
    var ol = $("flow"), F = e && !e.error ? e.flow : null, err = F && F.error ? F.error : "";
    ol.textContent = "";
    if (err) F = null;
    $("secFlow").dataset.state = F && F.d1 ? "ok" : (e && e.error) || err ? "error" : "missing";
    flowStages(F, ops, m).forEach(function (s, i, all) {
      var li = el("li", "fstage"); li.dataset.stage = s.key;
      var L = el("div", "fl"), R = el("div", "fr"); li.appendChild(L); li.appendChild(R);
      L.appendChild(el("h3", "fname", s.name));
      var fig = el("p", "ffig"); fig.appendChild(el("span", "fnum", s.fig));
      if (s.key !== "sources" && s.key !== "map") fig.appendChild(el("span", "fper", s.fig === "—" ? " not available" : " in 24 h"));
      if (s.f7) { fig.appendChild(el("span", "fsep", " · ")); fig.appendChild(el("span", "f7", s.f7 + " in 7 days")); }
      L.appendChild(fig);
      if (s.sub) R.appendChild(el("p", "fsub", s.sub));
      R.appendChild(el("p", "fwhat", s.what));
      if (s.reasons && s.reasons.length) {
        var ul = el("ul", "freasons");
        s.reasons.forEach(function (r) { var x = el("li"); x.title = sentence(r.reason); x.appendChild(el("span", "frn", fmt(r.n))); x.appendChild(document.createTextNode(" " + sentence(r.reason.split(",")[0].replace(/^(a|an) /, "")))); ul.appendChild(x); });
        li.appendChild(ul);
      }
      if (s.share) li.appendChild(el("p", "fshare", s.share));
      if (i < all.length - 1) { var ar = el("span", "farrow", "→"); ar.setAttribute("aria-hidden", "true"); li.appendChild(ar); }
      ol.appendChild(li);
    });
    var ld = F ? F.lead_days : null;
    $("flowNote").textContent = e && e.error ? e.error : err ? err : !F ? "The flow figures are not available yet; they are worked out at every build by a script with no AI model." :
      "Each stage counts what it did in the window (leads when seen, decisions when made, events when published, reviews when first done), so the stages need not add up." +
      (ld !== null && ld < 7 ? " The 7-day figures rest on " + ld + " days of lead data, all there is so far." : "");
  }

  /* ---------------- B2. where the data comes from: the week's events by tier, collector, region and language ---------------- */

  var TIER_LABEL = { gov: "Government or CERT", vendor: "Security vendor", news: "News", database: "Database row (CVE, breach)", untraced: "No lead (own search)", "before-leads": "Before lead files" };
  var FAMILY_LABEL = { rss: "Agency, vendor, news RSS", "bing-news": "Bing News", gdelt: "GDELT", "google-news": "Google News (retired)", "cve-kev": "CVE corpus, NVD and KEV", claims: "Leak-site claims",
    grid: "Grid operators", other: "Other open sources", untraced: "No lead (own search)", "before-leads": "Before lead files" };
  function barList(counts, label, keep, max) {
    var c = {}; Object.keys(counts).forEach(function (k) { c[k] = counts[k]; }); (keep || []).forEach(function (k) { if (!has(c, k)) c[k] = 0; });
    var keys = Object.keys(c).sort(function (x, y) { return c[y] - c[x] || (x < y ? -1 : 1); }), top = Math.max.apply(null, keys.map(function (k) { return c[k]; }).concat([1])), ul = el("ul", "hbars");
    keys.slice(0, max || 8).forEach(function (k) {
      var row = el("li", "hrow"); row.dataset.key = k; row.title = label(k); row.appendChild(el("span", "hlab", label(k)));
      var t = el("span", "htrack"), f = el("span", "hfill"); f.style.width = (c[k] / top * 100) + "%"; t.appendChild(f); row.appendChild(t);
      row.appendChild(el("span", "hval", fmt(c[k]))); ul.appendChild(row);
    });
    if (!keys.length) ul.appendChild(el("li", "muted", "No events yet."));
    var none = keys.filter(function (k) { return !c[k]; }), shown = keys.filter(function (k) { return c[k]; }).slice(0, max || 8);
    Array.prototype.slice.call(ul.children).forEach(function (r) { if (r.dataset.key && shown.indexOf(r.dataset.key) < 0) ul.removeChild(r); });
    var more = keys.length - none.length - shown.length;
    if (more > 0) ul.appendChild(el("li", "muted", more + " more with fewer events"));
    if (none.length) { var z = el("li", "muted hnone", "None this week: " + none.map(label).join(", ")); z.dataset.none = none.join(" "); ul.appendChild(z); }
    return ul;
  }
  function renderFrom(e) {
    var box = $("from"), S = e && !e.error ? e.sources : null; box.textContent = "";
    if (!S || S.error) { $("fromNote").textContent = S && S.error ? S.error : "The source breakdown is in the efficiency report, which is not available yet."; $("secFrom").dataset.state = "missing"; return; }
    $("secFrom").dataset.state = "ok";
    function block(key, title, jumpTo, list) {
      var d = el("div", "fblock"); d.dataset.from = key;
      var h = el("h3"); h.appendChild(document.createTextNode(title + " ")); h.appendChild(jump(jumpTo, "details")); d.appendChild(h);
      d.appendChild(list); box.appendChild(d);
    }
    block("tier", "By source tier", "dFeeds", barList(S.tier, function (k) { return has(TIER_LABEL, k) ? TIER_LABEL[k] : dimLabel("", k); }, ["gov", "vendor", "news", "database"], 7));
    block("family", "By collector", "dFeeds", barList(S.family, function (k) { return has(FAMILY_LABEL, k) ? FAMILY_LABEL[k] : dimLabel("", k); }, ["rss", "bing-news", "gdelt", "cve-kev", "claims", "grid"], 7));
    // phones show five rows per block (the rest is counted on the "more" line and listed in the details)
    var rows = window.matchMedia && window.matchMedia("(max-width: 600px)").matches ? 5 : 6;
    block("region", "By region", "dCoverage", barList(e.d7.region, function (k) { return dimLabel("region", k); }, [], rows));
    block("language", "By language", "dCoverage", barList(e.d7.language, function (k) { return dimLabel("language", k); }, [], rows));
    var pub = {}, names = {}; S.publishers.forEach(function (p) { pub[p.host] = p.events; names[p.host] = p.name; });
    var pl = barList(pub, function (k) { return names[k]; }, [], 10);
    Array.prototype.forEach.call(pl.querySelectorAll(".hrow"), function (r) { r.title = names[r.dataset.key] + " (" + r.dataset.key + ")"; });
    block("publishers", "Top publishers cited", "dCoverage", pl);
    var dd = e.days_of_data;
    $("fromNote").textContent = fmt(S.events) + " events first seen in the last 7 days" + (dd !== null && dd < 7 ? " (the event files hold " + dd + " days so far)" : "") + ".";
  }

  /* ---------------- D. routines: schedule and state merged with usage and output ---------------- */

  function renderRoutines(ops, e, attn) {
    var rows = ops ? ops.routines : [], effBy = {}, act = $("routines").querySelector("tbody"), off = $("routinesOff").querySelector("tbody"), counts = { ok: 0, active: 0, off: 0 };
    act.textContent = ""; off.textContent = "";
    if (e && !e.error) e.routines.forEach(function (x) { effBy[x.key] = x; });
    var list = rows.slice();
    // routines the efficiency report saw that routines.json does not list (its "other" row)
    if (e && !e.error) e.routines.forEach(function (x) { if (!rows.some(function (r) { return r.key === x.key; }) && (x.runs || x.tokens)) list.push({ key: x.key, name: x.name, does: "Work the report could not match to a routine.", tier: "ai", active: true, max_age_hours: 24, extra: true }); });
    list.sort(function (a, b) { return (b.active ? 1 : 0) - (a.active ? 1 : 0); });
    list.forEach(function (r) {
      // a routine whose job wrote no status timestamp is judged by its last run in the run logs and usage log
      var x0 = effBy[r.key];
      if (!r.last_at && x0 && x0.last_run && r.status_key) { r = Object.assign({}, r, { last_at: x0.last_run, from_log: true }); }
      var s = r.extra ? { cls: "info", text: "Not in routines.json" } : state(r), x = effBy[r.key] || null, tr = el("tr");
      tr.dataset.routine = r.key;
      if (r.active) { counts.active++; if (s.cls === "ok" || s.cls === "info") counts.ok++; else attn.push({ cls: s.cls, badge: s.text, text: r.name + " last ran " + (r.last_at ? ago(r.last_at) : "never as far as the logs show") + (r.max_age_hours ? " (expected within " + r.max_age_hours + " h)" : ""), href: s.link || "", jump: s.link ? "" : "dRoutines" }); }
      else counts.off++;
      var name = el("td", "rname"); name.appendChild(el("strong", null, r.name));
      name.appendChild(el("span", "sub2", (r.tier === "ai" ? "AI · " + (MODEL[r.model] || r.model || "model not set") : "Script, no AI model") + (r.does ? " — " + r.does : "")));
      tr.appendChild(name);
      cell(tr, "When", r.workflow === "flow" && !r.cron ? "in the research loop" : when(r.cron) || "—", "nowrap");
      var st = s.link ? link(s.link, s.text) : el("span", null, s.text); st.className = "badge " + s.cls;
      cell(tr, "Last run", frag(st, " ", r.last_at ? ago(r.last_at) + (r.from_log ? " (run log)" : "") : ""));
      cell(tr, "Runs", !x ? "—" : (x.runs === null ? "not logged" : String(x.runs)) + (x.idle_pct !== null ? " (" + x.idle + " idle, " + x.idle_pct + "%" + (x.idle_tokens ? ", " + big(x.idle_tokens) + " tokens" : "") + ")" : ""));
      cell(tr, "Usage", !x ? "—" : x.usage === "none (script)" ? "none (script)" : x.tokens === null ? frag(badge(x.usage === "no runs" ? "neutral" : "warn", x.usage)) : big(x.tokens) + " tokens" + (x.cost !== null ? " ($" + x.cost.toFixed(2) + ")" : "") + (x.usage === "partly logged" ? " (partly logged)" : ""));
      cell(tr, "Output", !x ? "—" : x.filed !== null ? x.filed + " leads filed" : x.added + " added, " + x.updated + " updated, " + x.reviewed + " reviewed, " + x.closed + " closed" + (x.failures ? "; " + x.failures + " failed" : ""));
      (r.active ? act : off).appendChild(tr);
    });
    $("routinesSum").textContent = counts.ok + " of " + counts.active + " active on time" + (counts.off ? " · " + counts.off + " retired or paused" : "");
    $("dRetired").hidden = !counts.off; $("retiredSum").textContent = "Retired and paused routines (" + counts.off + ")";
    return counts;
  }
  function renderUsage(e) {
    if (!e || e.error) return;
    var w = e.windows, b = w.budget, p = $("effUsage");
    p.textContent = "Usage: " + big(w.five.tokens) + " tokens in the last 5 hours (" + w.five.runs + " worker runs) and " + big(w.week.tokens) + " in the last 7 days (" + w.week.runs + " worker runs), cache reads included" +
      (b && b.level ? "; budget level " + b.level + (b.window_pct !== null ? ", " + b.window_pct + "% of the estimated 5-hour window" : "") + (b.week_pct !== null ? ", " + b.week_pct + "% of the estimated week" : "") + (b.limited_until ? ", limited until " + b.limited_until.slice(11, 16) + " UTC" : "") : "") +
      (w.estimate ? ". This is an estimate from the worker log: the plan's limits are not known here, and jobs run inside the ops session are not logged." : ". Only headless workers are logged; jobs run inside the ops session are not.");
    var L = e.loop;
    if (L) p.appendChild(document.createTextNode(" Research loop: " + L.cycles + " cycles, " + L.idle + " idle" + (L.idle_pct !== null ? " (" + L.idle_pct + "%)" : "") +
      "; budget level per cycle: " + L.ok + " ok, " + L.tight + " tight, " + L.stop + " stopped" + (L.unknown ? ", " + L.unknown + " not recorded" : "") +
      (L.leader ? "; the running loop last saw " + L.leader : L.last ? "; last cycle saw " + L.last : "") + "."));
    if (e.covered.runs !== null) p.appendChild(document.createTextNode(" Runs, usage and output cover the last " + e.days + " days, of which the run logs hold " + e.covered.runs + "."));
  }

  /* ---------------- D. feeds and collectors ---------------- */

  function feedRow(tb, f) {
    var tr = el("tr"), lab = feedLabel(f.name), name = el("td", "rname"); tr.dataset.feed = f.name;
    name.appendChild(el("strong", null, lab[0]));
    name.appendChild(el("span", "sub2", lab[1] + (f.sources.length && lab[1] === "RSS feed" ? ": " + f.sources.join(", ") : "") + (f.ok ? "" : " · not loading" + (f.error ? ": " + f.error : ""))));
    tr.appendChild(name);
    cell(tr, "Leads", String(f.leads), "num"); cell(tr, "Used", String(f.used), "num");
    cell(tr, "Yield", yieldBar(f.yield));
    cell(tr, "Last useful lead", f.days_since_useful !== null ? f.days_since_useful + " days ago" : f.verdict === "noise" ? "none (noise)" : "none yet");
    tb.appendChild(tr);
  }
  function renderFeeds(ops, e, attn) {
    var P = ops ? ops.pipeline : null, srcs = ops ? ops.sources : [], col = {}, failed = ops ? ops.leads.failed : [];
    if (P) P.collectors.forEach(function (c) { col[c.name] = c; });
    safe(function () {
      if (P && P.leads_7d !== null) $("pipe").textContent = (P.feeds ? P.feeds + " RSS feeds and " : "") + srcs.length + " other collectors. " + (P.days !== null && P.days < 7 ? "Last 7 days (the lead files hold only " + P.days + " days so far): " : "Last 7 days: ") + P.leads_7d + " leads" +
        (P.used_7d !== null ? " (" + P.used_7d + " in stories that became or updated an event)" : "") + ", " + P.events_7d + " events" + (P.median_hours !== null ? ", median " + P.median_hours + " h from first lead to the map" : "") + ". " +
        (P.open !== null ? P.open + " stories waiting, " + (P.corroborated || 0) + " of them reported by two or more publishers." : "");
    });
    safe(function () {
      var tb = $("sources").querySelector("tbody"); tb.textContent = "";
      var rows = [{ name: "rss", ok: !failed.length, error: failed.length ? plural(failed.length, "feed") + " not loading" : "", at: "" }].concat(srcs);
      rows.slice(0, 20).forEach(function (x) {
        var c = col[x.name] || {}, tr = el("tr"), name = el("td", "rname"); tr.dataset.src = x.name;
        name.appendChild(el("strong", null, has(COLLECTOR, x.name) ? COLLECTOR[x.name] : x.name)); name.appendChild(el("span", "sub2", x.name)); tr.appendChild(name);
        cell(tr, "Last check", x.at ? ago(x.at) : x.name === "rss" ? "every 30 min" : "—");
        cell(tr, "State", frag(badge(x.ok ? "ok" : "warn", x.ok ? "Working" : "Not loading"), !x.ok && x.error ? " " + x.error : ""));
        cell(tr, "Leads", c.leads != null ? String(c.leads) : "—", "num"); cell(tr, "In events", c.used != null ? String(c.used) : "—", "num");
        tb.appendChild(tr);
        if (!x.ok && x.name !== "rss") attn.push({ cls: "warn", badge: "Not loading", text: "Collector " + (has(COLLECTOR, x.name) ? COLLECTOR[x.name] : x.name) + (x.error ? ": " + x.error : ""), jump: "dFeeds" });
      });
      failed.forEach(function (f) { attn.push({ cls: "warn", badge: "Not loading", text: "Feed " + f, jump: "dFeeds" }); });
    });
    var nFeeds = 0, notLoading = 0;
    safe(function () {
      if (!e || e.error) return;
      var withLeads = e.feeds.filter(function (f) { return f.leads > 0; }), silent = e.feeds.filter(function (f) { return !f.leads; }), top = withLeads.slice(0, 15), rest = withLeads.slice(15);
      nFeeds = e.feeds.length; notLoading = e.feeds.filter(function (f) { return !f.ok; }).length;
      var tb = $("effFeeds").querySelector("tbody"); tb.textContent = ""; top.forEach(function (f) { feedRow(tb, f); });
      var tb2 = $("effFeedsAll").querySelector("tbody"); tb2.textContent = ""; rest.forEach(function (f) { feedRow(tb2, f); });
      $("dFeedsAll").hidden = !rest.length && !silent.length;
      $("feedsAllSum").textContent = "Show all " + withLeads.length + " feeds with leads" + (silent.length ? " and " + silent.length + " that filed none" : "");
      $("effFeedsMore").textContent = silent.length ? plural(silent.length, "configured feed") + " filed no lead at all: " + silent.map(function (f) { return f.name.replace(/^feed:/, "") + (f.ok ? "" : " (not loading)"); }).join(", ") + "." : "";
    });
    safe(function () {
      var R = (e && !e.error ? e.retired_feeds : []), RC = P ? P.retired : [], p = $("retiredFeeds"), seen = {};
      var items = R.map(function (f) { seen[f.name] = 1; return feedLabel(f.name)[0] + " (retired " + (f.at || "") + "; " + f.leads + " leads on file, still counted)"; })
        .concat(RC.filter(function (c) { return !seen[c.name]; }).map(function (c) { return (has(COLLECTOR, c.name) ? COLLECTOR[c.name] : c.name) + " (retired " + c.retired + ")"; }));
      if (!items.length) return;
      p.textContent = "No longer collected: " + items.join("; ") + ". " + ((R[0] && R[0].why) || (RC[0] && RC[0].why) || "");
      p.hidden = false;
    });
    $("feedsSum").textContent = (P && P.feeds ? P.feeds + " RSS feeds, " : nFeeds ? nFeeds + " feeds, " : "") + srcs.length + " collectors" + (failed.length || notLoading ? " · " + (failed.length || notLoading) + " not loading" : "");
  }

  /* ---------------- D. grid sources ---------------- */

  // human names for every source key; the data's own name comes first (health.json grid_sources)
  var GRID_SRC = { hydroquebec: ["Hydro-Québec", "outages in Quebec"], bchydro: ["BC Hydro", "outages in British Columbia"], ukpn: ["UK Power Networks", "faults in London, the South East and East of England"],
    eskom: ["Eskom", "load shedding in South Africa"], ercot: ["ERCOT", "grid conditions in Texas"], aemo: ["AEMO", "market notices in Australia"],
    eia: ["EIA", "US electricity demand (needs a key)"], cfradar: ["Cloudflare Radar", "internet outages with a power cause (needs a key)"], entsoe: ["ENTSO-E", "generation and transmission outages in Europe (needs a key)"],
    ioda: ["IODA internet outages", "internet disruption signals"], gdacs: ["GDACS disaster alerts", "disaster alerts"] };
  var FLAG_WORDS = { failing_over_24h: "failing for over a day", stale_data: "the operator's data is old", dormant: "the feed has published nothing for weeks",
    suddenly_empty: "suddenly empty", surge: "ten times more items than usual", customers_missing: "items without customer counts", zero_customers: "no customers in any item",
    customers_fell: "customer total fell sharply", locations_suspect: "locations far from the country", future_times: "start times in the future", duplicate_ids: "duplicate ids", links_off_host: "links off the operator's site" };
  function renderGrid(h, attn) {
    var gs = h && h.grid_sources; if (!gs) return;
    var rows = Object.keys(gs).filter(function (k) { return /^[a-z0-9_-]{1,40}$/.test(k) && obj(gs[k]); }).slice(0, 200).map(function (k) {
      var x = gs[k], err = txt(x.error, 120), nc = x.ok !== true && /^not connected/i.test(err);
      var flags = Array.isArray(x.flags) ? x.flags.filter(function (f) { return typeof f === "string" && has(FLAG_WORDS, f); }).slice(0, 4) : [];
      var st = x.paused === true ? ["neutral", "Paused", 3] : nc ? ["neutral", "Not connected", 4] : x.ok !== true ? ["warn", "Not loading", 0]
        : x.dormant === true ? ["warn", "Dormant", 1] : x.stale === true ? ["warn", "Stale data", 1] : flags.length ? ["warn", "Check", 2] : ["ok", "Working", 5];
      var d = has(GRID_SRC, k) ? GRID_SRC[k] : null;
      return { k: k, x: x, err: err, nc: nc, flags: flags, st: st, d: d, name: txt(x.name, 60).trim() || (d ? d[0] : k), cc: /^[A-Z]{2}$/.test(String(x.country || "")) ? x.country : "", at: isoOk(x.at) };
    });
    rows.sort(function (a, b) { return a.st[2] - b.st[2] || (a.cc < b.cc ? -1 : a.cc > b.cc ? 1 : 0) || (a.k < b.k ? -1 : 1); });
    function li(r) {
      var n = el("li"); n.appendChild(badge(r.st[0], r.st[1]));
      n.appendChild(document.createTextNode(" " + r.name + (r.d && r.d[0] !== r.name ? " (" + r.d[0] + ")" : "") + (r.d ? ": " + r.d[1] : r.cc ? " (" + r.cc + ")" : "") +
        (r.nc ? " · no key saved" : r.x.ok !== true && r.err ? " · " + r.err : (r.x.stale || r.x.dormant) && r.err ? " · " + r.err : "") +
        (r.flags.length ? " · " + r.flags.map(function (f) { return FLAG_WORDS[f]; }).join(", ") : "") + (r.at ? " · checked " + ago(r.at) : "")));
      n.dataset.src = r.k; return n;
    }
    var all = $("gridSources"), probs = $("gridProblems"); all.textContent = ""; probs.textContent = "";
    var c = { working: 0, paused: 0, key: 0, bad: 0 };
    rows.forEach(function (r) {
      all.appendChild(li(r));
      if (r.st[1] === "Working") c.working++; else if (r.st[1] === "Paused") c.paused++; else if (r.st[1] === "Not connected") c.key++; else c.bad++;
      if (r.st[1] !== "Working") probs.appendChild(li(r));
      if (r.st[0] === "warn") attn.push({ cls: "warn", badge: r.st[1], text: "Grid source " + r.name + (r.x.ok !== true && r.err ? ": " + r.err : r.flags.length ? ": " + r.flags.map(function (f) { return FLAG_WORDS[f]; }).join(", ") : ""), jump: "gridSrcBox" });
    });
    if (!probs.children.length) probs.appendChild(el("li", "muted", "Every grid source is working."));
    var sum = c.working + " of " + rows.length + " working" + (c.bad ? " · " + c.bad + " failing or flagged" : "") + (c.paused ? " · " + c.paused + " paused" : "") + (c.key ? " · " + c.key + " need" + (c.key === 1 ? "s" : "") + " a key" : "");
    $("gridSum").textContent = sum; $("gridAllSum").textContent = "All " + rows.length + " grid sources";
    $("gridSrcBox").dataset.working = String(c.working); $("gridSrcBox").hidden = false;
  }

  /* ---------------- D. coverage ---------------- */

  function renderCoverage(e) {
    if (!e || e.error) { $("covNote").textContent = "Coverage is in the efficiency report, which is not available."; return; }
    var box = $("effCoverage"); box.textContent = "";
    var same = e.d7.events === e.d30.events, dd = e.days_of_data;
    [["region", "By region"], ["language", "By language"], ["sector", "By sector (critical infrastructure)"]].forEach(function (d) {
      var div = el("div"); div.dataset.cov = d[0]; div.appendChild(el("h3", null, d[1]));
      var a = e.d7[d[0]], b = e.d30[d[0]], keys = Object.keys(a).concat(Object.keys(b).filter(function (k) { return !(k in a); }));
      keys.sort(function (x, y) { return (a[y] || 0) - (a[x] || 0) || (b[y] || 0) - (b[x] || 0) || (x < y ? -1 : 1); });
      var max = Math.max.apply(null, keys.map(function (k) { return a[k] || 0; }).concat([1])), ul = el("ul", "hbars");
      keys.slice(0, 12).forEach(function (k) {
        var v = a[k] || 0, w = b[k] || 0, row = el("li", "hrow"); row.dataset.key = k;
        row.appendChild(el("span", "hlab", dimLabel(d[0], k)));
        var t = el("span", "htrack"), f = el("span", "hfill"); f.style.width = (v / max * 100) + "%"; t.appendChild(f); row.appendChild(t);
        row.appendChild(el("span", "hval", String(v) + (!same && w !== v ? " · " + w + " in 30 d" : "")));
        ul.appendChild(row);
      });
      if (!keys.length) ul.appendChild(el("li", "muted", "No events yet."));
      if (keys.length > 12) ul.appendChild(el("li", "muted", (keys.length - 12) + " more with fewer events"));
      div.appendChild(ul);
      if (d[0] === "sector") { var sb = e.d7.sector_basis || {}, bn = el("p", "note", "Sector of the " + e.d7.events + " events in 7 days: " + (sb.stated || 0) + " stated by the source, " + (sb.inferred || 0) + " inferred by CyberView AI (a Claude model), " + (sb.keyword || 0) + " keyword-assigned from the wording (can be wrong)."); bn.dataset.basis = "sector"; div.appendChild(bn); }
      box.appendChild(div);
    });
    $("covNote").textContent = same ? e.d7.events + " events first seen in the last " + (dd !== null && dd < 7 ? dd + " days (all the event files hold so far, so the 7- and 30-day counts are the same)" : "7 days") + "."
      : e.d7.events + " events first seen in the last 7 days; " + e.d30.events + " in the last 30" + (dd !== null && dd < 30 ? " (the event files hold " + dd + " days)" : "") + ". Bars show 7 days.";
    $("covSum").textContent = e.d7.events + " events" + (dd !== null ? " · " + dd + " days of data" : "");
  }

  /* ---------------- D. accuracy ---------------- */

  function renderAccuracy(e) {
    if (!e || e.error) return;
    var A = e.accuracy, tb = $("accTotals").querySelector("tbody"); tb.textContent = "";
    $("accDays").textContent = String(A.days);
    [["Reviewed", String(A.reviewed)], ["Corrected", A.corrected + (A.corrected_pct !== null ? " (" + A.corrected_pct + "%)" : "")], ["Flagged", String(A.flagged)]].forEach(function (r) {
      var tr = el("tr"); tr.appendChild(el("th", null, r[0])).scope = "row"; tr.appendChild(el("td", "num", r[1])); tb.appendChild(tr);
    });
    var wb = $("accWeeks").querySelector("tbody"); wb.textContent = "";
    A.weeks.forEach(function (w) { var tr = el("tr"); tr.appendChild(el("td", null, w.week)); tr.appendChild(el("td", "num", String(w.reviewed))); tr.appendChild(el("td", "num", w.corrected + (w.corrected_pct !== null ? " (" + w.corrected_pct + "%)" : ""))); wb.appendChild(tr); });
    if (!A.weeks.length) { var tr0 = el("tr"); tr0.appendChild(el("td", "muted", "No reviews yet.")); wb.appendChild(tr0); }
    var cb = $("accCats").querySelector("tbody"); cb.textContent = "";
    A.categories.forEach(function (c) { var tr = el("tr"); tr.appendChild(el("td", null, c.name.replace(/-/g, " "))); tr.appendChild(el("td", "num", String(c.n))); cb.appendChild(tr); });
    if (!A.categories.length) { var tr1 = el("tr"); tr1.appendChild(el("td", "muted", "Nothing recorded yet.")); cb.appendChild(tr1); }
    var ul = $("effGaps"); ul.textContent = "";
    e.gaps.forEach(function (g) { var li = el("li"); li.appendChild(badge("info", "Note")); li.appendChild(document.createTextNode(" " + g)); ul.appendChild(li); });
    $("accSum").textContent = A.corrected_pct === null ? "nothing reviewed yet" : A.corrected_pct + "% corrected of " + A.reviewed;
  }

  /* ---------------- D. improver ---------------- */

  function renderImprove(I) {
    if (!I) return;
    // the improver's own cost figures; its review rate and speed are left out (the current review rate is under Accuracy)
    if (I.at) $("impSum").textContent = "Improver report from " + ago(I.at) + " (last " + (I.days || 7) + " days): " + (I.events_added !== null ? I.events_added : 0) + " events added" +
      (I.cost_usd !== null ? "; worker cost $" + I.cost_usd.toFixed(2) : "") + (I.cost_per_event !== null ? " ($" + I.cost_per_event.toFixed(2) + " per event)" : "") + "." +
      (I.guard ? " Quality guard " + (I.guard.blocked ? "on: nothing is made cheaper until the second review corrects 15% or less." : "off.") : "");
    var tb = $("impRoles").querySelector("tbody"); tb.textContent = "";
    I.roles.forEach(function (r) {
      var tr = el("tr"); tr.appendChild(el("td", "rname")).appendChild(el("strong", null, r.name));
      cell(tr, "Model", r.model || "—"); cell(tr, "Runs", String(r.runs), "num"); cell(tr, "Finished", r.ok_rate === null ? "—" : Math.round(r.ok_rate * 100) + "%" + (r.timeouts ? " (" + r.timeouts + " timed out)" : ""));
      cell(tr, "Cost per run", r.cost_per_run === null ? "—" : "$" + r.cost_per_run.toFixed(3), "num"); cell(tr, "Turns", r.turns === null ? "—" : String(r.turns), "num");
      tb.appendChild(tr);
    });
    var ul = $("impChanges"); ul.textContent = "";
    I.changes.forEach(function (c) { var li = el("li"); li.appendChild(el("strong", null, c.key + ": " + c.from + " to " + c.to)); li.appendChild(document.createTextNode(" · " + (c.at ? ago(c.at) : "") + " · " + c.reason)); ul.appendChild(li); });
    if (!ul.children.length) ul.appendChild(el("li", null, "None yet."));
    $("impDs").textContent = I.changes.length ? plural(I.changes.length, "change") + ", last " + (I.changes[0].at ? ago(I.changes[0].at) : "") : "no changes yet";
  }

  /* ---------------- D. lead queue and runs ---------------- */

  function renderQueue(ops) {
    if (!ops) return;
    var L = ops.leads;
    $("leads").textContent = L.last_24h + " new leads";
    var ul = $("leadTiers"); ul.textContent = "";
    [["gov", "from government agencies and CERTs"], ["vendor", "from security vendors' research"], ["news", "from security news"]].forEach(function (t) { ul.appendChild(el("li", null, int0(L.by_tier[t[0]]) + " " + t[1])); });
    L.failed.forEach(function (f) { ul.appendChild(el("li", "warnline", "Not loading: " + f)); });
    $("queueSum").textContent = L.last_24h + " leads in 24 h";
  }
  function renderRuns(ops) {
    var runs = $("runs"); runs.textContent = "";
    var list = ops ? ops.runs : [];
    if (!list.length) runs.appendChild(el("li", "muted", "No runs logged in the last 7 days."));
    list.slice(0, 14).forEach(function (r) {
      var li = el("li"); li.appendChild(el("span", "when", r.at ? ago(r.at) : "—")); li.appendChild(el("strong", null, " " + r.job));
      li.appendChild(document.createTextNode(": " + r.added + " added, " + r.updated + " updated" + (r.failed ? ", " + r.failed + " source(s) failed" : ""))); runs.appendChild(li);
    });
    var latest = list.filter(function (r) { return r.at; }).map(function (r) { return r.at; }).sort().pop();
    $("runsSum").textContent = list.length ? plural(list.length, "run") + (latest ? ", latest " + ago(latest) : "") : "none logged";
  }

  /* ---------------- C. what needs attention ---------------- */

  function renderAttention(h, attn) {
    if (h && h.backlog && h.backlog.waiting) attn.push({ cls: h.backlog.waiting > 60 || h.backlog.oldest_incident_hours > 2 ? "warn" : "info", badge: "Waiting", text: plural(h.backlog.waiting, "report") + " in the research queue waiting for a decision; oldest " + h.backlog.oldest_hours + " h", jump: "dQueue" });
    if (h && h.grid_waiting && h.grid_waiting.count) attn.push({ cls: h.grid_waiting.oldest_min > 120 ? "warn" : "info", badge: "Waiting", text: plural(h.grid_waiting.count, "grid outage") + " waiting for a cause check", jump: "gridSrcBox" });
    if (h && h.quarantined_count) attn.push({ cls: "bad", badge: "Left out", text: plural(h.quarantined_count, "record") + " failed validation" + (h.quarantined.length ? ": " + h.quarantined.slice(0, 2).join("; ") : ""), href: REPO + "/issues?q=label%3Adata-quarantine" });
    // the pipeline check (scripts/pipecheck.mjs, every hour): late stages and data quality; one that outlasted its threshold
    // also has a GitHub issue labelled pipeline-alert
    if (h && h.quality) h.quality.problems.forEach(function (p) {
      attn.push({ cls: p.level, badge: qualityBadge(p.id), kind: "quality", id: p.id,
        text: p.text.charAt(0).toUpperCase() + p.text.slice(1) + (p.since ? " (first seen " + ago(p.since) + ")" : ""),
        href: p.over ? REPO + "/issues?q=is%3Aopen+label%3Apipeline-alert" : "", jump: p.over ? "" : "dRoutines" });
    });
    var ul = $("attention"); ul.textContent = "";
    var rank = { bad: 0, warn: 1, info: 2, neutral: 3, wait: 3 };
    // "bad" ranks 0: `rank[cls] || 3` sorted every red item LAST (found 2026-11-21), so look the rank up explicitly
    var rk = function (c) { return has(rank, c) ? rank[c] : 3; };
    attn.sort(function (a, b) { return rk(a.cls) - rk(b.cls); });
    attn.slice(0, 20).forEach(function (x) {
      var li = el("li"); li.dataset.kind = x.cls; if (x.id) li.dataset.check = x.id; li.appendChild(badge(x.cls, x.badge)); li.appendChild(document.createTextNode(" " + x.text + " "));
      if (x.href) li.appendChild(link(x.href, "details")); else if (x.jump) li.appendChild(jump(x.jump, "details"));
      ul.appendChild(li);
    });
    if (attn.length > 20) ul.appendChild(el("li", "muted", (attn.length - 20) + " more in the details below."));
    if (!attn.length) ul.appendChild(el("li", "okline", "Nothing needs attention right now."));
    return attn.length;
  }

  /* ---------------- load ---------------- */

  function get(f, bust) { return fetch("data/" + f + (bust ? "?t=" + Date.now() : ""), { cache: bust ? "no-store" : "no-cache" }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }); }
  Promise.all([get("ops.json"), get("health.json", true), get("manifest.json", true), get("efficiency.json")]).then(function (a) {
    var ops = null, h = null, e = null, m = obj(a[2]), attn = [], counts = null, nAttn = 0;
    safe(function () { ops = cleanOps(a[0]); }); safe(function () { h = cleanHealth(a[1]); }); safe(function () { e = cleanEff(a[3]); });
    safe(function () { renderHealth(h, m); });
    safe(function () { liveCommits(m); });
    safe(function () { renderFlow(e, ops, m); });
    safe(function () { renderFrom(e); });
    safe(function () { counts = renderRoutines(ops, e, attn); });
    safe(function () { renderUsage(e); });
    safe(function () { renderFeeds(ops, e, attn); });
    safe(function () { renderGrid(h, attn); });
    safe(function () { renderCoverage(e); });
    safe(function () { renderAccuracy(e); });
    safe(function () { renderImprove(ops && ops.improve); });
    safe(function () { renderQueue(ops); });
    safe(function () { renderRuns(ops); });
    safe(function () { nAttn = renderAttention(h, attn); });
    safe(function () {
      if (!ops) { $("summary").textContent = "Status can't be loaded right now. Try again in a minute."; return; }
      var old = ops.built_at && (Date.now() - Date.parse(ops.built_at)) / 36e5 > 3;
      $("summary").textContent = (checks.bad ? checks.bad + " of " + (checks.ok + checks.bad) + " health checks need a look" : "All " + checks.ok + " health checks OK") +
        (counts ? "; " + counts.ok + " of " + counts.active + " active routines on time" : "") + (nAttn ? "; " + plural(nAttn, "item") + " need" + (nAttn === 1 ? "s" : "") + " attention" : "") +
        ". Data built " + (ops.built_at ? ago(ops.built_at) : "at an unknown time") + (old ? ", so this page may be out of date" : "") + ".";
    });
    safe(openFromHash);
  });
})();
