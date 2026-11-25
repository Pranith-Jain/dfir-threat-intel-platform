// CyberView trends page. Reads data/trends.json (written by scripts/build.mjs). All text is inserted as text.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var TITLES = { category: "Event types", sector: "Sectors", surface: "Attack surfaces", country: "Countries", actor: "Threat actors", product: "Products", tag: "Themes" };
  var AI_TX = "CyberView AI (a Claude model)";
  function int0(v) { return typeof v === "number" && isFinite(v) && v >= 0 ? Math.round(v) : 0; }
  // where the sector and surface rows came from (trends.json "basis"): the source, CyberView AI, or the free-text sector field
  function basisLine(k, b) {
    b = b && typeof b === "object" ? b[k] : null; if (!b || typeof b !== "object") return null;
    var s = int0(b.stated), i = int0(b.inferred), p;
    if (k === "sector") p = el("p", "note", "Of these two weeks' events, " + s + " have sectors stated by the source, " + i + " inferred by " + AI_TX + " (both from a fixed list based on the US CISA critical infrastructure sectors), and " + int0(b.free) + " only the free-text sector field written with the event, counted as written.");
    else p = el("p", "note", "Of these two weeks' events, " + s + " have an attack surface stated by the source and " + i + " inferred by " + AI_TX + "; " + int0(b.none) + " have none yet or none is known, and are not counted here.");
    p.dataset.basis = k; return p;
  }
  var CAT = { incident: "Incidents", vuln: "Patches and advisories", report: "Threat reports", policy: "Law and policy", enforcement: "Law enforcement", investment: "Investment and vendors", outage: "Outages" };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  var AI_BY = "CyberView AI (a Claude model)";
  // one failing section must not blank the page: each one renders inside safe() and says so if it breaks
  function safe(name, fn, box) { try { fn(); } catch (e) { if (box) { box.hidden = false; box.appendChild(el("p", "note bad", "The " + name + " section could not be shown.")); } } }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n).trim() : ""; }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function own(o, k) { return !!o && typeof k === "string" && Object.prototype.hasOwnProperty.call(o, k); }
  function fmtNum(n) { return n >= 1e9 ? (n / 1e9).toFixed(1).replace(/\.0$/, "") + "B" : n >= 1e6 ? (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M" : n >= 1e4 ? Math.round(n / 1e3) + "K" : Math.round(n).toLocaleString("en"); }
  function fmt(d, o) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, o || { month: "short", day: "numeric" }); } catch (e) { return d; } }

  var Q = { k: ["category", "sector", "surface", "country", "actor", "product", "tag"],
    ask: { category: "Which kinds of event led?", sector: "Which sectors were hit most?", surface: "Which attack surfaces were used?", country: "Where did events happen?", actor: "Which threat actors were named?", product: "Which products were named?", tag: "Which themes came up?" } };
  // the map's category symbols (d3 symbols at size 110), drawn as text-free SVG so category is shown by shape as well as colour
  var SYM = { incident: "M5.91,0A5.91,5.91,0,1,1,-5.91,0A5.91,5.91,0,1,1,5.91,0", report: "M0,-9.76L5.63,0L0,9.76L-5.63,0Z", vuln: "M0,-9.20L7.96,4.60L-7.96,4.60Z", policy: "M-5.24,-5.24h10.48v10.48h-10.48Z",
    enforcement: "M0,-9.89L2.22,-3.05L9.41,-3.05L3.59,1.16L5.81,8.00L0,3.78L-5.81,8.00L-3.59,1.16L-9.41,-3.05L-2.22,-3.05Z", investment: "M-7.03,-2.34L-2.34,-2.34L-2.34,-7.03L2.34,-7.03L2.34,-2.34L7.03,-2.34L7.03,2.34L2.34,2.34L2.34,7.03L-2.34,7.03L-2.34,2.34L-7.03,2.34Z",
    outage: "M2.83,1.63L2.83,7.29L-2.83,7.29L-2.83,1.63L-7.73,-1.19L-4.90,-6.09L0,-3.26L4.90,-6.09L7.73,-1.19Z" };
  var NS = "http://www.w3.org/2000/svg";
  function glyph(cat) {
    var s = document.createElementNS(NS, "svg"); s.setAttribute("viewBox", "-10 -10 20 20"); s.setAttribute("width", "13"); s.setAttribute("height", "13"); s.setAttribute("aria-hidden", "true"); s.setAttribute("class", "glyph");
    var p = document.createElementNS(NS, "path"); p.setAttribute("d", own(SYM, cat) ? SYM[cat] : SYM.incident); p.setAttribute("fill", "var(--c-" + (own(SYM, cat) ? cat : "incident") + ")"); s.appendChild(p); return s;
  }
  function cleanRows(rows) {
    return (Array.isArray(rows) ? rows : []).slice(0, 400).map(function (r) { return r && typeof r === "object" ? { k: str(r.k, 120), cur: int0(r.cur), prev: int0(r.prev) } : null; })
      .filter(function (r) { return r && r.k; });
  }
  function label(k, r) { return k === "category" ? (CAT[r.k] || r.k) : r.k; }
  function byCur(a, b) { return b.cur - a.cur || (b.cur - b.prev) - (a.cur - a.prev) || (a.k < b.k ? -1 : 1); }
  // nice axis step: 1, 2 or 5 x 10^n
  function niceStep(max, n) { var raw = Math.max(1, max) / n, p = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; }

  fetch("data/trends.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(render)
    .catch(function () { $("summary").textContent = "Trends can't be loaded right now. Try again in a minute."; });

  var cards = [];
  function render(t) {
    var complete = !!(t.prev && t.prev.complete);
    $("summary").textContent = int0(t.cur.total) + " events from " + fmt(t.cur.from) + " to " + fmt(t.cur.to) + "; " + int0(t.prev.total) + " in the week before.";
    if (!complete) {
      var c = $("caveat"); c.hidden = false;
      var ready = new Date(Date.parse(t.collection_started + "T12:00:00Z") + 14 * 864e5).toISOString().slice(0, 10);
      c.textContent = "CyberView began collecting on " + fmt(t.collection_started, { month: "long", day: "numeric" }) + ". Events before that were filled in afterwards and are incomplete, so the week before is undercounted. Until about " + fmt(ready, { month: "long", day: "numeric" }) + ", read this week's counts as a ranking, not the changes as real trends.";
    }
    var dims = {};
    Q.k.forEach(function (k) { dims[k] = cleanRows(t.dims && t.dims[k]); });
    safe("summary figures", function () { kpis(t, dims, complete); });
    safe("daily events", function () { days(t.daily || []); });
    safe("power grid", function () { grid(t.grid); }, $("grid"));
    var box = $("dims");
    Q.k.forEach(function (k) { var rows = dims[k]; if (rows.filter(function (r) { return r.cur > 0; }).length >= 2) safe(TITLES[k], function () { var sec = dim(k, rows, complete), bl = basisLine(k, t.basis); if (bl) sec.appendChild(bl); box.appendChild(sec); }, box); });
    safe("search", search);
  }

  // ---------- the KPI band: six figures that answer "what is the situation this week" ----------
  function delta(cur, prev, complete, unit) {
    var d = cur - prev, cls = !complete ? "flat" : d > 0 ? "up" : d < 0 ? "down" : "flat";
    var s = el("span", "kd " + cls);
    if (prev === 0 && cur > 0) { s.appendChild(el("span", null, "new this week")); return s; }
    s.appendChild(el("span", "ar", d > 0 ? "▲" : d < 0 ? "▼" : "—"));
    var pct = prev > 0 ? Math.round((d / prev) * 100) : 0;
    s.appendChild(el("span", null, (d > 0 ? "+" : "") + d + (unit === "%" && prev > 0 ? " (" + (pct > 0 ? "+" : "") + pct + "%)" : "")));
    s.appendChild(el("span", "kn", complete ? "vs last week" : "vs partial week"));
    return s;
  }
  function kpi(box, lbl, val, sub, cat) {
    var k = el("div", "kpi"); k.setAttribute("role", "listitem");
    k.appendChild(el("div", "kl", lbl));
    var v = el("div", "kv"); if (cat) { v.appendChild(glyph(cat)); v.appendChild(document.createTextNode(" ")); } v.appendChild(document.createTextNode(val)); v.title = val; k.appendChild(v);
    if (sub) k.appendChild(typeof sub === "string" ? el("span", "kd flat", sub) : sub);
    box.appendChild(k);
  }
  function riser(rows) { var best = null; rows.forEach(function (r) { var d = r.cur - r.prev; if (r.cur > 0 && d > 0 && (!best || d > best.cur - best.prev)) best = r; }); return best; }
  function kpis(t, dims, complete) {
    var box = $("kpis"), cur = int0(t.cur.total), prev = int0(t.prev.total);
    kpi(box, "Events this week", cur.toLocaleString("en"), delta(cur, prev, complete, "%"));
    var cat = dims.category.slice().sort(byCur)[0];
    if (cat) kpi(box, "Leading type", CAT[cat.k] || cat.k, (cur ? Math.round((cat.cur / cur) * 100) : 0) + "% of this week's events", cat.k);
    var cr = riser(dims.category);
    if (cr) kpi(box, "Biggest riser", CAT[cr.k] || cr.k, delta(cr.cur, cr.prev, complete), cr.k);
    var sr = riser(dims.sector);
    if (sr) kpi(box, "Fastest-rising sector", sr.k, delta(sr.cur, sr.prev, complete));
    var co = dims.country.slice().sort(byCur)[0];
    if (co && co.cur) kpi(box, "Most events in", co.k, co.cur + " event" + (co.cur === 1 ? "" : "s") + " this week");
    var tg = dims.tag.slice().sort(byCur)[0];
    if (tg && tg.cur) kpi(box, "Top theme", tg.k, tg.cur + " event" + (tg.cur === 1 ? "" : "s") + " this week");
    box.hidden = !box.children.length;
  }

  // ---------- daily chart: 28 single-colour columns on a rounded axis, last 7 days brighter ----------
  function days(list) {
    list = (Array.isArray(list) ? list : []).slice(-28).map(function (d) { return { date: str(d && d.date, 10), total: int0(d && d.total) }; });
    var box = $("days"), yax = $("yax"), tip = $("dayTip");
    var max = Math.max(1, Math.max.apply(null, list.map(function (d) { return d.total; }))), step = niceStep(max, 4), top = Math.ceil(max / step) * step, ticks = Math.round(top / step);
    for (var y = ticks; y >= 0; y--) yax.appendChild(el("span", null, String(y * step)));
    var gl = el("div", "grid"); gl.setAttribute("aria-hidden", "true"); for (var g = 0; g <= ticks; g++) gl.appendChild(el("i")); box.appendChild(gl);
    var sum = function (a) { return a.reduce(function (s, d) { return s + d.total; }, 0); };
    var last = list.slice(-7), before = list.slice(-14, -7);
    var avg = last.length ? Math.round(sum(last) / last.length) : 0, avgB = before.length ? Math.round(sum(before) / before.length) : 0;
    var hint = "Last 7 days averaged " + avg + " a day, against " + avgB + " a day the 7 days before (today is still counting). Tap a bar to see that day's count.";
    var cap = el("p", "note daycap", hint); cap.setAttribute("aria-live", "polite");
    var axis = box.parentNode.nextSibling; while (axis && !(axis.classList && axis.classList.contains("axis"))) axis = axis.nextSibling;
    box.parentNode.parentNode.insertBefore(cap, axis ? axis.nextSibling : null);
    list.forEach(function (d, i) {
      var text = fmt(d.date, { weekday: "short", month: "short", day: "numeric" }) + ": " + d.total + " event" + (d.total === 1 ? "" : "s") + (i === list.length - 1 ? " so far" : "");
      var col = el("button", "day"); col.type = "button"; col.setAttribute("aria-label", text);
      if (i >= list.length - 7) col.setAttribute("data-hi", "");
      col.addEventListener("click", function () { cap.textContent = text; Array.prototype.forEach.call(box.querySelectorAll(".day.on"), function (x) { x.classList.remove("on"); }); col.classList.add("on"); });
      col.addEventListener("mouseenter", function () { tip.textContent = text; var bx = box.getBoundingClientRect(), cx = col.getBoundingClientRect(), pw = box.parentNode.getBoundingClientRect(); tip.style.left = Math.max(0, Math.min(pw.width - 170, cx.left - pw.left + cx.width / 2 - 70)) + "px"; tip.style.top = "-6px"; tip.classList.add("show"); void bx; });
      col.addEventListener("mouseleave", function () { tip.classList.remove("show"); });
      var bar = el("span", "daybar"); bar.style.height = ((d.total / top) * 100).toFixed(1) + "%"; if (!d.total) bar.hidden = true; col.appendChild(bar);
      col.appendChild(el("span", "lab", i % 7 === 6 || i === list.length - 1 ? fmt(d.date) : ""));
      box.appendChild(col);
    });
  }

  // ---------- mover cards: one table per dimension, share bar, count and the change ----------
  function dim(k, rows, complete) {
    var sec = el("section", "mcard");
    var hd = el("header", "mhead"); hd.appendChild(el("h3", null, TITLES[k])); hd.appendChild(el("span", "mq", Q.ask[k])); sec.appendChild(hd);
    var all = rows.slice().sort(byCur), max = Math.max(1, all[0] ? all[0].cur : 1);
    var tb = el("table", "mtab"), cg = el("colgroup");
    if (k === "category") cg.appendChild(el("col", "c-sh"));
    ["c-nm", "c-sha", "c-ct", "c-dl"].forEach(function (c) { cg.appendChild(el("col", c)); });
    tb.appendChild(cg);
    var th = el("thead"), tr = el("tr");
    var heads = (k === "category" ? [["", ""]] : []).concat([["Name", ""], ["Share", ""], ["This wk", "num"], [complete ? "vs last" : "vs last*", "num"]]);
    heads.forEach(function (h, i) { var c = el("th", h[1], h[0]); c.scope = "col"; if (!h[0]) c.appendChild(el("span", "sr-only", "Type")); if (h[0] === "vs last*") c.title = "The week before is partial, so read the change as rough"; tr.appendChild(c); void i; });
    th.appendChild(tr); tb.appendChild(th);
    var body = el("tbody"); tb.appendChild(body); sec.appendChild(tb);
    var none = el("p", "pnone", "No match in this card."); none.hidden = true; sec.appendChild(none);
    function fill(q) {
      while (body.firstChild) body.removeChild(body.firstChild);
      var shown = (q ? all.filter(function (r) { return label(k, r).toLowerCase().indexOf(q) >= 0; }) : all.filter(function (r) { return r.cur > 0 || r.prev > 0; })).slice(0, 8);
      shown.forEach(function (r) {
        var row = el("tr"), name = label(k, r);
        row.title = name + ": " + r.cur + " this week, " + r.prev + " the week before" + (complete ? "" : " (partial)");
        if (k === "category") { var sh = el("td"); sh.appendChild(glyph(r.k)); row.appendChild(sh); }
        var nm = el("td"), a = el("a", null, name);
        a.href = "archive.html#q=" + encodeURIComponent(k === "category" ? "" : r.k) + (k === "category" ? "&cat=" + encodeURIComponent(r.k) : "");
        nm.appendChild(a); row.appendChild(nm);
        var sc = el("td"), mb = el("span", "mbar"), mi = el("i"); mi.style.width = Math.max(r.cur ? 3 : 0, Math.round((r.cur / max) * 100)) + "%"; mb.appendChild(mi); mb.style.display = "block"; sc.appendChild(mb); row.appendChild(sc);
        row.appendChild(el("td", "num mct", String(r.cur)));
        var d = r.cur - r.prev, ch = el("td", "num mdl " + (complete ? (d > 0 ? "up" : d < 0 ? "down" : "flat") : "flat"));
        ch.textContent = r.prev === 0 && r.cur > 0 ? "new" : (d > 0 ? "+" : "") + d;
        row.appendChild(ch);
        row.addEventListener("click", function (e) { if (e.target !== a) a.click(); });
        body.appendChild(row);
      });
      none.hidden = !!shown.length; tb.hidden = !shown.length;
      return shown.length;
    }
    fill("");
    cards.push({ sec: sec, fill: fill });
    return sec;
  }

  // ---------- page search: filters every card; "/" focuses it ----------
  function search() {
    var q = $("trQ"), none = $("trNone"); if (!q) return;
    q.addEventListener("input", function () {
      var v = q.value.trim().toLowerCase().slice(0, 80), hits = 0;
      cards.forEach(function (c) { var n = c.fill(v); hits += n; c.sec.hidden = !!v && !n; });
      none.hidden = !v || hits > 0;
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "") && !(document.activeElement && document.activeElement.isContentEditable)) { e.preventDefault(); q.focus(); }
      else if (e.key === "Escape" && document.activeElement === q && q.value) { q.value = ""; q.dispatchEvent(new Event("input")); }
    });
  }
  // ---------- power grid (data/grid/analysis.json via build.mjs; computed by scripts/grid-analysis.mjs, no AI model) ----------
  var GRID_OPS = { hydroquebec: "Hydro-Québec", bchydro: "BC Hydro", ukpn: "UK Power Networks", eskom: "Eskom", ercot: "ERCOT", aemo: "AEMO", eia: "EIA", entsoe: "ENTSO-E", cfradar: "Cloudflare Radar" };
  var GRID_DEC = { weather: "weather", equipment: "equipment failure", planned: "planned work", supply_shortfall: "supply shortfall", wildfire_safety: "wildfire safety shut-off", third_party: "damage by a third party",
    cyber_official: "cyberattack, stated by an official source", cyber_reported: "reported as a cyberattack, not confirmed by an official source", under_investigation: "under investigation", unknown: "not stated by the operator" };
  // every region row goes through here: known fields only, with length and range limits (trends may be a list or keyed by region)
  function cleanGridRow(key, r) {
    if (!r || typeof r !== "object") return null;
    var src = str(r.source, 20).toLowerCase(), cc = str(r.country, 2).toUpperCase();
    var region = str(r.region, 80) || str(key, 80);
    var ch = num(r.customer_hours != null ? r.customer_hours : r.customer_hours_30d, 0, 1e12);
    var inc = num(r.incidents != null ? r.incidents : r.incidents_opened != null ? r.incidents_opened : r.opened, 0, 1e6);
    if (!region || ch === null) return null;
    var lg = r.largest && typeof r.largest === "object" ? r.largest : null, largest = null;
    if (lg) {
      var lc = num(lg.peak_customers != null ? lg.peak_customers : lg.customers, 0, 1e9), ck = lg.checked && typeof lg.checked === "object" ? str(lg.checked.decision, 30) : "";
      largest = { name: str(lg.name, 120), customers: lc === null ? null : Math.round(lc), checked: own(GRID_DEC, ck) ? ck : "" };
      if (!largest.name && largest.customers === null) largest = null;
    }
    var causes = [];
    if (Array.isArray(r.causes)) r.causes.slice(0, 20).forEach(function (c) { if (!c || typeof c !== "object") return; var n = num(c.customers != null ? c.customers : c.count != null ? c.count : c.n, 0, 1e12), t = str(c.cause, 60); if (n !== null) causes.push({ cause: t || "no cause reported", n: n }); });
    else if (r.causes && typeof r.causes === "object") Object.keys(r.causes).slice(0, 20).forEach(function (k) { var n = num(r.causes[k], 0, 1e12); if (n !== null) causes.push({ cause: str(k, 60) || "no cause reported", n: n }); });
    causes.sort(function (a, b) { return b.n - a.n; });
    var w = r.wow || r.week_over_week || r.week, wow = null;
    if (w && typeof w === "object") { var a = num(w.cur != null ? w.cur : w.this_week != null ? w.this_week : w.customer_hours, 0, 1e12), b = num(w.prev != null ? w.prev : w.last_week != null ? w.last_week : w.prev_customer_hours, 0, 1e12); if (a !== null && b !== null) wow = { cur: a, prev: b }; }
    return { source: /^[a-z0-9_-]+$/.test(src) ? src : "", country: /^[A-Z]{2}$/.test(cc) ? cc : "", region: region, hours: ch, incidents: inc === null ? null : Math.round(inc), largest: largest, causes: causes.slice(0, 5), wow: wow, coverage: num(r.coverage, 0, 1) };
  }
  function cleanGrid(g) {
    if (!g || typeof g !== "object" || !g.trends || typeof g.trends !== "object") return null;
    var t = g.trends, rows = [];
    var reg = t.regions && typeof t.regions === "object" ? t.regions : null;
    if (Array.isArray(reg)) reg.slice(0, 60).forEach(function (r) { rows.push(cleanGridRow("", r)); });
    else if (reg) Object.keys(reg).slice(0, 60).forEach(function (k) { if (reg[k] && typeof reg[k] === "object" && !Array.isArray(reg[k])) rows.push(cleanGridRow(k, reg[k])); });
    else Object.keys(t).slice(0, 60).forEach(function (k) { if (t[k] && typeof t[k] === "object" && !Array.isArray(t[k])) rows.push(cleanGridRow(k, t[k])); });
    rows = rows.filter(Boolean).sort(function (a, b) { return b.hours - a.hours; }).slice(0, 20);
    var days = num(t.days != null ? t.days : t.window_days, 1, 365);
    return { at: str(g.updated_at, 30), days: days === null ? 30 : Math.round(days), rows: rows, anomalies: num(g.anomalies, 0, 1e4) };
  }
  function grid(raw) {
    var sec = $("grid"); if (!sec) return;
    var g = cleanGrid(raw); if (!g) return;
    sec.hidden = false;
    var sum = $("gridSum"), box = $("gridBars");
    if (!g.rows.length) { sum.textContent = "No operator reported unplanned outages in the last " + g.days + " days, or the first analysis has not run yet."; return; }
    var tot = g.rows.reduce(function (s, r) { return s + r.hours; }, 0);
    sum.textContent = fmtNum(tot) + " customer-hours without power across " + g.rows.length + " operator region" + (g.rows.length === 1 ? "" : "s") + " in the last " + g.days + " days" +
      (g.anomalies ? "; " + g.anomalies + " outage" + (g.anomalies === 1 ? " was" : "s were") + " unusual for the hour of the week" : "") + "." +
      (g.rows.some(function (r) { return r.coverage !== null && r.coverage < 0.9; }) ? " Some operators' feeds were not read for part of the period, so their totals undercount; each row says how much is covered, and no week-on-week change is shown without 90% coverage in both weeks." : "");
    var max = Math.max(1, g.rows[0].hours);
    var cap = el("p", "note daycap", "Tap a bar for the causes as the operators reported them."); cap.setAttribute("aria-live", "polite");
    g.rows.forEach(function (r) {
      var op = GRID_OPS[r.source] || r.source || "";
      var who = op && r.region && r.region !== op ? op + ", " + r.region : op || r.region;
      var detail = [];
      if (r.incidents !== null) detail.push(r.incidents + " incident" + (r.incidents === 1 ? "" : "s") + " opened");
      if (r.wow) detail.push("this week " + fmtNum(r.wow.cur) + ", week before " + fmtNum(r.wow.prev));
      if (r.coverage !== null && r.coverage < 0.9) detail.push("data for " + Math.round(r.coverage * 100) + "% of the " + g.days + " days");
      if (r.largest) detail.push("largest: " + (r.largest.name || "") + (r.largest.customers !== null && !/customers/i.test(r.largest.name) ? (r.largest.name ? ", " : "") + fmtNum(r.largest.customers) + " customers" : ""));
      var mix = r.causes.length ? "Causes as reported: " + r.causes.map(function (c) { return c.cause + " (" + fmtNum(c.n) + ")"; }).join(", ") : "No causes reported";
      var text = who + ": " + fmtNum(r.hours) + " customer-hours" + (detail.length ? ", " + detail.join(", ") : "") + ". " + mix + ".";
      var b = el("button", "gbar"); b.type = "button"; b.title = text; b.setAttribute("aria-label", text);
      b.appendChild(el("span", "glab", who));
      var track = el("span", "gtrack"), fill = el("span", "gfill"); fill.style.width = Math.max(1, Math.round((r.hours / max) * 100)) + "%"; track.appendChild(fill); b.appendChild(track);
      b.appendChild(el("span", "gval", fmtNum(r.hours)));
      b.addEventListener("click", function () { cap.textContent = text; Array.prototype.forEach.call(box.querySelectorAll(".gbar.on"), function (x) { x.classList.remove("on"); }); b.classList.add("on"); });
      var row = el("div", "grow"); row.appendChild(b);
      if (detail.length) row.appendChild(el("p", "gsub", detail.join(" · ")));
      if (r.largest && r.largest.checked) row.appendChild(el("p", "gsub aiby", "Cause of the largest checked by " + AI_BY + ": " + GRID_DEC[r.largest.checked]));
      box.appendChild(row);
    });
    box.parentNode.insertBefore(cap, box.nextSibling);
  }
})();
