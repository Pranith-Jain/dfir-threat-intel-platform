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

  fetch("data/trends.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(render)
    .catch(function () { $("summary").textContent = "Trends can't be loaded right now. Try again in a minute."; });

  function render(t) {
    var complete = !!(t.prev && t.prev.complete);
    $("summary").textContent = t.cur.total + " events from " + fmt(t.cur.from) + " to " + fmt(t.cur.to) + "; " + t.prev.total + " in the week before.";
    if (!complete) {
      var c = $("caveat"); c.hidden = false;
      var ready = new Date(Date.parse(t.collection_started + "T12:00:00Z") + 14 * 864e5).toISOString().slice(0, 10);
      c.textContent = "CyberView began collecting on " + fmt(t.collection_started, { month: "long", day: "numeric" }) + ". Events before that were filled in afterwards and are incomplete, so the week before is undercounted. Until about " + fmt(ready, { month: "long", day: "numeric" }) + ", read this week's counts as a ranking, not the changes as real trends.";
    }
    safe("daily events", function () { days(t.daily || []); });
    safe("power grid", function () { grid(t.grid); }, $("grid"));
    var box = $("dims");
    ["category", "sector", "surface", "country", "actor", "product", "tag"].forEach(function (k) { var rows = (t.dims && t.dims[k]) || []; if (rows.filter(function (r) { return r.cur > 0; }).length >= 2) safe(TITLES[k], function () { var sec = dim(k, rows, complete), bl = basisLine(k, t.basis); if (bl) sec.appendChild(bl); box.appendChild(sec); }, box); });
  }

  function days(list) {
    var box = $("days"), max = Math.max(1, Math.max.apply(null, list.map(function (d) { return d.total; })));
    var cap = el("p", "note daycap", "Tap a bar to see that day's count."); cap.setAttribute("aria-live", "polite"); box.parentNode.insertBefore(cap, box.nextSibling);
    list.forEach(function (d, i) {
      var text = fmt(d.date, { weekday: "short", month: "short", day: "numeric" }) + ": " + d.total + " event" + (d.total === 1 ? "" : "s");
      var col = el("button", "day"); col.type = "button"; col.title = text; col.setAttribute("aria-label", text);
      col.addEventListener("click", function () { cap.textContent = text; Array.prototype.forEach.call(box.querySelectorAll(".day.on"), function (x) { x.classList.remove("on"); }); col.classList.add("on"); });
      var bar = el("span", "daybar"); bar.style.height = Math.round((d.total / max) * 128) + "px"; if (!d.total) bar.hidden = true; col.appendChild(bar);
      col.appendChild(el("span", "lab", i % 7 === 6 || i === list.length - 1 ? fmt(d.date) : ""));
      box.appendChild(col);
    });
  }

  function dim(k, rows, complete) {
    var sec = el("section", "panel");
    sec.appendChild(el("h2", null, TITLES[k]));
    var top = rows.slice().sort(function (a, b) { return b.cur - a.cur || (b.cur - b.prev) - (a.cur - a.prev); }).slice(0, 8);
    var max = Math.max(1, top[0] ? top[0].cur : 1);
    var tb = el("table"), th = el("thead"), tr = el("tr");
    [["Name", ""], ["This week", "num"], [complete ? "Week before" : "Week before (partial)", "num"], ["Change", "num"]].forEach(function (h) { var c = el("th", h[1], h[0]); c.scope = "col"; tr.appendChild(c); });
    th.appendChild(tr); tb.appendChild(th);
    var body = el("tbody");
    top.forEach(function (r) {
      var row = el("tr"), name = el("td"), a = el("a", null, k === "category" ? (CAT[r.k] || r.k) : r.k);
      a.href = "archive.html#q=" + encodeURIComponent(k === "category" ? "" : r.k) + (k === "category" ? "&cat=" + encodeURIComponent(r.k) : "");
      name.appendChild(a); row.appendChild(name);
      var cur = el("td", "num"), bw = el("span", "mini"), b = el("span", "fill"); b.style.width = Math.round((r.cur / max) * 100) + "%"; bw.appendChild(b);
      cur.appendChild(bw); cur.appendChild(el("span", null, String(r.cur))); row.appendChild(cur);
      row.appendChild(el("td", "num", String(r.prev)));
      var d = r.cur - r.prev, ch = el("td", "num " + (complete ? (d > 0 ? "up" : d < 0 ? "down" : "") : "muted"));
      ch.textContent = r.prev === 0 && r.cur > 0 ? "new" : (d > 0 ? "+" : "") + d;
      row.appendChild(ch); body.appendChild(row);
    });
    tb.appendChild(body); sec.appendChild(tb);
    return sec;
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
