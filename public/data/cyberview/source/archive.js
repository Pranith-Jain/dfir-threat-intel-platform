// CyberView archive page. Reads data/archive/search.json (one compact row per event) and loads a month's
// full records only when an event is opened. All text is inserted as text, never as HTML.
(function () {
  "use strict";
  var CAT = { incident: "Incident", vuln: "Patch / advisory", report: "Threat report", policy: "Law and policy", enforcement: "Law enforcement", investment: "Investment", outage: "Outage" };
  var PAGE = 60;
  var rows = [], shown = PAGE, months = {}, $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function safeUrl(u) { return /^https?:\/\//i.test(String(u || "")) ? String(u) : ""; }
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
      readHash(); render(); recent();
      $("recentAll").addEventListener("click", function () { recentAll = !recentAll; if (!recentAll && location.hash === "#recent") history.replaceState(null, "", location.pathname + location.search); recent(); });
      window.addEventListener("hashchange", function () { readHash(); render(); });
      // a link to one event (archive.html#q=<id>) opens it straight away
      var q = $("q").value.trim(), only = $("list").querySelectorAll(".row > button");
      if (only.length === 1 && rows.some(function (r) { return r.id === q; })) only[0].click();
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
    $("count").textContent = list.length + " event" + (list.length === 1 ? "" : "s") + (list.length > shown ? ", showing " + shown : "");
    if (!list.length) { box.appendChild(el("li", "empty", "Nothing matches. Clear a filter or try another word.")); }
    list.slice(0, shown).forEach(function (r) { box.appendChild(rowEl(r)); });
    $("more").hidden = list.length <= shown;
  }
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
    list.slice(0, all ? list.length : RECENT_FEW).forEach(function (r) { var li = rowEl(r), meta = li.querySelector(".meta"), when = el("span", "pill filed", "Filed " + ago(r.first_seen) + ", happened " + fmt(r.date)); meta.insertBefore(when, meta.firstChild); ol.appendChild(li); });
  }
  function ago(iso) {
    var m = Math.round((Date.now() - Date.parse(iso)) / 6e4); if (!isFinite(m)) return "";
    return m < 60 ? m + " min ago" : m < 1440 ? Math.round(m / 60) + " h ago" : Math.round(m / 1440) + " days ago";
  }
  function rowEl(r) {
      var li = el("li", "row"); li.style.setProperty("--cc", "var(--c-" + r.category + ")");
      var b = el("button"); b.type = "button"; b.setAttribute("aria-expanded", "false");
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
      b.addEventListener("click", function () { toggle(li, b, r); });
      li.appendChild(b); return li;
    writeHash();
  }

  function month(m) {
    if (!months[m]) months[m] = fetch("data/archive/" + m + ".json").then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
      var by = {}; (d.events || []).forEach(function (e) { by[e.id] = e; }); return by;
    });
    return months[m];
  }

  function toggle(li, b, r) {
    var open = li.querySelector(".more-info");
    if (open) { open.remove(); b.setAttribute("aria-expanded", "false"); return; }
    var box = el("div", "more-info", "Loading"); li.appendChild(box); b.setAttribute("aria-expanded", "true");
    month(String(r.date).slice(0, 7)).then(function (by) {
      var e = by[r.id]; box.textContent = "";
      if (!e) { box.textContent = "Details are not available."; return; }
      if (e.summary) box.appendChild(el("p", null, e.summary));
      box.appendChild(el("p", "note", "Researched and written by CyberView AI (a Claude model) from the sources listed."));
      if (e.action) { var p = el("p"); p.appendChild(el("strong", null, "What to do: ")); p.appendChild(document.createTextNode(e.action)); box.appendChild(p); }
      if (e.actor) box.appendChild(el("p", null, "Actor: " + e.actor));
      var lp = el("p"), la = el("a", null, "Link to this event");
      la.href = "archive.html#q=" + encodeURIComponent(r.id); lp.appendChild(la); box.appendChild(lp);
      var src = (e.sources || []).filter(function (s) { return s && safeUrl(s.url); });
      if (src.length) {
        box.appendChild(el("h3", null, "Sources"));
        var ul = el("ul"); src.slice(0, 6).forEach(function (s) {
          var a = el("a", null, s.name || s.url.replace(/^https?:\/\//, "").split("/")[0]); a.href = safeUrl(s.url); a.target = "_blank"; a.rel = "noopener noreferrer";
          var item = el("li"); item.appendChild(a); ul.appendChild(item);
        }); box.appendChild(ul);
      }
    }).catch(function () { box.textContent = "Details could not be loaded."; });
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

  $("filters").addEventListener("submit", function (e) { e.preventDefault(); });
  var t; $("q").addEventListener("input", function () { clearTimeout(t); t = setTimeout(function () { shown = PAGE; render(); }, 150); });
  ["month", "cat", "sev", "claims"].forEach(function (k) { $(k).addEventListener("change", function () { shown = PAGE; render(); }); });
  $("more").addEventListener("click", function () { shown += PAGE; render(); });
  load();
})();
