// CyberView weekly tabletop exercise. Reads data/tabletop.json (written by scripts/build.mjs from data/tabletop.json and
// data/snapshots/tabletop/). Every field passes through clean() with length limits; all text is inserted as text.
// The facilitator clock lives only in this page while it is open; nothing is stored or sent.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function strs(a, k, n) { return (Array.isArray(a) ? a : []).map(function (x) { return str(x, n).trim(); }).filter(Boolean).slice(0, k); }
  function https(u) { u = str(u, 600); return /^https:\/\/[^\s"'<>]+$/.test(u) ? u : ""; }
  function isId(s) { return /^[a-z0-9][a-z0-9-]{2,119}$/.test(s); }
  function fmtDay(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { weekday: "short", month: "long", day: "numeric", year: "numeric" }); } catch (e) { return d; } }
  // links come only from https sources or the map's own permalinks; anything else becomes about:blank
  function safeUrl(u) { u = String(u || ""); return /^https:\/\//.test(u) || /^\.\/#e=[a-z0-9-]+$/.test(u) ? u : "about:blank"; }
  function blobUrl(b) { return b instanceof Blob ? URL.createObjectURL(b) : "about:blank"; }
  function link(href, text) { var a = el("a", null, text); a.href = safeUrl(href); if (/^https:/.test(href)) { a.target = "_blank"; a.rel = "noopener noreferrer"; } return a; }

  function clean(t) {
    if (!t || typeof t !== "object" || t.label !== "exercise") return null;
    var x = {
      date: /^\d{4}-\d{2}-\d{2}$/.test(t.date || "") ? t.date : "", title: str(t.title, 120), story: str(t.real_story, 900), scenario: str(t.scenario, 1200),
      based: strs(t.based_on, 6, 120).filter(isId), duration: Math.min(180, Math.max(20, Math.round(+t.duration_min) || 60)), roles: strs(t.roles, 12, 60),
      facts: (Array.isArray(t.facts) ? t.facts : []).slice(0, 12).map(function (f) { return f && str(f.text, 300) && https(f.source_url) ? { text: str(f.text, 300), url: https(f.source_url) } : null; }).filter(Boolean),
      injects: (Array.isArray(t.injects) ? t.injects : []).slice(0, 10).map(function (i) {
        return i && str(i.title, 90) && str(i.text, 600) ? { at: Math.max(0, Math.round(+i.at_min) || 0), title: str(i.title, 90), text: str(i.text, 600), ask: str(i.ask, 300) } : null; }).filter(Boolean),
      questions: strs(t.questions, 12, 300), good: strs(t.good_looks_like, 10, 300), adapt: str(t.adapt, 600),
      sources: (Array.isArray(t.sources) ? t.sources : []).slice(0, 10).map(function (s) { return s && https(s.url) ? { name: str(s.name, 80) || "source", url: https(s.url) } : null; }).filter(Boolean)
    };
    x.injects.sort(function (a, b) { return a.at - b.at; });
    return x.title && x.scenario && x.injects.length ? x : null;
  }

  var all = [], cur = null, clock = { start: 0, held: 0, timer: 0, reveal: false };

  fetch("data/tabletop.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
    var list = [];
    var c = clean(d && d.current); if (c) list.push(c);
    (Array.isArray(d && d.exercises) ? d.exercises : []).forEach(function (t) { var x = clean(t); if (x && !list.some(function (y) { return y.date === x.date && y.title === x.title; })) list.push(x); });
    all = list;
    if (!all.length) { $("ttTitle").textContent = "No exercise yet"; $("ttMeta").textContent = "The tabletop job writes a new exercise every Friday from a real event of the week. Check back then."; return; }
    var pick = $("ttPick");
    all.forEach(function (x, i) { var o = el("option", null, (i === 0 ? "This week: " : "") + (x.date ? x.date + " · " : "") + x.title); o.value = String(i); pick.appendChild(o); });
    pick.addEventListener("change", function () { show(+pick.value); });
    var want = (location.hash.match(/^#d=(\d{4}-\d{2}-\d{2})$/) || [])[1], at = 0;
    if (want) all.forEach(function (x, i) { if (x.date === want && !at) at = i; });
    pick.value = String(at); show(at);
    $("ttBar").hidden = false; $("ttBanner").hidden = false;
  }).catch(function () { $("ttTitle").textContent = "The exercise can't be loaded right now"; $("ttMeta").textContent = "Try again in a minute."; });

  function show(i) {
    cur = all[i]; stopClock(true);
    try { history.replaceState(null, "", cur.date && i ? "#d=" + cur.date : location.pathname); } catch (e) {}
    $("ttTitle").textContent = cur.title;
    $("ttMeta").textContent = [cur.date ? fmtDay(cur.date) : "", cur.duration + " minutes", cur.roles.length ? "for " + cur.roles.join(", ") : ""].filter(Boolean).join(" · ");
    var b = $("ttBody"); b.textContent = "";

    var real = el("section", "panel");
    real.appendChild(el("h2", null, "What really happened"));
    if (cur.story) real.appendChild(el("p", null, cur.story));
    if (cur.facts.length) {
      real.appendChild(el("h3", null, "Verified facts"));
      var fl = el("ul", "ttfacts");
      cur.facts.forEach(function (f) { var li = el("li", null, f.text + " "); li.appendChild(link(f.url, "source")); fl.appendChild(li); });
      real.appendChild(fl);
    }
    if (cur.based.length) { var on = el("p", "note", "On the map: "); cur.based.forEach(function (id, k) { if (k) on.appendChild(document.createTextNode(", ")); on.appendChild(link("./#e=" + encodeURIComponent(id), id)); }); real.appendChild(on); }
    b.appendChild(real);

    var sc = el("section", "panel ttscenario");
    sc.appendChild(el("h2", null, "Your scenario"));
    sc.appendChild(el("p", "note", "Hypothetical: read this aloud to start. It adapts the real event to an organisation like yours."));
    sc.appendChild(el("p", "ttlead", cur.scenario));
    b.appendChild(sc);

    var inj = el("section", "panel");
    var ih = el("div", "tthead"); ih.appendChild(el("h2", null, "Timed updates (injects)"));
    var ctl = el("div", "ttclock");
    var face = el("span", "ttface", "00:00"); face.id = "ttFace"; face.setAttribute("role", "timer"); face.setAttribute("aria-label", "Elapsed time");
    var go = el("button", "btn", "Start clock"); go.type = "button"; go.id = "ttGo";
    var rs = el("button", "btn", "Reset"); rs.type = "button"; rs.id = "ttReset";
    var rv = el("label", "ttrev"); var cb = el("input"); cb.type = "checkbox"; cb.id = "ttReveal"; cb.checked = clock.reveal; rv.appendChild(cb); rv.appendChild(document.createTextNode(" Reveal each update when its time comes"));
    ctl.appendChild(face); ctl.appendChild(go); ctl.appendChild(rs); ctl.appendChild(rv); ih.appendChild(ctl); inj.appendChild(ih);
    inj.appendChild(el("p", "note", "The facilitator drops each update in at its minute. Turn on reveal to hide updates until the clock reaches them, so the team can't read ahead on a shared screen."));
    var ol = el("ol", "ttinj"); ol.id = "ttInj";
    cur.injects.forEach(function (x, k) {
      var li = el("li"); li.dataset.at = String(x.at);
      li.appendChild(el("span", "ttat", "+" + x.at + " min"));
      var body = el("div"); body.appendChild(el("h3", null, x.title)); body.appendChild(el("p", null, x.text));
      if (x.ask) { var a = el("p", "ttask"); a.appendChild(el("b", null, "Ask: ")); a.appendChild(document.createTextNode(x.ask)); body.appendChild(a); }
      li.appendChild(body); li.appendChild(el("p", "tthidden", "Update " + (k + 1) + " opens at +" + x.at + " min")); ol.appendChild(li);
    });
    inj.appendChild(ol); b.appendChild(inj);
    go.addEventListener("click", function () { if (clock.timer) stopClock(false); else startClock(); });
    rs.addEventListener("click", function () { stopClock(true); });
    cb.addEventListener("change", function () { clock.reveal = cb.checked; tick(); });

    var q = el("section", "panel"); q.appendChild(el("h2", null, "Discussion questions"));
    var qo = el("ol", "ttlist"); cur.questions.forEach(function (x) { qo.appendChild(el("li", null, x)); }); q.appendChild(qo); b.appendChild(q);
    var g = el("section", "panel"); g.appendChild(el("h2", null, "What good looks like"));
    var gu = el("ul", "ttlist good"); cur.good.forEach(function (x) { gu.appendChild(el("li", null, x)); }); g.appendChild(gu); b.appendChild(g);
    if (cur.adapt) { var ad = el("section", "panel"); ad.appendChild(el("h2", null, "Make it yours")); ad.appendChild(el("p", null, cur.adapt)); b.appendChild(ad); }
    if (cur.sources.length) { var so = el("p", "note ttsrc", "Sources read: "); cur.sources.forEach(function (s, k) { if (k) so.appendChild(document.createTextNode(" · ")); so.appendChild(link(s.url, s.name)); }); b.appendChild(so); }
    b.appendChild(el("p", "note", "Written by CyberView AI (a Claude model) from the event's verified record and the sources above, under the same rules as every event. Check the facts against the sources before you rely on them. Free to use and adapt for your own team's exercises."));
    tick();
  }

  function elapsed() { return clock.held + (clock.start ? Date.now() - clock.start : 0); }
  function startClock() { clock.start = Date.now(); clock.timer = setInterval(tick, 1000); $("ttGo").textContent = "Pause"; tick(); }
  function stopClock(reset) {
    if (clock.start) clock.held += Date.now() - clock.start; clock.start = 0; clearInterval(clock.timer); clock.timer = 0;
    if (reset) clock.held = 0; var g = $("ttGo"); if (g) g.textContent = reset || !clock.held ? "Start clock" : "Resume"; tick();
  }
  function tick() {
    var face = $("ttFace"); if (!face || !cur) return;
    var s = Math.floor(elapsed() / 1000), m = Math.floor(s / 60);
    face.textContent = (m < 10 ? "0" : "") + m + ":" + (s % 60 < 10 ? "0" : "") + (s % 60);
    var items = document.querySelectorAll("#ttInj > li"), next = null;
    Array.prototype.forEach.call(items, function (li) {
      var on = (clock.start || clock.held) > 0, at = +li.dataset.at, due = on && m >= at;
      if (due && !li.classList.contains("due") && clock.start && at > 0) { try { li.scrollIntoView({ block: "nearest", behavior: "smooth" }); } catch (e) {} }
      li.classList.toggle("due", due);
      li.classList.toggle("locked", clock.reveal && !due);
      if (m < at && next === null) next = at;
    });
    face.title = next === null ? "All updates are out" : "Next update at +" + next + " min";
  }

  function asText() {
    var L = ["TABLETOP EXERCISE: " + cur.title, (cur.date ? fmtDay(cur.date) + " · " : "") + cur.duration + " minutes" + (cur.roles.length ? " · " + cur.roles.join(", ") : ""),
      "Exercise only. Built from a real, verified event; the scenario for your organisation is invented for practice.", "", "WHAT REALLY HAPPENED", cur.story];
    cur.facts.forEach(function (f) { L.push("- " + f.text + " (" + f.url + ")"); });
    L.push("", "YOUR SCENARIO", cur.scenario, "", "TIMED UPDATES");
    cur.injects.forEach(function (x) { L.push("+" + x.at + " min  " + x.title, "  " + x.text); if (x.ask) L.push("  Ask: " + x.ask); });
    L.push("", "DISCUSSION QUESTIONS"); cur.questions.forEach(function (x, i) { L.push((i + 1) + ". " + x); });
    L.push("", "WHAT GOOD LOOKS LIKE"); cur.good.forEach(function (x) { L.push("- " + x); });
    if (cur.adapt) L.push("", "MAKE IT YOURS", cur.adapt);
    if (cur.sources.length) { L.push("", "SOURCES"); cur.sources.forEach(function (s) { L.push("- " + s.name + ": " + s.url); }); }
    L.push("", "From CyberView: " + location.href.split("#")[0]);
    return L.join("\n");
  }
  $("ttCopy").addEventListener("click", function () {
    var b = $("ttCopy"), done = function (t) { b.textContent = t; setTimeout(function () { b.textContent = "Copy as text"; }, 2200); };
    try { navigator.clipboard.writeText(asText()).then(function () { done("Copied"); }, function () { done("Copy blocked"); }); } catch (e) { done("Copy blocked"); }
  });
  $("ttSave").addEventListener("click", function () {
    var a = el("a"); a.href = blobUrl(new Blob([asText()], { type: "text/plain" })); var u = a.href; a.download = "cyberview-exercise-" + (cur.date || "latest") + ".txt";
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(u); }, 4000);
  });
  $("ttPrint").addEventListener("click", function () { window.print(); });
})();
