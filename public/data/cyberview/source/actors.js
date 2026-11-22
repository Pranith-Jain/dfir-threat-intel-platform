// CyberView threat actor profiles. Reads data/actors.json (written by scripts/build.mjs through scripts/actors.mjs, no AI
// model). Every record goes through clean*() first; all text is inserted as text. Claims are always labelled as claims.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  // one failing profile must not blank the page: each renders inside safe() and says so if it breaks
  function safe(name, fn, box) { try { fn(); } catch (e) { if (box) box.appendChild(el("p", "note bad", "The " + name + " profile could not be shown.")); } }
  function str(v, n) { return typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, n) : ""; }
  function date(v) { return typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : ""; }
  function id(v) { return typeof v === "string" && /^[a-z0-9][a-z0-9-]{1,119}$/.test(v) ? v : ""; }
  function https(v) { if (typeof v !== "string" || v.length > 600) return ""; try { var u = new URL(v); return u.protocol === "https:" ? u.href : ""; } catch (e) { return ""; } }
  function list(v, n) { return Array.isArray(v) ? v.slice(0, n) : []; }
  function fmt(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { return d; } }
  function plural(n, w) { return n + " " + w + (n === 1 ? "" : "s"); }
  var ATTACK_URL = /^https:\/\/attack\.mitre\.org\/groups\/G\d{4}\/$/;

  // ---------- clean: known fields only, with length limits ----------
  function cleanAttack(a) {
    if (!a || typeof a !== "object" || !/^G\d{4}$/.test(a.id || "")) return null;
    var url = "https://attack.mitre.org/groups/" + a.id + "/";
    return { id: a.id, name: str(a.name, 80), url: ATTACK_URL.test(url) ? url : "" };
  }
  function cleanEv(r) {
    if (!r || typeof r !== "object" || !id(r.event_id)) return null;
    return { event_id: r.event_id, title: str(r.title, 160) || r.event_id, date: date(r.date), as_written: str(r.as_written, 200), org: str(r.org, 80),
      by: str(r.by, 120), by_type: r.by_type === "government" ? "government" : "investigator", url: https(r.url), origin: str(r.origin_country, 60), note: str(r.note, 200) };
  }
  function cleanAlias(a) {
    if (!a || typeof a !== "object" || !str(a.name, 80)) return null;
    var basis = a.basis === "attack" ? "attack" : a.basis === "event" ? "event" : "";
    if (!basis) return null;
    return { name: str(a.name, 80), basis: basis, source: str(a.source, 220), url: basis === "attack" && ATTACK_URL.test(a.url || "") ? a.url : "", event_id: id(a.event_id) };
  }
  function cleanCount(c) { return c && typeof c === "object" && str(c.k, 60) && typeof c.n === "number" && c.n > 0 && c.n < 1e6 ? { k: str(c.k, 60), n: Math.round(c.n) } : null; }
  function cleanProfile(p) {
    if (!p || typeof p !== "object" || !id(p.id) || !str(p.name, 80)) return null;
    var out = {
      id: p.id, name: str(p.name, 80), attack: cleanAttack(p.attack), namesake: cleanAttack(p.attack_namesake),
      aliases: list(p.aliases, 60).map(cleanAlias).filter(Boolean),
      attributed: list(p.attributed, 200).map(cleanEv).filter(function (r) { return r && r.by && r.url; }),
      named: list(p.named, 200).map(cleanEv).filter(Boolean),
      claimed: list(p.claimed, 300).map(cleanEv).filter(Boolean),
      sectors: list(p.sectors, 12).map(cleanCount).filter(Boolean), countries: list(p.countries, 12).map(cleanCount).filter(Boolean),
      cves: list(p.cves, 40).filter(function (c) { return c && /^CVE-\d{4}-\d{4,7}$/.test(c.id || ""); }).map(function (c) { return { id: c.id, n: list(c.event_ids, 10).length }; }),
      advisories: list(p.advisories, 20).map(function (a) { return a && https(a.url) ? { publisher: str(a.publisher, 120) || "Advisory", doc_id: str(a.doc_id, 60), url: https(a.url), event_id: id(a.event_id) } : null; }).filter(Boolean),
      related: list(p.related, 10).map(function (r) { return r && str(r.name, 80) && id(r.event_id) ? { name: str(r.name, 80), event_id: r.event_id, title: str(r.title, 160) } : null; }).filter(Boolean),
      ambiguous: list(p.ambiguous, 5).map(function (a) { return a && str(a.name, 80) ? { name: str(a.name, 80), ids: list(a.attack_ids, 6).filter(function (x) { return /^G\d{4}$/.test(x); }) } : null; }).filter(Boolean),
      first: date(p.first_seen), last: date(p.last_seen)
    };
    out.claimsOnly = !out.attributed.length && !out.named.length;
    if (out.claimsOnly && !out.claimed.length) return null;
    if (out.claimsOnly) { out.attack = null; out.cves = []; out.advisories = []; out.sectors = []; out.countries = []; }   // a claim never makes a fact
    out.hay = [out.name].concat(out.aliases.map(function (a) { return a.name; }), out.attack ? [out.attack.id, out.attack.name] : []).join(" ").toLowerCase();
    return out;
  }

  // ---------- render ----------
  var all = [], box = $("list");
  function evLink(r) { var a = el("a", null, r.title); a.href = "archive.html#q=" + encodeURIComponent(r.event_id); return a; }
  function safeUrl(u) { return https(u) || "#"; }
  function ext(text, url) { var a = el("a", null, text); a.href = safeUrl(url); a.rel = "noopener noreferrer"; a.target = "_blank"; return a; }
  function section(parent, title, cls) { var s = el("section", "asec" + (cls ? " " + cls : "")); s.appendChild(el("h3", null, title)); parent.appendChild(s); return s; }

  function profile(p) {
    var d = el("details", "actor" + (p.claimsOnly ? " claimsonly" : "")); d.id = "a-" + p.id;
    var sm = el("summary"), h = el("span", "aname", p.name); sm.appendChild(h);
    var badges = el("span", "abadges");
    if (p.attributed.length) badges.appendChild(el("span", "pill att", plural(p.attributed.length, "attributed event")));
    if (p.named.length) badges.appendChild(el("span", "pill", "named in " + plural(p.named.length, "event")));
    if (p.claimed.length) badges.appendChild(el("span", "pill claimed", plural(p.claimed.length, "claim") + ", not confirmed"));
    sm.appendChild(badges);
    if (p.last) sm.appendChild(el("span", "alast", "last on file " + fmt(p.last)));
    d.appendChild(sm);
    var body = el("div", "abody"); d.appendChild(body);

    if (p.aliases.length) {
      var s = section(body, "Also called"), ul = el("ul", "aalias");
      p.aliases.forEach(function (a) {
        var li = el("li"); li.appendChild(el("span", "aal", a.name)); li.appendChild(document.createTextNode(" (per "));
        if (a.basis === "attack") li.appendChild(a.url ? ext(a.source || "MITRE ATT&CK", a.url) : el("span", null, a.source));
        else { li.appendChild(document.createTextNode("the sources of ")); var ea = el("a", null, a.source.replace(/^named as one group in /, "") || "an event"); ea.href = "archive.html#q=" + encodeURIComponent(a.event_id); li.appendChild(ea); }
        li.appendChild(document.createTextNode(")")); ul.appendChild(li);
      });
      s.appendChild(ul);
    }
    if (p.attack) { var at = el("p", "note"); at.appendChild(document.createTextNode("MITRE ATT&CK: ")); at.appendChild(ext(p.attack.id + " " + p.attack.name, p.attack.url)); body.appendChild(at); }
    if (p.namesake) { var ns = el("p", "note"); ns.appendChild(document.createTextNode("MITRE ATT&CK tracks a group also called " + p.namesake.name + " (")); ns.appendChild(ext(p.namesake.id, p.namesake.url)); ns.appendChild(document.createTextNode("). CyberView does not treat them as the same group: here the name appears only in leak-site claims.")); body.appendChild(ns); }
    p.ambiguous.forEach(function (a) { body.appendChild(el("p", "note", "MITRE ATT&CK lists the name " + a.name + " under more than one group (" + a.ids.join(", ") + "), so it is not matched to any of them.")); });
    p.related.forEach(function (r) { var rp = el("p", "note"); rp.appendChild(document.createTextNode("Named alongside " + r.name + " in ")); var ra = el("a", null, r.title || r.event_id); ra.href = "archive.html#q=" + encodeURIComponent(r.event_id); rp.appendChild(ra); rp.appendChild(document.createTextNode("; MITRE ATT&CK keeps them as separate groups, so they are not merged here.")); body.appendChild(rp); });

    var origins = {}; p.attributed.forEach(function (r) { if (r.origin) origins[r.origin + "|" + r.by] = r; });
    var ok = Object.keys(origins);
    if (ok.length) {
      var op = el("p", "aorig"); op.appendChild(el("strong", null, "Said to be based in: "));
      ok.forEach(function (k, i) { var r = origins[k]; if (i) op.appendChild(document.createTextNode("; ")); op.appendChild(document.createTextNode(r.origin + ", per ")); op.appendChild(ext(r.by, r.url)); op.appendChild(document.createTextNode(r.by_type === "government" ? " (government)" : " (investigating firm)")); });
      body.appendChild(op);
    }

    if (p.attributed.length) {
      var sa = section(body, "Attributed by a government or the investigating firm"), ua = el("ul", "aev");
      p.attributed.forEach(function (r) {
        var li = el("li"); li.appendChild(el("span", "date", fmt(r.date))); li.appendChild(evLink(r));
        var w = el("span", "awho"); w.appendChild(document.createTextNode("Attributed by ")); w.appendChild(ext(r.by, r.url)); w.appendChild(document.createTextNode(r.by_type === "government" ? " (government)" : " (investigating firm)") );
        if (r.note) w.appendChild(document.createTextNode(": " + r.note)); li.appendChild(w); ua.appendChild(li);
      });
      sa.appendChild(ua);
    }
    if (p.named.length) {
      var sn = section(body, "Named in the reporting an event cites"), un = el("ul", "aev");
      p.named.forEach(function (r) { var li = el("li"); li.appendChild(el("span", "date", fmt(r.date))); li.appendChild(evLink(r)); if (r.as_written) li.appendChild(el("span", "awho", "As the sources put it: " + r.as_written)); un.appendChild(li); });
      sn.appendChild(un);
      sn.appendChild(el("p", "note", "The sources' words, not an attribution by CyberView."));
    }
    if (p.sectors.length || p.countries.length) {
      var st = section(body, "Who it went after, in these events");
      if (p.sectors.length) st.appendChild(el("p", null, "Sectors: " + p.sectors.map(function (c) { return c.k + " (" + c.n + ")"; }).join(", ")));
      if (p.countries.length) st.appendChild(el("p", null, "Countries: " + p.countries.map(function (c) { return c.k + " (" + c.n + ")"; }).join(", ")));
      st.appendChild(el("p", "note", "From attributed and named events only; claims are not counted."));
    }
    if (p.cves.length) {
      var sc = section(body, "CVEs in these events"), cp = el("p", "acves");
      p.cves.forEach(function (c, i) { if (i) cp.appendChild(document.createTextNode(", ")); var a = el("a", "mono", c.id); a.href = "vulnerabilities.html#" + encodeURIComponent(c.id); cp.appendChild(a); });
      sc.appendChild(cp); sc.appendChild(el("p", "note", "Listed in attributed or named events; whether this group exploited each one is in the event itself."));
    }
    if (p.advisories.length) {
      var sv = section(body, "Government advisories cited"), uv = el("ul", "aev");
      p.advisories.forEach(function (a) { var li = el("li"); li.appendChild(ext(a.publisher + (a.doc_id ? " " + a.doc_id : ""), a.url)); uv.appendChild(li); });
      sv.appendChild(uv);
    }
    if (p.claimed.length) {
      var sk = section(body, "Claimed by the group, not confirmed", "aclaims"), uk = el("ul", "aev");
      p.claimed.forEach(function (r) { var li = el("li"); li.appendChild(el("span", "date", fmt(r.date))); li.appendChild(evLink(r)); li.appendChild(el("span", "awho", (r.org ? r.org + ": " : "") + "the group's claim; the organisation has not confirmed it.")); uk.appendChild(li); });
      sk.appendChild(uk);
      sk.appendChild(el("p", "note", "Leak-site claims are the attackers' own statements and are often false or exaggerated."));
    }
    var foot = el("p", "afoot");
    if (p.first) foot.appendChild(document.createTextNode("On file " + (p.first === p.last ? fmt(p.first) : fmt(p.first) + " to " + fmt(p.last)) + ". "));
    var aa = el("a", null, "Search the archive for " + p.name); aa.href = "archive.html#q=" + encodeURIComponent(p.name); foot.appendChild(aa);
    var pl = el("a", "aperm", "Link to this profile"); pl.href = "#a=" + encodeURIComponent(p.id); foot.appendChild(document.createTextNode(" · ")); foot.appendChild(pl);
    body.appendChild(foot);
    return d;
  }

  function want() { var h = location.hash.slice(1); if (h.indexOf("a=") !== 0) return ""; try { return id(decodeURIComponent(h.slice(2))); } catch (e) { return ""; } }
  function render() {
    var q = $("q").value.trim().toLowerCase(), showClaims = $("claims").checked, target = want();
    while (box.firstChild) box.removeChild(box.firstChild);
    var shown = all.filter(function (p) { return (showClaims || !p.claimsOnly || p.id === target) && (!q || p.hay.indexOf(q) >= 0); });
    var checked = shown.filter(function (p) { return !p.claimsOnly; }), claims = shown.filter(function (p) { return p.claimsOnly; });
    checked.forEach(function (p) { safe(p.name, function () { box.appendChild(profile(p)); }, box); });
    if (claims.length) {
      box.appendChild(el("h2", "agroup", "Seen only in leak-site claims"));
      box.appendChild(el("p", "note", "These groups appear on file only through their own claims. Nothing here is confirmed."));
      claims.forEach(function (p) { safe(p.name, function () { box.appendChild(profile(p)); }, box); });
    }
    var hidden = all.filter(function (p) { return p.claimsOnly && shown.indexOf(p) < 0; }).length;
    $("count").textContent = shown.length ? plural(shown.length, "group") + " shown" + (!showClaims && hidden ? "; " + hidden + " seen only in claims " + (hidden === 1 ? "is" : "are") + " hidden" : "") + "." : "No group matches. Try another name, or show groups seen only in claims.";
    if (target) { var t = $("a-" + target); if (t) { t.open = true; try { t.scrollIntoView({ block: "start" }); } catch (e) {} } }
  }

  fetch("data/actors.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (j) {
    if (!j || typeof j !== "object") throw new Error();
    all = list(j.profiles, 2000).map(function (p) { try { return cleanProfile(p); } catch (e) { return null; } }).filter(Boolean);
    var n = all.filter(function (p) { return !p.claimsOnly; }), att = n.filter(function (p) { return p.attributed.length; }).length, co = all.length - n.length;
    $("summary").textContent = j.error && !all.length ? "The actor profiles could not be built this time. The last good copy will return with the next build."
      : plural(n.length, "group") + " named in CyberView's checked events, " + att + " of them attributed by a government or the investigating firm; " + co + (co === 1 ? " more appears only in its own" : " more appear only in their own") + " leak-site claims.";
    var notice = str(j.attack_notice, 300);
    if (notice) { var an = $("attackNote"); an.hidden = false; an.textContent = "Other names and IDs from MITRE ATT&CK" + (str(j.attack_version, 20) ? " v" + str(j.attack_version, 20) : "") + " (names, aliases and IDs only). " + notice; }
    $("q").addEventListener("input", render);
    $("claims").addEventListener("change", render);
    window.addEventListener("hashchange", render);
    render();
  }).catch(function () { $("summary").textContent = "The actor profiles can't be loaded right now. Try again in a minute."; });
})();
