// CyberView community feed. Reads data/chat.json: posts that passed the fixed rules (scripts/chat.mjs) and the moderator job.
// Posting happens on GitHub (an issue form); this page never sends anything itself. Posts are untrusted text from the
// public: every field passes clean() with length limits, is inserted as text, and links are https only with rel=nofollow.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var NEW_URL = "https://github.com/xanderhutch/CyberView/issues/new";
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function isId(s) { return /^[a-z0-9][a-z0-9-]{2,119}$/.test(s || ""); }
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/[^\s"'<>]+$/.test(u) || /^\.\/#e=[a-z0-9-]+$/.test(u) ? u : "about:blank"; }
  function ago(iso) { var m = Math.round((Date.now() - Date.parse(iso)) / 60000); if (!isFinite(m)) return ""; return m < 1 ? "just now" : m < 60 ? m + " min ago" : m < 1440 ? Math.round(m / 60) + " h ago" : Math.round(m / 1440) + " d ago"; }
  var KIND = { tip: "Tip", question: "Question", comment: "Comment" };

  function clean(p) {
    if (!p || typeof p !== "object") return null;
    var id = typeof p.id === "number" && isFinite(p.id) && p.id > 0 ? Math.round(p.id) : 0, text = str(p.text, 600).replace(/[\u0000-\u001f<>]/g, " ").trim();
    var author = str(p.author, 39); if (!id || !text || !/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(author) || !str(p.reviewed_at, 30)) return null;   // never show an unreviewed post
    return { id: id, at: str(p.at, 30), author: author, kind: KIND[p.kind] ? p.kind : "comment", text: text, event: isId(p.event_id) ? p.event_id : "",
      links: (Array.isArray(p.links) ? p.links : []).slice(0, 2).map(function (u) { return str(u, 600); }).filter(function (u) { return /^https:\/\/[^\s"'<>]+$/.test(u); }), note: str(p.note, 200) };
  }
  // the text with its approved links made clickable; anything else stays plain text
  function body(p) {
    var box = el("p", "cmtext"), rest = p.text;
    p.links.forEach(function (u) {
      var i = rest.indexOf(u); if (i < 0) return;
      if (i) box.appendChild(document.createTextNode(rest.slice(0, i)));
      var a = el("a", null, u.replace(/^https:\/\//, "").slice(0, 70)); a.href = safeUrl(u); a.target = "_blank"; a.rel = "nofollow ugc noopener noreferrer"; box.appendChild(a);
      rest = rest.slice(i + u.length);
    });
    if (rest) box.appendChild(document.createTextNode(rest));
    return box;
  }

  var posts = [], scope = "";
  function render() {
    var kind = $("cmShow").value, list = posts.filter(function (p) { return (!kind || p.kind === kind) && (!scope || p.event === scope); }), box = $("cmList"); box.textContent = "";
    $("cmSummary").textContent = posts.length ? posts.length + " reviewed post" + (posts.length === 1 ? "" : "s") + ", newest first." : "No posts yet. Be the first: share what you are seeing.";
    $("cmScope").textContent = scope ? "About event " + scope : ""; $("cmClear").hidden = !scope;
    if (!list.length && posts.length) { box.appendChild(el("li", "empty", "No posts match.")); return; }
    list.forEach(function (p) {
      var li = el("li", "cmpost"); li.id = "post-" + p.id;
      var head = el("div", "cmhead"); head.appendChild(el("b", null, p.author)); head.appendChild(el("span", "badge info", KIND[p.kind]));
      var when = el("span", "note", ago(p.at)); when.title = p.at; head.appendChild(when);
      head.appendChild(el("span", "note cmrev", "Reviewed")); li.appendChild(head);
      li.appendChild(body(p));
      if (p.note) li.appendChild(el("p", "note cmnote", "Moderator's note: " + p.note));
      var foot = el("div", "cmfoot");
      if (p.event) { var ev = el("a", null, "About: " + p.event); ev.href = safeUrl("./#e=" + p.event); foot.appendChild(ev); }
      var rp = el("a", null, "Report #" + p.id); rp.href = "https://github.com/xanderhutch/CyberView/issues/new?template=chat-report.yml&post=" + encodeURIComponent(String(p.id)) + "&title=" + encodeURIComponent("Report community post " + p.id);
      rp.target = "_blank"; rp.rel = "noopener noreferrer"; foot.appendChild(rp);
      li.appendChild(foot); box.appendChild(li);
    });
  }
  function load() {
    fetch("data/chat.json?t=" + Date.now(), { cache: "no-store" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
      posts = (Array.isArray(d && d.posts) ? d.posts : []).slice(0, 300).map(clean).filter(Boolean); render();
    }).catch(function () { if (!posts.length) $("cmSummary").textContent = "The feed can't be loaded right now. Try again in a minute."; });
  }

  /* the same first checks the intake script applies, so people find out before they leave the page */
  function precheck(t) {
    if (t.length < 3) return "Write a message first.";
    var links = t.match(/\bhttps?:\/\/\S+/gi) || [];
    if (links.length > 2) return "At most 2 links.";
    if (links.some(function (u) { return !/^https:/i.test(u); })) return "Links must be https.";
    if (/[\w.+-]+@[\w-]+\.[\w.-]{2,}/.test(t)) return "Leave out email addresses: posts are public.";
    if (/AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN|password\s*[:=]/i.test(t)) return "That looks like a credential. Do not post it.";
    return "";
  }
  var text = $("cmText");
  text.addEventListener("input", function () { $("cmCount").textContent = text.value.length + " / 600"; $("cmWarn").hidden = true; });
  $("cmPost").addEventListener("click", function () {
    var t = text.value.replace(/\s+/g, " ").trim(), bad = precheck(t), w = $("cmWarn");
    if (bad) { w.textContent = bad; w.hidden = false; text.focus(); return; }
    var ev = $("cmEvent").value.trim().toLowerCase().replace(/^.*#e=/, "");
    var u = NEW_URL + "?template=chat.yml&title=" + encodeURIComponent("Community post") + "&message=" + encodeURIComponent(t) + "&kind=" + encodeURIComponent($("cmKind").value) + (isId(ev) ? "&event=" + encodeURIComponent(ev) : "");
    var win = null; try { win = window.open(u, "_blank"); if (win) win.opener = null; } catch (e) { win = null; }
    w.textContent = win ? "GitHub opened in a new tab: press Submit there to send your post for review." : "The new tab was blocked. Allow pop-ups for this site and try again."; w.hidden = false; w.classList.toggle("bad", !win);
  });
  $("cmShow").addEventListener("change", render);
  $("cmClear").addEventListener("click", function () { scope = ""; try { history.replaceState(null, "", location.pathname); } catch (e) {} render(); });
  var h = location.hash.match(/^#e=([a-z0-9-]+)$/); if (h && isId(h[1])) { scope = h[1]; $("cmEvent").value = h[1]; }
  load(); setInterval(function () { if (!document.hidden) load(); }, 5 * 60 * 1000);
})();
