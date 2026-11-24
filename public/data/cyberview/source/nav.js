// Site navigation for every page: inline links on wide screens; on narrow screens a menu button opens a sheet.
// Esc, a click outside or choosing a link closes it; focus moves into the sheet and back to the button.
(function () {
  "use strict";
  // not framed by another site (pen test 2026-11-23): GitHub Pages cannot send frame-ancestors, so a framed copy hides
  // itself and tries to take over the top window; this blocks clickjacking of the list and account controls
  if (window.top !== window.self) { document.documentElement.style.display = "none"; try { window.top.location = window.self.location.href; } catch (e) {} return; }
  // offline copy (sw.js): if the site cannot be reached, the last good pages and data are shown instead of an error
  try { if ("serviceWorker" in navigator && /^https:$|^http:$/.test(location.protocol)) navigator.serviceWorker.register("sw.js").catch(function () {}); } catch (e) {}
  // tables with class "stack" turn into cards on phones; each cell needs its column name (CSS reads data-label)
  function label(t) { var hs = Array.prototype.map.call(t.querySelectorAll("thead th"), function (h) { return h.textContent.trim(); }); if (!hs.length) return;
    Array.prototype.forEach.call(t.querySelectorAll("tbody tr"), function (tr) { Array.prototype.forEach.call(tr.children, function (td, i) { if (hs[i] && !td.hasAttribute("data-label")) td.setAttribute("data-label", hs[i]); }); }); }
  Array.prototype.forEach.call(document.querySelectorAll("table.stack"), function (t) { label(t); try { new MutationObserver(function () { label(t); }).observe(t, { childList: true, subtree: true }); } catch (e) {} });
  // pages added after a page's markup was written: added to its links (inline and menu) after the named link, once
  function safeUrl(u) { return /^[a-z]+\.html$/.test(u) ? u : "./"; }   // own pages only
  [["scanner.html", "Scanner", "vulnerabilities.html"], ["actors.html", "Actors", "trends.html"]].forEach(function (x) {
    Array.prototype.forEach.call(document.querySelectorAll("nav.sitenav, nav.sheetnav"), function (nav) {
      if (nav.querySelector('a[href="' + x[0] + '"]')) return;
      var after = nav.querySelector('a[href="' + x[2] + '"]'), a = document.createElement("a"); a.href = safeUrl(x[0]); a.textContent = x[1];
      if (after) after.parentNode.insertBefore(a, after.nextSibling); else nav.appendChild(a);
    });
  });
  var bar = document.querySelector("header.bar, .bar");
  function barh() { if (bar && getComputedStyle(bar).position === "sticky") document.documentElement.style.setProperty("--barh", bar.offsetHeight + "px"); }
  if (bar && !document.getElementById("stage")) { barh(); window.addEventListener("resize", barh); }
  var btn = document.getElementById("navBtn"), sheet = document.getElementById("navSheet");
  if (!btn || !sheet) return;
  function set(open) {
    sheet.hidden = !open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    btn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    document.body.classList.toggle("nav-open", open);
    if (open) { var f = sheet.querySelector(".sheetnav a"); if (f) f.focus(); }
  }
  btn.addEventListener("click", function (ev) { ev.stopPropagation(); set(sheet.hidden); });
  var close = document.getElementById("navClose");
  if (close) close.addEventListener("click", function () { set(false); btn.focus(); });
  document.addEventListener("keydown", function (ev) { if (ev.key === "Escape" && !sheet.hidden) { set(false); btn.focus(); } });
  document.addEventListener("click", function (ev) { if (!sheet.hidden && !sheet.contains(ev.target) && !btn.contains(ev.target)) set(false); });
  Array.prototype.forEach.call(sheet.querySelectorAll("a"), function (a) { a.addEventListener("click", function () { set(false); }); });
  window.addEventListener("resize", function () { if (!sheet.hidden && window.innerWidth > 760) set(false); });
})();

/* Dropdowns that match the site. On a mouse or trackpad, each <select> keeps working as the real control (its value,
   its change event, every existing listener) while the open list is drawn in the site's own style instead of the
   browser's white system menu. On touch screens the native picker stays: it is the better experience there.
   Keyboard: Enter, Space or Alt+Down opens; Up, Down, Home, End move; a letter jumps; Enter picks; Esc or Tab closes.
   Text only: options are copied with textContent, never as HTML. */
(function () {
  "use strict";
  if (!window.matchMedia || !matchMedia("(hover: hover) and (pointer: fine)").matches) return;
  var css = ".cvsel{position:relative;display:inline-block;min-width:0;vertical-align:middle}" +
    ".cvsel>select{position:absolute!important;inset:0;width:100%;height:100%;opacity:0;pointer-events:none}" +
    ".cvsel-btn{all:unset;box-sizing:border-box;display:flex;align-items:center;gap:8px;width:100%;min-height:40px;padding:8px 32px 8px 11px;border-radius:10px;border:1px solid var(--line,rgba(255,255,255,.14));" +
    "background:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1.5l5 5 5-5' fill='none' stroke='%23b9bdc6' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E\") no-repeat right 12px center,linear-gradient(180deg,rgba(255,255,255,.16),rgba(255,255,255,.05) 55%,rgba(255,255,255,.03)),rgba(255,255,255,.06);" +
    "box-shadow:inset 0 1px 0 rgba(255,255,255,.18),inset 0 -1px 0 rgba(0,0,0,.12),0 2px 8px rgba(0,0,0,.14);" +
    "color:var(--ink,#f5f5f7);font:inherit;font-size:15px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}" +
    ".cvsel-btn:hover{background-color:rgba(255,255,255,.12);box-shadow:inset 0 1px 0 rgba(255,255,255,.26),inset 0 -1px 0 rgba(0,0,0,.12),0 3px 10px rgba(0,0,0,.18)}" +
    ".cvsel-btn[aria-expanded=true]{border-color:var(--accent,#6cb6ff)}.cvsel-btn:focus-visible{outline:2px solid var(--accent,#6cb6ff);outline-offset:1px}" +
    ".cvsel-btn[aria-disabled=true]{opacity:.5;cursor:default}" +
    ".cvsel-list{position:fixed;z-index:1000;margin:0;padding:6px;list-style:none;max-height:min(340px,60vh);overflow:auto;border-radius:12px;" +
    "border:1px solid var(--glass-brd,rgba(255,255,255,.18));color:var(--ink,#f5f5f7);" +
    "background:linear-gradient(180deg,rgba(255,255,255,.16),rgba(255,255,255,.05) 40%,rgba(255,255,255,.02)),color-mix(in srgb,var(--solid,#2b2d33) 88%,transparent);" +
    "box-shadow:0 20px 50px rgba(0,0,0,.38),0 2px 6px rgba(0,0,0,.2),inset 0 1px 0 var(--glass-hi,rgba(255,255,255,.22)),inset 0 -1px 0 rgba(255,255,255,.06);" +
    "-webkit-backdrop-filter:blur(30px) saturate(190%);backdrop-filter:blur(30px) saturate(190%)}" +
    ".cvsel-list li{padding:8px 30px 8px 10px;border-radius:8px;font-size:14px;cursor:pointer;position:relative;white-space:nowrap}" +
    ".cvsel-list li[aria-selected=true]{font-weight:600}" +
    ".cvsel-list li[aria-selected=true]::after{content:'';position:absolute;right:11px;top:50%;width:6px;height:10px;margin-top:-7px;border:solid var(--accent,#6cb6ff);border-width:0 2px 2px 0;transform:rotate(45deg)}" +
    ".cvsel-list li.on{background:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,.04)),var(--tint,rgba(108,182,255,.2));box-shadow:inset 0 1px 0 rgba(255,255,255,.16)}.cvsel-list li[aria-disabled=true]{opacity:.45;cursor:default}" +
    ".cvsel-list li.grp{font-size:12px;color:var(--muted,#b9bdc6);cursor:default;padding-top:10px}";
  var st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
  var open = null, n = 0;
  function label(sel) { var o = sel.options[sel.selectedIndex]; return o ? o.textContent : ""; }
  function enhance(sel) {
    if (sel.multiple || sel.size > 1 || sel.dataset.native === "1" || (sel.parentNode && sel.parentNode.classList && sel.parentNode.classList.contains("cvsel"))) return;
    var wrap = document.createElement("span"), btn = document.createElement("button"), id = "cvsel" + (++n);
    wrap.className = "cvsel"; var cs = getComputedStyle(sel);
    if (cs.display === "block" || cs.width === "100%" || sel.style.width === "100%") wrap.style.display = "block";
    wrap.style.maxWidth = cs.maxWidth !== "none" ? cs.maxWidth : ""; wrap.style.flex = cs.flex;
    /* keep the size each page gave its own field */
    btn.style.fontSize = cs.fontSize; btn.style.minHeight = cs.height !== "auto" ? cs.height : ""; btn.style.borderRadius = cs.borderRadius;
    btn.type = "button"; btn.className = "cvsel-btn"; btn.setAttribute("aria-haspopup", "listbox"); btn.setAttribute("aria-expanded", "false"); btn.id = id;
    var lab = sel.labels && sel.labels[0]; if (lab) { var t = (lab.querySelector("span") || lab).textContent.replace(label(sel), "").trim(); if (t) btn.setAttribute("aria-label", t); }
    else if (sel.getAttribute("aria-label")) btn.setAttribute("aria-label", sel.getAttribute("aria-label"));
    sel.parentNode.insertBefore(wrap, sel); wrap.appendChild(sel); wrap.appendChild(btn);
    sel.tabIndex = -1; sel.setAttribute("aria-hidden", "true");
    var sync = function () { btn.textContent = label(sel); btn.setAttribute("aria-disabled", sel.disabled ? "true" : "false"); btn.disabled = false; btn.title = btn.textContent; };
    sync(); sel.addEventListener("change", sync);
    new MutationObserver(sync).observe(sel, { childList: true, subtree: true, attributes: true, characterData: true });
    sel._cvsync = sync;
    btn.addEventListener("click", function (e) { e.preventDefault(); if (sel.disabled) return; open && open.sel === sel ? close(true) : show(sel, btn); });
    btn.addEventListener("keydown", function (e) {
      if (sel.disabled) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") { e.preventDefault(); show(sel, btn); }
    });
  }
  function show(sel, btn) {
    close(false);
    var ul = document.createElement("ul"), items = [], cur = sel.selectedIndex;
    ul.className = "cvsel-list"; ul.setAttribute("role", "listbox"); ul.id = btn.id + "-list"; ul.tabIndex = -1;
    if (btn.getAttribute("aria-label")) ul.setAttribute("aria-label", btn.getAttribute("aria-label"));
    Array.prototype.forEach.call(sel.children, function (ch) {
      var add = function (o) { var li = document.createElement("li"); li.setAttribute("role", "option"); li.id = ul.id + "-" + o.index; li.textContent = o.textContent;
        li.setAttribute("aria-selected", o.index === cur ? "true" : "false"); if (o.disabled) li.setAttribute("aria-disabled", "true");
        li.addEventListener("mousemove", function () { move(items.indexOf(li)); });
        li.addEventListener("click", function () { if (!o.disabled) pick(o.index); });
        items.push(li); li._i = o.index; ul.appendChild(li); };
      if (ch.tagName === "OPTGROUP") { var g = document.createElement("li"); g.className = "grp"; g.setAttribute("role", "presentation"); g.textContent = ch.label; ul.appendChild(g); Array.prototype.forEach.call(ch.children, add); }
      else add(ch);
    });
    document.body.appendChild(ul);
    place(btn, ul);
    btn.setAttribute("aria-expanded", "true"); btn.setAttribute("aria-controls", ul.id);
    var at = Math.max(0, items.findIndex(function (li) { return li._i === cur; }));
    open = { sel: sel, btn: btn, ul: ul, items: items, at: at, typed: "", tt: 0 };
    move(at); ul.focus({ preventScroll: true });
    ul.addEventListener("keydown", key);
    ul.addEventListener("focusout", function (e) { if (open && open.ul === ul && !ul.contains(e.relatedTarget)) setTimeout(function () { if (open && open.ul === ul && document.activeElement !== ul) close(false); }, 0); });
  }
  function move(i) {
    if (!open || !open.items.length) return;
    i = Math.max(0, Math.min(open.items.length - 1, i));
    open.items.forEach(function (li, k) { li.classList.toggle("on", k === i); });
    open.at = i; open.ul.setAttribute("aria-activedescendant", open.items[i].id);
    var li = open.items[i], ul = open.ul; if (li.offsetTop < ul.scrollTop) ul.scrollTop = li.offsetTop - 6; else if (li.offsetTop + li.offsetHeight > ul.scrollTop + ul.clientHeight) ul.scrollTop = li.offsetTop + li.offsetHeight - ul.clientHeight + 6;
  }
  function pick(idx) {
    var sel = open.sel; close(true);
    if (sel.selectedIndex !== idx) { sel.selectedIndex = idx; sel.dispatchEvent(new Event("input", { bubbles: true })); sel.dispatchEvent(new Event("change", { bubbles: true })); }
    if (sel._cvsync) sel._cvsync();
  }
  function close(refocus) {
    if (!open) return; var o = open; open = null;
    o.btn.setAttribute("aria-expanded", "false"); o.btn.removeAttribute("aria-controls");
    if (o.ul.parentNode) o.ul.parentNode.removeChild(o.ul);
    if (refocus) o.btn.focus({ preventScroll: true });
  }
  function key(e) {
    if (!open) return; var k = e.key;
    if (k === "ArrowDown") { e.preventDefault(); move(open.at + 1); }
    else if (k === "ArrowUp") { e.preventDefault(); move(open.at - 1); }
    else if (k === "Home") { e.preventDefault(); move(0); } else if (k === "End") { e.preventDefault(); move(open.items.length - 1); }
    else if (k === "PageDown") { e.preventDefault(); move(open.at + 8); } else if (k === "PageUp") { e.preventDefault(); move(open.at - 8); }
    else if (k === "Enter" || k === " ") { e.preventDefault(); var li = open.items[open.at]; if (li && li.getAttribute("aria-disabled") !== "true") pick(li._i); }
    else if (k === "Escape") { e.preventDefault(); close(true); }
    else if (k === "Tab") { close(false); open = null; }
    else if (k.length === 1 && /\S/.test(k)) {
      clearTimeout(open.tt); open.typed += k.toLowerCase(); var o = open; open.tt = setTimeout(function () { o.typed = ""; }, 700);
      var start = o.typed.length === 1 ? o.at + 1 : o.at;
      for (var j = 0; j < o.items.length; j++) { var li2 = o.items[(start + j) % o.items.length]; if (li2.textContent.toLowerCase().indexOf(o.typed) === 0) { move(o.items.indexOf(li2)); break; } }
    }
  }
  document.addEventListener("mousedown", function (e) { if (open && !open.ul.contains(e.target) && !open.btn.contains(e.target)) close(false); });
  window.addEventListener("resize", function () { close(false); });
  // the list is fixed to the viewport: when the page scrolls (by hand, or because content above it finished loading),
  // move it with its button, and close it only once the button has left the screen
  function place(btn, ul) {
    var r = btn.getBoundingClientRect(), h = Math.min(ul.scrollHeight, 340), below = innerHeight - r.bottom - 8;
    ul.style.minWidth = r.width + "px"; ul.style.left = Math.max(8, Math.min(r.left, innerWidth - ul.offsetWidth - 8)) + "px";
    if (below >= Math.min(h, 200) || below >= r.top) ul.style.top = (r.bottom + 4) + "px"; else ul.style.top = Math.max(8, r.top - 4 - h) + "px";
  }
  document.addEventListener("scroll", function (e) {
    if (!open || open.ul.contains(e.target)) return;
    var r = open.btn.getBoundingClientRect();
    if (r.bottom < 0 || r.top > innerHeight) close(false); else place(open.btn, open.ul);
  }, true);
  function all(root) { Array.prototype.forEach.call((root || document).querySelectorAll("select"), enhance); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { all(); }); else all();
  /* selects added or refilled later (the year list, the file formats, a tab drawn on demand) */
  new MutationObserver(function (ms) { ms.forEach(function (m) { Array.prototype.forEach.call(m.addedNodes, function (nd) { if (nd.nodeType === 1) { if (nd.tagName === "SELECT") enhance(nd); else if (nd.querySelectorAll) all(nd); } }); }); })
    .observe(document.documentElement, { childList: true, subtree: true });
  /* scripts sometimes set a value in code without a change event (Refresh, Clear): keep every button's text in step */
  setInterval(function () { Array.prototype.forEach.call(document.querySelectorAll(".cvsel>select"), function (s) { if (s._cvsync) { var b = s.nextSibling; if (b && b.textContent !== label(s)) s._cvsync(); } }); }, 400);
})();
