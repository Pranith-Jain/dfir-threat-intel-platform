// CyberView offline copy. The network always comes first, so visitors get the newest data whenever the site answers.
// If the site cannot be reached (an outage at the host, a dropped connection), the last good copy of each page and
// data file is served instead, and the page says how old the data is. Same-origin GET requests only; nothing else is touched.
"use strict";
// the name changes when the worker changes, so a deploy of a new sw.js drops every older stored copy
var CACHE = "cyberview-v2";
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (ev) {
  ev.waitUntil(caches.keys().then(function (keys) { return Promise.all(keys.filter(function (k) { return k !== CACHE && /^cyberview-/.test(k); /* only our own older copies, never another site on this origin */ }).map(function (k) { return caches.delete(k); })); }).then(function () { return self.clients.claim(); }));
});
// one stored copy per file: the key is the path only (no query, no hash), so links with made-up query strings cannot
// fill a visitor's storage with copies (pen test 2026-11-23)
function keyOf(req) { var u = new URL(req.url); return u.origin + u.pathname; }
function timeout(ms) { return new Promise(function (_, no) { setTimeout(function () { no(new Error("timeout")); }, ms); }); }
self.addEventListener("fetch", function (ev) {
  var req = ev.request, url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  // the CVE lookup files are many and large: always straight from the network, never stored in the offline copy
  if (/\/data\/cve\//.test(url.pathname)) return;
  var key = keyOf(req);
  // pages, scripts and styles skip the browser's 10-minute HTTP cache (revalidated, so still cheap): after a deploy a
  // phone never runs a new page with an old script or the reverse
  var net = fetch(/\.(html|js|css)$|\/$/.test(url.pathname) || req.mode === "navigate" ? new Request(req, { cache: "no-cache" }) : req).then(function (res) {
    // keep only complete, successful answers from this site; a slow answer is still stored when it lands
    if (res && res.status === 200 && res.type === "basic") { var copy = res.clone(); caches.open(CACHE).then(function (c) { return c.put(key, copy); }).catch(function () {}); }
    return res;
  });
  ev.waitUntil(net.then(function () {}, function () {}));
  // after 12 s (or offline) the stored copy is shown; with nothing stored, keep waiting for the network instead of failing
  ev.respondWith(Promise.race([net, timeout(12000)]).catch(function () {
    return caches.open(CACHE).then(function (c) { return c.match(key); }).then(function (hit) { return hit || net; });
  }));
});
