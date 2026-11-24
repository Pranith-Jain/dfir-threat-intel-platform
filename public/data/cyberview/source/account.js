// CyberView account page. Optional accounts on Supabase (sign-in, Postgres with row-level security).
// Privacy by design:
//   - the environment list is encrypted HERE (AES-GCM 256, key from the passphrase with PBKDF2-SHA256, 600,000 rounds)
//     and only ciphertext is sent; the passphrase never leaves this page;
//   - alert terms are stored readable only after an explicit, unticked-by-default consent, recorded with its wording;
//   - export and deletion are self-service. No HTML string sinks: every node is built and filled with textContent.
(function () {
  "use strict";
  // not framed by another site (pen test 2026-11-23): GitHub Pages cannot send frame-ancestors, so a framed copy hides
  // itself and tries to take over the top window; this blocks clickjacking of the list and account controls
  if (window.top !== window.self) { document.documentElement.style.display = "none"; try { window.top.location = window.self.location.href; } catch (e) {} return; }
  var $ = function (id) { return document.getElementById(id); };
  var meta = function (n) { var m = document.querySelector('meta[name="' + n + '"]'); return m ? m.getAttribute("content") || "" : ""; };
  var URL_ = meta("cv-supabase-url"), KEY = meta("cv-supabase-key");
  var CONSENT_VERSION = "1", KDF = "PBKDF2-SHA256-600000", ITER = 600000, WL_KEY = "cwm.wl";
  var show = function (id, on) { $(id).hidden = !on; };
  var say = function (id, text, bad) { var n = $(id); n.textContent = text || ""; n.classList.toggle("bad", !!bad); };
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  // same rules as the map's list: 2-60 characters, no markup or control characters, at most 150
  function cleanTerms(a) {
    var seen = {}, out = [];
    (Array.isArray(a) ? a : String(a || "").split(/[,\n]/)).forEach(function (t) {
      t = String(t || "").replace(/[\u0000-\u001f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 60);
      var k = t.toLowerCase(); if (t.length >= 2 && !seen[k]) { seen[k] = 1; out.push(t); }
    });
    return out.slice(0, 150);
  }
  function localTerms() { try { return cleanTerms(JSON.parse(lsGet(WL_KEY) || "[]")); } catch (e) { return []; } }

  if (!URL_ || !KEY || !window.supabase || !window.crypto || !crypto.subtle) { show("offline", true); return; }
  // Where the sign-in lives (pen test, 2026-11-24): the session (with its refresh token) is kept in this tab's
  // sessionStorage and ends when the tab closes, so other pages served from the same github.io origin cannot read a
  // long-lived token from localStorage. Only the one-time PKCE code verifier goes to localStorage, because an email
  // sign-in link opens in a new tab that must find it; it is removed as soon as the sign-in completes.
  var authStore = {
    pick: function (k) { return /code-verifier$/.test(k) ? window.localStorage : window.sessionStorage; },
    getItem: function (k) { try { return authStore.pick(k).getItem(k); } catch (e) { return null; } },
    setItem: function (k, v) { try { authStore.pick(k).setItem(k, v); } catch (e) {} },
    removeItem: function (k) { try { authStore.pick(k).removeItem(k); } catch (e) {} }
  };
  try { Object.keys(window.localStorage).forEach(function (k) { if (/^sb-.*-auth-token$/.test(k)) window.localStorage.removeItem(k); }); } catch (e) {}   // an older long-lived copy
  var sb = window.supabase.createClient(URL_, KEY, { auth: { flowType: "pkce", persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, storage: authStore } });
  var user = null;

  // ---------- encryption ----------
  var b64 = function (buf) { var s = "", a = new Uint8Array(buf); for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
  var unb64 = function (s) { var r = atob(s), a = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) a[i] = r.charCodeAt(i); return a; };
  function keyFrom(pass, salt) {
    return crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]).then(function (k) {
      return crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: ITER, hash: "SHA-256" }, k, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    });
  }
  function encrypt(pass, obj) {
    var salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    return keyFrom(pass, salt).then(function (k) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, k, new TextEncoder().encode(JSON.stringify(obj)));
    }).then(function (ct) { return { ciphertext: b64(ct), iv: b64(iv), salt: b64(salt), kdf: KDF }; });
  }
  function decrypt(pass, row) {
    if (row.kdf !== KDF) return Promise.reject(new Error("unknown format"));
    return keyFrom(pass, unb64(row.salt)).then(function (k) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(row.iv) }, k, unb64(row.ciphertext));
    }).then(function (pt) { return JSON.parse(new TextDecoder().decode(pt)); });
  }
  function passphrase() {
    var p = $("pass").value;
    if (p.length < 12) { say("syncMsg", "Use a passphrase of at least 12 characters. A few unrelated words work well.", true); return null; }
    return p;
  }

  // ---------- views ----------
  function render() {
    show("offline", false); show("signedOut", !user); show("signedIn", !!user);
    $("github").hidden = meta("cv-github") !== "1";
    if (!user) return;
    $("who").textContent = user.email || "(no email)";
    var r = meta("cv-region"); $("region").textContent = r ? ", data stored in " + r : "";
    loadAccount(); loadSyncState();
  }
  function ensureAccount() {
    return sb.from("accounts").select("user_id").eq("user_id", user.id).maybeSingle().then(function (res) {
      if (res.error) throw res.error;
      if (res.data) return;
      return sb.from("accounts").insert({ user_id: user.id }).then(function (r2) { if (r2.error) throw r2.error; });
    });
  }
  function loadAccount() {
    ensureAccount().then(function () {
      return sb.from("accounts").select("alerts_enabled,alert_frequency,alert_min_severity,alert_terms,consent_at").eq("user_id", user.id).single();
    }).then(function (res) {
      if (res.error) throw res.error;
      var a = res.data;
      $("terms").value = (a.alert_terms || []).join("\n");
      $("freq").value = a.alert_frequency; $("minsev").value = String(a.alert_min_severity);
      $("consent").checked = false;
      say("alertMsg", a.alerts_enabled ? "Alerts are ON (" + a.alert_frequency + ") for " + (a.alert_terms || []).length + " terms, since you agreed on " + String(a.consent_at).slice(0, 10) + "." : "Alerts are off.");
    }).catch(function () { say("alertMsg", "Your settings could not be loaded. Try again in a minute.", true); });
  }
  function loadSyncState() {
    var n = localTerms().length;
    sb.from("environments").select("updated_at").eq("user_id", user.id).maybeSingle().then(function (res) {
      var cloud = res.data ? "A synced copy was saved " + String(res.data.updated_at).slice(0, 16).replace("T", " ") + " UTC." : "Nothing synced yet.";
      say("syncState", "This device's list has " + n + " term" + (n === 1 ? "" : "s") + ". " + cloud);
    });
  }

  // ---------- sign in ----------
  $("emailForm").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var email = $("email").value.trim();
    if (!/^[^\s@<>]+@[^\s@<>]+\.[a-z]{2,}$/i.test(email)) { say("signMsg", "Enter a valid email address.", true); return; }
    if (!$("agree").checked) { say("signMsg", "Please confirm you are 16 or older and agree to the terms and privacy policy.", true); return; }
    $("sendLink").disabled = true;
    sb.auth.signInWithOtp({ email: email, options: { emailRedirectTo: location.origin + location.pathname, shouldCreateUser: true } }).then(function (res) {
      $("sendLink").disabled = false;
      // the same message whether or not the address has an account, so the form cannot be used to find out
      if (res.error && !/rate|limit|seconds/i.test(res.error.message || "")) say("signMsg", "The link could not be sent. Try again in a minute.", true);
      else if (res.error) say("signMsg", "Too many attempts. Wait a minute, then try again.", true);
      else say("signMsg", "If that address can sign in, a link is on its way. Open it in this same browser. It expires in one hour.");
    });
  });
  $("github").addEventListener("click", function () {
    if (!$("agree").checked) { say("signMsg", "Please confirm you are 16 or older and agree to the terms and privacy policy.", true); return; }
    sb.auth.signInWithOAuth({ provider: "github", options: { redirectTo: location.origin + location.pathname, scopes: "user:email" } });
  });
  $("signOut").addEventListener("click", function () { sb.auth.signOut().then(function () { user = null; render(); }); });

  // ---------- sync ----------
  $("push").addEventListener("click", function () {
    var p = passphrase(); if (!p) return;
    var terms = localTerms();
    if (!terms.length) { say("syncMsg", "This device has no environment list yet. Add one on the map with My environment.", true); return; }
    say("syncMsg", "Encrypting");
    encrypt(p, { v: 1, terms: terms, saved: new Date().toISOString() }).then(function (row) {
      row.user_id = user.id;
      return sb.from("environments").upsert(row, { onConflict: "user_id" });
    }).then(function (res) {
      if (res.error) throw res.error;
      say("syncMsg", "Saved, encrypted: " + terms.length + " terms. Use the same passphrase on your other devices."); loadSyncState();
    }).catch(function () { say("syncMsg", "Could not save. Try again in a minute.", true); });
  });
  $("pull").addEventListener("click", function () {
    var p = passphrase(); if (!p) return;
    sb.from("environments").select("ciphertext,iv,salt,kdf").eq("user_id", user.id).maybeSingle().then(function (res) {
      if (res.error) throw res.error;
      if (!res.data) { say("syncMsg", "There is no synced copy yet.", true); return; }
      return decrypt(p, res.data).then(function (obj) {
        var terms = cleanTerms(obj && obj.terms);
        lsSet(WL_KEY, JSON.stringify(terms));
        say("syncMsg", "Restored " + terms.length + " terms to this device. Reload the map to see the matches."); loadSyncState();
      }, function () { say("syncMsg", "That passphrase does not open the synced copy.", true); });
    }).catch(function () { say("syncMsg", "Could not load the synced copy. Try again in a minute.", true); });
  });
  $("unsync").addEventListener("click", function () {
    sb.from("environments").delete().eq("user_id", user.id).then(function (res) {
      say("syncMsg", res.error ? "Could not remove it. Try again." : "The synced copy is deleted. This device's list is unchanged.", !!res.error); loadSyncState();
    });
  });

  // ---------- alerts ----------
  $("useEnv").addEventListener("click", function () {
    var t = localTerms();
    if (!t.length) { say("alertMsg", "This device has no environment list yet.", true); return; }
    $("terms").value = t.join("\n"); say("alertMsg", "Copied " + t.length + " terms. Check them before saving: they will be stored readable.");
  });
  $("alertsOn").addEventListener("click", function () {
    var terms = cleanTerms($("terms").value);
    if (!terms.length) { say("alertMsg", "Add at least one term.", true); return; }
    if (!$("consent").checked) { say("alertMsg", "Tick the box to agree to alert emails first.", true); return; }
    sb.from("accounts").update({
      alerts_enabled: true, alert_terms: terms, alert_frequency: $("freq").value, alert_min_severity: +$("minsev").value,
      consent_at: new Date().toISOString(), consent_text: $("consentText").textContent.trim(), consent_version: CONSENT_VERSION, unsubscribed_at: null,
    }).eq("user_id", user.id).then(function (res) {
      if (res.error) say("alertMsg", "Could not save. Check the terms (2 to 60 characters each) and try again.", true); else loadAccount();
    });
  });
  $("alertsOff").addEventListener("click", function () {
    sb.from("accounts").update({ alerts_enabled: false, unsubscribed_at: new Date().toISOString() }).eq("user_id", user.id).then(function (res) {
      if (res.error) say("alertMsg", "Could not turn alerts off. Try again, or use the unsubscribe link in any alert.", true); else loadAccount();
    });
  });

  // ---------- data rights ----------
  $("export").addEventListener("click", function () {
    sb.rpc("export_my_data").then(function (res) {
      if (res.error) { say("dataMsg", "Export failed. Try again in a minute.", true); return; }
      var out = $("exportOut"); out.hidden = false; out.value = JSON.stringify(res.data, null, 2); out.select();
      say("dataMsg", "Everything we hold about you is shown above. Copy it to keep it. Your synced list is encrypted; your passphrase opens it.");
    });
  });
  $("delete").addEventListener("click", function () {
    if ($("delConfirm").value.trim() !== "DELETE") { say("dataMsg", "Type DELETE in the box to confirm.", true); return; }
    $("delete").disabled = true;
    sb.rpc("delete_my_account").then(function (res) {
      if (res.error) { $("delete").disabled = false; say("dataMsg", "Deletion failed. Nothing was removed. Try again.", true); return; }
      return sb.auth.signOut().catch(function () {}).then(function () {
        user = null; render(); say("signMsg", "Your account and all its data are deleted. Your environment list on this device is unchanged.");
      });
    });
  });

  sb.auth.getSession().then(function (r) { user = r.data && r.data.session ? r.data.session.user : null; render(); });
  sb.auth.onAuthStateChange(function (_e, session) { var u = session ? session.user : null; if ((u && u.id) !== (user && user.id)) { user = u; render(); } });
})();
