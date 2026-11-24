// One-click unsubscribe from CyberView alerts. The token in the link (?t=<uuid>) is random and identifies only the
// subscription; it is sent to one database function that can do nothing but switch alerts off.
// A button press is required so that email security scanners that follow links do not unsubscribe people.
(function () {
  "use strict";
  // not framed by another site (pen test 2026-11-23): GitHub Pages cannot send frame-ancestors, so a framed copy hides
  // itself and tries to take over the top window; this blocks clickjacking of the list and account controls
  if (window.top !== window.self) { document.documentElement.style.display = "none"; try { window.top.location = window.self.location.href; } catch (e) {} return; }
  var $ = function (id) { return document.getElementById(id); };
  var meta = function (n) { var m = document.querySelector('meta[name="' + n + '"]'); return m ? m.getAttribute("content") || "" : ""; };
  var token = new URLSearchParams(location.search).get("t") || "";
  var ok = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token);
  var msg = function (t) { $("unsubMsg").textContent = t; };
  if (!ok) { $("unsub").disabled = true; msg("This link is incomplete. Open the unsubscribe link from the email again, or turn alerts off in your account."); return; }
  if (!meta("cv-supabase-url") || !window.supabase) { $("unsub").disabled = true; msg("Alerts are not running, so there is nothing to stop."); return; }
  var sb = window.supabase.createClient(meta("cv-supabase-url"), meta("cv-supabase-key"), { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } });
  try { history.replaceState(null, "", location.pathname); } catch (e) {}   // keep the token out of the address bar and history
  $("unsub").addEventListener("click", function () {
    $("unsub").disabled = true; msg("Working");
    sb.rpc("unsubscribe", { token: token }).then(function (res) {
      if (res.error) { $("unsub").disabled = false; msg("That did not work. Try again in a minute, or turn alerts off in your account."); return; }
      msg(res.data ? "Done. You will not get any more CyberView alerts." : "This link is not valid any more. If you still get alerts, turn them off in your account.");
    });
  });
})();
