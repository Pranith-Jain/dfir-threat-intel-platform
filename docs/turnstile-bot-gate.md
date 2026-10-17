# Turnstile bot gate

## What it protects, and why it exists

`authenticate('external-only')` in `api/src/lib/auth.ts` grants the same-origin
exemption when a request carries `Origin`, `Referer`, or
`Sec-Fetch-Site: same-origin`. `csrfGuard` likewise lets a mutation through when
it carries none of those headers. Both are correct defences against a hostile
_browser_ — which is what CSRF actually is — and neither is an authorisation
check against anything else: a script with a socket can set any header it
likes. The practical consequence is that every route gated only by
"same-origin OR a valid API key" is reachable with no credentials at all.

For most of the API that is fine and intended — the site is a free public
toolkit. It stops being fine on the routes that write **shared state with no
per-user ownership** (the estate whiteboard, saved reports, workspaces, SOC
playbooks, campaigns, watchlists) or that **spend upstream quota on a
caller-supplied trigger** (tool-chain runs, CyberPulse ingestion, the X firehose
batch probe). There are no user accounts to hold a session against, so the
credential that fits is a bot challenge.

Turnstile is invisible for real visitors, free, and proves the caller ran this
site's JavaScript.

## Turning it on

The gate is **off until `TURNSTILE_SECRET` exists**, which is what makes it safe
to deploy before the widget does. Nothing about the site's behaviour changes
until then — no extra request, no third-party script, no new header.

1. Create a widget (Turnstile → Add widget, mode _Managed_) at
   <https://dash.cloudflare.com/?to=/:account/turnstile>, registering
   `pranithjain.qzz.io`, `www.pranithjain.qzz.io`, `localhost` and `127.0.0.1`.
2. Store both keys as Worker secrets:

   ```sh
   wrangler secret put TURNSTILE_SECRET
   wrangler secret put TURNSTILE_SITE_KEY
   ```

3. Optionally pin the hostnames a token must come from:

   ```sh
   wrangler secret put TURNSTILE_HOSTNAMES   # e.g. pranithjain.qzz.io,www.pranithjain.qzz.io
   ```

`GET /api/v1/features` then reports `turnstile_required: true` plus the public
site key, and `src/lib/turnstile.ts` starts attaching a token to the mutations
on `TURNSTILE_PREFIXES`.

To roll back: `wrangler secret delete TURNSTILE_SECRET`. The gate turns off
again on the next request; no deploy needed.

## How a request flows

1. `turnstileGuard()` (`api/src/lib/turnstile.ts`) runs before the route.
2. **No `TURNSTILE_SECRET`** → the middleware is a no-op (current state).
3. **Reads (GET/HEAD/OPTIONS)** → untouched. Browse paths, the read cache, and
   the SPA's polling are all unaffected.
4. **Caller already authenticated** (a valid API key, set by `authenticate`)
   → untouched. MCP clients and scripted callers cannot run a browser widget.
5. Otherwise the `cf-turnstile-response` header is verified against Cloudflare's
   siteverify endpoint, and the request is admitted only when
   `success === true` (plus optional `action` / `hostname` binding).

Every failure is a 403 with `cache-control: no-store` and a machine-readable
reason: `missing_token`, `token_too_large`, `verification_failed`,
`hostname_mismatch`, `action_mismatch`, `siteverify_unavailable`.

**Siteverify failures fail closed** — a network error, a 5xx or a non-JSON body
rejects the write rather than letting it through. That is deliberate: these
endpoints mutate shared state, and an unauthenticated caller who can trigger
writes during a Cloudflare outage is exactly the case worth being strict about.

## Client side

`src/lib/turnstile.ts` exposes one helper:

```ts
const res = await fetch('/api/v1/cyberpulse/scan', {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(await turnstileHeaders('cyberpulse-scan')) },
  body: JSON.stringify({}),
});
```

It loads `api.js?render=explicit` once, renders an off-screen widget,
`execute()`s it, and returns the header. Tokens are single-use and never cached.
If a token can't be produced (blocked script, ad-blocker, timeout) the helper
**throws** rather than returning `{}` — a silent empty header would come back as
an unexplained 403.

## Changing the gated set

`TURNSTILE_PREFIXES` in `api/src/lib/turnstile.ts` is the whole list, and the bar
for adding to it is: _writes shared state with no per-user ownership, or fans
out to paid/slow upstream on a caller-supplied trigger._ Cheaper per-caller work
belongs in the rate limiter (`api/src/lib/ratelimit.ts`), which is why
`/api/v1/intel-bundle` — whose POST fires on card render — is deliberately not
gated.

Adding a prefix without teaching the SPA to send a token breaks that button for
every visitor, so the two halves move together. `api/test/lib/turnstile.test.ts`
pins the off-by-default and fail-closed behaviour; run it after any change.
