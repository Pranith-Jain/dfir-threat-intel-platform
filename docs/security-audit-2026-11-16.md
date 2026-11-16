# Security Audit — pranithjain.qzz.io

**Date:** 16 November 2026
**Scope:** `pranithjain.qzz.io` and the seven deployed subdomains (`crucible`, `panopticon`, `scout`, `argus`, `agent`, `copilot`, `brief`), plus the source in this repository.
**Method:** Non-intrusive external testing (DNS, TLS, HTTP headers, unauthenticated/forged-header API requests) and source review. No brute force, no exploitation, no destructive writes. Rate-limit testing was capped at seven requests.
**Authorization:** Target is the repository owner's own deployment; the repo documents the domain as the author's platform.

## Executive summary

The edge and application security posture is strong: nonce-based CSP, HSTS, strict CORS, HttpOnly admin sessions, constant-time token comparison, Turnstile on shared-state writes, robust SSRF protection, parameterised SQL, DOMPurify-sanitised HTML, and no secrets in 3,894 commits of history or in the client bundle.

The material gaps are not classic injection bugs. They are **authorization boundaries around shared state**, **legacy TLS**, **one outdated runtime dependency**, and **one place where the master admin token is stored in JavaScript-readable storage**.

| Severity | Count | Findings                                                                                                                                                                             |
| -------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Critical |     0 | —                                                                                                                                                                                    |
| High     |     1 | Anonymous users share, read and can delete each other's AI chat sessions                                                                                                             |
| Medium   |     4 | TLS 1.0/1.1 + CBC/SHA1; vulnerable Hono 4.13.13; admin token in `localStorage`; unauthenticated costly AI/scanner endpoints                                                          |
| Low      |     9 | HSTS preload not submitted; no CAA; no DNSSEC; SPF softfail / DMARC quarantine; soft-404 path reflection; CSP relaxation; missing CORP/COEP; dev-dependency CVEs; public `/admin` UI |
| Info     |     4 | Same-origin trust is forgeable by design; operator metadata readable; stack/version hints; public scan surfaces                                                                      |

**Confirmed vs suspected:** all findings below are confirmed by live request/response, DNS/TLS observation, or direct source inspection, **except** the exploitability of the Hono advisories (CVE-class issue confirmed present, working bypass not found) and the impact of future data placed in ownerless rows (mechanism confirmed, data sensitivity depends on use).

## Findings

### HIGH

#### H-1. Anonymous users share, can read, and can delete each other's AI chat sessions

**Status:** Confirmed live (read); confirmed in source (delete). Delete was **not** executed.

**Evidence.** Any client can satisfy the `external-only` auth gate by sending a same-origin header. With no `Origin`, the API returns `401`; with a forged `Origin` (or `Sec-Fetch-Site` / `Referer`), the same read returns `200`:

```
GET /api/v1/briefings/today HTTP/2
(no Origin)                         -> 401 {"error":"unauthorized","message":"api key required …"}
Origin: https://pranithjain.qzz.io  -> 200
Sec-Fetch-Site: same-origin         -> 200
Referer: https://pranithjain.qzz.io/dfir -> 200
```

The chat list is not scoped to the caller. It returns all rows whose `owner_hash IS NULL`, which is exactly the set created by keyless visitors (`callerOwnerId()` returns `null`):

```
GET /api/v1/copilot/chat/sessions
Origin: https://pranithjain.qzz.io
HTTP/2 200
{"sessions":[{"id":"chat_1793771655333_6d6c1772-7f17-4523-8863-897b24c68e7f","title":"hi","messageCount":1,…}]}
```

Reading a session by ID returns the full message history:

```
GET /api/v1/copilot/chat/chat_1793771655333_6d6c1772-7f17-4523-8863-897b24c68e7f
Origin: https://pranithjain.qzz.io
HTTP/2 200
{"sessionId":"…","title":"hi","messages":[{"role":"user","content":"hi",…},{"role":"system",…}],…}
```

The delete handler performs no auth or ownership check beyond `loadSession()`, which treats `owner_hash = NULL` as visible:

```ts
// api/src/routes/copilot-chat.ts:458
const existing = await loadSession(c, db, sessionId);
if (!existing) return notFound(c, 'session not found');
await db.prepare('DELETE FROM copilot_sessions WHERE id = ?').bind(sessionId).run();
return c.json({ deleted: true });
```

Supporting code: `api/src/lib/ownership.ts:31-67` (`ownerCheck`/`ownerVisibilityFilter`), `api/src/routes/copilot-chat.ts:81-102` and `:122-153`.

**Risk.** Every anonymous visitor's AI conversation is readable by any other visitor who can call the list endpoint, and deletable by anyone holding the (listed) session ID. Prompts to a DFIR/CTI copilot can contain client names, IOCs, hostnames, or incident details. The current dataset contained only a test message (`"hi"`), so present impact is low, but the access-control flaw applies to all future anonymous sessions. The same ownerless-row pattern applies to saved reports, playbooks, watchlists and workspaces.

**Fix.**

1. Stop treating `owner_hash IS NULL` as globally visible for keyless callers. Issue a signed, HttpOnly visitor cookie (or a capability token) and scope chat/report rows to it; do not return legacy ownerless rows to anonymous list requests.
2. Require a verified caller (Turnstile, API key, or admin session) for `DELETE` and for list/history endpoints that return message bodies.
3. If public sharing is intentional, require an explicit, revocable share token (the saved-report share flow already does this correctly) rather than exposing the session ID.

---

### MEDIUM

#### M-1. TLS 1.0 and TLS 1.1 are enabled; CBC/SHA1 ciphers are accepted

**Status:** Confirmed live.

**Evidence.** A TLS 1.0 handshake completes at the Cloudflare edge and negotiates a CBC/SHA1 suite:

```
$ curl -v --tls-max 1.0 https://pranithjain.qzz.io/
* SSL connection using TLSv1 / ECDHE-RSA-AES128-SHA

$ curl -v --tls-max 1.1 https://pranithjain.qzz.io/
* SSL connection using TLSv1.1 / ECDHE-RSA-AES128-SHA

$ curl -v --tlsv1.2 --tls-max 1.2 --ciphers AES128-SHA https://pranithjain.qzz.io/
* SSL connection using TLSv1.2 / AES128-SHA
```

TLS 1.2 also accepts `ECDHE-RSA-AES128-SHA` and `AES256-SHA`. TLS 1.3 works and the certificate is a valid 90-day Google Trust Services wildcard (`pranithjain.qzz.io`, `*.pranithjain.qzz.io`).

**Risk.** Deprecated protocols and CBC/SHA1 suites widen the downgrade and legacy-client attack surface, fail PCI DSS and modern baseline requirements, and are unnecessary for this audience. No practical break was demonstrated.

**Fix.** In Cloudflare → SSL/TLS → Edge Certificates, set **Minimum TLS Version = 1.2** (1.3 where possible). If the plan allows, select a modern cipher suite that excludes CBC/SHA1; otherwise rely on the 1.2 floor and re-test. Confirm the origin/Worker has no separate TLS listener.

#### M-2. Hono 4.13.13 has known middleware-bypass advisories

**Status:** Confirmed vulnerable version; exploitation **not** confirmed.

**Evidence.** `npm audit` reports five advisories in the runtime Hono version:

```
hono  moderate  <=4.13.15
  GHSA-4m76-xfj5-7975  mount()/app.mount() path can bypass middleware scoped inside the mount prefix
  GHSA-h7mg-cq63-vhpq  RegExpRouter skips wildcard middleware for encoded line terminators
  GHSA-3gg2-335m-rxc6  css helper HTML injection
  GHSA-46wx-v44x-9hh2  csrf() hyperlink-auditing bypass
  GHSA-4h7h-rv7c-7m2v  validator('form') multipart bypass
```

Installed: `api/node_modules/hono` **4.13.13**; latest is **4.13.19**. The app uses `app.use('/api/v1/*', authenticate(...))` and `app.route(...)`. I attempted encoded line terminators, double slashes, dot segments, and `%23`/`%09`/`%0a` against an admin-gated route; all returned `401`, so no working bypass was found.

**Risk.** If a bypass payload exists, the API-key / admin middleware could be skipped, exposing operator-only data. The `csrf()` and `validator('form')` advisories do not apply (the app uses its own `csrfGuard` and `validate('json'|'query')`), but the router/mount advisories are relevant to the auth chain.

**Fix.** Upgrade `hono` to **>= 4.13.16** (ideally 4.13.19) in `api/package.json` and re-run the auth regression tests plus the encoded-path probes. Also update `@hono/node-server` to **2.1.8** if the Node MCP server is used.

#### M-3. The master admin token is persisted in `localStorage` by one admin client

**Status:** Confirmed in source.

**Evidence.** `src/pages/threatintel/ExternalResources.tsx` stores the raw token under the key `adminToken`:

```ts
const TOKEN_KEY = 'adminToken';
// line 57
window.localStorage.getItem(TOKEN_KEY);
// line 207
window.localStorage.setItem(TOKEN_KEY, trimmed);
```

The main admin flow correctly uses an HttpOnly cookie (`src/lib/admin-token.ts`, `api/src/routes/admin-keys.ts:29-34`), but this legacy component bypasses it. The admin session cookie itself is well configured:

```
Set-Cookie: admin_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=3600
```

**Risk.** Any XSS, malicious browser extension, or compromised npm dependency on the origin can read the master `ADMIN_TOKEN` and take full control of admin APIs. CSP reduces XSS likelihood but does not protect against extensions or supply-chain compromise.

**Fix.** Remove the `adminToken` localStorage path. Use `createAdminSession()` (HttpOnly cookie) for this component too, or gate the external-resource edits behind a server-side admin session. Never persist the master token in JS-readable storage. Rotate `ADMIN_TOKEN` after the change, and consider per-action admin keys instead of one shared master token.

#### M-4. Costly AI and scanner endpoints are callable without credentials

**Status:** Confirmed live (reachability); cost impact suspected.

**Evidence.** With a forged same-origin header, AI and scan endpoints reach their handlers:

```
POST /api/v1/copilot/investigate   -> 400 {"error":"validation_error",…}   (handler reached)
POST /api/v1/radar/scan            -> 400 {"error":"bad_request","message":"missing url"}
GET  /api/v1/web-scan?url=…        -> public SSRF-guarded scanner
GET  /api/v1/webamon/scan|search   -> public upstream proxy
```

These are not Turnstile-gated (only `/estate`, `/soc/playbooks`, `/saved-reports`, `/workspaces`, `/ioc-watchlist`, `/tool-chains`, `/cyberpulse/scan` are). They are rate-limited (10/min for AI, 30/min global, per IP per colo).

**Risk.** A scripted client can consume Workers AI quota, paid upstream API quota, and CPU, or use the platform as an unattributed public scanner against third parties. The per-colo limiter caps a single IP but does not cap a distributed client.

**Fix.** Require Turnstile (or a valid API key) for AI/costly endpoints, not only shared-state writes; add per-account/day budgets and Cloudflare alerts; keep the SSRF guard (already strong). Consider moving `web-scan`/`radar` behind the same Turnstile gate.

---

### LOW

#### L-1. HSTS advertises `preload` but the domain is not submitted

**Status:** Confirmed.

**Evidence.** Header is correct:

```
strict-transport-security: max-age=63072000; includeSubDomains; preload
```

But the preload list reports:

```
GET https://hstspreload.org/api/v2/status?domain=pranithjain.qzz.io
{"name":"pranithjain.qzz.io","status":"unknown","bulk":false,"preloadedDomain":""}
```

**Risk.** First-visit SSL-stripping remains possible; browsers will not have HSTS baked in. `includeSubDomains` is effective after the first HTTPS response.

**Fix.** Submit at <https://hstspreload.org/> (apex + `includeSubDomains` are already satisfied) or remove `preload` to avoid a false claim.

#### L-2. No CAA record

**Status:** Confirmed.

**Evidence.** `dig CAA pranithjain.qzz.io` returns no answer; Cloudflare DoH returns `NOERROR` with no CAA answer.

**Risk.** Any public CA can issue a certificate for the domain, increasing the impact of a mis-issuance or validation-path attack.

**Fix.** Add `CAA 0 issue "pki.goog"` (Google Trust Services, the current issuer) and optionally `CAA 0 iodef "mailto:security@pranithjain.qzz.io"`. Add `letsencrypt.org` only if used.

#### L-3. DNSSEC is not enabled

**Status:** Confirmed.

**Evidence.** The zone returns RRSIGs but the resolver does not validate: `flags: qr rd ra` (no `ad`), and there is no DS record for `pranithjain.qzz.io`. NS are `cory.ns.cloudflare.com` / `haley.ns.cloudflare.com`.

**Risk.** A resolver-path attacker can spoof DNS answers; there is no cryptographic chain from `.io` → `qzz.io` → `pranithjain.qzz.io`.

**Fix.** Enable DNSSEC in Cloudflare DNS, then add the DS record at the `qzz.io` delegation (provider permitting). Validate with `dig +dnssec` and confirm the `ad` flag.

#### L-4. SPF uses softfail and DMARC uses quarantine

**Status:** Confirmed.

**Evidence.** Public DNS:

```
pranithjain.qzz.io TXT  "v=spf1 include:_spf.mx.cloudflare.net ~all"
_dmarc.pranithjain.qzz.io TXT  "v=DMARC1; p=quarantine; rua=mailto:…@dmarc-reports.cloudflare.net"
cf2024-1._domainkey TXT  "v=DKIM1; h=sha256; k=rsa; p=…"   (DKIM present)
```

No MTA-STS or TLS-RPT records were found.

**Risk.** Spoofed mail is marked softfail rather than rejected, and DMARC asks receivers to quarantine rather than reject. Some receivers will still deliver; brand phishing and reply-channel abuse remain easier than necessary. DKIM is present and aligned, which is good.

**Fix.** Publish `v=spf1 include:_spf.mx.cloudflare.net -all`; move DMARC to `p=reject; sp=reject; pct=100; fo=1` after a monitoring period; add `ruf` if desired; add `_mta-sts` + `_smtp._tls` if mail is inbound-sensitive.

#### L-5. Soft 404: every unknown path returns 200 and reflects the path in title/meta

**Status:** Confirmed.

**Evidence.** Sensitive-path probes and random paths all return the SPA shell with `200`, not a real file or a 404:

```
GET /.env               -> 200 text/html 15,512 bytes (SPA shell, title ".env · pranithjain.qzz.io")
GET /.git/config        -> 200 text/html 15,497 bytes
GET /definitely-not…    -> 200
GET /%22%3E%3Cimg…      -> 307 -> 200, title "%22%3E%3Cimg%20src%3Dx… · pranithjain.qzz.io"
```

The path is percent-encoded and reflected as literal text, so **no XSS was found**. `/api/v1/` correctly returns JSON `404`; only the SPA fallback is affected.

**Risk.** Attackers can make arbitrary keyword-rich pages appear under the domain (SEO/brand abuse), poison caches/scanners, and generate misleading 200s. The soft 404 also makes exposure scanners report false positives for `.git`, `.env`, and backups.

**Fix.** Return a real `404` for unknown non-prerendered paths. If the SPA fallback is required, limit it to known route prefixes and do not echo arbitrary path text into `<title>`/`<meta description>`.

#### L-6. CSP relaxations: inline styles, any HTTPS image, third-party `connect-src`

**Status:** Confirmed in headers.

**Evidence.** Representative CSP on the apex:

```
script-src https://pranithjain.qzz.io 'nonce-…' 'wasm-unsafe-eval' https://static.cloudflareinsights.com;
style-src https://pranithjain.qzz.io 'unsafe-inline';
img-src https://pranithjain.qzz.io data: https:;
connect-src https://pranithjain.qzz.io … https://unpkg.com https://mr-akuma.github.io
             https://nominatim.openstreetmap.org https://goxdr.fyi https://mr-r3b00t.github.io
             wss://pranithjain.qzz.io;
frame-ancestors 'none'; base-uri …; form-action …; object-src 'none';
```

**Risk.** `style-src 'unsafe-inline'` permits CSS injection if an HTML sink is ever found; `img-src https:` permits tracking pixels and data exfiltration via image loads; `connect-src` to `unpkg.com` and user/third-party GitHub Pages expands exfiltration targets. Script execution remains nonce-gated, which is the important control.

**Fix.** Prefer nonce/hash-based styles (or accept the risk with a comment); restrict `img-src` to the image hosts actually used; narrow `connect-src` to the exact API/CDN hosts. Keep `script-src` nonce-based.

#### L-7. Missing cross-origin isolation headers

**Status:** Confirmed (absent).

**Evidence.** No `Cross-Origin-Resource-Policy`, `Cross-Origin-Embedder-Policy`, or `X-Permitted-Cross-Domain-Policies` on the HTML or API responses.

**Risk.** Other origins can embed resources more freely; cross-origin isolation is weaker than it could be. Low impact given `frame-ancestors 'none'` and `X-Frame-Options: DENY`.

**Fix.** Add `Cross-Origin-Resource-Policy: same-origin` (or `same-site` if subdomains need to consume assets) and `X-Permitted-Cross-Domain-Policies: none`. Test `COEP: require-corp` before enabling; it can break third-party images.

#### L-8. Vulnerable development-only dependencies

**Status:** Confirmed (`npm audit`).

**Evidence.** Root audit reports 2 high + 12 moderate; API audit reports 12 high + 10 moderate. Runtime-relevant items are covered in M-2. The rest are dev/build/test tooling:

```
vite 8.1.3           high  (dev server / launch-editor issues)
body-parser 2.3.0    high  (DoS via compressed-body trailing bytes; transitively via MCP SDK/Express)
@hono/node-server 1.19.17 moderate (serveStatic path decoding; Node adapter)
zod 4.4.3            high  (only under @cloudflare/vitest-pool-workers; runtime resolves 4.6.7)
```

**Risk.** Compromise of the developer machine or Node-based MCP server, not the deployed Worker. `zod` 4.4.3 is test-only.

**Fix.** `npm audit fix` + update Vite to >=8.1.6, `@hono/node-server` to 2.1.8, and refresh the API lockfile. Re-run `npm audit` in both the root and `api/`.

#### L-9. `/admin` UI is publicly reachable; no Cloudflare Access in front of it

**Status:** Confirmed.

**Evidence.**

```
GET /admin -> 200 text/html (prerendered admin shell, x-ssr-source: prerendered)
GET /login, /signin, /auth, /dashboard -> 200 SPA shell (soft 404)
```

The admin API is correctly token-gated (`/api/v1/admin/keys` → `401`, `/api/v1/malware-vault` → `401`), and rate limiting is enforced (see positives). No Cloudflare Access/JWT headers were observed.

**Risk.** Exposes the admin UI and its JS to unauthenticated visitors; the security boundary is entirely the token. This increases phishing/credential-harvesting surface and gives attackers a map of admin routes.

**Fix.** Put `/admin*` behind Cloudflare Access (or a Worker JWT check) so the UI is not publicly served; keep the token gate as defence in depth. Remove the admin route from `robots.txt` or leave it — robots is not an access control.

---

### INFORMATIONAL

#### I-1. The same-origin auth exemption is forgeable by any non-browser client — by design

`api/src/lib/auth.ts:184-226` documents this explicitly: `Sec-Fetch-Site`, `Origin`, and `Referer` are convenience signals, not authentication. The live test confirms it (`401` without, `200` with a forged `Origin`). This is acceptable **only** for data intended to be public. H-1 is the case where it is not acceptable. Keep the admin gate as the real boundary and classify every non-admin-gated read as public.

#### I-2. Operator metadata is readable on non-admin-gated endpoints

`GET /api/v1/soc/playbooks` returns playbook names, investigation UUIDs, IOCs and QA scores; `GET /api/v1/saved-reports` lists titles/source URLs and `GET /api/v1/saved-reports/:id` returns the full report plus `owner_hash` (null here). Current data appears to be public threat-intel research, so this is informational. If these stores can ever contain client data, move the prefixes into `ADMIN_GATED_PREFIXES`.

#### I-3. Stack/version hints

Responses disclose `Server: cloudflare`, `X-SSR-Source: prerendered`, `X-API-Version: 1`, `X-Request-Id`, and `Server-Timing`. No framework version, stack trace, or internal path was disclosed. Malformed JSON returns a clean `400`; a failed upstream returns a clean `500 {"error":"internal_error","message":"upstream error"}`.

#### I-4. Public scanning/proxy surfaces

`/api/v1/radar/scan` and `/api/v1/web-scan` are intentionally public and SSRF-guarded. They can still be used as unattributed scanners; rate limits are the only control. Document this as an accepted product risk or gate behind Turnstile.

---

## What is working (verified)

| Control            | Observation                                                                                                                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HSTS               | `max-age=63072000; includeSubDomains; preload` on apex and all 7 subdomains                                                                                                                                              |
| CSP                | Nonce-based `script-src`, `frame-ancestors 'none'`, `object-src 'none'`, locked `base-uri`/`form-action`; nonce rotates per response                                                                                     |
| Framing            | `X-Frame-Options: DENY` + `frame-ancestors 'none'`                                                                                                                                                                       |
| Sniffing           | `X-Content-Type-Options: nosniff`                                                                                                                                                                                        |
| Referrer           | `strict-origin-when-cross-origin`                                                                                                                                                                                        |
| Permissions        | `camera=(), microphone=(), geolocation=(), payment=(), usb=()`                                                                                                                                                           |
| COOP               | `same-origin`                                                                                                                                                                                                            |
| CORS               | Pinned to `https://pranithjain.qzz.io`; no reflection of `evil.example`, `null`, subdomain, localhost, or suffix tricks; no `Access-Control-Allow-Credentials`                                                           |
| Cookies            | `admin_session`: `HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=3600`; no cookie on public pages                                                                                                                 |
| Admin auth         | Constant-time `safeEqual`, optional `ADMIN_TOKEN_VERSION` revocation, HttpOnly cookie, 5/min strict bucket                                                                                                               |
| Rate limiting      | Admin session: `401` ×5 then `429` + `retry-after: 60`; global 30/min and AI 10/min in code                                                                                                                              |
| Turnstile          | Keyless writes to shared-state prefixes return `403 turnstile_required` (secret is configured)                                                                                                                           |
| SSRF               | `assertPublicHost` covers RFC1918, CGNAT, loopback, link-local, metadata `169.254.169.254`, `168.63.129.16`, IPv6 ULA/link-local/6to4/NAT64; `pinnedFetch`/`pinnedFetchFollow` pin DNS and revalidate every redirect hop |
| SQL                | D1 prepared statements with bound parameters; user values are not interpolated into SQL                                                                                                                                  |
| XSS                | React escaping by default; DOMPurify for AI/markdown HTML; report renderer has XSS tests; path reflection is percent-encoded                                                                                             |
| Secrets            | `gitleaks` scanned 3,894 commits / 3.74 GB: **no leaks**. `.dev.vars` is gitignored; client bundle contains no keys/tokens; `.map` requests return the SPA shell, not source maps                                        |
| Sensitive files    | `/.git/config`, `/.env`, `/.dev.vars`, `/wrangler.jsonc`, `/backup.zip`, `/db.sql`, `/node_modules/` return the SPA shell (soft 404), not file contents; no directory listing                                            |
| Security contact   | `/.well-known/security.txt` present with contact, canonical URL, policy, and 2027 expiry                                                                                                                                 |
| Subdomain takeover | CT shows only `pranithjain.qzz.io` + `*.pranithjain.qzz.io`; all 7 hosts resolve to Cloudflare; no dangling CNAME; unknown subdomains NXDOMAIN                                                                           |
| Email              | DKIM `cf2024-1` present; SPF and DMARC present (hardening in L-4)                                                                                                                                                        |

## Confirmed vs suspected

**Confirmed**

- TLS 1.0/1.1 enabled; CBC/SHA1 suites accepted (M-1).
- Hono 4.13.13 installed and within vulnerable range; encoded-path bypass attempts returned 401 (M-2).
- Raw admin token stored in `localStorage` by `ExternalResources.tsx` (M-3).
- Forged same-origin headers reach AI/scanner handlers; no credentials required (M-4, H-1).
- Chat sessions are listable/readable without credentials; delete route has no ownership check (H-1).
- HSTS preload not submitted; no CAA; no DNSSEC; SPF `~all`; DMARC `p=quarantine` (L-1–L-4).
- Soft 404 and path reflection; no XSS (L-5).
- CSP relaxations and missing CORP/COEP (L-6, L-7).
- Dev-dependency advisories (L-8).
- `/admin` public; admin API 401 (L-9).
- No secrets in git history or bundle; sensitive paths not exposed; CORS/headers/cookies/rate-limit/Turnstile/SSRF controls work.

**Suspected / conditional**

- A working Hono middleware-bypass payload may exist even though the tested payloads failed (M-2).
- The impact of H-1 depends on what visitors paste into the copilot; current data is a test message.
- The ownerless-row model may expose more stores than the ones sampled (saved reports, workspaces, watchlists, workspaces) as usage grows.
- The AI/scanner abuse cost is estimated, not measured (no quota data).
- Email spoofing may still be delivered by receivers that ignore DMARC quarantine; not tested by sending mail.

## Unable to test

- Authenticated admin flows and the full `/api/v1/admin/*` surface (no `ADMIN_TOKEN`).
- Actual deletion/creation against production shared state (deliberately not executed).
- Distributed brute force across Cloudflare colos; only a single-IP 5-request sample was run.
- Full port scan of the origin: the origin is hidden behind Cloudflare; only edge ports were checked. 80/443 and Cloudflare's standard alternate HTTP/HTTPS proxy ports (8080, 8443, 2053, 2083, 2087, 2096, 8880) answered; 21/22/25/3306/5432/6379 were filtered. These are Cloudflare proxy ports, not origin services.
- Complete cipher-suite enumeration (no `nmap`/`testssl.sh`; negotiated ciphers and selected legacy suites were tested).
- DNS zone transfer and historical DNS records (takeover history).
- Real email spoof/deliverability testing (no mail sent).
- WAF/DDoS behaviour and Cloudflare account-level controls.
- Third-party JS supply chain and browser-extension threat model.
- CSP-report abuse volume and OG-image render CPU limits.
- MCP/WebSocket auth beyond source review.
- Client-side behaviour of authenticated admin pages (no token).

## Top 5 priority fixes

1. **Fix chat/shared-state ownership (H-1).** Stop returning `owner_hash IS NULL` rows to keyless callers; issue a signed visitor cookie or capability token; require Turnstile/API key/admin for `DELETE` and for list/history endpoints that return message bodies. Do the same audit for saved reports, workspaces, watchlists, and playbooks.
2. **Raise the TLS floor (M-1).** Set Cloudflare minimum TLS to 1.2 (prefer 1.3) and remove CBC/SHA1 suites where the plan permits. Re-test with `curl --tls-max 1.1` (must fail) and a CBC-only client (must fail).
3. **Remove the master token from `localStorage` (M-3).** Migrate `ExternalResources.tsx` to the HttpOnly `admin_session` flow, delete the `adminToken` key path, then rotate `ADMIN_TOKEN` and invalidate sessions with `ADMIN_TOKEN_VERSION`.
4. **Patch Hono (M-2).** Upgrade `hono` to >=4.13.16 (4.13.19 current) and `@hono/node-server` to 2.1.8 if used; re-run auth regression tests and encoded-path probes.
5. **Harden DNS and email (L-1–L-4).** SPF `-all`, DMARC `p=reject; sp=reject`, add CAA for the actual CA, enable DNSSEC + DS at the delegation, and submit the domain to the HSTS preload list (or drop the `preload` token).

---

## Remediation — 16 Nov 2026

Code fixes were applied and the affected test suites pass. Deployment is still required for any live effect.

### H-1 — Fixed in code

- Added `api/src/lib/visitor.ts`: a per-browser, HttpOnly, Secure, SameSite=Lax `pj_vid` cookie. The cookie value is random 256-bit; only its SHA-256 hash is stored in `owner_hash` (`anon:<hash>`).
- Mounted `visitorIdentity()` on `/api/v1/copilot/*` and `/api/v1/agents/*` in `api/src/index.ts`.
- Copilot and Vera now use `visitorOwnerId()` / `visitorVisibilityFilter()` / `visitorOwns()` (`api/src/routes/copilot-chat.ts`, `api/src/routes/vera.ts`).
- Legacy `owner_hash IS NULL` sessions are hidden from anonymous visitors and remain visible to the operator. They are not deleted.
- New sessions are owned by the visitor cookie; API-key callers keep their existing `keyId` owner; the admin session bypasses ownership.
- Covered by `api/test/lib/visitor.test.ts`.

Verification after deploy: a fresh browser gets a `pj_vid` cookie; its session list is empty; the old `"hi"` session returns `404` when requested by id; a second browser cannot see or delete the first browser's session.

### M-1 — Script provided; live zone not changed

`scripts/fix-tls-min-version.sh` sets `min_tls_version=1.2`, attempts `tls_1_3=on`, and verifies that a TLS 1.1 handshake fails. It requires a Cloudflare API token with **Zone Settings:Edit**; the environment here has only read access to zone settings, so the zone change was not applied.

Dashboard equivalent: **SSL/TLS → Edge Certificates → Minimum TLS Version = TLS 1.2**, TLS 1.3 = On. If the plan allows custom ciphers, remove CBC/SHA1 suites and re-test. Confirm with:

```bash
curl -v --tls-max 1.1 https://pranithjain.qzz.io/   # must fail
curl -v --tlsv1.2 --tls-max 1.2 --ciphers AES128-SHA https://pranithjain.qzz.io/  # should fail after cipher hardening
```

### M-2 — Fixed

- `api/package.json` and the root override now pin `hono` to `^4.13.19`; installed and locked at 4.13.19.
- `npm audit --omit=dev` in `api/` reports 0 vulnerabilities.
- The root tree still contains `@hono/node-server@1.19.17` via `@modelcontextprotocol/sdk`; it is the MCP/Node bridge, not the deployed Worker runtime. Its advisories remain in the Low/dev-tooling category. Do not force a 2.x override without testing the MCP bridge.

### M-3 — Fixed in code

- `src/pages/threatintel/ExternalResources.tsx` now exchanges the pasted token for an HttpOnly `admin_session` cookie via `createAdminSession()`, sends no `Authorization` header, and signs out with `clearAdminSession()`.
- The `adminToken` localStorage key path was removed. Only the `adminSessionActive` UI hint remains.
- Recommended follow-up: rotate `ADMIN_TOKEN` and bump `ADMIN_TOKEN_VERSION` so any token previously copied into localStorage is invalid. Existing browsers can clear the old `adminToken` key manually.

### M-4 — Fixed in code

- Added exact-path Turnstile gates for `/api/v1/copilot/chat`, `/api/v1/copilot/investigate`, `/api/v1/agents/chat`, `/api/v1/radar/scan`, and `/api/v1/webamon/scan`.
- Added read gates for `/api/v1/web-scan` and GET `/api/v1/copilot/investigate`, which perform caller-triggered outbound/LLM work.
- The SPA now attaches `cf-turnstile-response` on the corresponding calls (`Copilot.tsx`, `VeraChat.tsx`, `CveLookup.tsx`, `DfirCopilot.tsx`, `Radar/Home.tsx`, `Webamon.tsx`, `FullSpectrum.tsx`).
- The gate remains a no-op until `TURNSTILE_SECRET` is configured, so local development is unchanged.
- Cheap subpaths (cancel, history, session list, scan results) are deliberately not challenged.

### Verification run

- `cd api && npm run typecheck` — pass.
- `cd api && npx vitest run test/lib/turnstile.test.ts test/lib/visitor.test.ts` — 28 pass.
- `cd /Users/pranith/Documents/portfolio && npx vitest run src/lib/__tests__/turnstile.test.ts src/test/admin.test.tsx` — 10 pass.
- `npx eslint` on all changed files — pass.
- Root `npm run typecheck` reports one pre-existing error in `src/pages/threatintel/CigPortal.tsx` (`ExternalLink` imported but unused); it is unrelated to these changes.

### Residual items

- TLS zone setting must be applied in the dashboard or with the provided script.
- Rotate `ADMIN_TOKEN` / bump `ADMIN_TOKEN_VERSION`.
- Saved reports, workspaces, watchlists, and playbooks still use the shared `owner_hash IS NULL` model; H-1's chat-specific fix does not change those product surfaces.
- `@hono/node-server` remains on the MCP bridge; treat it as dev tooling and revisit when the MCP SDK allows a 2.x upgrade.
- Re-run the external probe after deployment, especially the TLS 1.1 test and the cross-browser chat-session test.

---

_Report generated from live observation on 16 Nov 2026. Re-test after fixes; severity may change with data classification and deployment changes._
