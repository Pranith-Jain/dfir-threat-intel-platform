# Security Audit — 2026-10-09

Scope: api/src routes, worker/, src/ client code. Each finding was verified by
reading the code; none were live-tested against production.

## Confirmed findings (GitHub issues filed)

### 1. [HIGH] Unauthenticated SSRF via `GET /api/v1/threat-monitor/proxy` (`api/src/routes/threat-monitor.ts:29`)

The handler fetches an arbitrary attacker-supplied `?url=` with no ssrf-guard:
no `assertPublicHost`, no allow-list, no DNS pinning, no redirect control
(`redirect: follow` is the fetch default). It passes the protocol check with
`u.protocol.startsWith('http')` (so `httpxxx:` variants need care but `http:`
and `https:` to any host pass), and returns the body with
`Access-Control-Allow-Origin: *`.

Compare `feeds.ts:286` `feedProxyHandler`, which allow-lists hosts, and
`url-preview.ts` / `web-scan.ts`, which use `assertPublicHost` +
connection pinning. The surrounding `darknet-intel/*` EXEMPT-context shows the
pattern is available in-repo.

Note: this route is NOT in `EXEMPT_PATHS`, so external callers need an API key
— but `authenticate('external-only')` waives keys for same-origin-looking
requests (forgeable `Sec-Fetch-Site`, per the project's own `csrf-guard.ts`
"Known gap" note), so the key gate is not a reliable boundary. Fix: route the
fetch through `api/src/lib/ssrf-guard.ts` (`assertPublicHost` + pinned fetch)
and add a host allow-list like `feeds.ts`.

### 2. [MEDIUM] The same-origin mutation bypass is documented, not fixed (`api/src/lib/csrf-guard.ts:41`, `api/src/lib/auth.ts:222`)

The repo's own comments state that `authenticate('external-only')` waives API
keys for ALL methods including mutations, and that `Sec-Fetch-Site`/`Origin`/
`Referer` are forgeable by any non-browser client — i.e. ~128 SPA POST/DELETE
endpoints under `/api/v1/*` are reachable keylessly. The code comment frames
this as deliberate and points to a Turnstile-style capability as the real fix.
Filed as a tracking issue: adopt a real capability gate (e.g. Cloudflare
Turnstile) for mutating routes, or restrict the same-origin exemption to
GET/HEAD.

### 3. [LOW] `tor2webUrl()` allows gateway/host confusion (`api/src/lib/darknet.ts:166`)

`torFetchOnion()` correctly validates the hostname is an `[a-z2-7]{16|56}.onion`
before calling `tor2webUrl()`. But `tor2webUrl()` itself does no validation, and
any other caller passing a non-validated string gets `https://<input>.<gw>/`
— a concatenation into a fetch URL. Today's call sites are safe (verified);
future ones won't be. Move the `.onion` validation INSIDE `tor2webUrl()` so the
invariant is enforced where the URL is built. Also: `.onion` fetches follow
redirects (`redirect: 'follow'`) — a tor2web gateway could redirect anywhere;
consider `redirect: 'manual'` + re-validate per hop or bounded redirects.

### 4. [LOW] `darkwebScrapeDeep()` / `darkwebCrawl()` helper duplication + weaker onion regex (`api/src/lib/darkweb-osint.ts:77`)

`onionHost()` in `darkweb-osint.ts` accepts `[a-z2-7]{16,56}` (any length in
range) while `isValidOnionAddress()` in `darknet.ts` requires exactly 16 or 56.
The two validators disagree; dedupe on one shared implementation. Not directly
exploitable (both constrain hostnames into `https://<host>.<gateway>/`), but
it is the kind of drift that becomes one.

### 5. [INFO] `fortibleed-check.ts` batch endpoint probes arbitrary public hosts

`POST /fortibleed/batch` probes up to 10 attacker-chosen targets across 4 ports.
Individual checks DO use `assertPublicHost` (good). The route is key-gated the
same way as everything else (same caveat as #2). This is an "open port scanner
using our egress IP" abuse channel — consider rate-limiting/burn-limits or a
Turnstile gate, since severity reputational (platform IP scanning random hosts).

## Verified NON-findings (checked, OK)

- **SQL injection via template literals**: all 54 matches of
  ``.prepare(`...${...}`)`` interpolate developer-controlled constants or
  fully parameter-bound values (`?` placeholders + `.bind()`). Table names are
  hardcoded constants (`intel_bundles`, `address_watch`,
  `procedure_jobs`…). `safeFilename()` (`worker/lib/threat-intel-manifest.ts:804`)
  sanitizes slug→path. No injection found.
- **admin auth**: `requireAdmin` uses `safeEqual()` — a real constant-time
  compare that folds length into the accumulator (`admin-auth.ts:38`).
- **API keys**: SHA-256 hashed at rest, failed-auth lockout per IP
  (`trackFailedAuth`), sampled last_used_at writes. Solid.
- **XSS**: every `dangerouslySetInnerHTML` sink routes through DOMPurify or
  `report-view-helpers.ts renderMarkdown`, which de-tags THEN escapes BEFORE
  transforms (the file documents the double-render vulnerability it already
  fixed). JSON-LD script blocks escape `<` as `\u003c`. `ChatShared` uses
  `ALLOWED_TAGS: []` + `sanitizeAiHtml`. No gap found.
- **Telegram webhook**: `/api/v1/telegram-leaks/bot-webhook` is exempt from
  API-key auth but validates `X-Telegram-Bot-Api-Secret-Token` with
  `safeEqual()` and fails closed when the secret isn't configured.
- **report uploads**: `MAX_FILE_BYTES = 10MB` + `MAX_TEXT_LENGTH = 100KB` caps
  exist on both ingest paths.
- **No committed secrets**: only `.env.example`; no live token patterns in
  tracked source (`gho_`, `sk-`, `AKIA`, `xox*`).

## Verification status

All findings verified by code reading + cross-referencing the repo's existing
SSRF guard (`assertPublicHost`, `pinnedFetchFollow` in
`api/src/lib/ssrf-guard.ts`) and the allow-list proxy in `feeds.ts`.
Not executed: live requests against deployed endpoints (out of scope for a
code audit).
