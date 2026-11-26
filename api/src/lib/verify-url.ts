export type LinkStatus = 'ok' | 'broken' | 'unchecked';

export interface VerifyResult {
  /** True for a final 2xx. Kept for backward compatibility. */
  ok: boolean;
  /** Final HTTP status (after any HEAD→GET fallback), or null on a thrown fetch. */
  status: number | null;
  statusText: string;
  /**
   * Nuanced liveness verdict. This is the field callers should branch on.
   *  - 'ok'        — resolves (2xx, not a soft-404)
   *  - 'broken'    — confirmed not-there: 404/410, a soft-404 (redirect to
   *                  host root), or a DoH-confirmed NXDOMAIN (fabricated host)
   *  - 'unchecked' — could not be confirmed dead: 401/403/429/451, any 5xx,
   *                  timeouts, or thrown fetches whose host still resolves.
   *                  Callers must NOT delete a citation on 'unchecked' — a WAF
   *                  block or transient outage is not proof the page is gone.
   */
  linkStatus: LinkStatus;
  /** Final URL after redirects (when known). */
  finalUrl?: string;
  /** Short machine-ish reason for the verdict (diagnostics). */
  reason?: string;
  error?: string;
}

export interface VerifyOptions {
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /**
   * Injectable DNS-over-HTTPS resolver used only when a fetch THROWS, to tell
   * a fabricated host (NXDOMAIN) apart from a transient network error. Returns
   * the DoH `Status` code (3 = NXDOMAIN) or null when the lookup itself fails.
   * Defaults to a Cloudflare DoH lookup.
   */
  dohResolve?: (host: string) => Promise<number | null>;
  /**
   * Opt-in deep soft-404 probe. A HEAD-200 never fetches a body, so a fabricated
   * article slug on a host that answers HEAD 200 for ANY path sails through as
   * 'ok'. When enabled, a HEAD-200 URL gets ONE extra ranged GET whose <title>
   * is sniffed for not-found markers. OFF by default because it spends one
   * extra subrequest per HEAD-200 URL (free-plan budget is 50/invocation) —
   * callers enable it only when they can afford it, and the verdict is cached.
   */
  deepSoft404?: boolean;
}

// A current full-browser UA + Accept headers. Datacenter egress with a bot-ish
// or empty UA is the most common cause of a spurious 403/429 from WAF-fronted
// sites (bleepingcomputer, thehackernews, vendor blogs), so we look like a
// real browser to avoid wrongly classifying live pages as dead.
const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
};

/** Statuses where HEAD is unreliable (method blocked / bot challenge) → retry GET. */
const HEAD_RETRY_STATUSES = new Set([403, 405, 429, 501]);
/** The ONLY statuses we treat as a hard "the page is not there". */
const BROKEN_STATUSES = new Set([404, 410]);

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Default DoH resolver: returns the JSON `Status` (3 = NXDOMAIN) or null. */
async function defaultDohResolve(host: string, fetchImpl: typeof fetch, timeoutMs: number): Promise<number | null> {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    const r = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
    });
    clearTimeout(id);
    if (!r.ok) return null;
    const j = (await r.json()) as { Status?: number };
    return typeof j.Status === 'number' ? j.Status : null;
  } catch {
    return null;
  }
}

/** Cheap soft-404 signal from a resolved (2xx) response: did it collapse to the host root? */
function isSoftRedirectToRoot(reqUrl: string, res: Response): boolean {
  if (!res.redirected) return false;
  try {
    const finalPath = new URL(res.url).pathname.replace(/\/+$/, '');
    const reqPath = new URL(reqUrl).pathname.replace(/\/+$/, '');
    // A deep article URL that ends up at "" (host root) is the classic soft-404.
    return finalPath === '' && reqPath !== '';
  } catch {
    return false;
  }
}

/**
 * Not-found markers in a page's <title>. The strongest, least-spoofable
 * soft-404 signal: a real article about "404 errors" still has its own title
 * first, whereas a custom not-found page puts the 404 phrase IN the title.
 * Matched only inside `<title>…</title>` so body prose mentioning "not found"
 * never false-positives.
 */
const SOFT_404_TITLE_RE =
  /<title[^>]*>[^<]*(?:404|not[ -]?found|page (?:does not exist|could not be found)|content not found|article not found|no such page)[^<]*<\/title>/i;

/**
 * Content-based soft-404: read the (already-fetched, 2KB Range) body and
 * return true when the <title> is a not-found page. Only ever called when a
 * body is already in hand (the GET-fallback path) or when the caller opted
 * into the extra deep GET, so it never adds an unexpected subrequest. Catches
 * the fake-article-slug hallucination on WAF-fronted hosts (bleepingcomputer,
 * thehackernews, vendor blogs).
 */
async function isSoft404Body(res: Response): Promise<boolean> {
  try {
    const slice = await res.text();
    return SOFT_404_TITLE_RE.test(slice);
  } catch {
    return false;
  }
}

function classifyStatus(status: number): LinkStatus {
  if (status >= 200 && status < 300) return 'ok';
  if (BROKEN_STATUSES.has(status)) return 'broken';
  // 401/403/429/451, all 5xx, and any other non-2xx → not provably dead.
  return 'unchecked';
}

async function doFetch(
  fetchImpl: typeof fetch,
  url: string,
  method: 'HEAD' | 'GET',
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = { ...BROWSER_HEADERS };
    if (method === 'GET') headers['Range'] = 'bytes=0-2047'; // tiny slice, near-zero transfer
    return await fetchImpl(url, { method, headers, redirect: 'follow', signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

/**
 * Verify that a URL is live, biased toward NOT deleting real citations.
 *
 * Probe order (1 subrequest in the common case, up to 2, +1 DoH only on throw):
 *   1. HEAD with browser headers.
 *   2. On 403/405/429/501 → retry GET with a 2KB Range (WAFs reject HEAD).
 *   3. On a thrown fetch → DoH lookup: NXDOMAIN ⇒ broken, else unchecked.
 *
 * `broken` is reserved for 404/410, a soft-404 (redirect to host root), or a
 * confirmed-fabricated host. Everything ambiguous is `unchecked`.
 */
export async function verifyUrl(url: string, timeoutMs = 5000, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  try {
    let res = await doFetch(fetchImpl, url, 'HEAD', timeoutMs);
    let usedGet = false;
    if (HEAD_RETRY_STATUSES.has(res.status)) {
      res = await doFetch(fetchImpl, url, 'GET', timeoutMs);
      usedGet = true;
    }
    let linkStatus = classifyStatus(res.status);
    let reason = `http ${res.status}`;
    if (linkStatus === 'ok' && isSoftRedirectToRoot(url, res)) {
      linkStatus = 'broken';
      reason = 'soft-404 (redirect to host root)';
    }
    // Content-based soft-404: a 2xx whose <title> is a not-found page. Only
    // reliable when a body was actually fetched (the GET-fallback path), so
    // this never adds a subrequest to the common HEAD-200 case.
    if (linkStatus === 'ok' && usedGet && (await isSoft404Body(res))) {
      linkStatus = 'broken';
      reason = 'soft-404 (not-found page body)';
    }
    // Opt-in deep soft-404: the HEAD-200 path fetched no body, so do ONE
    // ranged GET and sniff its <title>. Catches fabricated slugs on hosts
    // that answer HEAD 200 for any path. Off by default (extra subrequest).
    if (linkStatus === 'ok' && !usedGet && opts.deepSoft404) {
      try {
        const getRes = await doFetch(fetchImpl, url, 'GET', timeoutMs);
        if (getRes.status >= 200 && getRes.status < 300 && (await isSoft404Body(getRes))) {
          linkStatus = 'broken';
          reason = 'soft-404 (deep: not-found page body)';
        }
      } catch {
        // An inconclusive deep GET leaves the HEAD verdict standing.
      }
    }
    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      linkStatus,
      finalUrl: res.url,
      reason,
    };
  } catch (err) {
    // Network error. Distinguish a fabricated host (NXDOMAIN ⇒ broken) from a
    // transient failure (timeout/reset ⇒ unchecked) via DoH.
    const host = hostOf(url);
    const resolve = opts.dohResolve ?? ((h: string) => defaultDohResolve(h, fetchImpl, timeoutMs));
    let linkStatus: LinkStatus = 'unchecked';
    let reason = 'network error (host resolves or unknown)';
    if (host) {
      const dnsStatus = await resolve(host);
      if (dnsStatus === 3) {
        linkStatus = 'broken';
        reason = 'NXDOMAIN (fabricated host)';
      }
    }
    return {
      ok: false,
      status: null,
      statusText: 'error',
      linkStatus,
      reason,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function verifyUrls(
  urls: string[],
  timeoutMs = 5000,
  opts: VerifyOptions = {}
): Promise<Map<string, VerifyResult>> {
  const results = new Map<string, VerifyResult>();
  const entries = await Promise.allSettled(urls.map((u) => verifyUrl(u, timeoutMs, opts)));
  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    const result = entries[i];
    if (url) {
      if (result?.status === 'fulfilled') {
        results.set(url, result.value);
      } else {
        results.set(url, {
          ok: false,
          status: null,
          statusText: 'error',
          linkStatus: 'unchecked',
          reason: 'promise rejected',
          error: 'promise rejected',
        });
      }
    }
  }
  return results;
}

export function statusLabel(s: LinkStatus): string {
  return s === 'ok' ? 'verified' : s === 'broken' ? 'broken' : 'unchecked';
}

/**
 * Canonical authority records do not need a liveness probe: the lookup that
 * produced the URL already established the record exists. Probing NVD/KEV/
 * MITRE deep links spends one subrequest each and was the single largest
 * consumer in discovery (26 KEV entries = 26 probes on a 50/invocation plan).
 *
 * Callers should still CITE these URLs — only the HEAD check is skipped.
 */
export function isCanonicalAuthorityUrl(url: string): boolean {
  return /nvd\.nist\.gov|known-exploited-vulnerabilities|attack\.mitre\.org/i.test(url);
}
