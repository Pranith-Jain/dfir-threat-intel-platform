/**
 * Newly-registered domain monitor.
 *
 * Ported from DominiosINT (github.com/Ivancastl/dominiosint), which fetches
 * a daily list of newly registered domains and filters it by keyword.
 *
 * The upstream list lives at:
 *   https://raw.githubusercontent.com/ccas10ca-prog/domain/main/dominios/<YYYY-MM-DD>.txt
 * — one plain-text file per day, one domain per line.
 *
 * ## Why the normalization matters
 *
 * The upstream matcher strips accents, lowercases, and keeps only
 * alphanumerics, dots and dashes before comparing. That is what makes a
 * watch for "banco" also catch "BANCO-SEGUR0", "bancó" and "banco.com.mx".
 * It is also what makes it a *substring* match rather than a label match:
 * "banco" matches "banco-de-mexico.com" and "bancoseguro.net", which is
 * the intent — a new registration containing the brand is the signal.
 *
 * ## Cost
 *
 * One subrequest per day examined. The default window is three days, and
 * each day's file is cached at the edge for an hour, so a watchlist check
 * and a manual search of the same day cost one fetch between them.
 */

/** The upstream daily domain list. */
const DOMAIN_FEED_BASE = 'https://raw.githubusercontent.com/ccas10ca-prog/domain/main/dominios';

const UA = 'pranithjain-dfir/1.0 (+https://pranithjain.qzz.io)';
const FETCH_TIMEOUT_MS = 15_000;
const CACHE_TTL_SECONDS = 3600;
/** A day file is a few thousand domains; this is a runaway guard. */
const MAX_FILE_BYTES = 8 * 1024 * 1024;
/** Longest window the route will look back. */
export const MAX_LOOKBACK_DAYS = 30;

/**
 * Normalize text for matching.
 *
 * Strips combining marks (so "ó" becomes "o"), lowercases, and keeps only
 * alphanumerics, dots and dashes. Dots and dashes are kept because they
 * are part of a domain name — dropping them would turn "a-b.com" into
 * "ab.com" and break the comparison.
 */
export function normalizeText(value: string): string {
  const stripped = [...value.normalize('NFD')].filter((c) => c.normalize('NFD').length === 1).join('');
  return stripped
    .toLowerCase()
    .split('')
    .filter((c) => /[a-z0-9.\-]/.test(c))
    .join('');
}

/**
 * Prepare a set of keywords for matching.
 *
 * Keywords shorter than three characters are dropped: they match far too
 * much to be a signal ("com" is in every domain), and the upstream tool
 * applies the same floor. Longer keywords are tried first so a specific
 * term wins over a generic one that happens to be a substring of it.
 */
export function prepareKeywords(keywords: string[]): string[] {
  const seen = new Set<string>();
  for (const raw of keywords) {
    const normalized = normalizeText(raw);
    if (normalized.length < 3) continue;
    seen.add(normalized);
  }
  return [...seen].sort((a, b) => b.length - a.length);
}

/**
 * Extract the domains from one day's file that match any keyword.
 *
 * Lines without a dot are discarded before matching — they are not domains,
 * and matching them would produce noise from anything else in the feed.
 */
export function matchDomains(text: string, keywords: string[]): string[] {
  if (keywords.length === 0) return [];
  const out = new Set<string>();
  for (const line of text.split('\n')) {
    const raw = line.trim();
    if (!raw || !raw.includes('.')) continue;
    const normalized = normalizeText(raw);
    if (!normalized) continue;
    for (const keyword of keywords) {
      if (normalized.includes(keyword)) {
        out.add(raw);
        break;
      }
    }
  }
  return [...out].sort();
}

/** `YYYY-MM-DD` for a date offset from today (UTC). */
export function isoDaysAgo(days: number, from: Date = new Date()): string {
  const d = new Date(from);
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

/** The upstream URL for one day's file. */
export function dayFeedUrl(date: string): string {
  return `${DOMAIN_FEED_BASE}/${date}.txt`;
}

/**
 * Fetch one day's domain list, cached at the edge.
 *
 * A 404 means the feed has no file for that day — which happens for the
 * current day before the upstream publishes, and on days the upstream
 * skipped. That is an empty result, not an error.
 */
export async function fetchDayDomains(
  date: string,
  opts: { fetch?: typeof globalThis.fetch; useCache?: boolean } = {}
): Promise<{ date: string; domains: string[]; ok: boolean }> {
  const fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const useCache = opts.useCache !== false;
  const cacheKey = new Request(`https://domain-monitor.internal/v1/${date}`);

  if (useCache) {
    try {
      const hit = await caches.default.match(cacheKey);
      if (hit) {
        const json = (await hit.json()) as { domains: string[] };
        return { date, domains: json.domains ?? [], ok: true };
      }
    } catch {
      /* cache miss is fine */
    }
  }

  const url = dayFeedUrl(date);
  try {
    const res = await fetchFn(url, {
      headers: { 'user-agent': UA, accept: 'text/plain,*/*' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (res.status === 404) return { date, domains: [], ok: false };
    if (!res.ok) return { date, domains: [], ok: false };
    const text = await res.text();
    if (text.length > MAX_FILE_BYTES) return { date, domains: [], ok: false };
    const domains = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && l.includes('.'));
    if (useCache) {
      await caches.default
        .put(
          cacheKey,
          new Response(JSON.stringify({ domains }), {
            headers: {
              'content-type': 'application/json',
              'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
            },
          })
        )
        .catch(() => {});
    }
    return { date, domains, ok: true };
  } catch {
    return { date, domains: [], ok: false };
  }
}

export interface DomainMonitorMatch {
  date: string;
  domains: string[];
  /** Number of domains registered that day, before filtering. */
  total_domains: number;
}

/**
 * Search the daily feed over a window.
 *
 * The days are fetched concurrently — the Workers runtime caps concurrent
 * outbound connections anyway, so a sequential loop would only be slower.
 */
export async function searchDomains(
  keywords: string[],
  days: number,
  opts: { fetch?: typeof globalThis.fetch; useCache?: boolean } = {}
): Promise<{ days: DomainMonitorMatch[]; total: number; window: string[] }> {
  const prepared = prepareKeywords(keywords);
  const window = Array.from({ length: Math.max(1, days) }, (_, i) => isoDaysAgo(i));
  if (prepared.length === 0) return { days: [], total: 0, window };

  const results = await Promise.all(window.map((date) => fetchDayDomains(date, opts)));
  const daysOut: DomainMonitorMatch[] = [];
  let total = 0;
  for (const r of results) {
    if (!r.ok) continue;
    const matches = matchDomains(r.domains.join('\n'), prepared);
    daysOut.push({ date: r.date, domains: matches, total_domains: r.domains.length });
    total += matches.length;
  }
  return { days: daysOut, total, window };
}
