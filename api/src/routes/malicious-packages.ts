import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { fetchResilient } from '../lib/fetch-resilient';
import { writeLastGood } from '../lib/lastgood';

/**
 * Malicious-package directory backed by ossf/malicious-packages — the OpenSSF
 * curated mirror of npm + PyPI + RubyGems + Maven malware reports (OSV
 * format). Public, no auth, no API key.
 *
 * Layout: each ecosystem under `osv/malicious/<eco>/` contains one
 * directory per package name. Inside each is one or more MAL-YYYY-NNNN.json
 * OSV records describing the malicious version range.
 *
 * For the public-facing view we fetch JUST the package-name listing per
 * ecosystem and cache it. Per-package detail (the actual OSV record) is
 * deferred — analysts click through to GitHub for full details.
 */

const CACHE_TTL_SECONDS = 3600;
// Long-lived KV-backed fallback. GitHub Contents API limits anonymous
// callers to 60 req/hr per IP; Workers share IPs so we hit the cap
// quickly and used to 403 the whole page. The KV last-good cache survives
// long enough that an analyst landing during a throttle window still
// sees a usable (just slightly stale) listing instead of a hard error.
const KV_LAST_GOOD_TTL_SECONDS = 7 * 24 * 60 * 60;
const KV_LAST_GOOD_PREFIX = 'malpkg:lastgood:';
const GH_API_BASE = 'https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious';

const ECOSYSTEMS = ['npm', 'pypi', 'rubygems', 'maven', 'go', 'crates.io'] as const;
type Ecosystem = (typeof ECOSYSTEMS)[number];

interface PackageEntry {
  name: string;
  ecosystem: Ecosystem;
  ossf_url: string;
}

interface MaliciousPackagesResponse {
  ecosystem: Ecosystem;
  total: number;
  packages: PackageEntry[];
  source: string;
  source_url: string;
  generated_at: string;
}

function isEcosystem(s: string | undefined): s is Ecosystem {
  return !!s && (ECOSYSTEMS as readonly string[]).includes(s);
}

export async function maliciousPackagesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const ecoQ = c.req.query('ecosystem') ?? 'npm';
  if (!isEcosystem(ecoQ)) {
    return badRequest(c, `invalid ecosystem; supported: `);
  }
  const ecosystem = ecoQ;

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(`https://malicious-packages-cache.internal/v2?e=${ecosystem}`);
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const kv = c.env.KV_CACHE;
  const kvKey = `${KV_LAST_GOOD_PREFIX}${ecosystem}`;

  // GitHub Contents API caps at 1000 entries per directory page; we don't
  // page beyond the first 1000 because the response would balloon past
  // Worker memory anyway. Analysts who need exhaustive lookup click
  // through to the repo.
  let raw: Array<{ name: string; path: string; html_url: string; type: string }> | null = null;
  let upstreamError: string | null = null;
  // Some env shapes (test fixtures) carry a GITHUB_TOKEN secret which
  // bumps the anonymous 60/hr cap to 5000/hr. Optional — we'll try
  // without and fall through to the KV last-good when it 403s.
  const ghToken = c.env.GITHUB_TOKEN;
  try {
    const res = await fetchResilient(
      `${GH_API_BASE}/${ecosystem}`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'pranithjain-dfir/1.0',
          ...(ghToken ? { Authorization: `Bearer ${ghToken}` } : {}),
        },
      },
      { attempts: 3, timeoutMs: 15_000 }
    );
    if (res.ok) {
      raw = (await res.json()) as Array<{ name: string; path: string; html_url: string; type: string }>;
    } else {
      upstreamError = `github contents ${res.status}`;
    }
  } catch (err) {
    logError('handler failed', err);
    upstreamError = `fetch failed: ${(err as Error).message}`;
  }

  // Live fetch failed (403, rate-limited, timeout). Serve the KV
  // last-good if we have one — the data is curated and changes slowly,
  // so a 24h-7d stale view is still useful.
  if (!raw) {
    if (kv) {
      try {
        const stale = await kv.get(kvKey);
        if (stale) {
          const staleBody = JSON.parse(stale) as MaliciousPackagesResponse;
          return c.json(
            { ...staleBody, generated_at: staleBody.generated_at, upstream_error: upstreamError, stale: true },
            200,
            { 'Cache-Control': 'public, max-age=300' }
          );
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* stale read failed; fall through to error */
      }
    }
    return c.json(
      {
        error: upstreamError ?? 'github contents unavailable',
        hint: 'GitHub Contents API rate-limits anonymous callers to 60/hr per IP. Retry in a few minutes — the page will warm a long-lived cache on the next success.',
      },
      502
    );
  }

  const packages: PackageEntry[] = (Array.isArray(raw) ? raw : [])
    .filter((entry) => entry.type === 'dir' && entry.name && !entry.name.startsWith('.'))
    .map((entry) => ({
      name: entry.name,
      ecosystem,
      ossf_url:
        entry.html_url ??
        `https://github.com/ossf/malicious-packages/tree/main/osv/malicious/${ecosystem}/${encodeURIComponent(entry.name)}`,
    }));

  const body: MaliciousPackagesResponse = {
    ecosystem,
    total: packages.length,
    packages,
    source: 'ossf/malicious-packages',
    source_url: `https://github.com/ossf/malicious-packages/tree/main/osv/malicious/${ecosystem}`,
    generated_at: new Date().toISOString(),
  };

  const response = c.json(body, 200, {
    'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}, stale-while-revalidate=${CACHE_TTL_SECONDS * 4}`,
  });
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  // Refresh the KV last-good so future 403s can serve stale instead of
  // erroring. Debounced via caches.default so we don't write on every
  // cache-miss-success — once every few hours per ecosystem is plenty.
  c.executionCtx.waitUntil(writeLastGood(c.env, kvKey, body, { ttlSeconds: KV_LAST_GOOD_TTL_SECONDS, keyPrefix: '' }));
  return response;
}
