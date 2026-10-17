import { fetchResilient } from './fetch-resilient';

export interface OffseqThreat {
  externalId: string | null;
  source: string | null;
  type: string | null;
  title: string | null;
  description: string | null;
  severity: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  publishedDate: string | null;
  cveId: string | null;
  cveIds: string[];
  tags: string[];
  knownExploitsInWild: boolean;
  exploited: boolean;
  mirageCountries: string[];
  patchAvailable: boolean;
  knownThreatActors: string[];
  affectedCountries: string[];
  references: string[];
  slug: string | null;
  url: string | null;
  aiSummary: string | null;
  aiImpact: string | null;
}

export interface OffseqFetchResult {
  ok: boolean;
  threats: OffseqThreat[];
  total: number;
  partial: boolean;
  error?: string;
}

const PAGE_SIZE = 25;
const DEFAULT_MAX_PAGES = 3;
const CACHE_TTL_SECONDS = 5 * 60;
const FETCH_TIMEOUT_MS = 20_000;

export function extractCveIds(...inputs: Array<string | null | undefined | string[]>): string[] {
  const out = new Set<string>();
  const scan = (s: string) => {
    const direct = s.match(/CVE-\d{4}-\d+/gi);
    if (direct) for (const x of direct) out.add(x.toUpperCase());
    const tagged = s.match(/cve[-_](\d{4})[-_](\d+)/gi);
    if (tagged) {
      for (const x of tagged) {
        const m = x.match(/cve[-_](\d{4})[-_](\d+)/i);
        if (m) out.add(`CVE-${m[1]}-${m[2]}`);
      }
    }
  };
  for (const inp of inputs) {
    if (!inp) continue;
    if (Array.isArray(inp))
      for (const s of inp)
        if (typeof s === 'string') scan(s);
        else if (typeof inp === 'string') scan(inp);
  }
  return [...out];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function asString(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}
function asNumber(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string') {
    const n = Number.parseFloat(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}
function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export function mapOffseqThreat(raw: unknown): OffseqThreat | null {
  const r = asRecord(raw);
  if (!r) return null;
  const feed = asRecord(r.feed);
  const mirage = asRecord(r.mirageIntel);
  const enrichment = asRecord(r.enrichment);
  const slug = asString(r.slug);
  const title = asString(r.title);
  const externalId = asString(r.externalId) ?? asString(r._id) ?? asString(r.id);
  const source = asString(r.source) ?? asString(feed?.name);
  const type = asString(r.type);
  const description = asString(r.description);
  const severity = asString(r.severity)?.toLowerCase() ?? null;
  const cvssScore = asNumber(r.cvssScore);
  const cvssVector = asString(r.cvssVector);
  const publishedDate = asString(r.publishedDate) ?? asString(r.createdAt);
  const cveId = asString(r.cveId);
  const tags = asStringArray(r.tags);
  const cveIds = extractCveIds(cveId, tags, title, description);
  const knownExploitsInWild = r.knownExploitsInWild === true;
  const exploited = mirage?.exploited === true || knownExploitsInWild;
  const mirageCountries = asStringArray(mirage?.countries);
  const patchAvailable = r.patchAvailable === true;
  const knownThreatActors = asStringArray(r.knownThreatActors);
  const affectedCountries = asStringArray(r.affectedCountries);
  const references = asStringArray(r.references).slice(0, 20);
  const aiSummary = asString(enrichment?.aiGeneratedSummary) ?? asString(enrichment?.summary);
  const aiImpact = asString(enrichment?.aiGeneratedImpact);
  const url = slug ? `https://radar.offseq.com/threats/${slug}` : null;
  return {
    externalId,
    source,
    type,
    title,
    description,
    severity,
    cvssScore,
    cvssVector,
    publishedDate,
    cveId,
    cveIds,
    tags,
    knownExploitsInWild,
    exploited,
    mirageCountries,
    patchAvailable,
    knownThreatActors,
    affectedCountries,
    references,
    slug,
    url,
    aiSummary,
    aiImpact,
  };
}

export async function fetchOffseqRecent(
  opts: { days?: number; limit?: number; maxPages?: number; type?: string; apiKey?: string } = {}
): Promise<OffseqFetchResult> {
  const days = opts.days ?? 2;
  const maxPages = opts.maxPages ?? DEFAULT_MAX_PAGES;
  const pageSize = Math.min(100, Math.max(1, opts.limit ?? PAGE_SIZE));
  const cacheKey = `https://offseq-cache.internal/v1?days=${days}&limit=${pageSize}&pages=${maxPages}&type=${opts.type ?? ''}`;

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(cacheKey);
  try {
    const cached = await cache.match(cacheReq);
    if (cached) {
      const body = (await cached.json()) as OffseqFetchResult;
      return body;
    }
  } catch {
    /* cache unavailable */
  }

  const headers: Record<string, string> = {
    accept: 'application/json',
    'user-agent': 'pranithjain-dfir/1.0',
  };
  if (opts.apiKey) headers['X-API-Key'] = opts.apiKey;

  const threats: OffseqThreat[] = [];
  let total = 0;
  let partial = false;
  let ok = true;
  let error: string | undefined;

  try {
    let page = 1;
    for (let p = 0; p < maxPages; p++) {
      const url = new URL('https://radar.offseq.com/api/threats');
      url.searchParams.set('limit', String(pageSize));
      url.searchParams.set('page', String(page));
      url.searchParams.set('sort', '-publishedDate');
      url.searchParams.set('days', String(days));
      if (opts.type) url.searchParams.set('type', opts.type);

      const res = await fetchResilient(
        url.toString(),
        { headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) },
        { attempts: 2, timeoutMs: FETCH_TIMEOUT_MS }
      );
      if (!res.ok) {
        ok = false;
        error = `HTTP ${res.status}`;
        break;
      }

      const body = (await res.json()) as { threats?: unknown[]; pagination?: { total?: number; pages?: number } };
      const batch = Array.isArray(body.threats) ? body.threats : [];
      for (const raw of batch) {
        const t = mapOffseqThreat(raw);
        if (t) threats.push(t);
      }
      if (typeof body.pagination?.total === 'number') total = body.pagination.total;
      if (batch.length < pageSize) break;
      if (typeof body.pagination?.pages === 'number' && page >= body.pagination.pages) break;
      page += 1;
    }
  } catch (err) {
    ok = false;
    error = err instanceof Error ? err.message : String(err);
  }

  const seen = new Set<string>();
  const deduped: OffseqThreat[] = [];
  for (const t of threats) {
    const key = t.externalId || t.slug || t.title || '';
    if (key && seen.has(key)) continue;
    if (key) seen.add(key);
    deduped.push(t);
  }

  if (total > 0 && deduped.length < total && deduped.length >= pageSize * maxPages) partial = true;

  const result: OffseqFetchResult = {
    ok,
    threats: deduped,
    total: total || deduped.length,
    partial,
    ...(error ? { error } : {}),
  };

  try {
    await cache.put(
      cacheReq,
      new Response(JSON.stringify(result), {
        status: 200,
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_TTL_SECONDS}` },
      })
    );
  } catch {
    /* best-effort */
  }
  return result;
}

export async function fetchOffseqOverview(apiKey?: string): Promise<{
  ok: boolean;
  overview: Record<string, unknown> | null;
  error?: string;
}> {
  const headers: Record<string, string> = { accept: 'application/json', 'user-agent': 'pranithjain-dfir/1.0' };
  if (apiKey) headers['X-API-Key'] = apiKey;
  try {
    const res = await fetchResilient(
      'https://radar.offseq.com/api/threats/stats/overview',
      { headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) },
      { attempts: 2, timeoutMs: FETCH_TIMEOUT_MS }
    );
    if (!res.ok) return { ok: false, overview: null, error: `HTTP ${res.status}` };
    const body = (await res.json()) as Record<string, unknown>;
    return { ok: true, overview: body };
  } catch (err) {
    return { ok: false, overview: null, error: err instanceof Error ? err.message : String(err) };
  }
}
