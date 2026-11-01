/**
 * MANTIS infrastructure-hunt planner (fareedfauzi/MANTIS, MIT) —
 * deterministic seed → engine-query planner running on Workers:
 *   GET /mantis-hunt/preview?seed=<ip|domain>
 *
 * Keyless seed intel only (crt.sh for domains, RIPEstat for IPs), so the
 * surface works with no stored credentials. The response carries the ranked
 * feature map, per-engine compound queries with launch links (same shape and
 * semantics as upstream compose_queries — pinned by golden tests), the
 * built-in C2 signature packs, and provider readiness derived from the
 * worker's optional engine secrets. Executing keyed engine queries is left
 * to the analyst (launch links); only pass-through reads happen here.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, badRequest } from '../lib/api-error';
import {
  classifySeed,
  extractFeatures,
  composeQueries,
  matchSignaturePacks,
  EXPANSION_PROVIDERS,
} from '../lib/mantis-infra-hunt';

const HUNT_CACHE_TTL_SECONDS = 3600; // plan-level cache
const HUNT_MISS_TTL_SECONDS = 600; // failed upstream reads retry sooner
const UPSTREAM_TIMEOUT_MS = 25_000;

export const mantisHuntRouter = new Hono<{ Bindings: Env }>();

// ─── upstream helpers (ported from MANTIS intel_query.py) ───────────────────

interface CrtshCert {
  certificate_id: string;
  common_name: string;
  san: string[];
  issuer: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  source: string;
}

/** query_crtsh — exact + wildcard certs, SANs deduped upstream-style. */
async function queryCrtsh(
  domain: string
): Promise<{ source: string; domain: string; certificates: CrtshCert[]; count: number; errors: string[] }> {
  const d = (domain || '').trim().toLowerCase();
  const res = { source: 'crt.sh', domain: d, certificates: [] as CrtshCert[], count: 0, errors: [] as string[] };
  if (!d) {
    res.errors.push('Empty domain for crt.sh lookup');
    return res;
  }
  const seen = new Set<string>();
  for (const q of [d, `%.${d}`]) {
    try {
      const resp = await fetch(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json`, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      });
      if (!resp.ok) {
        res.errors.push(`crt.sh: HTTP ${resp.status} for q=${q}`);
        continue;
      }
      const results = (await resp.json()) as Array<Record<string, unknown>>;
      if (!Array.isArray(results)) continue;
      for (const cert of results) {
        if (!cert || typeof cert !== 'object') continue;
        const id = String(cert.id ?? '');
        if (id && seen.has(id)) continue;
        if (id) seen.add(id);
        const sans: string[] = [];
        for (const name of String(cert.name_value ?? '').split(/\r?\n/)) {
          const cleaned = name.trim().toLowerCase().replace(/\.$/, '');
          if (cleaned && !sans.includes(cleaned)) sans.push(cleaned);
        }
        if (res.certificates.length >= 200) break;
        res.certificates.push({
          certificate_id: id,
          common_name: String(cert.common_name ?? ''),
          san: sans.slice(0, 50),
          issuer: String(cert.issuer_name ?? ''),
          not_before: String(cert.not_before ?? ''),
          not_after: String(cert.not_after ?? ''),
          serial_number: String(cert.serial_number ?? ''),
          source: 'crt.sh',
        });
      }
    } catch (e) {
      res.errors.push(`crt.sh: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (res.certificates.length >= 200) break;
  }
  res.count = res.certificates.length;
  return res;
}

interface RipeResult {
  source: string;
  ip: string;
  prefix: string;
  asns: string[];
  asn_overview: Record<string, unknown>;
  announced_prefixes: string[];
  whois: Array<Record<string, string>>;
  errors: string[];
}

/** RIPEstat data call — returns the data dict or {} on error. */
async function ripeGet(endpoint: string, resource: string): Promise<{ data: Record<string, unknown>; error: string }> {
  try {
    const resp = await fetch(
      `https://stat.ripe.net/data/${endpoint}/data.json?resource=${encodeURIComponent(resource)}`,
      {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(20_000),
      }
    );
    if (!resp.ok) return { data: {}, error: `RIPEstat: HTTP ${resp.status}` };
    const payload = (await resp.json()) as Record<string, unknown>;
    if (!payload || payload.status !== 'ok') {
      const msg = typeof payload?.message === 'string' ? payload.message : 'unavailable';
      return { data: {}, error: `RIPEstat: ${msg.slice(0, 200)}` };
    }
    const data =
      typeof payload.data === 'object' && payload.data !== null ? (payload.data as Record<string, unknown>) : {};
    return { data, error: '' };
  } catch (e) {
    return { data: {}, error: `RIPEstat: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/** query_ripe_network — IP → prefix + ASNs → overview + announced + WHOIS. */
async function queryRipeNetwork(ip: string): Promise<RipeResult> {
  const target = (ip || '').trim();
  const res: RipeResult = {
    source: 'RIPEstat',
    ip: target,
    prefix: '',
    asns: [],
    asn_overview: {},
    announced_prefixes: [],
    whois: [],
    errors: [],
  };
  if (!target) {
    res.errors.push('Empty IP for RIPEstat lookup');
    return res;
  }
  const net = await ripeGet('network-info', target);
  if (net.error) {
    res.errors.push(net.error);
    return res;
  }
  const rawPrefixes: unknown = net.data.prefix;
  let prefixList: string[] = [];
  if (typeof rawPrefixes === 'string') prefixList = [rawPrefixes];
  else if (Array.isArray(rawPrefixes)) prefixList = rawPrefixes.map((p) => String(p));
  res.prefix = prefixList[0] ?? '';
  const asns = Array.isArray(net.data.asns) ? (net.data.asns as unknown[]) : [];
  res.asns = asns.filter(Boolean).map((a) => String(a));
  const firstAsn = res.asns[0];
  if (firstAsn) {
    const asnId = firstAsn.toUpperCase().startsWith('AS') ? firstAsn : `AS${firstAsn}`;
    const overview = await ripeGet('as-overview', asnId);
    if (overview.error) res.errors.push(overview.error);
    else
      res.asn_overview = {
        asn: String(overview.data.resource ?? '') || asnId,
        announced: Boolean(overview.data.announced),
        holder: String(overview.data.holder ?? ''),
        block: typeof overview.data.block === 'object' && overview.data.block !== null ? overview.data.block : {},
      };
    const announced = await ripeGet('announced-prefixes', asnId);
    if (announced.error) res.errors.push(announced.error);
    else {
      const raw = Array.isArray(announced.data.prefixes) ? announced.data.prefixes : [];
      for (const p of raw.slice(0, 20)) {
        if (typeof p === 'object' && p !== null && 'prefix' in p && (p as Record<string, unknown>).prefix) {
          res.announced_prefixes.push(String((p as Record<string, unknown>).prefix));
        } else if (typeof p === 'string' && p.trim()) {
          res.announced_prefixes.push(p.trim());
        }
      }
    }
  }
  const whois = await ripeGet('whois', target);
  if (whois.error) res.errors.push(whois.error);
  else {
    const records = Array.isArray(whois.data.records) ? whois.data.records : [];
    for (const rec of records.slice(0, 5)) {
      if (Array.isArray(rec)) {
        const row: Record<string, string> = {};
        for (const entry of rec as Array<Record<string, unknown>>) {
          if (entry && typeof entry === 'object' && entry.key)
            row[String(entry.key)] = String(entry.value ?? '').slice(0, 300);
        }
        res.whois.push(row);
      } else if (rec && typeof rec === 'object') {
        const row: Record<string, string> = {};
        for (const [k, v] of Object.entries(rec as Record<string, unknown>)) row[k] = String(v ?? '').slice(0, 300);
        res.whois.push(row);
      }
    }
  }
  return res;
}

// ─── provider readiness (optional worker secrets) ───────────────────────────

const READINESS_ENV: Record<string, { envName: string; label: string } | null> = {
  shodan: { envName: 'SHODAN_API_KEY', label: 'Shodan' },
  censys: { envName: 'CENSYS_PAT', label: 'Censys' },
  netlas: { envName: 'NETLAS_API_KEY', label: 'Netlas' },
  zoomeye: { envName: 'ZOOMEYE_API_KEY', label: 'ZoomEye' },
  greynoise: { envName: 'GREYNOISE_API_KEY', label: 'GreyNoise' },
  fofa: null,
  silentpush: null,
  driftnet: null,
  validin: null,
  etugen: null,
};

mantisHuntRouter.get('/mantis-hunt/preview', async (c) => {
  const seedParam = (c.req.query('seed') || '').trim();
  if (!seedParam) return badRequest(c, 'seed query parameter is required (IP or domain)');
  const seed = classifySeed(seedParam);
  if (seed.kind === 'invalid') {
    return badRequest(c, `seed must be an IPv4 address or a domain name, got: ${seedParam.slice(0, 80)}`);
  }

  const cacheKey = `https://hunt-cache.mantis-hunt.internal/preview?seed=${encodeURIComponent(seed.value)}`;
  try {
    const hit = await caches.default.match(new Request(cacheKey));
    if (hit) {
      const cached = await hit.json<Record<string, unknown>>();
      if (cached)
        return c.json({ ...cached, cached: true }, 200, {
          'cache-control': `public, max-age=${HUNT_CACHE_TTL_SECONDS}`,
        });
    }
  } catch {
    /* cache reads are non-fatal */
  }

  try {
    const payload =
      seed.kind === 'domain' ? { crtsh: await queryCrtsh(seed.value) } : { ripe: await queryRipeNetwork(seed.value) };

    const features = extractFeatures(payload);
    const queries = composeQueries(features, 3);
    const signatures = matchSignaturePacks(features);
    const readiness = Object.entries(EXPANSION_PROVIDERS).map(([provider, def]) => {
      const mapping = READINESS_ENV[provider];
      const keyEnv = mapping?.envName ?? null;
      const available = mapping
        ? Boolean((c.env as unknown as Record<string, string | undefined>)[mapping.envName])
        : false;
      return { provider, label: def.label, role: def.role, keyEnv, available };
    });

    const plan = {
      engine: 'mantis-infra-hunt',
      upstream: 'fareedfauzi/MANTIS (MIT) — infra_hunt_service.py planner port',
      seed: seed.value,
      seedKind: seed.kind,
      sources: Object.keys(payload),
      generatedAt: new Date().toISOString(),
      features,
      queries,
      signatures,
      readiness,
      notes:
        'Plan only: crt.sh + RIPEstat seed intel is keyless; keyed engines appear as launch links. Executing engine searches with your own keys stays client-side by design.',
    };

    c.header('cache-control', `public, max-age=${HUNT_CACHE_TTL_SECONDS}`);
    try {
      await caches.default.put(
        new Request(cacheKey),
        new Response(JSON.stringify(plan), {
          headers: {
            'content-type': 'application/json',
            'cache-control': `public, max-age=${HUNT_MISS_TTL_SECONDS}, s-maxage=${HUNT_CACHE_TTL_SECONDS}`,
          },
        })
      );
    } catch {
      /* cache writes are non-fatal */
    }
    return c.json(plan);
  } catch (e) {
    logError('mantis-hunt preview failed', e);
    return internalError(c, `mantis_hunt_preview_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
