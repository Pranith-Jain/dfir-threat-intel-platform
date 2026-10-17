import { errMessage } from './err';
export interface TieEnrichResult {
  ioc: string;
  iocType: 'ip' | 'hash' | 'domain' | 'url';
  reputation?: unknown;
  geo?: unknown;
  phantomcandle?: unknown;
  domainIntel?: unknown;
  phishingAnalysis?: unknown;
  malpedia?: unknown;
  mitre?: unknown;
  diagnostics: Array<{ provider: string; status: 'ok' | 'skipped' | 'failed'; ms: number; error?: string }>;
}

async function fetchJson(
  self: Fetcher,
  path: string,
  internalToken?: string
): Promise<{ data?: unknown; ok: boolean; ms: number }> {
  const t0 = Date.now();
  const headers: Record<string, string> = { accept: 'application/json' };
  if (internalToken) headers['x-internal-token'] = internalToken;
  try {
    const res = await self.fetch(`https://placeholder${path}`, { headers });
    const ms = Date.now() - t0;
    if (!res.ok) return { ok: false, ms };
    return { data: await res.json(), ok: true, ms };
  } catch (_catchErr) {
    console.error('fetchJson failed:', errMessage(_catchErr));
    return { ok: false, ms: Date.now() - t0 };
  }
}

/**
 * Enrich an IOC via authenticated in-process SELF calls.
 *
 * `internalToken` must be a signed internal token (mint it at the call site
 * with `signInternalToken('tie-enrich', env.INTERNAL_TOKEN_SECRET)`) — without
 * it the SELF calls hit the API key gate and every provider returns empty.
 * Minting lives at the call site because this file is symlinked into
 * `api/src/lib/` and cannot carry cross-tree relative imports.
 */
export async function enrichIoc(
  self: Fetcher,
  ioc: string,
  iocType: 'ip' | 'hash' | 'domain' | 'url',
  internalToken?: string
): Promise<TieEnrichResult> {
  const result: TieEnrichResult = { ioc, iocType, diagnostics: [] };

  if (iocType === 'ip') {
    const [rep, geo, pc] = await Promise.all([
      fetchJson(self, `/api/v1/ioc/check?indicator=${encodeURIComponent(ioc)}`, internalToken),
      fetchJson(self, `/api/v1/ip-geo?ip=${encodeURIComponent(ioc)}`, internalToken),
      fetchJson(self, `/api/v1/ip/${encodeURIComponent(ioc)}/phantomcandle`, internalToken),
    ]);
    if (rep.ok) result.reputation = rep.data;
    result.diagnostics.push({ provider: 'check_ioc', status: rep.ok ? 'ok' : 'failed', ms: rep.ms });
    if (geo.ok) result.geo = geo.data;
    result.diagnostics.push({ provider: 'lookup_ip_geo', status: geo.ok ? 'ok' : 'failed', ms: geo.ms });
    if (pc.ok) result.phantomcandle = pc.data;
    result.diagnostics.push({ provider: 'phantomcandle', status: pc.ok ? 'ok' : 'skipped', ms: pc.ms });
  } else if (iocType === 'hash') {
    const [rep, mal] = await Promise.all([
      fetchJson(self, `/api/v1/ioc/check?indicator=${encodeURIComponent(ioc)}`, internalToken),
      fetchJson(self, `/api/v1/search-malpedia?q=${encodeURIComponent(ioc)}`, internalToken),
    ]);
    if (rep.ok) result.reputation = rep.data;
    result.diagnostics.push({ provider: 'check_ioc', status: rep.ok ? 'ok' : 'failed', ms: rep.ms });
    if (mal.ok) result.malpedia = mal.data;
    result.diagnostics.push({ provider: 'search_malpedia', status: mal.ok ? 'ok' : 'skipped', ms: mal.ms });
  } else if (iocType === 'domain') {
    const [rep, dom] = await Promise.all([
      fetchJson(self, `/api/v1/ioc/check?indicator=${encodeURIComponent(ioc)}`, internalToken),
      fetchJson(self, `/api/v1/domain?domain=${encodeURIComponent(ioc)}`, internalToken),
    ]);
    if (rep.ok) result.reputation = rep.data;
    result.diagnostics.push({ provider: 'check_ioc', status: rep.ok ? 'ok' : 'failed', ms: rep.ms });
    if (dom.ok) result.domainIntel = dom.data;
    result.diagnostics.push({ provider: 'lookup_domain', status: dom.ok ? 'ok' : 'failed', ms: dom.ms });
  } else if (iocType === 'url') {
    const [rep, ph] = await Promise.all([
      fetchJson(self, `/api/v1/ioc/check?indicator=${encodeURIComponent(ioc)}`, internalToken),
      fetchJson(self, `/api/v1/phishing/url?url=${encodeURIComponent(ioc)}`, internalToken),
    ]);
    if (rep.ok) result.reputation = rep.data;
    result.diagnostics.push({ provider: 'check_ioc', status: rep.ok ? 'ok' : 'failed', ms: rep.ms });
    if (ph.ok) result.phishingAnalysis = ph.data;
    result.diagnostics.push({ provider: 'analyze_phishing_url', status: ph.ok ? 'ok' : 'skipped', ms: ph.ms });
  }

  // MITRE extraction
  const mitre = await fetchJson(self, `/api/v1/attack/extract?text=${encodeURIComponent(ioc)}`, internalToken);
  if (mitre.ok) result.mitre = mitre.data;
  result.diagnostics.push({ provider: 'extract_ttps', status: mitre.ok ? 'ok' : 'skipped', ms: mitre.ms });

  return result;
}
