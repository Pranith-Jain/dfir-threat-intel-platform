/**
 * ENISA EUVD (EU Vulnerability Database) client.
 *
 * Ported from CVE Intel's `crates/cve-core/src/feeds.rs` + the EUVD calls in
 * `clients.rs`.
 *
 * EUVD is interesting for two reasons: it publishes an `exploited` flag that
 * is **independent of CISA KEV**, and it is the only source that reports
 * EU-level exploitation reporting. A CVE that EUVD marks exploited while KEV
 * has not listed it is a real gap, not a duplicate — so the two are compared
 * rather than merged.
 *
 * EUVD timestamps arrive in `Apr 12, 2024, 7:20:00 AM` form, which no
 * standard parser handles, so they are normalised here.
 */

const EUVD_API = 'https://euvdservices.enisa.europa.eu/api';
const UA = 'pranithjain-dfir/1.0 (+https://pranithjain.qzz.io)';

/** `Apr 12, 2024, 7:20:00 AM` → `2024-04-12`. */
export function euvdDate(value: string | undefined | null): string | undefined {
  if (!value) return undefined;
  const parts = value.split(',');
  if (parts.length < 2) return undefined;
  const monthDay = (parts[0] ?? '').trim();
  const year = (parts[1] ?? '').trim();
  const d = new Date(`${monthDay} ${year} UTC`);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString().slice(0, 10);
}

export interface EuvdItem {
  euvdId: string;
  cveIds: string[];
  description: string;
  published?: string;
  updated?: string;
  exploited: boolean;
  exploitedSince?: string;
  cvss?: number;
  epssPercent?: number;
  vendors: string[];
  products: string[];
  affected: string[];
  url: string;
}

interface EuvdRaw {
  id?: string;
  aliases?: string;
  description?: string;
  datePublished?: string;
  dateUpdated?: string;
  exploitedSince?: string;
  baseScore?: number | string;
  baseScoreVersion?: string;
  baseScoreVector?: string;
  epss?: number | string;
  assigner?: string;
  references?: string;
  enisaIdProduct?: Array<{
    product?: { name?: string; vendor?: { name?: string } };
    product_version?: string;
  }>;
  enisaIdVendor?: Array<{ vendor?: { name?: string } }>;
}

function lines(value: string | undefined): string[] {
  return (value ?? '')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function pushUnique(list: string[], value: string): void {
  if (value && !list.includes(value)) list.push(value);
}

/** Reduce one raw EUVD search item to what the platform surfaces. */
export function euvdItem(raw: EuvdRaw): EuvdItem {
  const id = raw.id ?? '';
  const aliases = lines(raw.aliases);
  const cveIds: string[] = [];
  for (const a of aliases) {
    const m = /^CVE-\d{4}-\d{4,7}$/i.exec(a.trim());
    if (m) pushUnique(cveIds, m[0].toUpperCase());
  }
  const vendors: string[] = [];
  const products: string[] = [];
  const affected: string[] = [];
  for (const p of raw.enisaIdProduct ?? []) {
    const product = p.product?.name ?? '';
    const vendor = p.product?.vendor?.name ?? '';
    pushUnique(vendors, vendor);
    pushUnique(products, product);
    if (affected.length < 8) {
      pushUnique(affected, `${product} ${p.product_version ?? ''}`.trim());
    }
  }
  for (const x of raw.enisaIdVendor ?? []) pushUnique(vendors, x.vendor?.name ?? '');

  const exploitedSince = euvdDate(raw.exploitedSince);
  const cvss = Number(raw.baseScore);

  return {
    euvdId: id,
    cveIds,
    description: (raw.description ?? '').slice(0, 300),
    published: euvdDate(raw.datePublished),
    updated: euvdDate(raw.dateUpdated),
    exploited: exploitedSince !== undefined,
    exploitedSince,
    cvss: Number.isFinite(cvss) && cvss > 0 ? cvss : undefined,
    epssPercent: Number.isFinite(Number(raw.epss)) ? Number(raw.epss) : undefined,
    vendors,
    products,
    affected,
    url: `https://euvd.enisa.europa.eu/vulnerability/${id}`,
  };
}

/**
 * Find the EUVD entry for one CVE in a search response.
 *
 * Matches on the `aliases` list, which EUVD populates with the CVE id.
 */
export function euvdFind(response: unknown, cveId: string): EuvdItem | undefined {
  const items = (response as { items?: EuvdRaw[] })?.items;
  if (!Array.isArray(items)) return undefined;
  const target = cveId.toUpperCase();
  const hit = items.find((i) => lines(i.aliases).some((a) => a.trim().toUpperCase() === target));
  return hit ? euvdItem(hit) : undefined;
}

export interface EuvdOptions {
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * Look up one CVE in EUVD.
 *
 * Returns null when EUVD has no entry — which is the common case for most
 * CVEs and is not an error.
 */
export async function euvdCve(cveId: string, opts: EuvdOptions = {}): Promise<EuvdItem | null> {
  const fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const url = `${EUVD_API}/search?text=${encodeURIComponent(cveId)}&size=5`;
  try {
    const res = await fetchFn(url, {
      headers: { accept: 'application/json', 'user-agent': UA },
      signal: opts.signal ?? AbortSignal.timeout(opts.timeoutMs ?? 8000),
    });
    if (!res.ok) return null;
    const json = await res.json();
    return euvdFind(json, cveId) ?? null;
  } catch {
    return null;
  }
}

/**
 * EUVD entries flagged as exploited and updated on or after `since`.
 *
 * Paged at 100 per request, two pages maximum (200 entries). The cap is
 * deliberate: this feeds a weekly panel that keeps 25 items, and a week of
 * EUVD exploitation reporting does not run to thousands of entries. The
 * truncation is reported rather than silent — if EUVD ever does exceed the
 * cap, `truncated` says so instead of the panel quietly under-reporting.
 */
export async function euvdExploited(
  since: string,
  opts: EuvdOptions = {}
): Promise<{ items: EuvdItem[]; truncated: boolean }> {
  const fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const PAGE = 100;
  const MAX_PAGES = 2;
  const out: EuvdItem[] = [];
  let total = Infinity;

  for (let page = 0; page < MAX_PAGES; page++) {
    const url =
      `${EUVD_API}/search?exploited=true&fromUpdatedDate=${encodeURIComponent(since)}` + `&size=${PAGE}&page=${page}`;
    let json: { items?: EuvdRaw[]; total?: number } | null = null;
    try {
      const res = await fetchFn(url, {
        headers: { accept: 'application/json', 'user-agent': UA },
        signal: opts.signal ?? AbortSignal.timeout(opts.timeoutMs ?? 10_000),
        // The search is a public, slowly-changing document; caching it at
        // the edge keeps the weekly panel from re-fetching five pages per
        // request.
        cf: { cacheTtlByStatus: { '200-299': 3600, '400-599': 0 }, cacheEverything: true },
      } as RequestInit);
      if (!res.ok) break;
      json = (await res.json()) as { items?: EuvdRaw[]; total?: number };
    } catch {
      break;
    }
    const items = json.items ?? [];
    out.push(...items.map(euvdItem));
    if (typeof json.total === 'number') total = json.total;
    if (items.length < PAGE || out.length >= total) break;
  }

  return { items: out, truncated: out.length < total };
}
