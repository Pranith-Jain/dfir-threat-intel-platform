import type { Env } from '../../env';
import { FEED_SOURCES, UNCAPPED, buildSummary, type IocEntry, type SourceId } from '../ioc-feed-parsers';
import { fetchResilient } from '../fetch-resilient';
import { readLastGood, writeLastGood } from '../lastgood';
import { NVD_UA, NVD_API, KEV_FEED, LASTGOOD_TTL_SEC, nvdHeaders } from './config';
import { fetchDbugsRecent as fetchDbugsSource, type DbugsVuln } from '../dbugs';
import type { KevDoc, KevEntry, NvdCve, NvdResponse } from './types';

export interface MaliciousPackageEntry {
  name: string;
  ecosystem: string;
  ossf_url: string;
  /** ISO timestamp of the advisory's first appearance in the OSSF repo
   * (the commit date that added the package directory). Used to window
   * daily/weekly briefings to "newly disclosed" packages only. */
  publishedAt?: string;
  /** Short advisory summary when available from the commit's OSV file. */
  summary?: string;
}

export interface DailyHuntIocFamily {
  slug: string;
  family: string;
  category: 'ransomware' | 'malware' | 'apt' | 'c2' | 'phishing' | 'stealer' | 'other';
  aliases: string[];
  firstSeen: string | null;
  mitreTechniques: string[];
  indicatorCount: number;
  description: string;
}

export async function withLastGood<T>(env: Env | undefined, cacheKey: string, live: () => Promise<T>): Promise<T> {
  try {
    const v = await live();
    if (env) await writeLastGood(env, cacheKey, v, { ttlSeconds: LASTGOOD_TTL_SEC });
    return v;
  } catch (err) {
    if (!env) throw err;
    const hit = await readLastGood<T>(env, cacheKey);
    if (hit !== null) return hit;
    throw err;
  }
}

export async function fetchKev(): Promise<KevEntry[]> {
  const res = await fetchResilient(
    KEV_FEED,
    {
      headers: { 'user-agent': NVD_UA, accept: 'application/json' },
      cf: { cacheTtlByStatus: { '200-299': 1800, '400-599': 0 }, cacheEverything: true },
    } as RequestInit,
    { attempts: 3, timeoutMs: 20_000 }
  );
  if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
  const doc = (await res.json()) as KevDoc;
  return doc.vulnerabilities ?? [];
}

export async function fetchNvdRecent(start: Date, end: Date, apiKey?: string): Promise<NvdCve[]> {
  const fmt = (d: Date) => d.toISOString().replace(/Z$/, '+00:00');
  const out: NvdCve[] = [];
  const PAGE = 2000;
  const HARD_CAP = 4000;
  let startIndex = 0;
  let anyPageOk = false;
  for (let i = 0; i < 4 && out.length < HARD_CAP; i++) {
    const url =
      `${NVD_API}?pubStartDate=${encodeURIComponent(fmt(start))}` +
      `&pubEndDate=${encodeURIComponent(fmt(end))}` +
      `&resultsPerPage=${PAGE}&startIndex=${startIndex}`;
    let pageOk = false;
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, 1500 * attempt + Math.random() * 800));
      try {
        const res = await fetch(url, {
          headers: nvdHeaders(apiKey),
          signal: AbortSignal.timeout(20_000),
          cf: { cacheTtlByStatus: { '200-299': 1800, '400-599': 0 }, cacheEverything: true },
        } as RequestInit);
        if (!res.ok) {
          lastErr = new Error(`NVD ${res.status}`);
          if (res.status !== 429 && res.status < 500) break;
          continue;
        }
        const json = (await res.json()) as NvdResponse & { totalResults?: number };
        const batch = json.vulnerabilities ?? [];
        for (const v of batch) if (v.cve) out.push(v.cve);
        pageOk = true;
        anyPageOk = true;
        if (batch.length < PAGE) return out;
        startIndex += PAGE;
        break;
      } catch (e) {
        lastErr = e;
      }
    }
    if (!pageOk) {
      if (!anyPageOk) throw lastErr instanceof Error ? lastErr : new Error('NVD unreachable');
      break;
    }
  }
  return out;
}

export async function fetchCirclRecent(start: Date, end: Date): Promise<NvdCve[]> {
  const days = Math.ceil((end.getTime() - start.getTime()) / 86400_000);
  const limit = Math.min(2000, Math.max(300, days * 220));
  const res = await fetchResilient(
    `https://cve.circl.lu/api/last/${limit}`,
    { headers: { 'user-agent': NVD_UA, accept: 'application/json' } } as RequestInit,
    { attempts: 2, timeoutMs: 15_000 }
  );
  if (!res.ok) throw new Error(`CIRCL last ${res.status}`);
  const items = (await res.json()) as Record<string, unknown>[];
  const out: NvdCve[] = [];
  for (const it of Array.isArray(items) ? items : []) {
    const cveId = resolveCirclCveId(it);
    if (!cveId) continue;
    const pubIso = resolveCirclPublished(it);
    if (!pubIso) continue;
    const pub = new Date(pubIso);
    if (Number.isNaN(pub.getTime()) || pub < start || pub >= end) continue;
    const baseScore = resolveCirclBaseScore(it);
    if (baseScore == null) continue;
    const description = resolveCirclDescription(it);
    const cweIds = resolveCirclCweIds(it);
    out.push({
      id: cveId,
      descriptions: [{ lang: 'en', value: description }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore } }] },
      weaknesses: cweIds.map((c) => ({ description: [{ lang: 'en', value: c }] })),
    });
  }
  return out;
}

export function resolveCirclCveId(it: Record<string, unknown>): string | null {
  const cveMeta = (it.cveMetadata as Record<string, unknown> | undefined) ?? {};
  if (typeof cveMeta.cveId === 'string' && /^CVE-\d{4}-\d+$/.test(cveMeta.cveId)) {
    return cveMeta.cveId;
  }
  const aliases = Array.isArray(it.aliases) ? (it.aliases as unknown[]) : [];
  for (const a of aliases) {
    if (typeof a === 'string' && /^CVE-\d{4}-\d+$/.test(a)) return a;
  }
  if (typeof it.id === 'string' && /^CVE-\d{4}-\d+$/.test(it.id)) return it.id;
  return null;
}

export function resolveCirclPublished(it: Record<string, unknown>): string {
  const cveMeta = (it.cveMetadata as Record<string, unknown> | undefined) ?? {};
  if (typeof cveMeta.datePublished === 'string' && cveMeta.datePublished) {
    return cveMeta.datePublished;
  }
  const cna = ((it.containers as Record<string, unknown> | undefined)?.cna ?? {}) as Record<string, unknown>;
  if (typeof cna.datePublic === 'string' && cna.datePublic) return cna.datePublic;
  const ds = (it.database_specific as Record<string, unknown> | undefined) ?? {};
  if (typeof ds.nvd_published_at === 'string' && ds.nvd_published_at) {
    return ds.nvd_published_at;
  }
  if (typeof it.published === 'string' && it.published) return it.published;
  return '';
}

export function resolveCirclBaseScore(it: Record<string, unknown>): number | undefined {
  const cna = ((it.containers as Record<string, unknown> | undefined)?.cna ?? {}) as Record<string, unknown>;
  for (const m of (cna.metrics as Record<string, unknown>[]) ?? []) {
    const v = (m.cvssV3_1 ?? m.cvssV3_0) as { baseScore?: number; baseSeverity?: string } | undefined;
    if (v?.baseScore != null) return v.baseScore;
  }
  return undefined;
}

function resolveCirclDescription(it: Record<string, unknown>): string {
  const cna = ((it.containers as Record<string, unknown> | undefined)?.cna ?? {}) as Record<string, unknown>;
  const descs = cna.descriptions as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(descs)) {
    const en = descs.find((d) => d.lang === 'en' && typeof d.value === 'string');
    if (en) return String(en.value);
    if (descs[0] && typeof descs[0].value === 'string') return String(descs[0].value);
  }
  return typeof it.details === 'string' ? it.details : '';
}

function resolveCirclCweIds(it: Record<string, unknown>): string[] {
  const cna = ((it.containers as Record<string, unknown> | undefined)?.cna ?? {}) as Record<string, unknown>;
  const out = new Set<string>();
  for (const pt of (cna.problemTypes as Array<Record<string, unknown>>) ?? []) {
    for (const d of (pt.descriptions as Array<Record<string, unknown>>) ?? []) {
      if (typeof d.cweId === 'string') out.add(d.cweId);
    }
  }
  const ds = (it.database_specific as Record<string, unknown> | undefined) ?? {};
  for (const c of (ds.cwe_ids as string[] | undefined) ?? []) {
    if (typeof c === 'string') out.add(c);
  }
  return Array.from(out);
}

export async function fetchNvdByIds(cveIds: string[], apiKey?: string): Promise<Map<string, NvdCve>> {
  const out = new Map<string, NvdCve>();
  const ids = cveIds.slice(0, 15);
  for (const id of ids) {
    try {
      const url = `${NVD_API}?cveId=${encodeURIComponent(id)}`;
      const res = await fetch(url, {
        headers: nvdHeaders(apiKey),
        signal: AbortSignal.timeout(8000),
        cf: { cacheTtlByStatus: { '200-299': 86400, '400-599': 0 }, cacheEverything: true },
      } as RequestInit);
      if (!res.ok) continue;
      const json = (await res.json()) as NvdResponse;
      const cve = json.vulnerabilities?.[0]?.cve;
      if (cve) out.set(id, cve);
    } catch {
      /* noop */
    }
  }
  return out;
}

async function fetchAbuseFeed(
  source: SourceId,
  opts: { startMs?: number; endMs?: number; timeoutMs?: number } = {}
): Promise<IocEntry[]> {
  const { startMs, endMs, timeoutMs = 15_000 } = opts;
  const meta = FEED_SOURCES[source];
  const sep = meta.url.includes('?') ? '&' : '?';
  const url = `${meta.url}${sep}_briefing=${Date.now()}`;
  const res = await fetch(url, {
    headers: { 'user-agent': NVD_UA },
    signal: AbortSignal.timeout(timeoutMs),
    cf: { cacheEverything: false },
  } as RequestInit);
  if (!res.ok) throw new Error(`${source} feed ${res.status}`);
  const body = await res.text();
  // `cap` exists to bound how many entries the parser materialises. We used to
  // pass UNCAPPED and filter to the reporting window afterwards, which meant
  // regex-parsing every row of a 7.6 MB urlhaus CSV (~33k lines) and a 1.6 MB
  // threatfox CSV (~7k) on every build — ~40k entries constructed to keep the
  // ~2k that fall in a 24h window. That is what pushed the daily build past the
  // free-plan 10ms CPU limit.
  //
  // The window is bounded, so cap generously above the expected in-window count
  // (feeds are mostly last-24h already, but ordering is not guaranteed) and let
  // the caller's own `matchTimestamp` filter still run afterwards for safety.
  const cap = startMs !== undefined && endMs !== undefined ? 8_000 : UNCAPPED;
  const summary = buildSummary(source, body, cap);
  return summary.entries;
}

export async function fetchFeedResilient(
  env: Env | undefined,
  source: SourceId,
  window?: { startMs: number; endMs: number }
): Promise<IocEntry[]> {
  const key = `briefing-feed-${source}`;
  try {
    const entries = await fetchAbuseFeed(source, { startMs: window?.startMs, endMs: window?.endMs });
    if (entries.length > 0) {
      if (env) await writeLastGood(env, key, entries, { ttlSeconds: LASTGOOD_TTL_SEC });
      return entries;
    }
    if (env) {
      const hit = await readLastGood<IocEntry[]>(env, key);
      if (hit && hit.length > 0) return hit;
    }
    return entries;
  } catch {
    try {
      if (env) {
        const hit = await readLastGood<IocEntry[]>(env, key);
        if (hit) return hit;
      }
    } catch {
      /* lastgood fallback failed — return empty */
    }
    return [];
  }
}

/* ─── OSSF Malicious Packages ──────────────────────────────────────────── */
// Fetches the package-name listing from the ossf/malicious-packages GitHub
// repo (Contents API). Each ecosystem is a separate directory; we fetch all
// in parallel and flatten. No per-package OSV detail (deferred — analysts
// click through to GitHub). Uses GITHUB_TOKEN if available to bump the
// anonymous 60/hr cap to 5000/hr.

const OSSF_ECOSYSTEMS = ['npm', 'pypi', 'rubygems', 'maven', 'go', 'crates.io'] as const;
const OSSF_GH_BASE = 'https://api.github.com/repos/ossf/malicious-packages';

/**
 * Fetch malicious packages newly disclosed in the OSSF malicious-packages
 * repo within `[since, until)`. Uses the GitHub Commits API on the
 * `osv/malicious` path with `since`/`until`, then fetches each commit's
 * file list to extract the package directories that were *added* in that
 * window.
 *
 * Why commits and not the Contents API: the Contents API returns the full
 * cumulative directory listing with no per-package date, so a daily briefing
 * would surface the entire catalog every day. The Commits API gives us the
 * exact set of packages disclosed in the window.
 *
 * Subrequest budget: 1 commits-list call + N per-commit file-list calls
 * (capped at `MAX_COMMITS`). Worst case ~1 + 5 = 6 subrequests, keeping
 * the daily build's total fan-out safely under the free-plan 50 cap.
 */
const MAX_COMMITS = 5;

export async function fetchMaliciousPackages(
  env?: Env,
  window?: { since: Date; until: Date }
): Promise<MaliciousPackageEntry[]> {
  const ghToken = env?.GITHUB_TOKEN;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'pranithjain-briefing/1.0',
  };
  if (ghToken) headers.Authorization = `Bearer ${ghToken}`;

  // No window → return empty (the cumulative catalog is not useful in a
  // time-boxed briefing; callers that want the full catalog use the depx
  // feed / threat-intel vertical instead).
  if (!window) return [];

  const sinceIso = window.since.toISOString();
  const untilIso = window.until.toISOString();
  const commitsUrl =
    `${OSSF_GH_BASE}/commits?path=osv/malicious&since=${encodeURIComponent(sinceIso)}` +
    `&until=${encodeURIComponent(untilIso)}&per_page=${MAX_COMMITS}`;

  let commits: Array<{ sha: string; commit?: { author?: { date?: string } } }> = [];
  try {
    const res = await fetchResilient(commitsUrl, { headers }, { attempts: 2, timeoutMs: 10_000 });
    if (!res.ok) return [];
    commits = (await res.json()) as typeof commits;
    if (!Array.isArray(commits)) return [];
  } catch {
    return [];
  }
  if (commits.length === 0) return [];

  // Fetch each commit's file list in parallel to extract added package dirs.
  // Path shape: osv/malicious/<ecosystem>/<package>/MAL-*.json
  const ecoSet = new Set(OSSF_ECOSYSTEMS);
  const seen = new Set<string>();
  const out: MaliciousPackageEntry[] = [];
  const fileResults = await Promise.allSettled(
    commits.map((c) => {
      // Defense in depth: c.sha comes from the GitHub API response, but
      // validate it's a hex SHA before interpolating into the URL so a
      // compromised upstream can't inject path traversal / query params.
      if (!/^[0-9a-f]{7,40}$/i.test(c.sha))
        return Promise.resolve({
          sha: c.sha,
          date: c.commit?.author?.date ?? '',
          files: [] as Array<{ filename: string; status: string }>,
        });
      return fetchResilient(`${OSSF_GH_BASE}/commits/${c.sha}`, { headers }, { attempts: 2, timeoutMs: 10_000 }).then(
        async (r) => {
          if (!r.ok)
            return {
              sha: c.sha,
              date: c.commit?.author?.date ?? '',
              files: [] as Array<{ filename: string; status: string }>,
            };
          const body = (await r.json()) as { files?: Array<{ filename: string; status: string }> };
          return { sha: c.sha, date: c.commit?.author?.date ?? '', files: body.files ?? [] };
        }
      );
    })
  );
  for (const r of fileResults) {
    if (r.status !== 'fulfilled') continue;
    const { date, files } = r.value;
    for (const f of files) {
      const parts = f.filename.split('/');
      // osv/malicious/<eco>/<pkg>/MAL-*.json  →  parts[2]=eco, parts[3]=pkg
      if (parts.length < 5 || parts[0] !== 'osv' || parts[1] !== 'malicious') continue;
      const eco = parts[2];
      const pkg = parts[3];
      if (!eco || !ecoSet.has(eco as (typeof OSSF_ECOSYSTEMS)[number]) || !pkg || pkg.startsWith('.')) continue;
      const key = `${eco}|${pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        name: pkg,
        ecosystem: eco,
        ossf_url: `https://github.com/ossf/malicious-packages/tree/main/osv/malicious/${encodeURIComponent(eco)}/${encodeURIComponent(pkg)}`,
        publishedAt: date || undefined,
      });
    }
  }
  return out;
}

/* ─── Daily-Hunt IOC families (via threat-intel manifest) ──────────────── */
// Daily-Hunt IOC families are replicated into public/data/threat-intel/ by
// the weekly sync (scripts/sync-threat-intel.mjs → build-threat-intel.mjs).
// We read the slim index via env.ASSETS — no public internet hop, no
// subrequest budget cost (ASSETS is a binding, not a fetch).

export type { DbugsVuln } from '../dbugs';

/**
 * dbu.gs rows for the briefing window.
 *
 * Re-exported through this module so the briefing's source adapters all live
 * behind one import surface (and one last-good namespace) rather than build.ts
 * reaching into three different libs. Returns `{ vulns, ok }` — a dead
 * upstream yields an empty list so the builder degrades instead of failing.
 */
export async function fetchDbugsRecent(): Promise<{ vulns: DbugsVuln[]; ok: boolean }> {
  const r = await fetchDbugsSource().catch(() => ({ vulns: [] as DbugsVuln[], ok: false }));
  return r;
}

export async function fetchDailyHuntIocFamilies(
  env?: Env,
  window?: { since: Date; until: Date }
): Promise<DailyHuntIocFamily[]> {
  if (!env?.ASSETS) return [];
  try {
    const { loadTiIndex } = await import('../threat-intel-manifest');
    const idx = await loadTiIndex(env.ASSETS);
    const all = idx.iocIndex ?? [];
    if (!window) return all;
    // Daily-Hunt families are a cumulative knowledge base. For a time-boxed
    // briefing, keep only families whose `firstSeen` (the earliest date
    // parsed from the upstream markdown) falls inside the window. Families
    // with no parseable firstSeen are reference material, not daily intel,
    // and are excluded from daily/weekly briefings.
    const startMs = window.since.getTime();
    const endMs = window.until.getTime();
    return all.filter((f) => {
      if (!f.firstSeen) return false;
      const t = Date.parse(f.firstSeen);
      if (Number.isNaN(t)) return false;
      return t >= startMs && t < endMs;
    });
  } catch {
    return [];
  }
}
