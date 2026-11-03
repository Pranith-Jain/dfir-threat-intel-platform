/**
 * AI Security hub manifest loader — matrix tools + incident reports +
 * escape parity + vulns + advisories + research.
 *
 * Reads the static JSON manifest shipped in /public/data/ai-security/ (built by
 * scripts/build-ai-security.mjs from threat-intel-staging/ai-security/).
 * Served through env.ASSETS — no per-request upstream, no secrets.
 *
 * Shape:
 *   /data/ai-security/index.json              (hub meta + counts)
 *   /data/ai-security/escape-parity.json      (two-way parity report)
 *   /data/ai-security/matrix/index.json       (slim tool rows + byCategory)
 *   /data/ai-security/matrix/tools/<repo>.json (full tool bodies)
 *   /data/ai-security/incidents/index.json    (slim report rows)
 *   /data/ai-security/incidents/bodies.json   (all report bodies, bundled)
 *   /data/ai-security/vulns/index.json        (slim vuln rows, KEV first)
 *   /data/ai-security/vulns/bodies.json       (all vuln bodies, bundled)
 *   /data/ai-security/advisories/index.json   (advisory firehose rows)
 *   /data/ai-security/research/index.json     (research rows)
 */

import { classifyCveStack, CVE_STACK_FACETS } from './cve-stack.mjs';

export interface AiSecurityHubIndex {
  hub: string;
  builtAt: string;
  sources: Record<string, string>;
  counts: {
    matrixTools: number;
    matrixCategories: number;
    incidentReports: number;
    escapeDrift: boolean | null;
    vulns?: number;
    vulnKev?: number;
    advisories?: number;
    research?: number;
  };
  matrixByCategory: Record<string, number>;
  advisoryBySource?: Record<string, number>;
  researchBySource?: Record<string, number>;
  latestIncidentAt: string | null;
  latestMatrixCheck: string | null;
  latestAdvisoryAt?: string | null;
  latestResearchAt?: string | null;
}

export interface MatrixTool {
  slug: string;
  repo: string;
  category: string;
  scope: string[];
  stars: number;
  description: string;
  homepage: string | null;
  added: string | null;
  checkedAt: string | null;
  pushedAt: string | null;
  daysIdle: number | null;
  archived: boolean;
  license: string | null;
}

export interface MatrixIndex {
  updatedAt: string;
  total: number;
  byCategory: Record<string, number>;
  tools: MatrixTool[];
}

export interface IncidentReport {
  id: string;
  guid: string;
  title: string;
  link: string;
  pubDate: string | null;
  citeId: string | null;
  reportNum: string | null;
}

export interface IncidentsIndex {
  updatedAt: string;
  source: string;
  total: number;
  reports: IncidentReport[];
}

export interface EscapeParity {
  checkedAt: string;
  builtAt?: string;
  upstream: { registryEntries: number; queuePending: number; embeddedIds: number; ids: string[] };
  local: { entries: number; version: string | null; compiled: string | null };
  drift: boolean;
  onlyUpstream: string[];
  onlyLocal: string[];
  note: string;
}

const DATA_PREFIX = '/data/ai-security';
const MAX_BODY_CACHE = 100;

let cachedHub: AiSecurityHubIndex | null = null;
let cachedMatrix: MatrixIndex | null = null;
let cachedIncidents: IncidentsIndex | null = null;
let cachedBodies: Record<string, IncidentReport & { description: string }> | null = null;
let cachedParity: EscapeParity | null = null;
const toolCache = new Map<string, MatrixTool & { upstream?: unknown }>();

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://ai-security.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

export async function loadAiSecurityHub(assets: Fetcher): Promise<AiSecurityHubIndex> {
  if (cachedHub) return cachedHub;
  const idx = await fetchJson<AiSecurityHubIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx)
    throw new Error(
      `AI Security index not found at ${DATA_PREFIX}/index.json — run 'node scripts/build-ai-security.mjs' first.`
    );
  cachedHub = idx;
  return idx;
}

export async function loadMatrixIndex(assets: Fetcher): Promise<MatrixIndex> {
  if (cachedMatrix) return cachedMatrix;
  const idx = await fetchJson<MatrixIndex>(assets, `${DATA_PREFIX}/matrix/index.json`);
  if (!idx) throw new Error(`Matrix index not found at ${DATA_PREFIX}/matrix/index.json.`);
  cachedMatrix = idx;
  return idx;
}

export async function getMatrixTool(
  assets: Fetcher,
  slug: string
): Promise<(MatrixTool & { upstream?: unknown }) | null> {
  const hit = toolCache.get(slug);
  if (hit) return hit;
  const body = await fetchJson<MatrixTool & { upstream?: unknown }>(assets, `${DATA_PREFIX}/matrix/tools/${slug}.json`);
  if (!body) return null;
  toolCache.set(slug, body);
  while (toolCache.size > MAX_BODY_CACHE) {
    const oldest = toolCache.keys().next().value;
    if (oldest === undefined) break;
    toolCache.delete(oldest);
  }
  return body;
}

export function filterMatrixTools(
  idx: MatrixIndex,
  opts: { category?: string; q?: string; minStars?: number; limit?: number } = {}
): MatrixTool[] {
  const { category, q, minStars, limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const out: MatrixTool[] = [];
  for (const t of idx.tools) {
    if (category && category !== 'all' && t.category !== category) continue;
    if (minStars !== undefined && t.stars < minStars) continue;
    if (needle && !`${t.repo} ${t.description} ${(t.scope ?? []).join(' ')}`.toLowerCase().includes(needle)) continue;
    out.push(t);
    if (out.length >= limit) break;
  }
  return out;
}

export async function loadIncidentsIndex(assets: Fetcher): Promise<IncidentsIndex> {
  if (cachedIncidents) return cachedIncidents;
  const idx = await fetchJson<IncidentsIndex>(assets, `${DATA_PREFIX}/incidents/index.json`);
  if (!idx) throw new Error(`Incidents index not found at ${DATA_PREFIX}/incidents/index.json.`);
  cachedIncidents = idx;
  return idx;
}

export async function getIncidentReport(
  assets: Fetcher,
  id: string
): Promise<(IncidentReport & { description: string }) | null> {
  if (!cachedBodies) {
    const all = await fetchJson<Record<string, IncidentReport & { description: string }>>(
      assets,
      `${DATA_PREFIX}/incidents/bodies.json`
    );
    if (!all) return null;
    cachedBodies = all;
  }
  return cachedBodies[id] ?? null;
}

export function filterIncidentReports(
  idx: IncidentsIndex,
  opts: { q?: string; citeId?: string; limit?: number } = {}
): IncidentReport[] {
  const { q, citeId, limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const out: IncidentReport[] = [];
  for (const r of idx.reports) {
    if (citeId && r.citeId !== citeId) continue;
    if (needle && !`${r.title} ${r.id} ${r.citeId ?? ''}`.toLowerCase().includes(needle)) continue;
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export async function loadEscapeParity(assets: Fetcher): Promise<EscapeParity | null> {
  if (cachedParity) return cachedParity;
  const doc = await fetchJson<EscapeParity>(assets, `${DATA_PREFIX}/escape-parity.json`);
  cachedParity = doc;
  return doc;
}

export interface AiVuln {
  id: string;
  title: string;
  sources: string[];
  severity: string | null;
  cvssBase: number | null;
  epss: number | null;
  kev: boolean;
  kevSources: string[];
  published: string | null;
  link: string;
  aliases: string[];
  packages: string[];
  vendor: string | null;
  product: string | null;
  /** AI / agent stack facets classified at load time (canonical order). */
  stack?: string[];
}

export interface AiStackFacet {
  id: string;
  label: string;
  description: string;
  count: number;
}

export interface VulnsIndex {
  updatedAt: string;
  total: number;
  kev: number;
  vulns: AiVuln[];
  /** Facet counts over the full index; computed once at load. */
  stackFacets?: AiStackFacet[];
  byStack?: Record<string, number>;
}

export interface AdvisoryItem {
  id: string;
  title: string;
  link: string;
  updated: string | null;
  source: string;
  kind: string;
  cves: string[];
  description: string;
}

export interface AdvisoriesIndex {
  updatedAt: string;
  total: number;
  bySource: Record<string, number>;
  items: AdvisoryItem[];
}

export interface ResearchItem {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  source: string;
  description: string;
}

export interface ResearchIndex {
  updatedAt: string;
  total: number;
  bySource: Record<string, number>;
  items: ResearchItem[];
}

let cachedVulns: VulnsIndex | null = null;
let cachedVulnBodies: Record<
  string,
  AiVuln & {
    description: string;
    references: string[];
    euvdId: string | null;
    kevDateAdded: string | null;
    epssPercentile: number | null;
  }
> | null = null;
let cachedAdvisories: AdvisoriesIndex | null = null;
let cachedResearch: ResearchIndex | null = null;

export async function loadVulnsIndex(assets: Fetcher): Promise<VulnsIndex> {
  if (cachedVulns) return cachedVulns;
  const idx = await fetchJson<VulnsIndex>(assets, `${DATA_PREFIX}/vulns/index.json`);
  if (!idx) throw new Error(`Vulns index not found at ${DATA_PREFIX}/vulns/index.json.`);
  // The source index predates the stack facet. Classify once here (the index
  // is cached for the isolate lifetime) so the JSON manifest stays unchanged
  // and the counts cover all rows, not just the page the UI requested.
  const byStack: Record<string, number> = {};
  for (const v of idx.vulns) {
    v.stack = classifyCveStack(v);
    for (const facet of v.stack) byStack[facet] = (byStack[facet] ?? 0) + 1;
  }
  idx.byStack = byStack;
  idx.stackFacets = CVE_STACK_FACETS.map((facet) => ({ ...facet, count: byStack[facet.id] ?? 0 }));
  cachedVulns = idx;
  return idx;
}

export async function getVuln(
  assets: Fetcher,
  id: string
): Promise<
  | (AiVuln & {
      description: string;
      references: string[];
      euvdId: string | null;
      kevDateAdded: string | null;
      epssPercentile: number | null;
    })
  | null
> {
  if (!cachedVulnBodies) {
    const all = await fetchJson<
      Record<
        string,
        AiVuln & {
          description: string;
          references: string[];
          euvdId: string | null;
          kevDateAdded: string | null;
          epssPercentile: number | null;
        }
      >
    >(assets, `${DATA_PREFIX}/vulns/bodies.json`);
    if (!all) return null;
    cachedVulnBodies = all;
  }
  const body = cachedVulnBodies[id] ?? null;
  if (body) body.stack = classifyCveStack(body);
  return body;
}

export function filterVulns(
  idx: VulnsIndex,
  opts: {
    q?: string;
    kevOnly?: boolean;
    minEpss?: number;
    source?: string;
    stack?: string;
    limit?: number;
  } = {}
): AiVuln[] {
  const { q, kevOnly, minEpss, source, stack, limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const stackNeedle = stack?.toLowerCase();
  const out: AiVuln[] = [];
  for (const v of idx.vulns) {
    if (kevOnly && !v.kev) continue;
    if (minEpss !== undefined && (v.epss ?? -1) < minEpss) continue;
    if (source && source !== 'all' && !v.sources.includes(source)) continue;
    if (stackNeedle && !(v.stack ?? []).some((s) => s.toLowerCase() === stackNeedle)) continue;
    if (
      needle &&
      !`${v.id} ${v.title} ${(v.aliases ?? []).join(' ')} ${(v.packages ?? []).join(' ')} ${v.vendor ?? ''} ${v.product ?? ''}`
        .toLowerCase()
        .includes(needle)
    )
      continue;
    out.push(v);
    if (out.length >= limit) break;
  }
  return out;
}

export async function loadAdvisoriesIndex(assets: Fetcher): Promise<AdvisoriesIndex> {
  if (cachedAdvisories) return cachedAdvisories;
  const idx = await fetchJson<AdvisoriesIndex>(assets, `${DATA_PREFIX}/advisories/index.json`);
  if (!idx) throw new Error(`Advisories index not found at ${DATA_PREFIX}/advisories/index.json.`);
  cachedAdvisories = idx;
  return idx;
}

export function filterAdvisories(
  idx: AdvisoriesIndex,
  opts: { q?: string; source?: string; kind?: string; limit?: number } = {}
): AdvisoryItem[] {
  const { q, source, kind, limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const out: AdvisoryItem[] = [];
  for (const it of idx.items) {
    if (source && source !== 'all' && it.source !== source) continue;
    if (kind && kind !== 'all' && it.kind !== kind) continue;
    if (needle && !`${it.title} ${it.source} ${(it.cves ?? []).join(' ')}`.toLowerCase().includes(needle)) continue;
    out.push(it);
    if (out.length >= limit) break;
  }
  return out;
}

export async function loadResearchIndex(assets: Fetcher): Promise<ResearchIndex> {
  if (cachedResearch) return cachedResearch;
  const idx = await fetchJson<ResearchIndex>(assets, `${DATA_PREFIX}/research/index.json`);
  if (!idx) throw new Error(`Research index not found at ${DATA_PREFIX}/research/index.json.`);
  cachedResearch = idx;
  return idx;
}

export function filterResearch(
  idx: ResearchIndex,
  opts: { q?: string; source?: string; limit?: number } = {}
): ResearchItem[] {
  const { q, source, limit = 100 } = opts;
  const needle = q?.toLowerCase().trim();
  const out: ResearchItem[] = [];
  for (const it of idx.items) {
    if (source && source !== 'all' && it.source !== source) continue;
    if (needle && !`${it.title} ${it.source}`.toLowerCase().includes(needle)) continue;
    out.push(it);
    if (out.length >= limit) break;
  }
  return out;
}

export function _resetAiSecurityCacheForTests(): void {
  cachedHub = null;
  cachedMatrix = null;
  cachedIncidents = null;
  cachedBodies = null;
  cachedParity = null;
  cachedVulns = null;
  cachedVulnBodies = null;
  cachedAdvisories = null;
  cachedResearch = null;
  toolCache.clear();
}
