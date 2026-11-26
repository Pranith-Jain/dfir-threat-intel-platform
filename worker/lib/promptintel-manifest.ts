/**
 * PromptIntel IoPC taxonomy manifest — Indicators of Prompt Compromise.
 *
 * Edge loader for the mirrored public taxonomy of
 * promptintel.securitybreak.io (SecurityBreak). IoPC is an open, versioned
 * classification of how AI systems and agents are attacked: 9 domains, 35
 * techniques, each mapped to OWASP LLM, OWASP Agentic, MITRE ATLAS, Google
 * SAIF, CSA AARM and NIST AI RMF.
 *
 * Data source: public/data/promptintel/ (built by scripts/sync-promptintel.mjs),
 * read through env.ASSETS — no D1, no KV, no public fetch. The mirror holds
 * identifiers, names, one-sentence descriptions, maturity/review dates and the
 * framework mapping rows only: prompt attack text, agent-threat analyses and
 * NOVA rules stay behind the keyed PromptIntel API.
 *
 * The taxonomy answers the question the live API would answer for these two
 * endpoints (`/taxonomy`, `/taxonomy/entries/{id}`) without spending the
 * account's 100-requests-a-day Community quota, so those routes serve the
 * mirror first and only fall back to upstream when a key is configured and the
 * caller asks for live data.
 */

export type PromptIntelMaturity = 'active' | 'experimental' | 'deprecated' | 'unknown';

export interface PromptIntelFramework {
  name: string;
  version: string | null;
  url: string | null;
}

export interface PromptIntelMapping {
  framework: string;
  ref: string;
  name: string;
  relationship: string;
}

/** One flat row of the index-level mapping table (`entry` → `framework:ref`). */
export interface PromptIntelMappingRow {
  entry: string;
  name: string;
  domain: string;
  framework: string;
  ref: string;
  item: string;
  relationship: string;
}

export interface PromptIntelDomain {
  id: string;
  name: string;
  description: string;
  techniques: string[];
}

export interface PromptIntelEntrySlim {
  id: string;
  name: string;
  domain: string;
  domainName: string;
  summary: string;
  url: string;
  maturity: string;
  evidence: string | null;
  reviewed: string | null;
  frameworks: string[];
  mappingCount: number;
}

export interface PromptIntelEntryBody {
  id: string;
  name: string;
  domain?: string;
  domainName?: string;
  description: string;
  differs: string;
  maturity: string;
  evidence: string | null;
  reviewed: string | null;
  statusLine: string;
  mappings: PromptIntelMapping[];
  url: string;
}

export interface PromptIntelIndex {
  source: string;
  sourceUrl: string;
  license: string;
  syncedAt: string;
  taxonomyVersion: string;
  counts: { domains: number; techniques: number; frameworks: number; mappings: number };
  frameworks: PromptIntelFramework[];
  domains: PromptIntelDomain[];
  entries: PromptIntelEntrySlim[];
  /** Flat `entry → framework:ref` table (308 rows for IoPC 2.2.0). */
  mappings: PromptIntelMappingRow[];
}

const DATA_PREFIX = '/data/promptintel';
const BODY_CACHE_MAX = 64;

let cachedIndex: PromptIntelIndex | null = null;
let cachedIndexAt: number | null = null;
const bodyCache = new Map<string, PromptIntelEntryBody>();
let bodyHits = 0;
let bodyMisses = 0;

async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  const res = await assets.fetch(new Request(`https://promptintel.local${path}`));
  if (!res.ok) return null;
  return (await res.json()) as T;
}

export async function loadPromptIntelIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<PromptIntelIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<PromptIntelIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `PromptIntel taxonomy not found at ${DATA_PREFIX}/index.json — run 'node scripts/sync-promptintel.mjs' first.`
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

function bodyGet(key: string): PromptIntelEntryBody | null {
  const v = bodyCache.get(key);
  if (v === undefined) {
    bodyMisses++;
    return null;
  }
  bodyHits++;
  bodyCache.delete(key);
  bodyCache.set(key, v);
  return v;
}

function bodySet(key: string, value: PromptIntelEntryBody): void {
  if (bodyCache.has(key)) bodyCache.delete(key);
  bodyCache.set(key, value);
  while (bodyCache.size > BODY_CACHE_MAX) {
    const oldest = bodyCache.keys().next();
    if (oldest.done) break;
    bodyCache.delete(oldest.value);
  }
}

/** Only a canonical IoPC id ever reaches the ASSETS path. */
export function normalizeIopcId(raw: string): string | null {
  const id = String(raw ?? '')
    .trim()
    .toUpperCase();
  // Techniques are `IOPC-T<domain>.<nnn>`; registry entries are `IOPC-R<nnn>`.
  return /^IOPC-(?:T\d{1,2}\.\d{3}|R\d{3})$/.test(id) ? id : null;
}

export async function getPromptIntelEntry(assets: Fetcher, rawId: string): Promise<PromptIntelEntryBody | null> {
  const id = normalizeIopcId(rawId);
  if (!id) return null;
  const cached = bodyGet(id);
  if (cached) return cached;
  const body = await fetchJson<PromptIntelEntryBody>(assets, `${DATA_PREFIX}/entries/${id}.json`);
  if (!body) return null;
  bodySet(id, body);
  return body;
}

export interface PromptIntelFilterOptions {
  domain?: string;
  framework?: string;
  maturity?: string;
  keyword?: string;
  limit?: number;
}

/** Filter slim rows by domain, mapped framework, maturity or free text. */
export function filterPromptIntelEntries(
  rows: PromptIntelEntrySlim[],
  opts: PromptIntelFilterOptions = {}
): PromptIntelEntrySlim[] {
  const { domain, framework, maturity, keyword, limit = 100 } = opts;
  const dom = domain?.toUpperCase();
  const needle = keyword?.toLowerCase();
  const out: PromptIntelEntrySlim[] = [];
  for (const r of rows) {
    if (dom && r.domain.toUpperCase() !== dom) continue;
    if (maturity && r.maturity.toLowerCase() !== maturity.toLowerCase()) continue;
    if (framework && !r.frameworks.some((f) => f.toLowerCase() === framework.toLowerCase())) continue;
    if (needle) {
      const hay = `${r.id} ${r.name} ${r.summary} ${r.domainName} ${r.frameworks.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(r);
    if (out.length >= limit) break;
  }
  return out;
}

export interface PromptIntelTranslation {
  framework: string;
  ref: string;
  item: string;
  entries: Array<{ id: string; name: string; domain: string; relationship: string }>;
}

/** Framework-name match that tolerates case, aliases and "(AARM)"-style suffixes. */
const FRAMEWORK_ALIASES: Record<string, string> = {
  owasp_llm: 'owasp top 10 for llm applications',
  'owasp llm': 'owasp top 10 for llm applications',
  owasp_llm_top_10: 'owasp top 10 for llm applications',
  owasp_agentic: 'owasp top 10 for agentic applications',
  'owasp agentic': 'owasp top 10 for agentic applications',
  mitre_atlas: 'mitre atlas',
  atlas: 'mitre atlas',
  saif: 'google secure ai framework (saif)',
  google_saif: 'google secure ai framework (saif)',
  aarm: 'csa autonomous action runtime management (aarm)',
  csa_aarm: 'csa autonomous action runtime management (aarm)',
  nist_ai_rmf: 'nist ai risk management framework (ai rmf)',
  nist_rmf: 'nist ai risk management framework (ai rmf)',
  'nist ai rmf': 'nist ai risk management framework (ai rmf)',
};

export function canonicalFrameworkName(value: string): string {
  const key = value
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, ' ');
  return FRAMEWORK_ALIASES[key] ?? FRAMEWORK_ALIASES[key.replace(/ /g, '_')] ?? key;
}

function sameFramework(a: string, b: string): boolean {
  return canonicalFrameworkName(a) === canonicalFrameworkName(b);
}

/** Filter the flat mapping table (framework / ref / relationship / entry). */
export function filterPromptIntelMappings(
  index: PromptIntelIndex,
  opts: { framework?: string; ref?: string; relationship?: string; entry?: string; limit?: number } = {}
): PromptIntelMappingRow[] {
  const { framework, ref, relationship, entry, limit = 200 } = opts;
  const out: PromptIntelMappingRow[] = [];
  for (const row of index.mappings ?? []) {
    if (framework && !sameFramework(row.framework, framework)) continue;
    if (ref && row.ref.trim().toLowerCase() !== ref.trim().toLowerCase()) continue;
    if (relationship && row.relationship.toLowerCase() !== relationship.toLowerCase()) continue;
    if (entry && row.entry.toUpperCase() !== entry.toUpperCase()) continue;
    out.push(row);
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * Invert the mapping table: "which IoPC techniques does OWASP LLM01 map to?".
 * Answers from the index alone — no per-technique asset reads.
 */
export function translateFrameworkRef(
  index: PromptIntelIndex,
  framework: string,
  ref: string
): PromptIntelTranslation | null {
  if (!framework?.trim() || !ref?.trim()) return null;
  const rows = filterPromptIntelMappings(index, { framework, ref, limit: 200 });
  if (!rows.length) return null;
  return {
    framework: rows[0]!.framework,
    ref: rows[0]!.ref,
    item: rows[0]!.item,
    entries: rows.map((r) => ({ id: r.entry, name: r.name, domain: r.domain, relationship: r.relationship })),
  };
}

export interface PromptIntelFrameworkMatch {
  framework: string;
  ref: string;
  item: string;
  relationship: string;
  /** IoPC techniques both items map to — the reason the link exists. */
  via: string[];
  /** `threat` for attack techniques, `control` for defensive controls. */
  kind: 'threat' | 'control';
}

/**
 * Cross-framework translation: "OWASP LLM01 is which ATLAS technique?".
 *
 * There is no direct framework↔framework table upstream, so the link is
 * derived the way PromptIntel documents it (`via`): both items map to the same
 * IoPC technique. Two hops over the flat index, no per-entry reads.
 *
 * `to` narrows the answer to one framework. Matches are ordered by how many
 * techniques corroborate them, then by relationship strength.
 */
export function translateAcrossFrameworks(
  index: PromptIntelIndex,
  framework: string,
  ref: string,
  to?: string
): { source: { framework: string; ref: string; item: string } | null; matches: PromptIntelFrameworkMatch[] } {
  const seed = translateFrameworkRef(index, framework, ref);
  if (!seed) return { source: null, matches: [] };
  const entryIds = new Set(seed.entries.map((e) => e.id));
  const grouped = new Map<string, PromptIntelFrameworkMatch>();
  for (const row of index.mappings ?? []) {
    if (!entryIds.has(row.entry)) continue;
    // Skip the source item itself.
    if (
      sameFramework(row.framework, seed.framework) &&
      row.ref.trim().toLowerCase() === seed.ref.trim().toLowerCase()
    ) {
      continue;
    }
    if (to && !sameFramework(row.framework, to)) continue;
    const key = `${row.framework}\u0000${row.ref}`;
    const existing = grouped.get(key);
    if (existing) {
      if (!existing.via.includes(row.entry)) existing.via.push(row.entry);
      continue;
    }
    grouped.set(key, {
      framework: row.framework,
      ref: row.ref,
      item: row.item,
      relationship: row.relationship,
      via: [row.entry],
      kind: /^(control|risk):/i.test(row.ref) ? 'control' : 'threat',
    });
  }
  const strength: Record<string, number> = {
    equivalent: 5,
    related: 4,
    narrower_than: 3,
    broader_than: 2,
    control_relevant: 1,
    evidence_supports: 0,
  };
  const matches = [...grouped.values()].sort(
    (a, b) =>
      b.via.length - a.via.length ||
      (strength[b.relationship] ?? 0) - (strength[a.relationship] ?? 0) ||
      a.framework.localeCompare(b.framework)
  );
  return {
    source: { framework: seed.framework, ref: seed.ref, item: seed.item },
    matches,
  };
}

/** Framework names present in the mirror, deduped, with their upstream version. */
export function promptIntelFrameworkNames(index: PromptIntelIndex): string[] {
  return index.frameworks.map((f) => f.name);
}

export function promptIntelCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  bodies: number;
  bodyHits: number;
  bodyMisses: number;
  taxonomyVersion: string | null;
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    bodies: bodyCache.size,
    bodyHits,
    bodyMisses,
    taxonomyVersion: cachedIndex?.taxonomyVersion ?? null,
  };
}

export function _resetPromptIntelCacheForTests(): void {
  cachedIndex = null;
  cachedIndexAt = null;
  bodyCache.clear();
  bodyHits = 0;
  bodyMisses = 0;
}
