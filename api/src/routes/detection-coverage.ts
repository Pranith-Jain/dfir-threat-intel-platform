/**
 * CVE -> detection coverage.
 *
 * "This CVE is known-exploited" is the first half of the job. The second half is
 * knowing whether the SIEM you actually run has a published rule for it, because
 * a KEV entry you cannot detect is a KEV entry you find out about from an
 * incident report rather than from an alert.
 *
 * This route joins two things we already had and had never joined:
 *   - the exploitation side (CISA KEV, EPSS, CVSS) fetched live
 *   - the rule side, built by scripts/build-detection-coverage.mjs into
 *     public/data/detection-coverage/
 *
 * Endpoints:
 *   GET /api/v1/detection-coverage            summary + gap list
 *   GET /api/v1/detection-coverage/cve/:id    per-CVE detection detail
 *   GET /api/v1/detection-coverage/library    rules by ATT&CK technique
 *
 * A caveat worth stating plainly, because the numbers invite the opposite
 * conclusion: a "gap" here means no PUBLISHED rule in the corpora we index
 * exists for that CVE. It does not mean the product is undetectable. Plenty of
 * vendors ship coverage in private content, and behavioural detections cover
 * whole classes rather than one CVE. The UI says so too.
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { normaliseCveId } from '../lib/cve-id';
import { enrichEpssBulk } from '../lib/cve-enrich';
import { loadCvssMap } from './cisa-kev';
import { findUnknownParams, unknownParamHeaders } from '../lib/filter-catalog';
import { shodanCveDb } from '../lib/shodan-cvedb';

const ASSET_HOST = 'https://detection-coverage.local';
const DATA_PREFIX = '/data/detection-coverage';

/** Re-exported so /api/v1/feed-status can probe this feed like any other. */
export const DETECTION_COVERAGE_CACHE_KEY = 'https://detection-coverage-cache.internal/v1-mcq';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEV_TIMEOUT_MS = 15_000;

// ── build-artifact types ─────────────────────────────────────────────

interface CoverageRule {
  rid: string;
  source: string;
  title: string;
  url: string | null;
  level: string | null;
  techniques: string[];
  cves: string[];
  updated: string | null;
  products?: string[];
  author?: string | null;
}

interface CoverageIndex {
  schemaVersion: string;
  generatedAt: string;
  rules: number;
  detections: number;
  exploits: number;
  distinctCves: number;
  perSource: Record<string, number>;
  /** Share of the detection corpus that cites a CVE at all. Low, by design of upstream. */
  detectionCveLinkRate: number;
  detectionRulesCveTagged: number;
  detectionRulesTotal: number;
  techniques: number;
  kevJoined: number;
  kevWithExplicitDetection: number;
  kevWithProductInference: number;
  sources: Array<{
    id: string;
    label: string;
    kind: 'detection' | 'exploit';
    format: string;
    homepage: string;
    license: string;
    licenseUrl: string;
    attribution: string;
    accessUrl: string;
    ruleCount: number;
    scanned: number;
    status: string;
    error?: string;
  }>;
}

/**
 * One KEV row's coverage.
 *
 * `d` (explicit, a rule cites the CVE) and `p` (inferred, a rule names the
 * product) are kept apart because they are not equally strong. Collapsing them
 * into one "covered" boolean is what made the first version of this page
 * misleading in the opposite direction: 4% of detection rules cite any CVE, so
 * an explicit-only number describes a tagging convention rather than coverage.
 */
interface KevCoverageRow {
  d: string[];
  p: string[];
  /** Total product matches before the build-time cap, so the UI can be honest about truncation. */
  pTotal: number;
  e: string[];
}

// ── asset loading ────────────────────────────────────────────────────

/**
 * Isolate-level caches for the built artifacts.
 *
 * These files are immutable for the life of a deployment (they only change on
 * a build), so there is no TTL to honour and no invalidation story: whatever
 * the deploy shipped is what this isolate serves until it is recycled.
 *
 * Detection rules are sharded by source and exploit rules 16 ways by rule id,
 * so a request loads only the shards it needs. That is what keeps a per-CVE
 * detail lookup at ~600 KB of parse rather than the ~20 MB of the full
 * combined corpus.
 */
let indexPromise: Promise<CoverageIndex | null> | null = null;
let kevCoveragePromise: Promise<Record<string, KevCoverageRow> | null> | null = null;
let techniqueIndexPromise: Promise<Record<string, string[]> | null> | null = null;
let epssHistoryPromise: Promise<Record<string, EpssPoint[]> | null> | null = null;
let historyPromise: Promise<CoverageHistory | null> | null = null;

interface CoverageHistory {
  schemaVersion: string;
  generatedAt: string;
  points: Array<{
    date: string;
    detections: number;
    exploits: number;
    techniques: number;
    cveTagged: number;
    perSource: Record<string, number>;
  }>;
}

const detectionShardPromises = new Map<string, Promise<Map<string, CoverageRule>>>();
const exploitShardPromises = new Map<number, Promise<Map<string, CoverageRule>>>();

/** Must stay in lockstep with SHARD_COUNT / fnv1a in the build script. */
const EXPLOIT_SHARDS = 16;

/** FNV-1a 32-bit. */
function fnv1a(str: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function assetsOf(env: Env): Fetcher {
  if (!env.ASSETS) {
    throw new Error('ASSETS binding missing — cannot read detection-coverage artifacts');
  }
  return env.ASSETS;
}

async function fetchJson<T>(env: Env, file: string): Promise<T | null> {
  try {
    const res = await assetsOf(env).fetch(new Request(`${ASSET_HOST}${DATA_PREFIX}/${file}`));
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

function loadIndex(env: Env): Promise<CoverageIndex | null> {
  indexPromise ??= fetchJson<CoverageIndex>(env, 'index.json');
  return indexPromise;
}

function loadKevCoverage(env: Env): Promise<Record<string, KevCoverageRow> | null> {
  kevCoveragePromise ??= fetchJson<Record<string, KevCoverageRow>>(env, 'kev-coverage.json');
  return kevCoveragePromise;
}

function loadTechniqueIndex(env: Env): Promise<Record<string, string[]> | null> {
  techniqueIndexPromise ??= fetchJson<Record<string, string[]>>(env, 'technique-index.json');
  return techniqueIndexPromise;
}

function loadEpssHistory(env: Env): Promise<Record<string, EpssPoint[]> | null> {
  epssHistoryPromise ??= fetchJson<Record<string, EpssPoint[]>>(env, 'epss-history.json');
  return epssHistoryPromise;
}

function loadHistory(env: Env): Promise<CoverageHistory | null> {
  historyPromise ??= fetchJson<CoverageHistory>(env, 'history.json');
  return historyPromise;
}

/**
 * Detection rules for one source, by id.
 *
 * Sharded by source rather than by hash because every consumer of this data
 * thinks in terms of "the Sigma rules", so a source filter is the common case
 * and this is the split that lets a request load one file.
 */
function loadDetectionShard(env: Env, source: string): Promise<Map<string, CoverageRule>> {
  let p = detectionShardPromises.get(source);
  if (!p) {
    p = fetchJson<CoverageRule[]>(env, `detections/${source}.json`).then(
      (rows) => new Map((rows ?? []).map((r) => [r.rid, r]))
    );
    detectionShardPromises.set(source, p);
  }
  return p;
}

/**
 * One exploit shard, as an id -> rule map.
 *
 * Cached per shard rather than as one promise over all sixteen, because a
 * worker handling many different CVEs will accumulate shards over its life and
 * lazily populating them is what keeps a cold isolate from parsing all of them.
 */
function loadExploitShard(env: Env, shard: number): Promise<Map<string, CoverageRule>> {
  let p = exploitShardPromises.get(shard);
  if (!p) {
    const name = String(shard).padStart(2, '0');
    p = fetchJson<CoverageRule[]>(env, `exploits/${name}.json`).then(
      (rows) => new Map((rows ?? []).map((r) => [r.rid, r]))
    );
    exploitShardPromises.set(shard, p);
  }
  return p;
}

/** Rule ids prefixed by these live in the exploit shards, not the detection ones. */
const EXPLOIT_SOURCES = new Set(['exploitdb', 'metasploit', 'nuclei']);

/**
 * Resolve rule ids to rule objects, reading only the shards those ids live in.
 *
 * Detection and exploit ids carry their source in the id prefix
 * (`splunk:detections/...`), so the right shard follows from the id itself and
 * no separate lookup table is needed.
 *
 * Returns in the caller's id order rather than map iteration order so a detail
 * response is byte-stable between requests.
 */
async function resolveRules(env: Env, ids: string[]): Promise<CoverageRule[]> {
  const detectionSources = new Set<string>();
  const exploitShards = new Set<number>();

  for (const id of ids) {
    const source = id.slice(0, id.indexOf(':'));
    if (EXPLOIT_SOURCES.has(source)) exploitShards.add(fnv1a(id) % EXPLOIT_SHARDS);
    else detectionSources.add(source);
  }

  const [detectionMaps, exploitMaps] = await Promise.all([
    Promise.all([...detectionSources].map((s) => loadDetectionShard(env, s))),
    Promise.all([...exploitShards].map((s) => loadExploitShard(env, s))),
  ]);

  const out = new Map<string, CoverageRule>();
  for (const m of detectionMaps) for (const [rid, rule] of m) out.set(rid, rule);
  for (const m of exploitMaps) for (const [rid, rule] of m) out.set(rid, rule);

  // An id that resolves in no shard means the index and the shards are out of
  // step (partial deploy). Drop it rather than inventing a placeholder rule.
  return ids.map((id) => out.get(id)).filter((r): r is CoverageRule => Boolean(r));
}

// ── live enrichment ──────────────────────────────────────────────────

interface KevEntry {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: string;
  requiredAction: string;
}

/**
 * CISA KEV, cached 1 h.
 *
 * This is a second fetch of the same upstream the cisa-kev route reads, but it
 * deliberately does not call that handler: that one is query-filtered and
 * returns a differently-shaped payload, and reusing it would force this route
 * through validation it does not need. Cache API makes the duplicate fetch free
 * at the edge. The CVSS map, by contrast, IS shared — see loadCvssMap.
 */
async function loadKev(): Promise<KevEntry[]> {
  try {
    const res = await fetch(KEV_URL, {
      headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
      cf: { cacheTtl: 3600, cacheEverything: true },
      signal: AbortSignal.timeout(KEV_TIMEOUT_MS),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      vulnerabilities?: Array<{
        cveID?: string;
        vendorProject?: string;
        product?: string;
        vulnerabilityName?: string;
        dateAdded?: string;
        dueDate?: string;
        knownRansomwareCampaignUse?: string;
        requiredAction?: string;
      }>;
    };
    return (data.vulnerabilities ?? [])
      .map((v) => ({
        cveId: v.cveID ?? '',
        vendor: v.vendorProject ?? '',
        product: v.product ?? '',
        name: v.vulnerabilityName ?? '',
        dateAdded: v.dateAdded ?? '',
        dueDate: v.dueDate ?? '',
        ransomware: v.knownRansomwareCampaignUse ?? 'Unknown',
        requiredAction: v.requiredAction ?? '',
      }))
      .filter((v) => v.cveId);
  } catch (err) {
    logError('detection-coverage: KEV fetch failed', err);
    return [];
  }
}

/**
 * EPSS, bulk.
 *
 * Delegates to `enrichEpssBulk`, which already handles the batching, the
 * Cache-API blob and the partial-resolution semantics. That client caps at 800
 * ids per call, so KEV (currently ~1,700 entries) is chunked across a few
 * calls rather than being truncated to the first 800 — silently dropping half
 * the scores would bias the exploit-likelihood ordering this page sorts by.
 *
 * A missing id means "no EPSS record", never "score 0", so the caller can tell
 * an unscored CVE from a genuinely unexploited one.
 */
async function loadEpss(ids: string[]): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  if (ids.length === 0) return out;

  const CHUNK = 800; // enrichEpssBulk's own EPSS_BULK_MAX_IDS ceiling
  for (let i = 0; i < ids.length; i += CHUNK) {
    const result = await enrichEpssBulk(ids.slice(i, i + CHUNK));
    for (const [id, v] of result.scores) out[id] = v.score;
  }
  return out;
}

// ── severity / exploitation banding ──────────────────────────────────

/**
 * CVSS v3.x severity bands. These are the canonical ranges, not a custom scale:
 * the whole point of the matrix is that an analyst can compare it against what
 * every other tool shows them.
 */
const CVSS_BANDS = [
  { id: 'none', label: 'None', min: 0, max: 0 },
  { id: 'low', label: 'Low', min: 0.1, max: 3.9 },
  { id: 'medium', label: 'Medium', min: 4.0, max: 6.9 },
  { id: 'high', label: 'High', min: 7.0, max: 8.9 },
  { id: 'critical', label: 'Critical', min: 9.0, max: 10.0 },
] as const;

/**
 * EPSS bands. Not an official FIRST banding; the thresholds are the ones
 * analysts already use conversationally ("10% within 30 days is the number
 * that matters"). Documented here because a reader who assumes these came from
 * FIRST would be wrong about their provenance.
 */
const EPSS_BANDS = [
  { id: 'unscored', label: 'Not scored', min: null as number | null, max: null },
  { id: 'severe', label: 'EPSS 10%+', min: 0.1, max: 1 },
  { id: 'elevated', label: 'EPSS 1-10%', min: 0.01, max: 0.1 },
  { id: 'moderate', label: 'EPSS 0.1-1%', min: 0.001, max: 0.01 },
  { id: 'low', label: 'EPSS under 0.1%', min: 0, max: 0.001 },
] as const;

function cvssBand(score: number | null): string {
  if (score === null) return 'unscored';
  const band = CVSS_BANDS.find((b) => b.id !== 'none' && score >= b.min && score <= b.max);
  return band?.id ?? 'none';
}

function epssBand(score: number | null): string {
  if (score === null) return 'unscored';
  const band = EPSS_BANDS.find((b) => b.min !== null && b.max !== null && score >= b.min && score <= b.max);
  return band?.id ?? 'unscored';
}

/**
 * The CVSS x EPSS matrix.
 *
 * CVSS is a severity claim made by the vendor; EPSS is a measured likelihood of
 * exploitation over the next 30 days. They disagree constantly, and the
 * disagreement is the interesting part: low-CVSS rows with high EPSS are
 * under-patched CVEs nobody prioritised, and the coverage percentage per cell
 * is the direct evidence for how visible that population is.
 *
 * Computed over whatever rows the current filters selected, so the matrix
 * always describes the set on screen rather than a global one the user did not
 * ask for.
 */
function buildMatrix(rows: CoverageRow[], isCovered: (r: CoverageRow) => boolean) {
  interface Cell {
    epss: string;
    total: number;
    covered: number;
    avgCvss: number | null;
    scoredCvss: number;
  }

  const cells = new Map<string, Cell>();
  for (const row of rows) {
    const key = `${cvssBand(row.cvss)}|${epssBand(row.epss)}`;
    const cell = cells.get(key) ?? {
      epss: epssBand(row.epss),
      total: 0,
      covered: 0,
      avgCvss: null,
      scoredCvss: 0,
    };
    cell.total += 1;
    if (isCovered(row)) cell.covered += 1;
    if (row.cvss !== null) {
      cell.avgCvss = (cell.avgCvss ?? 0) + row.cvss;
      cell.scoredCvss += 1;
    }
    cells.set(key, cell);
  }

  const matrix = EPSS_BANDS.map((eb) => ({
    epss: eb.id,
    epssLabel: eb.label,
    cells: CVSS_BANDS.map((cb) => {
      const cell = cells.get(`${cb.id}|${eb.id}`);
      return {
        cvss: cb.id,
        cvssLabel: cb.label,
        total: cell?.total ?? 0,
        // Coverage within the cell, at whichever tier the caller selected.
        // This is the cell's "% of these have a rule" figure.
        covered: cell?.covered ?? 0,
        coveragePct: cell && cell.total > 0 ? Number(((cell.covered / cell.total) * 100).toFixed(0)) : null,
        avgCvss:
          cell && cell.scoredCvss > 0 && cell.avgCvss !== null
            ? Number((cell.avgCvss / cell.scoredCvss).toFixed(1))
            : null,
      };
    }),
  }));

  return { cvssBands: CVSS_BANDS, epssBands: EPSS_BANDS, matrix };
}

// ── coverage computation ─────────────────────────────────────────────

/** One dated EPSS observation, from scripts/sync-epss-history.mjs. */
interface EpssPoint {
  date: string;
  score: number;
}

interface CoverageRow {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
  epss: number | null;
  /** Change in EPSS over the sampled history window. Null when no history exists. */
  epssDelta: number | null;
  /** EPSS points per day, normalised to a 30-day-equivalent rate. */
  epssTrend: number | null;
  epssHistoryPoints: number;
  cvss: number | null;
  severity: string | null;
  /** Rules citing this CVE id. Strong evidence. */
  explicit: number;
  /** Rules naming this CVE's product. Weaker, corroborated by token vote. */
  inferred: number;
  /** How many product matches existed before the build-time cap. */
  inferredTotal: number;
  exploits: number;
  explicitSources: string[];
  inferredSources: string[];
  coveredBy: string[];
  /** Strong evidence only: a rule cites the CVE. */
  covered: boolean;
  /** Either tier: a rule exists that plausibly covers this. */
  coveredAny: boolean;
}

function sourcePrefix(rid: string): string {
  return rid.slice(0, rid.indexOf(':'));
}

function summariseSources(rids: string[]): string[] {
  return [...new Set(rids.map(sourcePrefix))].sort();
}

/**
 * EPSS change and daily rate over the sampled history.
 *
 * `trend` is scaled to a 30-day equivalent so a reader comparing it against the
 * headline EPSS figure (which is itself a 30-day probability) is looking at
 * like with like. A 0.001 rise per day and a 0.03 rise over 30 days are the
 * same statement, and reporting the raw delta would make a 5-sample window
 * look like a 30-sample one.
 */
function epssMovement(points: EpssPoint[] | undefined): {
  delta: number | null;
  trend: number | null;
  count: number;
} {
  if (!points || points.length < 2) return { delta: null, trend: null, count: points?.length ?? 0 };
  const first = points[0];
  const last = points[points.length - 1];
  if (!first || !last) return { delta: null, trend: null, count: points.length };
  const days = (new Date(last.date).getTime() - new Date(first.date).getTime()) / 86_400_000;
  if (days <= 0) return { delta: null, trend: null, count: points.length };
  const delta = last.score - first.score;
  return { delta, trend: delta / days, count: points.length };
}

function computeRows(
  kev: KevEntry[],
  coverage: Record<string, KevCoverageRow>,
  epss: Record<string, number>,
  history: Record<string, EpssPoint[]>,
  cvss: Map<string, { score: number; severity: string }>
): CoverageRow[] {
  return kev.map((k) => {
    const slot = coverage[k.cveId] ?? { d: [], p: [], pTotal: 0, e: [] };
    const move = epssMovement(history[k.cveId]);
    const nvd = cvss.get(k.cveId);
    return {
      cveId: k.cveId,
      vendor: k.vendor,
      product: k.product,
      name: k.name,
      dateAdded: k.dateAdded,
      dueDate: k.dueDate,
      ransomware: k.ransomware.toLowerCase() === 'known',
      epss: epss[k.cveId] ?? null,
      epssDelta: move.delta,
      epssTrend: move.trend,
      epssHistoryPoints: move.count,
      cvss: nvd?.score ?? null,
      severity: nvd?.severity ?? null,
      explicit: slot.d.length,
      inferred: slot.p.length,
      inferredTotal: slot.pTotal ?? slot.p.length,
      exploits: slot.e.length,
      explicitSources: summariseSources(slot.d),
      inferredSources: summariseSources(slot.p),
      coveredBy: summariseSources([...slot.d, ...slot.p]),
      covered: slot.d.length > 0,
      coveredAny: slot.d.length > 0 || slot.p.length > 0,
    };
  });
}

// ── handlers ─────────────────────────────────────────────────────────

export async function detectionCoverageHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadIndex(c.env);
  if (!index) {
    return c.json(
      {
        error: 'detection coverage index unavailable',
        message: `public/data/detection-coverage/index.json not found. Run: node scripts/build-detection-coverage.mjs`,
      },
      503,
      { 'Cache-Control': 'no-store' }
    );
  }

  const coverage = await loadKevCoverage(c.env);
  if (!coverage) {
    return c.json(
      {
        error: 'detection coverage index unavailable',
        message: 'kev-coverage.json not found. Run: node scripts/build-detection-coverage.mjs',
      },
      503,
      { 'Cache-Control': 'no-store' }
    );
  }

  const detectionSources = index.sources.filter((s) => s.kind === 'detection');
  const exploitSources = index.sources.filter((s) => s.kind === 'exploit');
  const platformIds = new Set(detectionSources.map((s) => s.id));

  const platform = c.req.query('platform')?.trim().toLowerCase();

  // Typos like `?platfrom=splunk` would otherwise be silently ignored and the
  // caller would read the unfiltered result set as if it were filtered.
  const unknownParams = findUnknownParams('GET', '/api/v1/detection-coverage', Object.keys(c.req.queries()));

  if (platform && !platformIds.has(platform)) {
    return badRequest(c, `unknown platform "${platform}". Known: ${[...platformIds].join(', ')}`);
  }

  const days = Number(c.req.query('days') ?? 0);
  const ransomwareOnly = c.req.query('ransomware') === 'true';
  const coveredOnly = c.req.query('covered') === 'true';
  const gapOnly = c.req.query('gaps') === 'true';
  /**
   * Which coverage tier counts as "covered".
   *
   * `explicit` is the strict reading (a rule cites the CVE) and is what
   * `gaps=true` used to mean; it reports 4% of the corpus tagging any CVE at
   * all, which is a fact about tagging rather than about coverage.
   * `any` (the default) also counts product-inferred rules.
   */
  const tier = c.req.query('tier')?.trim().toLowerCase() === 'explicit' ? 'explicit' : 'any';
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 100), 1), 500);
  const offset = Math.max(Number(c.req.query('offset') ?? 0), 0);

  const kev = await loadKev();
  const [epss, cvss, history] = await Promise.all([
    loadEpss(kev.map((k) => k.cveId)),
    loadCvssMap(c.env),
    loadEpssHistory(c.env),
  ]);

  let rows = computeRows(kev, coverage, epss, history ?? {}, cvss);

  // When a platform is selected the question changes from "is this covered
  // anywhere" to "does THIS platform cover it", so coverage and the platform
  // breakdown both have to be recomputed rather than filtered after the fact.
  if (platform) {
    for (const r of rows) {
      const slot = coverage[r.cveId] ?? { d: [], p: [], pTotal: 0, e: [] };
      r.explicitSources = summariseSources(slot.d.filter((rid) => sourcePrefix(rid) === platform));
      r.inferredSources = summariseSources(slot.p.filter((rid) => sourcePrefix(rid) === platform));
      r.explicit = slot.d.filter((rid) => sourcePrefix(rid) === platform).length;
      r.inferred = slot.p.filter((rid) => sourcePrefix(rid) === platform).length;
      r.coveredBy = [...new Set([...r.explicitSources, ...r.inferredSources])].sort();
      r.covered = r.explicitSources.length > 0;
      r.coveredAny = r.coveredBy.length > 0;
    }
  }

  if (Number.isFinite(days) && days > 0) {
    const cutoff = Date.now() - days * 86_400_000;
    rows = rows.filter((r) => new Date(r.dateAdded).getTime() >= cutoff);
  }
  if (ransomwareOnly) rows = rows.filter((r) => r.ransomware);

  const isCovered = (r: CoverageRow) => (tier === 'explicit' ? r.covered : r.coveredAny);
  if (coveredOnly) rows = rows.filter(isCovered);
  if (gapOnly) rows = rows.filter((r) => !isCovered(r));

  const total = rows.length;
  const coveredAny = rows.filter((r) => r.coveredAny).length;
  const coveredExplicit = rows.filter((r) => r.covered).length;
  const pct = (n: number) => (total === 0 ? null : Number(((n / total) * 100).toFixed(1)));

  // Sort by the thing that decides whether you care: exploitation likelihood
  // first, then recency. A rising score outranks a high flat one, because that
  // is the one still moving.
  rows.sort(
    (a, b) =>
      (b.epssTrend ?? -Infinity) - (a.epssTrend ?? -Infinity) ||
      (b.epss ?? -1) - (a.epss ?? -1) ||
      b.dateAdded.localeCompare(a.dateAdded)
  );

  const perPlatform = detectionSources.map((s) => {
    const explicit = kev.filter((k) => (coverage[k.cveId]?.d ?? []).some((rid) => sourcePrefix(rid) === s.id)).length;
    const any = kev.filter((k) =>
      [...(coverage[k.cveId]?.d ?? []), ...(coverage[k.cveId]?.p ?? [])].some((rid) => sourcePrefix(rid) === s.id)
    ).length;
    return {
      id: s.id,
      label: s.label,
      format: s.format,
      homepage: s.homepage,
      license: s.license,
      licenseUrl: s.licenseUrl,
      attribution: s.attribution,
      accessUrl: s.accessUrl,
      rules: s.ruleCount,
      status: s.status,
      kevTotal: kev.length,
      kevCovered: any,
      kevCoveredExplicit: explicit,
      kevCoveragePct: kev.length === 0 ? null : Number(((any / kev.length) * 100).toFixed(1)),
    };
  });

  return c.json(
    {
      schemaVersion: 'detection-coverage-v2',
      generatedAt: index.generatedAt,
      ...(unknownParams.length > 0 ? { unknownParams } : {}),
      // The upstream crawl date of the rule corpora, which is what "as of"
      // means here. Not request time.
      indexAgeHours: Number(((Date.now() - new Date(index.generatedAt).getTime()) / 3_600_000).toFixed(1)),

      scope: {
        kevTotal: kev.length,
        kevEvaluated: total,
        /** A rule cites the CVE. Strong. */
        coveredExplicit,
        /** A rule cites the CVE, or names its product. The honest default. */
        coveredAny,
        gaps: total - coveredAny,
        coveragePct: pct(coveredAny),
        coverageExplicitPct: pct(coveredExplicit),
        withExploitAvailable: rows.filter((r) => r.exploits > 0).length,
        ransomwareLinked: rows.filter((r) => r.ransomware).length,
        // The headline that makes the page honest: no rule, but the bug is
        // trivially usable against you.
        gapsWithExploitAvailable: rows.filter((r) => !r.coveredAny && r.exploits > 0).length,
        withEpssHistory: rows.filter((r) => r.epssTrend !== null).length,
        risingFast: rows.filter((r) => (r.epssTrend ?? 0) > 0.001).length,
      },

      ruleCorpora: {
        detections: detectionSources.length,
        exploits: exploitSources.length,
        rules: index.rules,
        detectionRules: index.detectionRulesTotal,
        detectionRulesCveTagged: index.detectionRulesCveTagged,
        // The reason the two-tier split exists. Surfaced in the response so a
        // consumer cannot quote a coverage number without seeing this.
        detectionCveLinkRate: index.detectionCveLinkRate,
        techniques: index.techniques,
        distinctCves: index.distinctCves,
        sources: index.sources,
      },

      perPlatform,

      bands: buildMatrix(rows, tier === 'explicit' ? (r) => r.covered : (r) => r.coveredAny),

      rows: rows.slice(offset, offset + limit),
      page: { limit, offset, total, hasMore: offset + limit < total },

      filters: {
        platform: platform ?? null,
        days: Number.isFinite(days) && days > 0 ? days : null,
        ransomwareOnly,
        coveredOnly,
        gapOnly,
        tier,
      },
    },
    {
      headers: {
        // Rule data changes only on deploy; KEV/EPSS change hourly at most.
        'Cache-Control': 'public, max-age=300, s-maxage=900, stale-while-revalidate=3600',
        ...unknownParamHeaders(unknownParams, '/api/v1/detection-coverage'),
      },
    }
  );
}

/**
 * Detection-update changelog.
 *
 * Answers "what changed in detections since yesterday". Built from the daily
 * snapshot the index build accumulates, diffed against the previous point.
 *
 * The honest limit: a diff here can only report counts moving, not which rules
 * changed, because we keep one aggregate row per day rather than a full rule
 * snapshot. Count deltas catch a vendor retiring a corpus or renaming a tree,
 * which is the common case; they do not catch a rule silently rewritten in
 * place. That would need a per-rule snapshot per day and the repository growth
 * that comes with it.
 *
 * With a single point in history the diff is empty and `warmingUp` is true,
 * which is the correct answer on day one rather than an empty list that looks
 * like "nothing changed".
 */
export async function detectionCoverageUpdatesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const history = await loadHistory(c.env);
  if (!history) {
    return c.json({ error: 'detection coverage history unavailable' }, 503, { 'Cache-Control': 'no-store' });
  }

  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 30), 1), 90);
  const unknownParams = findUnknownParams('GET', '/api/v1/detection-coverage/updates', Object.keys(c.req.queries()));

  const points = history.points;
  const changes = [];
  // Walk oldest to newest so each entry is "what changed on this date".
  for (let i = 1; i < points.length; i += 1) {
    const prev = points[i - 1]!;
    const cur = points[i]!;
    const perSource: Record<string, number> = {};
    for (const id of new Set([...Object.keys(prev.perSource), ...Object.keys(cur.perSource)])) {
      const delta = (cur.perSource[id] ?? 0) - (prev.perSource[id] ?? 0);
      if (delta !== 0) perSource[id] = delta;
    }
    changes.push({
      date: cur.date,
      detections: cur.detections - prev.detections,
      exploits: cur.exploits - prev.exploits,
      techniques: cur.techniques - prev.techniques,
      cveTagged: cur.cveTagged - prev.cveTagged,
      perSource,
      total: cur.detections + cur.exploits - (prev.detections + prev.exploits),
    });
  }

  return c.json(
    {
      schemaVersion: 'detection-coverage-updates-v1',
      generatedAt: history.generatedAt,
      // Only meaningful once there are two points to compare.
      warmingUp: points.length < 2,
      pointsAvailable: points.length,
      current: points[points.length - 1] ?? null,
      series: points.slice(-limit),
      changes: changes.slice(-limit).reverse(),
      caveat:
        'Diffs are computed from daily aggregate counts, not per-rule snapshots. They catch a corpus being retired, renamed or added. They cannot catch a rule edited in place without its count changing.',
      ...(unknownParams.length > 0 ? { unknownParams } : {}),
    },
    {
      headers: {
        'Cache-Control': 'public, max-age=300, s-maxage=900, stale-while-revalidate=3600',
        ...unknownParamHeaders(unknownParams, '/api/v1/detection-coverage/updates'),
      },
    }
  );
}

export async function detectionCoverageCveHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const raw = c.req.param('cveId') ?? '';
  // Accepts CVE-2025-1974, 2025-1974 and cve-2025-1974 alike.
  const cveId = normaliseCveId(raw);
  if (!cveId) {
    return badRequest(c, `"${raw}" is not a CVE id. Try CVE-2025-1974 or 2025-1974.`);
  }

  const [index, coverage, kev, epssMap, cvss, history, shodan] = await Promise.all([
    loadIndex(c.env),
    loadKevCoverage(c.env),
    loadKev(),
    loadEpss([cveId]),
    loadCvssMap(c.env),
    loadEpssHistory(c.env),
    shodanCveDb(c.env, cveId),
  ]);

  if (!index || !coverage) {
    return c.json({ error: 'detection coverage index unavailable' }, 503, { 'Cache-Control': 'no-store' });
  }

  const slot = coverage[cveId] ?? { d: [], p: [], pTotal: 0, e: [] };
  // resolveRules reads only the shards these ids live in: detection ids name
  // their source, exploit ids hash to one of sixteen shards.
  const [explicitRows, inferredRows, exploitRows] = await Promise.all([
    resolveRules(c.env, slot.d),
    resolveRules(c.env, slot.p),
    resolveRules(c.env, slot.e),
  ]);

  const kevEntry = kev.find((k) => k.cveId === cveId);
  const nvd = cvss.get(cveId);
  const move = epssMovement(history?.[cveId]);

  // A CVE with no index entry is genuinely uncovered, which is a real answer,
  // not a 404. Only an index that failed to load would be a 503.
  return c.json(
    {
      schemaVersion: 'detection-coverage-detail-v2',
      cveId,
      generatedAt: index.generatedAt,
      epss: epssMap[cveId] ?? null,
      epssDelta: move.delta,
      epssTrend: move.trend,
      epssHistory: history?.[cveId] ?? [],
      cvss: nvd?.score ?? null,
      severity: nvd?.severity ?? null,
      kev: kevEntry ?? null,
      /**
       * Shodan CVEDB exploitation context. Reachable from a browsable surface
       * now, where before it was only available to the report generator.
       * Null when Shodan has no record, which is normal and not an error.
       */
      shodan,
      /** Strong: a rule cites this CVE. */
      covered: explicitRows.length > 0,
      /** Either tier. */
      coveredAny: explicitRows.length > 0 || inferredRows.length > 0,
      detections: explicitRows,
      detectionsInferred: inferredRows,
      exploits: exploitRows,
      counts: {
        detectionsExplicit: explicitRows.length,
        detectionsInferred: inferredRows.length,
        detectionsInferredTotal: slot.pTotal,
        exploits: exploitRows.length,
        platforms: [...new Set([...explicitRows, ...inferredRows].map((d) => d.source))].sort(),
        // Same coverage calculation the summary uses, surfaced per-CVE so the
        // two views cannot drift apart.
        severityBand: cvssBand(nvd?.score ?? null),
        epssBand: epssBand(epssMap[cveId] ?? null),
      },
      // Stated on every response so a consumer that stores one of these
      // records still carries the caveat.
      caveat:
        'Two tiers, not one number. "detections" are rules citing this CVE id (strong). "detectionsInferred" are rules naming its product (weaker: a Citrix rule is relevant to a Citrix CVE but may target a different bug). Only ~4% of published detection rules cite any CVE id, so the explicit tier alone describes a tagging convention rather than coverage. Private vendor content is not visible here either.',
    },
    { headers: { 'Cache-Control': 'public, max-age=300, s-maxage=900, stale-while-revalidate=3600' } }
  );
}

/**
 * ATT&CK technique coverage.
 *
 * The other half of the coverage question, and arguably the more actionable
 * one. A behavioural detection covers a class of activity, not one CVE, so
 * "is T1566.001 covered" generalises across every phishing CVE while a per-CVE
 * join only ever answers about the CVE it names.
 *
 * `platform=X&gapsOnly=true` returns techniques where X publishes nothing;
 * adding `compareTo=Y` narrows it further to those where Y does publish one,
 * which is the set of rules actually worth porting.
 */
export async function detectionCoverageTechniquesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const [index, techniqueIndex] = await Promise.all([loadIndex(c.env), loadTechniqueIndex(c.env)]);
  if (!index || !techniqueIndex) {
    return c.json({ error: 'technique coverage index unavailable' }, 503, { 'Cache-Control': 'no-store' });
  }

  const platform = c.req.query('platform')?.trim().toLowerCase();
  const compareTo = c.req.query('compareTo')?.trim().toLowerCase();
  const gapsOnly = c.req.query('gapsOnly') === 'true';
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 200), 1), 500);
  const unknownParams = findUnknownParams('GET', '/api/v1/detection-coverage/techniques', Object.keys(c.req.queries()));

  const detectionIds = index.sources.filter((s) => s.kind === 'detection').map((s) => s.id);
  if (platform && !detectionIds.includes(platform)) {
    return badRequest(c, `unknown platform "${platform}". Known: ${detectionIds.join(', ')}`);
  }
  if (compareTo && !detectionIds.includes(compareTo)) {
    return badRequest(c, `unknown compareTo platform "${compareTo}". Known: ${detectionIds.join(', ')}`);
  }

  // Rule ids are `source:path`, so a technique's platform breakdown is a prefix
  // count over the ids the index already gives us. No extra artifact needed.
  const perTechnique = new Map<string, { total: number; byPlatform: Record<string, number> }>();
  for (const [technique, rids] of Object.entries(techniqueIndex)) {
    const byPlatform: Record<string, number> = {};
    for (const rid of rids) {
      const source = rid.slice(0, rid.indexOf(':'));
      byPlatform[source] = (byPlatform[source] ?? 0) + 1;
    }
    perTechnique.set(technique, { total: rids.length, byPlatform });
  }

  let rows = [...perTechnique.entries()].map(([id, v]) => ({
    id,
    total: v.total,
    byPlatform: v.byPlatform,
    coveredHere: platform ? (v.byPlatform[platform] ?? 0) : v.total,
    coveredElsewhere: compareTo ? (v.byPlatform[compareTo] ?? 0) : 0,
  }));

  // The "worth porting" set: nothing for the platform I run, something for the
  // one I might copy from.
  if (gapsOnly && platform && compareTo) {
    rows = rows.filter((r) => r.coveredHere === 0 && r.coveredElsewhere > 0);
  } else if (gapsOnly && platform) {
    rows = rows.filter((r) => r.coveredHere === 0);
  } else if (platform) {
    rows = rows.filter((r) => r.coveredHere > 0);
  }

  rows.sort((a, b) => b.total - a.total || a.id.localeCompare(b.id));

  return c.json(
    {
      schemaVersion: 'detection-coverage-techniques-v1',
      generatedAt: index.generatedAt,
      total: rows.length,
      techniquesIndexed: Object.keys(techniqueIndex).length,
      filters: { platform: platform ?? null, compareTo: compareTo ?? null, gapsOnly },
      ...(unknownParams.length > 0 ? { unknownParams } : {}),
      techniques: rows.slice(0, limit),
    },
    {
      headers: {
        'Cache-Control': 'public, max-age=300, s-maxage=900, stale-while-revalidate=3600',
        ...unknownParamHeaders(unknownParams, '/api/v1/detection-coverage/techniques'),
      },
    }
  );
}

export async function detectionCoverageLibraryHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const index = await loadIndex(c.env);
  if (!index) {
    return c.json({ error: 'detection coverage library unavailable' }, 503, { 'Cache-Control': 'no-store' });
  }

  const technique = c.req.query('technique')?.trim().toUpperCase();
  const source = c.req.query('source')?.trim().toLowerCase();
  const q = c.req.query('q')?.trim().toLowerCase();
  const cveOnly = c.req.query('cveOnly') === 'true';
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 100), 1), 500);

  const unknownParams = findUnknownParams('GET', '/api/v1/detection-coverage/library', Object.keys(c.req.queries()));

  const detectionIds = index.sources.filter((s) => s.kind === 'detection').map((s) => s.id);
  if (source && !detectionIds.includes(source)) {
    return badRequest(c, `unknown detection source "${source}". Known: ${detectionIds.join(', ')}`);
  }

  // Load only the shards we need. A `source=X` filter reads one file; an
  // unfiltered browse reads all four, which is ~4.5 MB rather than the ~20 MB
  // the full mixed corpus (detections + exploits) would cost.
  const shards = await Promise.all((source ? [source] : detectionIds).map((s) => loadDetectionShard(c.env, s)));
  const rows = shards.flatMap((m) => [...m.values()]);

  let filtered = rows;
  if (technique) {
    // A sub-technique request also returns its parent, so T1566 returns both
    // T1566 and T1566.001 rules rather than only the latter.
    const parent = technique.split('.')[0];
    filtered = filtered.filter((r) => r.techniques.some((t) => t === technique || t === parent));
  }
  if (q) filtered = filtered.filter((r) => r.title.toLowerCase().includes(q) || r.rid.toLowerCase().includes(q));
  // cveOnly is the slice that participates in the per-CVE coverage join.
  if (cveOnly) filtered = filtered.filter((r) => r.cves.length > 0);

  // Technique frequency, computed over the same filtered set so the counts
  // always describe what the user is actually looking at.
  const techniqueCounts = new Map<string, number>();
  for (const r of filtered) for (const t of r.techniques) techniqueCounts.set(t, (techniqueCounts.get(t) ?? 0) + 1);

  const sorted = [...filtered].sort((a, b) => b.techniques.length - a.techniques.length || a.rid.localeCompare(b.rid));

  return c.json(
    {
      schemaVersion: 'detection-coverage-library-v2',
      generatedAt: index.generatedAt,
      ...(unknownParams.length > 0 ? { unknownParams } : {}),
      total: filtered.length,
      // How much of the corpus can even be joined to a CVE, so a reader of this
      // list knows the coverage numbers rest on a small minority of it.
      cveTagged: filtered.filter((r) => r.cves.length > 0).length,
      filters: { technique: technique ?? null, source: source ?? null, q: q ?? null, cveOnly },
      techniques: [...techniqueCounts.entries()]
        .map(([id, count]) => ({ id, rules: count }))
        .sort((a, b) => b.rules - a.rules || a.id.localeCompare(b.id))
        .slice(0, 100),
      rules: sorted.slice(0, limit),
    },
    {
      headers: {
        'Cache-Control': 'public, max-age=300, s-maxage=900, stale-while-revalidate=3600',
        ...unknownParamHeaders(unknownParams, '/api/v1/detection-coverage/library'),
      },
    }
  );
}
