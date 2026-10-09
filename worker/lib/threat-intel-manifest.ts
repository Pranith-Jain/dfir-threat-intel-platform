/**
 * Threat Intel manifest loader.
 *
 * Reads the static JSON manifest shipped in /public/data/threat-intel/.
 * Three product sources feed this vertical:
 *   - OpenThreat (NVD + CISA KEV + BSI CERT-Bund ingest, design ref only)
 *   - cyber_threat_intel (sector briefings)
 *   - Daily-Hunt (IOC family catalog, design ref only)
 *
 * Shape (mirrors public/data/si/ exactly so the build + test patterns reuse):
 *   /data/threat-intel/index.json           (~50-80 KB, slim — no bodies)
 *   /data/threat-intel/cves/<CVE-ID>.json   (one per CVE; CVSS, KEV, score)
 *   /data/threat-intel/cves/kev.json        (CISA KEV snapshot)
 *   /data/threat-intel/iocs/<family>.json   (one per ransomware/malware family)
 *   /data/threat-intel/sectors/<name>.json  (Financial/Healthcare/Government brief)
 *
 * In-memory cache: index is small so we keep it forever after first fetch.
 * Bodies cached on demand with a 200-entry LRU bound to stay under the
 * Worker's 128 MB memory cap when many distinct CVEs are requested.
 *
 * IMPORTANT: OpenThreat is AGPL-3.0. We do not vendor or copy its code;
 * the priority scoring here is derived independently from the README.
 */

import { fetchJsonAsset, recordHit, trackHit, type BodyCache } from './manifest-cache';

export type TiSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface TiCveIndexEntry {
  cveId: string;
  publishedAt: string;
  lastModifiedAt: string;
  cvssV3Score: number | null;
  cvssV3Severity: TiSeverity;
  vendor: string | null;
  product: string | null;
  inKev: boolean;
  inKevSince: string | null;
  priorityScore: number;
  description: string;
  sizeBytes: number;
  /** Argus trending hype score (0-100), set only when the CVE appears
   *  in the Argus trending feed. null when no Argus data is available
   *  for this CVE. */
  argusHypeScore: number | null;
  /** Argus trending velocity delta. Positive = gaining attention. */
  argusRising: number | null;
}

export interface TiKevEntry {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
}

export interface TiIocIndexEntry {
  slug: string;
  family: string;
  category: 'ransomware' | 'malware' | 'apt' | 'c2' | 'phishing' | 'stealer' | 'other';
  aliases: string[];
  firstSeen: string | null;
  mitreTechniques: string[];
  indicatorCount: number;
  description: string;
  sizeBytes: number;
}

export interface TiSectorEntry {
  sector: 'financial' | 'healthcare' | 'government';
  title: string;
  generatedAt: string;
  topCount: number;
  preview: string;
  sizeBytes: number;
}

export interface TiDetectionListIndexEntry {
  slug: string;
  title: string;
  category: string;
  sourceFile: string;
  valueColumn: string;
  entryCount: number;
  sizeBytes: number;
  description: string;
}

export interface TiDetectionListEntry {
  value: string;
  description?: string;
  tool?: string;
  category?: string;
  severity?: string;
  priority?: string;
  fpRisk?: string;
  link?: string;
  reference?: string;
  regex?: string;
  comment?: string;
  confidence?: string;
  toolType?: string;
  usage?: string;
  detectionType?: string;
  metadata: Record<string, string>;
}

export interface TiDetectionListBody extends TiDetectionListIndexEntry {
  columns: string[];
  entries: TiDetectionListEntry[];
}

// ─── Darknet directory (darknetlist.is) ─────────────────────────────────

export type TiDarknetCategory =
  'markets' | 'search' | 'forums' | 'news' | 'security' | 'communications' | 'crypto' | 'tools' | 'ai';

export interface TiDarknetSiteIndexEntry {
  slug: string;
  name: string;
  dwdId: string | null;
  category: string;
  status: 'up' | 'down' | 'unknown';
  upMirrors: number;
  totalMirrors: number;
  recommended: boolean;
  isOnion: boolean;
  url: string | null;
  onion: string | null;
}

export interface TiDarknetSiteBody extends TiDarknetSiteIndexEntry {
  url: string | null;
  onion: string | null;
  latencyMs: number | null;
  httpCode: string | null;
  pageSize: string | null;
  fingerprint: string | null;
}

export interface TiDarknetCategoryIndexEntry {
  id: string;
  title: string;
  description: string;
  siteCount: number;
  mirrorCount: number;
  upCount: number;
}

export interface TiDarknetCategoryBody extends TiDarknetCategoryIndexEntry {
  sites: TiDarknetSiteBody[];
}

export interface TiDarknetIndex {
  source: string;
  url: string;
  description: string;
  rebuiltAt: string;
  syncedAt: string;
  counts: {
    categories: number;
    sites: number;
    up: number;
    down: number;
    recommended: number;
    onion: number;
  };
  categories: TiDarknetCategoryIndexEntry[];
  sites: TiDarknetSiteIndexEntry[];
}

export interface TiIndex {
  source: string;
  license: string;
  replicatedAt: string;
  counts: { cves: number; iocs: number; sectors: number; kevTotal: number; lists: number };
  lastSyncedAt: string | null;
  cveIndex: TiCveIndexEntry[];
  iocIndex: TiIocIndexEntry[];
  listsIndex: TiDetectionListIndexEntry[];
  sectors: TiSectorEntry[];
  darknet?: TiDarknetIndex;
}

export interface TiCveBody extends TiCveIndexEntry {
  cvssVector: string | null;
  cweIds: string[];
  references: { url: string; source: string; tags: string[] }[];
  bsiDescription: string | null;
  llmSummary: string | null;
  llmRecommendedAction: string | null;
}

export interface TiIocBody extends TiIocIndexEntry {
  indicators: { type: string; value: string; firstSeen: string | null; confidence: 'low' | 'medium' | 'high' }[];
  context: string;
  references: string[];
  llmSummary: string | null;
}

export interface TiSectorBody extends TiSectorEntry {
  executiveSummary: string;
  topThreats: {
    cveId?: string;
    iocFamily?: string;
    title: string;
    relevance: 'sector-direct' | 'sector-implied' | 'broadly-critical';
    risk: string;
    recommendedAction: string;
  }[];
}

// ─── ThreatCluster feeds (threatcluster.io) ──────────────────────────

export interface TcClusterIndexEntry {
  slug: string;
  title: string;
  pubDate: string | null;
  sourceCount: number | null;
  sizeBytes: number;
}

export interface TcVulnIndexEntry {
  cveId: string;
  title: string;
  pubDate: string | null;
  sizeBytes: number;
}

export interface TcExploitIndexEntry {
  cveId: string;
  title: string;
  pubDate: string | null;
  severity: string | null;
  inKev: boolean;
  sizeBytes: number;
}

export interface TcVictimIndexEntry {
  id: string;
  victim: string;
  group: string | null;
  sector: string | null;
  country: string | null;
  pubDate: string | null;
  sizeBytes: number;
}

export interface TcIocSource {
  source: string;
  url: string;
  pub_date: string | null;
}

export interface TcIoc {
  type: 'domain' | 'ipv4' | 'ipv6' | 'url' | 'email' | 'hash' | string;
  value: string;
  confidence: string;
  reason: string | null;
  first_seen: string | null;
  last_seen: string | null;
  source_count: number;
  sources: TcIocSource[];
}

export interface TcMispEvent {
  uuid: string;
  info: string | null;
  date: string | null;
  analysis: string | null;
  threat_level_id: string | null;
  timestamp: string | null;
  tags: string[];
  orgc: string | null;
}

export interface TcFeedMeta {
  id: string;
  title: string;
  url: string;
  window: string;
}

export interface TcThreatClusterIndex {
  source: string;
  url: string;
  description: string;
  syncedAt: string;
  lastBuildDates: Partial<Record<'clusters' | 'vulnerabilities' | 'exploits' | 'victims' | 'iocs', string | null>>;
  counts: {
    clusters: number;
    vulnerabilities: number;
    exploits: number;
    victims: number;
    iocs: number;
    mispEvents: number;
  };
  feeds: TcFeedMeta[];
  clusters: TcClusterIndexEntry[];
  vulnerabilities: TcVulnIndexEntry[];
  exploits: TcExploitIndexEntry[];
  victims: TcVictimIndexEntry[];
}

export interface TcClusterBody extends TcClusterIndexEntry {
  link: string;
  guid: string;
  categories: string[];
  description: string;
}

export interface TcVulnBody extends TcVulnIndexEntry {
  link: string;
  guid: string;
  description: string;
}

export interface TcExploitBody extends TcExploitIndexEntry {
  link: string;
  guid: string;
  hasExploit: true;
  categories: string[];
  description: string;
}

export interface TcVictimBody extends TcVictimIndexEntry {
  title: string;
  link: string;
  guid: string;
  categories: string[];
  description: string;
}

export interface TcIocsBody {
  source: string;
  url: string;
  generatedAt: string | null;
  syncedAt: string;
  filters: { confidence: string; window_days: number; types: string[] } | null;
  count: number;
  iocs: TcIoc[];
}

export interface TcMispBody {
  source: string;
  url: string;
  syncedAt: string;
  eventCount: number;
  events: TcMispEvent[];
}

// ─── ThreatCluster entity intelligence ────────────────────────────────
//
// Derived entities from ThreatCluster data: threat actors (MISP galaxy
// attribution), ransomware groups + sectors (dark-web victims), malware
// (Daily-Hunt family dictionary matching), and CVEs (feed + cluster text
// regex). Each profile carries first/last seen, mention frequency by day,
// recent activity, and a weighted related-entity graph from record-level
// co-occurrence. Built by scripts/build-tc-entities.mjs.

export type TcEntityType = 'actor' | 'group' | 'malware' | 'cve' | 'sector';

export const TC_ENTITY_TYPES: TcEntityType[] = ['actor', 'group', 'malware', 'cve', 'sector'];

export interface TcEntityIndexEntry {
  type: TcEntityType;
  slug: string;
  name: string;
  aliases: string[];
  mentionCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface TcEntityIndex {
  source: string;
  url: string;
  description: string;
  builtAt: string;
  counts: Record<TcEntityType, number>;
  entities: Record<TcEntityType, TcEntityIndexEntry[]>;
}

export interface TcEntityRelated {
  type: TcEntityType;
  slug: string;
  name: string;
  weight: number;
}

export interface TcEntityActivity {
  recordType: 'cluster' | 'vulnerability' | 'exploit' | 'victim' | 'mispEvent';
  slug: string;
  title: string;
  pubDate: string | null;
}

export interface TcEntityBody extends TcEntityIndexEntry {
  sources: string[];
  summary: string;
  frequency: { date: string; count: number }[];
  recentActivity: TcEntityActivity[];
  relatedEntities: TcEntityRelated[];
  mitreTechniques: string[];
  victims?: { id: string; victim: string; sector: string | null; country: string | null; pubDate: string | null }[];
  description?: string | null;
}

// ─── Threaticon (threaticon.com) ───────────────────────────────────────
//
// A separate manifest tree under /data/threat-intel/threaticon/ with its
// own lazy index: actor catalog + profiles, malware family dictionary,
// ATT&CK detection-coverage dataset, and a country-level threat map.
// Mirrors the darknet/threatcluster pattern (own sync + build scripts,
// read through env.ASSETS).

export interface TiThreaticonActorIndexEntry {
  slug: string;
  id: number;
  name: string;
  mitreId: string | null;
  status: string | null;
  tlp: string | null;
  confidence: number | null;
  types: string[];
  originCode: string | null;
  countryOfOrigin: string | null;
  techniquesCount: number;
  toolsCount: number;
  targetedCountriesCount: number;
  tagsCount: number;
  added: string | null;
}

export interface TiThreaticonActorBody extends TiThreaticonActorIndexEntry {
  sophistication: string | null;
  resourceLevel: string | null;
  motivation: string | null;
  tags: string[];
  aliases: string[];
  targetedSectors: string[];
  targetedCountries: string[];
  tactics: string[];
  techniques: string[];
  tools: string[];
  iocPatterns: string[];
  keyCapabilities: string[];
  recommendedActions: string[];
  campaignsText: string | null;
  description: string | null;
  goals: string | null;
  killChain: string | null;
  sourceUrl: string;
}

export interface TiThreaticonIndex {
  source: string;
  url: string;
  description: string;
  syncedAt: string;
  builtAt: string;
  counts: {
    actors: number;
    actorsWithProfiles: number;
    malwareFamilies: number;
    malwareCategories: number;
    techniques: number;
    tactics: number;
    originCountries: number;
    targetedCountries: number;
    sectors: number;
  };
  tactics: Record<string, { techniqueCount: number; coveragePct: number }>;
  actors: TiThreaticonActorIndexEntry[];
}

export interface TiThreaticonMalwareEntry {
  id: number;
  name: string;
  category: string | null;
  tlp: string | null;
  confidence: number | null;
  status: string | null;
}

export interface TiThreaticonMalwareBody {
  source: string;
  syncedAt: string;
  familyCount: number;
  byCategory: Record<string, number>;
  families: TiThreaticonMalwareEntry[];
}

export interface TiThreaticonCoverageTechnique {
  patternId: number;
  techniqueId: string;
  name: string;
  tactic: string;
  rules: number;
}

export interface TiThreaticonCoverageBody {
  source: string;
  syncedAt: string;
  techniqueCount: number;
  tactics: Record<string, { techniqueCount: number; coveragePct: number }>;
  techniques: TiThreaticonCoverageTechnique[];
}

export interface TiThreaticonMapEntry {
  code: string;
  count: number;
}

export interface TiThreaticonMapBody {
  builtAt: string;
  origin: TiThreaticonMapEntry[];
  targeted: TiThreaticonMapEntry[];
  sectors: { sector: string; count: number }[];
}

// ─── dPhish phishing feed (dphish.com, TAXII 2.1) ───────────────────────
//
// A separate manifest tree under /data/threat-intel/dphish/ with its own
// lazy index: the public dPhish TAXII 2.1 collection of phishing
// indicators (malicious domains, phishing URLs, sender IPs, phone
// numbers, attachment rules). Mirrors the darknet/threatcluster pattern
// (own sync + build scripts, read through env.ASSETS).

export type DphishCategory = 'domain' | 'ipv4' | 'ipv6' | 'url' | 'phone' | 'file' | 'email' | 'other';

export interface DphishIndexEntry {
  slug: string;
  stixId: string | null;
  value: string | null;
  category: DphishCategory;
  mainObservableType: string | null;
  active: boolean;
  revoked: boolean;
  confidence: number | null;
  score: number | null;
  created: string | null;
  modified: string | null;
  validUntil: string | null;
  description: string | null;
  sizeBytes: number;
}

export interface DphishIndex {
  source: string;
  sourceUrl: string;
  collectionId: string;
  collectionUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  counts: {
    indicators: number;
    active: number;
    revoked: number;
    byCategory: Record<string, number>;
  };
  indicators: DphishIndexEntry[];
}

export interface DphishIndicatorBody extends DphishIndexEntry {
  name: string | null;
  observableValues: { type: string; value: string }[];
  pattern: string | null;
  patternType: string | null;
  validFrom: string | null;
  labels: string[];
  indicatorTypes: string[];
  detection: boolean | null;
}

// ─── Destroylist (phishdestroy/destroylist) ────────────────────────────

/** index.json emitted by scripts/build-destroylist.mjs. */
export interface TiDestroylistIndex {
  source: string;
  license: string;
  syncedAt: string;
  bucketCount: number;
  bucketsWritten: number;
  counts: {
    primary: number;
    primaryRoots: number;
    community: number | null;
    primaryActive: number | null;
  };
}

// ─── Living Threat Repository (living-threat.rabitanoor.com) ───────────
//
// A separate manifest tree under /data/threat-intel/living-threat/: the
// public Living Threat Repository API (github.com/HudKSD/Living-Threat,
// MIT) continuously maps real-world incidents to MITRE ATT&CK tactics and
// techniques. Bodies are AI-enriched (per-kill-chain-stage TTP mappings,
// detection + remediation notes, CVEs, actors, tools, priority scoring).
// The bootstrap API caps at 5000 docs, so the build ships the newest 5000
// in sharded files (10 × 500) to respect the 20k static-asset cap.

export interface LtTacticRef {
  tactic_id: string;
  tactic_name: string;
  tactic_description: string;
}

export interface LtTechniqueRef {
  technique_id: string;
  technique_name: string;
  technique_description: string;
}

export interface LtAnalysisStage {
  Stage: string;
  Description: string;
  Detection: string;
  Remediation: string;
  Tactics: LtTacticRef[];
  Technique_Details: LtTechniqueRef[];
  Techniques: string[];
}

export interface LivingThreatIndexEntry {
  slug: string;
  shard: number;
  sequence: number | null;
  id: string | null;
  title: string;
  timestamp: string | null;
  source: string;
  severity: string;
  priorityScore: number | null;
  relevanceScore: number | null;
  tactics: string[];
  techniques: string[];
  actors: string[];
  techniqueCount: number;
  cves: number;
  tools: number;
  sizeBytes: number;
}

export interface LivingThreatIndex {
  source: string;
  sourceUrl: string;
  repoUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  meta: {
    apiIndex: string | null;
    latestTs: string | null;
    latestSeq: number | null;
    anchorTs: string | null;
    fetchedAt: string | null;
    cap: string;
  };
  counts: {
    incidents: number;
    shards: number;
    shardSize: number;
    bySeverity: Record<string, number>;
    byTactic: Record<string, number>;
    uniqueCves: number;
    uniqueTechniques: number;
  };
  topTechniques: { id: string; count: number }[];
  topActors: { name: string; count: number }[];
  topTools: { name: string; count: number }[];
  topSources: { url: string; count: number }[];
  incidents: LivingThreatIndexEntry[];
}

export interface LivingThreatIncidentBody {
  slug: string;
  shard: number;
  sequence: number | null;
  id: string | null;
  index: string | null;
  source: string | null;
  Timestamp: string | null;
  Title: string | null;
  Severity: string | null;
  CVEs: string[];
  Threat_Actors: string[];
  Tools: string[];
  Analyses: LtAnalysisStage[];
  priority_score?: number | null;
  relevance_score?: number | null;
  operational_tags?: string[];
  doc_summary?: string | null;
  diamond_model_summary?: string | null;
  kill_chain_summary?: string | null;
  Detection_Hints?: string[];
  Detection_Rules_And_Indicators?: string[];
  Behavioral_Indicators_of_Attackers?: string[];
  Data_Exfiltration_Indicators?: string[];
  Pyramid_Of_Pain?: string[];
  Post_Incident_Recommendations?: string[];
  Extracted_Entities?: unknown;
  Adversary?: unknown;
  Victim?: unknown;
  Infrastructure?: unknown;
  Capability?: unknown;
}

// ─── MalwareAnalyzer by Cyble (malwareanalyzer.com) ────────────────────
//
// A separate manifest tree under /data/threat-intel/malwareanalyzer/: the
// free, keyless public API of MalwareAnalyzer by Cyble. Feeds are small
// flat records, so the build ships two whole-feed files + a slim index
// (only 4 static assets). Live reputation lookups go through
// worker/lib/malwareanalyzer.ts at request time.

export interface MaFeedEntry {
  url: string;
  hostname: string;
  apex: string | null;
  verdict: string;
  score: number | null;
  brands: string[];
  categories: string[];
  time: string | null;
}

export type MaFeedName = 'malicious' | 'newly-observed';

export interface MaIndex {
  source: string;
  sourceUrl: string;
  apiBase: string;
  description: string;
  license: string;
  syncedAt: string;
  counts: {
    malicious: number;
    newlyObserved: number;
    byVerdict: Record<string, number>;
    byCategory: Record<string, number>;
  };
  topApexes: { name: string; count: number }[];
  feeds: {
    malicious: MaFeedEntry[];
    newlyObserved: MaFeedEntry[];
  };
}

const DATA_PREFIX = '/data/threat-intel';
const MAX_BODY_CACHE = 200;

const cveBodyCache: BodyCache<TiCveBody> = { map: new Map(), hits: 0, misses: 0 };
const iocBodyCache: BodyCache<TiIocBody> = { map: new Map(), hits: 0, misses: 0 };
const sectorBodyCache: BodyCache<TiSectorBody> = { map: new Map(), hits: 0, misses: 0 };
const listBodyCache: BodyCache<TiDetectionListBody> = { map: new Map(), hits: 0, misses: 0 };
const darknetSiteCache: BodyCache<TiDarknetSiteBody> = { map: new Map(), hits: 0, misses: 0 };
const darknetCategoryCache: BodyCache<TiDarknetCategoryBody> = { map: new Map(), hits: 0, misses: 0 };
const tcClusterCache: BodyCache<TcClusterBody> = { map: new Map(), hits: 0, misses: 0 };
const tcVulnCache: BodyCache<TcVulnBody> = { map: new Map(), hits: 0, misses: 0 };
const tcExploitCache: BodyCache<TcExploitBody> = { map: new Map(), hits: 0, misses: 0 };
const tcVictimCache: BodyCache<TcVictimBody> = { map: new Map(), hits: 0, misses: 0 };
const tcEntityCache: BodyCache<TcEntityBody> = { map: new Map(), hits: 0, misses: 0 };
const tiActorCache: BodyCache<TiThreaticonActorBody> = { map: new Map(), hits: 0, misses: 0 };
const dphishBodyCache: BodyCache<DphishIndicatorBody> = { map: new Map(), hits: 0, misses: 0 };
const ltShardCache: BodyCache<LivingThreatIncidentBody[]> = { map: new Map(), hits: 0, misses: 0 };
const maFeedCache: BodyCache<MaFeedEntry[]> = { map: new Map(), hits: 0, misses: 0 };
let cachedIndex: TiIndex | null = null;
let cachedIndexAt: number | null = null;
let cachedKev: TiKevEntry[] | null = null;
let cachedKevAt: number | null = null;
let cachedTcIndex: TcThreatClusterIndex | null = null;
let cachedTcIndexAt: number | null = null;
let cachedTcIocs: TcIocsBody | null = null;
let cachedTcMisp: TcMispBody | null = null;
let cachedTcEntities: TcEntityIndex | null = null;
let cachedTcEntitiesAt: number | null = null;
let cachedTiIndex: TiThreaticonIndex | null = null;
let cachedTiIndexAt: number | null = null;
let cachedTiMalware: TiThreaticonMalwareBody | null = null;
let cachedTiCoverage: TiThreaticonCoverageBody | null = null;
let cachedTiMap: TiThreaticonMapBody | null = null;
let cachedDphishIndex: DphishIndex | null = null;
let cachedDphishIndexAt: number | null = null;
// ── Destroylist (phishdestroy/destroylist) ───────────────────────────
const destroylistBucketCache: BodyCache<string[]> = { map: new Map(), hits: 0, misses: 0 };
let cachedDestroylistIndex: TiDestroylistIndex | null = null;
let cachedDestroylistIndexAt: number | null = null;
let cachedDestroylistRoots: string[] | null = null;
let cachedLtIndex: LivingThreatIndex | null = null;
let cachedLtIndexAt: number | null = null;
let cachedMaIndex: MaIndex | null = null;
let cachedMaIndexAt: number | null = null;

function safeFilename(slug: string): string {
  return slug.replace(/\//g, '__').replace(/[^A-Za-z0-9._-]/g, '_');
}

// Fetch helper lives in manifest-cache.ts. The asset host is only an
// origin placeholder (env.ASSETS ignores it) but keeps cache keys readable.
async function fetchJson<T>(assets: Fetcher, path: string): Promise<T | null> {
  return fetchJsonAsset<T>(assets, path, 'https://ti.local');
}

export async function loadTiIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<TiIndex> {
  if (cachedIndex && !opts.forceRefresh) return cachedIndex;
  const idx = await fetchJson<TiIndex>(assets, `${DATA_PREFIX}/index.json`);
  if (!idx) {
    throw new Error(
      `Threat Intel manifest not found at ${DATA_PREFIX}/index.json — ` +
        'did the build run? Run `node scripts/build-threat-intel.mjs`.'
    );
  }
  cachedIndex = idx;
  cachedIndexAt = Date.now();
  return idx;
}

export async function getTiCve(assets: Fetcher, cveId: string): Promise<TiCveBody | null> {
  const key = cveId.toUpperCase();
  const hit = trackHit(cveBodyCache, key);
  if (hit) return hit;
  const body = await fetchJson<TiCveBody>(assets, `${DATA_PREFIX}/cves/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(cveBodyCache, key, body, MAX_BODY_CACHE);
}

export async function getTiIoc(assets: Fetcher, slug: string): Promise<TiIocBody | null> {
  const hit = trackHit(iocBodyCache, slug);
  if (hit) return hit;
  const body = await fetchJson<TiIocBody>(assets, `${DATA_PREFIX}/iocs/${safeFilename(slug)}.json`);
  if (!body) return null;
  return recordHit(iocBodyCache, slug, body, MAX_BODY_CACHE);
}

export async function getTiSector(assets: Fetcher, sector: string): Promise<TiSectorBody | null> {
  const key = sector.toLowerCase();
  const hit = trackHit(sectorBodyCache, key);
  if (hit) return hit;
  const body = await fetchJson<TiSectorBody>(assets, `${DATA_PREFIX}/sectors/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(sectorBodyCache, key, body, MAX_BODY_CACHE);
}

export async function getTiList(assets: Fetcher, slug: string): Promise<TiDetectionListBody | null> {
  const key = slug.toLowerCase();
  const hit = trackHit(listBodyCache, key);
  if (hit) return hit;
  const body = await fetchJson<TiDetectionListBody>(assets, `${DATA_PREFIX}/lists/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(listBodyCache, key, body, MAX_BODY_CACHE);
}

// ─── Darknet directory (darknetlist.is) ───────────────────────────────
//
// The darknet directory is a separate manifest tree under
// /data/threat-intel/darknet/. It has its own index + per-category and
// per-site bodies. We load the darknet index lazily (separate from the
// main TiIndex) because it changes every 30 minutes upstream and is
// fetched on a different sync cadence.

let cachedDarknetIndex: TiDarknetIndex | null = null;
let cachedDarknetIndexAt: number | null = null;

export async function loadDarknetIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TiDarknetIndex> {
  if (cachedDarknetIndex && !opts.forceRefresh) return cachedDarknetIndex;
  const idx = await fetchJson<TiDarknetIndex>(assets, `${DATA_PREFIX}/darknet/index.json`);
  if (!idx) {
    throw new Error(
      `Darknet directory manifest not found at ${DATA_PREFIX}/darknet/index.json — ` +
        'did the build run? Run `node scripts/sync-darknetlist.mjs && node scripts/build-darknetlist.mjs`.'
    );
  }
  cachedDarknetIndex = idx;
  cachedDarknetIndexAt = Date.now();
  return idx;
}

export async function getDarknetSite(assets: Fetcher, slug: string): Promise<TiDarknetSiteBody | null> {
  const key = slug.toLowerCase();
  const hit = trackHit(darknetSiteCache, key);
  if (hit) return hit;
  const body = await fetchJson<TiDarknetSiteBody>(assets, `${DATA_PREFIX}/darknet/sites/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(darknetSiteCache, key, body, MAX_BODY_CACHE);
}

export async function getDarknetCategory(assets: Fetcher, category: string): Promise<TiDarknetCategoryBody | null> {
  const key = category.toLowerCase();
  const hit = trackHit(darknetCategoryCache, key);
  if (hit) return hit;
  const body = await fetchJson<TiDarknetCategoryBody>(
    assets,
    `${DATA_PREFIX}/darknet/categories/${safeFilename(key)}.json`
  );
  if (!body) return null;
  return recordHit(darknetCategoryCache, key, body, MAX_BODY_CACHE);
}

export async function loadKevSnapshot(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<TiKevEntry[]> {
  if (cachedKev && !opts.forceRefresh) return cachedKev;
  const list = await fetchJson<TiKevEntry[]>(assets, `${DATA_PREFIX}/cves/kev.json`);
  if (!list) return [];
  cachedKev = list;
  cachedKevAt = Date.now();
  return list;
}

// ─── ThreatCluster feeds (threatcluster.io) ───────────────────────────
//
// A separate manifest tree under /data/threat-intel/threatcluster/ with
// its own lazy index: top-50 trending clusters, CVE vulnerability +
// exploit feeds, dark-web ransomware victims, a high-confidence IOC
// blocklist, and a slim MISP event pass-through. Loaded separately from
// the main TiIndex like the darknet directory (different sync cadence +
// upstream refresh).

export async function loadThreatClusterIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TcThreatClusterIndex> {
  if (cachedTcIndex && !opts.forceRefresh) return cachedTcIndex;
  const idx = await fetchJson<TcThreatClusterIndex>(assets, `${DATA_PREFIX}/threatcluster/index.json`);
  if (!idx) {
    throw new Error(
      `ThreatCluster manifest not found at ${DATA_PREFIX}/threatcluster/index.json — ` +
        'did the build run? Run `node scripts/sync-threatcluster.mjs && node scripts/build-threatcluster.mjs`.'
    );
  }
  cachedTcIndex = idx;
  cachedTcIndexAt = Date.now();
  return idx;
}

export async function getTcCluster(assets: Fetcher, slug: string): Promise<TcClusterBody | null> {
  const key = slug.toLowerCase();
  const hit = trackHit(tcClusterCache, key);
  if (hit) return hit;
  const body = await fetchJson<TcClusterBody>(
    assets,
    `${DATA_PREFIX}/threatcluster/clusters/${safeFilename(key)}.json`
  );
  if (!body) return null;
  return recordHit(tcClusterCache, key, body, MAX_BODY_CACHE);
}

export async function getTcVuln(assets: Fetcher, cveId: string): Promise<TcVulnBody | null> {
  const key = cveId.toUpperCase();
  const hit = trackHit(tcVulnCache, key);
  if (hit) return hit;
  const body = await fetchJson<TcVulnBody>(
    assets,
    `${DATA_PREFIX}/threatcluster/vulnerabilities/${safeFilename(key)}.json`
  );
  if (!body) return null;
  return recordHit(tcVulnCache, key, body, MAX_BODY_CACHE);
}

export async function getTcExploit(assets: Fetcher, cveId: string): Promise<TcExploitBody | null> {
  const key = cveId.toUpperCase();
  const hit = trackHit(tcExploitCache, key);
  if (hit) return hit;
  const body = await fetchJson<TcExploitBody>(
    assets,
    `${DATA_PREFIX}/threatcluster/exploits/${safeFilename(key)}.json`
  );
  if (!body) return null;
  return recordHit(tcExploitCache, key, body, MAX_BODY_CACHE);
}

export async function getTcVictim(assets: Fetcher, id: string): Promise<TcVictimBody | null> {
  const key = id.toLowerCase();
  const hit = trackHit(tcVictimCache, key);
  if (hit) return hit;
  const body = await fetchJson<TcVictimBody>(assets, `${DATA_PREFIX}/threatcluster/victims/${safeFilename(key)}.json`);
  if (!body) return null;
  return recordHit(tcVictimCache, key, body, MAX_BODY_CACHE);
}

export async function loadTcIocs(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<TcIocsBody | null> {
  if (cachedTcIocs && !opts.forceRefresh) return cachedTcIocs;
  const body = await fetchJson<TcIocsBody>(assets, `${DATA_PREFIX}/threatcluster/iocs.json`);
  if (!body) return null;
  cachedTcIocs = body;
  return body;
}

export async function loadTcMispEvents(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TcMispBody | null> {
  if (cachedTcMisp && !opts.forceRefresh) return cachedTcMisp;
  const body = await fetchJson<TcMispBody>(assets, `${DATA_PREFIX}/threatcluster/misp.json`);
  if (!body) return null;
  cachedTcMisp = body;
  return body;
}

export async function loadTcEntities(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<TcEntityIndex> {
  if (cachedTcEntities && !opts.forceRefresh) return cachedTcEntities;
  const idx = await fetchJson<TcEntityIndex>(assets, `${DATA_PREFIX}/threatcluster/entities/index.json`);
  if (!idx) {
    throw new Error(
      `ThreatCluster entity manifest not found at ${DATA_PREFIX}/threatcluster/entities/index.json — ` +
        'did the build run? Run `node scripts/build-tc-entities.mjs`.'
    );
  }
  cachedTcEntities = idx;
  cachedTcEntitiesAt = Date.now();
  return idx;
}

export async function getTcEntity(assets: Fetcher, type: TcEntityType, slug: string): Promise<TcEntityBody | null> {
  const key = `${type}/${slug.toLowerCase()}`;
  const hit = trackHit(tcEntityCache, key);
  if (hit) return hit;
  const body = await fetchJson<TcEntityBody>(
    assets,
    `${DATA_PREFIX}/threatcluster/entities/${type}/${safeFilename(slug.toLowerCase())}.json`
  );
  if (!body) return null;
  return recordHit(tcEntityCache, key, body, MAX_BODY_CACHE);
}

export function getTcEntityTypeOrNull(raw: string | undefined): TcEntityType | null {
  if (!raw) return null;
  const t = raw.toLowerCase() as TcEntityType;
  return TC_ENTITY_TYPES.includes(t) ? t : null;
}

// ─── Threaticon loaders ────────────────────────────────────────────────

export async function loadThreaticonIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TiThreaticonIndex> {
  if (cachedTiIndex && !opts.forceRefresh) return cachedTiIndex;
  const idx = await fetchJson<TiThreaticonIndex>(assets, `${DATA_PREFIX}/threaticon/index.json`);
  if (!idx) {
    throw new Error(
      `Threaticon manifest not found at ${DATA_PREFIX}/threaticon/index.json — ` +
        'did the build run? Run `node scripts/sync-threaticon.mjs && node scripts/build-threaticon.mjs`.'
    );
  }
  cachedTiIndex = idx;
  cachedTiIndexAt = Date.now();
  return idx;
}

export async function getThreaticonActor(assets: Fetcher, slug: string): Promise<TiThreaticonActorBody | null> {
  const key = slug.toLowerCase();
  const hit = trackHit(tiActorCache, key);
  if (hit) return hit;
  const body = await fetchJson<TiThreaticonActorBody>(
    assets,
    `${DATA_PREFIX}/threaticon/actors/${safeFilename(key)}.json`
  );
  if (!body) return null;
  return recordHit(tiActorCache, key, body, MAX_BODY_CACHE);
}

export async function loadThreaticonMalware(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TiThreaticonMalwareBody | null> {
  if (cachedTiMalware && !opts.forceRefresh) return cachedTiMalware;
  const body = await fetchJson<TiThreaticonMalwareBody>(assets, `${DATA_PREFIX}/threaticon/malware.json`);
  if (!body) return null;
  cachedTiMalware = body;
  return body;
}

export async function loadThreaticonCoverage(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TiThreaticonCoverageBody | null> {
  if (cachedTiCoverage && !opts.forceRefresh) return cachedTiCoverage;
  const body = await fetchJson<TiThreaticonCoverageBody>(assets, `${DATA_PREFIX}/threaticon/coverage.json`);
  if (!body) return null;
  cachedTiCoverage = body;
  return body;
}

export async function loadThreaticonMap(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TiThreaticonMapBody | null> {
  if (cachedTiMap && !opts.forceRefresh) return cachedTiMap;
  const body = await fetchJson<TiThreaticonMapBody>(assets, `${DATA_PREFIX}/threaticon/map.json`);
  if (!body) return null;
  cachedTiMap = body;
  return body;
}

export async function loadDphishIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<DphishIndex> {
  if (cachedDphishIndex && !opts.forceRefresh) return cachedDphishIndex;
  const idx = await fetchJson<DphishIndex>(assets, `${DATA_PREFIX}/dphish/index.json`);
  if (!idx) {
    throw new Error(
      `dPhish manifest not found at ${DATA_PREFIX}/dphish/index.json — ` +
        'did the build run? Run `node scripts/sync-dphish.mjs && node scripts/build-dphish.mjs`.'
    );
  }
  cachedDphishIndex = idx;
  cachedDphishIndexAt = Date.now();
  return idx;
}

export async function getDphishIndicator(assets: Fetcher, slug: string): Promise<DphishIndicatorBody | null> {
  const key = slug.toLowerCase();
  const hit = trackHit(dphishBodyCache, key);
  if (hit) return hit;
  const body = await fetchJson<DphishIndicatorBody>(
    assets,
    `${DATA_PREFIX}/dphish/indicators/${safeFilename(key)}.json`
  );
  if (!body) return null;
  return recordHit(dphishBodyCache, key, body, MAX_BODY_CACHE);
}

// ─── Destroylist loaders ──────────────────────────────────────────────

export async function loadDestroylistIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<TiDestroylistIndex | null> {
  if (cachedDestroylistIndex && !opts.forceRefresh) return cachedDestroylistIndex;
  const idx = await fetchJson<TiDestroylistIndex>(assets, `${DATA_PREFIX}/destroylist/index.json`);
  if (!idx) return null;
  cachedDestroylistIndex = idx;
  cachedDestroylistIndexAt = Date.now();
  return idx;
}

/**
 * Sorted root-domain rollup of the primary feed (roots.json). Consumed by
 * the blocklist builder's destroylist format and by search endpoints.
 */
export async function loadDestroylistRoots(assets: Fetcher): Promise<string[] | null> {
  if (cachedDestroylistRoots) return cachedDestroylistRoots;
  const roots = await fetchJson<string[]>(assets, `${DATA_PREFIX}/destroylist/roots.json`);
  if (!roots) return null;
  cachedDestroylistRoots = roots;
  return roots;
}

/** Same djb2 as scripts/build-destroylist.mjs — MUST stay in sync. */
const DESTROYLIST_BUCKETS = 64;
function destroylistBucketOf(domain: string): number {
  let h = 5381;
  const s = domain.toLowerCase();
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h % DESTROYLIST_BUCKETS;
}

async function getDestroylistBucket(assets: Fetcher, bucket: number): Promise<string[] | null> {
  const key = String(bucket).padStart(2, '0');
  const hit = trackHit(destroylistBucketCache, key);
  if (hit) return hit;
  const body = await fetchJson<string[]>(assets, `${DATA_PREFIX}/destroylist/buckets/${key}.json`);
  if (!body) return null;
  return recordHit(destroylistBucketCache, key, body, MAX_BODY_CACHE);
}

function binarySearch(sorted: string[], needle: string): boolean {
  let lo = 0;
  let hi = sorted.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const cmp = sorted[mid]!.localeCompare(needle);
    if (cmp === 0) return true;
    if (cmp < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

/**
 * Membership check against the replicated primary feed. Normalizes the
 * input (scheme/path/www/trailing-dot strip, lowercase), checks the exact
 * value, then walks up to two parent domains (subdomain → root) so a
 * phishing page on a listed apex matches too.
 *
 * Returns `null` when the manifest is unavailable (caller decides how to
 * degrade), otherwise `{ listed, matched }` where `matched` is the exact
 * feed entry that hit.
 */
export async function checkDestroylistDomain(
  assets: Fetcher | undefined,
  rawDomain: string
): Promise<{ listed: boolean; matched: string | null } | null> {
  if (!assets) return null;
  // Gate on the index: if it loads the manifest exists, and any bucket
  // miss afterwards means "empty bucket" (domain not listed), not absence.
  const idx = await loadDestroylistIndex(assets);
  if (!idx) return null;

  let d = rawDomain.trim().toLowerCase();
  try {
    if (d.includes('://')) d = new URL(d).hostname;
    else if (d.includes('/')) d = new URL(`https://${d}`).hostname;
  } catch {
    /* keep as-is */
  }
  d = d.replace(/^www\./i, '').replace(/\.$/, '');
  if (!d || !d.includes('.')) return { listed: false, matched: null };

  const candidates = [d];
  const parts = d.split('.');
  // Walk parent domains (max 2 hops: sub.sub.example.com → example.com).
  for (let i = 1; i < Math.min(parts.length - 1, 3); i += 1) {
    candidates.push(parts.slice(i).join('.'));
  }

  for (const candidate of candidates) {
    const bucket = await getDestroylistBucket(assets, destroylistBucketOf(candidate));
    if (!bucket) continue;
    if (binarySearch(bucket, candidate)) return { listed: true, matched: candidate };
  }
  return { listed: false, matched: null };
}

// ─── Living Threat loaders ──────────────────────────────────────────────

export async function loadLivingThreatIndex(
  assets: Fetcher,
  opts: { forceRefresh?: boolean } = {}
): Promise<LivingThreatIndex> {
  if (cachedLtIndex && !opts.forceRefresh) return cachedLtIndex;
  const idx = await fetchJson<LivingThreatIndex>(assets, `${DATA_PREFIX}/living-threat/index.json`);
  if (!idx) {
    throw new Error(
      `Living Threat manifest not found at ${DATA_PREFIX}/living-threat/index.json — ` +
        'did the build run? Run `node scripts/sync-living-threat.mjs && node scripts/build-living-threat.mjs`.'
    );
  }
  cachedLtIndex = idx;
  cachedLtIndexAt = Date.now();
  return idx;
}

export async function getLivingThreatIncident(assets: Fetcher, slug: string): Promise<LivingThreatIncidentBody | null> {
  const idx = await loadLivingThreatIndex(assets);
  const entry = idx.incidents.find((i) => i.slug === slug);
  if (!entry) return null;
  const shardKey = String(entry.shard).padStart(4, '0');
  const cacheKey = `shard-${shardKey}`;
  const hit = trackHit(ltShardCache, cacheKey);
  let shard: LivingThreatIncidentBody[] | null = hit ?? null;
  if (!shard) {
    shard = await fetchJson<LivingThreatIncidentBody[]>(assets, `${DATA_PREFIX}/living-threat/shards/${shardKey}.json`);
    if (!shard) return null;
    recordHit(ltShardCache, cacheKey, shard, MAX_BODY_CACHE);
  }
  return shard.find((b) => b.slug === slug) ?? null;
}

export interface TiListLivingThreatOptions {
  tactic?: string;
  technique?: string;
  severity?: string;
  actor?: string;
  keyword?: string;
  minPriority?: number;
  limit?: number;
}

export function filterLivingThreatIncidents(
  idx: LivingThreatIndex,
  opts: TiListLivingThreatOptions = {}
): LivingThreatIndexEntry[] {
  const { tactic, technique, severity, actor, keyword, minPriority, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const tacNeedle = tactic?.toLowerCase();
  const actNeedle = actor?.toLowerCase();
  const sevNeedle = severity?.toLowerCase();
  const out: LivingThreatIndexEntry[] = [];
  for (const e of idx.incidents) {
    if (sevNeedle && e.severity.toLowerCase() !== sevNeedle && !e.severity.toLowerCase().includes(sevNeedle)) continue;
    if (minPriority !== undefined && (e.priorityScore ?? 0) < minPriority) continue;
    if (tacNeedle && !e.tactics.some((t) => t.toLowerCase() === tacNeedle || t.toLowerCase().includes(tacNeedle)))
      continue;
    if (technique && !e.techniques.includes(technique.toUpperCase())) continue;
    if (actNeedle && !e.actors.some((a) => a.toLowerCase().includes(actNeedle))) continue;
    if (needle) {
      const hay = `${e.title} ${e.source} ${e.actors.join(' ')} ${e.techniques.join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── MalwareAnalyzer loaders ────────────────────────────────────────────

export async function loadMaIndex(assets: Fetcher, opts: { forceRefresh?: boolean } = {}): Promise<MaIndex> {
  if (cachedMaIndex && !opts.forceRefresh) return cachedMaIndex;
  const idx = await fetchJson<MaIndex>(assets, `${DATA_PREFIX}/malwareanalyzer/index.json`);
  if (!idx) {
    throw new Error(
      `MalwareAnalyzer manifest not found at ${DATA_PREFIX}/malwareanalyzer/index.json — ` +
        'did the build run? Run `node scripts/sync-malwareanalyzer.mjs && node scripts/build-malwareanalyzer.mjs`.'
    );
  }
  cachedMaIndex = idx;
  cachedMaIndexAt = Date.now();
  return idx;
}

export async function getMaFeed(assets: Fetcher, name: MaFeedName): Promise<MaFeedEntry[]> {
  const cacheKey = `feed-${name}`;
  const hit = trackHit(maFeedCache, cacheKey);
  if (hit) return hit;
  const feed = await fetchJson<MaFeedEntry[]>(assets, `${DATA_PREFIX}/malwareanalyzer/${name}.json`);
  if (!feed) return [];
  return recordHit(maFeedCache, cacheKey, feed, MAX_BODY_CACHE);
}

export interface TiListMaOptions {
  verdict?: string;
  category?: string;
  keyword?: string;
  limit?: number;
}

export function filterMaFeed(entries: MaFeedEntry[], opts: TiListMaOptions = {}): MaFeedEntry[] {
  const { verdict, category, keyword, limit = 200 } = opts;
  const needle = keyword?.toLowerCase();
  const out: MaFeedEntry[] = [];
  for (const e of entries) {
    if (verdict && e.verdict !== verdict) continue;
    if (category && !e.categories.some((c) => c.toLowerCase() === category.toLowerCase())) continue;
    if (needle && !`${e.url} ${e.hostname} ${e.apex ?? ''}`.toLowerCase().includes(needle)) continue;
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

export interface TiListDphishOptions {
  category?: string;
  /** Only indicators that are live right now (not revoked, within validity window if set). */
  activeOnly?: boolean;
  keyword?: string;
  limit?: number;
}

export function filterDphishIndicators(idx: DphishIndex, opts: TiListDphishOptions = {}): DphishIndexEntry[] {
  const { category, activeOnly, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const now = Date.now();
  const out: DphishIndexEntry[] = [];
  for (const i of idx.indicators) {
    if (category && i.category !== category) continue;
    if (activeOnly) {
      if (i.revoked) continue;
      if (i.validUntil) {
        const until = Date.parse(i.validUntil);
        if (!isNaN(until) && until < now) continue;
      }
    }
    if (needle) {
      const hay = `${i.value ?? ''} ${i.slug} ${i.mainObservableType ?? ''} ${i.description ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(i);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── Filter helpers ─────────────────────────────────────────────────────

export interface TiListCvesOptions {
  severity?: TiSeverity;
  kevOnly?: boolean;
  vendor?: string;
  daysBack?: number;
  minPriority?: number;
  keyword?: string;
  limit?: number;
  /** Only return CVEs whose Argus hype score is >= this value (0-100).
   *  CVEs without Argus data are excluded when this filter is active. */
  minArgusScore?: number;
}

export interface TiListIocsOptions {
  category?: TiIocIndexEntry['category'];
  keyword?: string;
  limit?: number;
}

function severityFromScore(score: number | null): TiSeverity {
  if (score === null) return 'unknown';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

export function filterCves(idx: TiIndex, opts: TiListCvesOptions = {}): TiCveIndexEntry[] {
  const { severity, kevOnly, vendor, daysBack, minPriority, keyword, minArgusScore, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const now = Date.now();
  const cutoffMs = daysBack ? daysBack * 86_400_000 : null;
  const vendorNeedle = vendor?.toLowerCase();

  const out: TiCveIndexEntry[] = [];
  for (const c of idx.cveIndex) {
    if (severity && c.cvssV3Severity !== severity) continue;
    if (kevOnly && !c.inKev) continue;
    if (vendorNeedle && !(c.vendor ?? '').toLowerCase().includes(vendorNeedle)) continue;
    if (minPriority !== undefined && c.priorityScore < minPriority) continue;
    if (cutoffMs) {
      const pub = Date.parse(c.publishedAt);
      if (!isNaN(pub) && now - pub > cutoffMs) continue;
    }
    if (minArgusScore !== undefined) {
      if (c.argusHypeScore === null || c.argusHypeScore < minArgusScore) continue;
    }
    if (needle) {
      const hay = `${c.cveId} ${c.vendor ?? ''} ${c.product ?? ''} ${c.description}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(c);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterIocs(idx: TiIndex, opts: TiListIocsOptions = {}): TiIocIndexEntry[] {
  const { category, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TiIocIndexEntry[] = [];
  for (const i of idx.iocIndex) {
    if (category && i.category !== category) continue;
    if (needle) {
      const hay = `${i.slug} ${i.family} ${i.aliases.join(' ')} ${i.description}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(i);
    if (out.length >= limit) break;
  }
  return out;
}

export interface TiListListsOptions {
  category?: string;
  keyword?: string;
  limit?: number;
}

export function filterLists(idx: TiIndex, opts: TiListListsOptions = {}): TiDetectionListIndexEntry[] {
  const { category, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TiDetectionListIndexEntry[] = [];
  for (const l of idx.listsIndex ?? []) {
    if (category && l.category !== category) continue;
    if (needle) {
      const hay = `${l.slug} ${l.title} ${l.description}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(l);
    if (out.length >= limit) break;
  }
  return out;
}

export interface TiSearchListEntriesOptions {
  keyword?: string;
  severity?: string;
  limit?: number;
}

export function searchListEntries(
  body: TiDetectionListBody,
  opts: TiSearchListEntriesOptions = {}
): TiDetectionListEntry[] {
  const { keyword, severity, limit = 500 } = opts;
  const needle = keyword?.toLowerCase();
  const sevNeedle = severity?.toLowerCase();
  const out: TiDetectionListEntry[] = [];
  for (const e of body.entries) {
    if (sevNeedle && (e.severity ?? '').toLowerCase() !== sevNeedle) continue;
    if (needle) {
      const hay = `${e.value} ${e.description ?? ''} ${e.tool ?? ''} ${e.category ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── Darknet directory filter helpers ─────────────────────────────────

export interface TiListDarknetOptions {
  category?: string;
  status?: 'up' | 'down';
  recommendedOnly?: boolean;
  onionOnly?: boolean;
  keyword?: string;
  limit?: number;
}

export function filterDarknetSites(idx: TiDarknetIndex, opts: TiListDarknetOptions = {}): TiDarknetSiteIndexEntry[] {
  const { category, status, recommendedOnly, onionOnly, keyword, limit = 200 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TiDarknetSiteIndexEntry[] = [];
  for (const s of idx.sites) {
    if (category && s.category !== category) continue;
    if (status && s.status !== status) continue;
    if (recommendedOnly && !s.recommended) continue;
    if (onionOnly && !s.isOnion) continue;
    if (needle) {
      const hay = `${s.name} ${s.dwdId ?? ''} ${s.category}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(s);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── ThreatCluster filter helpers ──────────────────────────────────────

export interface TcListClustersOptions {
  keyword?: string;
  limit?: number;
}

export interface TcListVulnsOptions {
  keyword?: string;
  limit?: number;
}

export interface TcListExploitsOptions {
  severity?: string;
  kevOnly?: boolean;
  keyword?: string;
  limit?: number;
}

export interface TcListVictimsOptions {
  group?: string;
  sector?: string;
  country?: string;
  keyword?: string;
  limit?: number;
}

export interface TcListIocsOptions {
  type?: string;
  keyword?: string;
  limit?: number;
}

export function filterTcClusters(idx: TcThreatClusterIndex, opts: TcListClustersOptions = {}): TcClusterIndexEntry[] {
  const { keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TcClusterIndexEntry[] = [];
  for (const c of idx.clusters) {
    if (needle && !`${c.title} ${c.slug}`.toLowerCase().includes(needle)) continue;
    out.push(c);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterTcVulns(idx: TcThreatClusterIndex, opts: TcListVulnsOptions = {}): TcVulnIndexEntry[] {
  const { keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TcVulnIndexEntry[] = [];
  for (const v of idx.vulnerabilities) {
    if (needle && !`${v.cveId} ${v.title}`.toLowerCase().includes(needle)) continue;
    out.push(v);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterTcExploits(idx: TcThreatClusterIndex, opts: TcListExploitsOptions = {}): TcExploitIndexEntry[] {
  const { severity, kevOnly, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const sevNeedle = severity?.toUpperCase();
  const out: TcExploitIndexEntry[] = [];
  for (const e of idx.exploits) {
    if (sevNeedle && e.severity !== sevNeedle) continue;
    if (kevOnly && !e.inKev) continue;
    if (needle && !`${e.cveId} ${e.title}`.toLowerCase().includes(needle)) continue;
    out.push(e);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterTcVictims(idx: TcThreatClusterIndex, opts: TcListVictimsOptions = {}): TcVictimIndexEntry[] {
  const { group, sector, country, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TcVictimIndexEntry[] = [];
  for (const v of idx.victims) {
    if (group && (v.group ?? '').toLowerCase() !== group.toLowerCase()) continue;
    if (sector && (v.sector ?? '').toLowerCase() !== sector.toLowerCase()) continue;
    if (country && (v.country ?? '').toLowerCase() !== country.toLowerCase()) continue;
    if (needle) {
      const hay = `${v.victim} ${v.group ?? ''} ${v.sector ?? ''} ${v.country ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(v);
    if (out.length >= limit) break;
  }
  return out;
}

export function filterTcIocs(iocs: TcIoc[], opts: TcListIocsOptions = {}): TcIoc[] {
  const { type, keyword, limit = 200 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TcIoc[] = [];
  for (const i of iocs) {
    if (type && i.type !== type) continue;
    if (needle) {
      const hay = `${i.value} ${i.reason ?? ''} ${i.sources.map((s) => s.source).join(' ')}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(i);
    if (out.length >= limit) break;
  }
  return out;
}

export interface TcListEntitiesOptions {
  type?: TcEntityType;
  keyword?: string;
  minMentions?: number;
  limit?: number;
}

/** Filter the entity index. With no `type` all five entity types are searched. */
export function filterTcEntities(idx: TcEntityIndex, opts: TcListEntitiesOptions = {}): TcEntityIndexEntry[] {
  const { type, keyword, minMentions, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TcEntityIndexEntry[] = [];
  const types = type ? [type] : TC_ENTITY_TYPES;
  for (const t of types) {
    for (const e of idx.entities[t] ?? []) {
      if (minMentions !== undefined && e.mentionCount < minMentions) continue;
      if (needle) {
        const hay = `${e.name} ${e.aliases.join(' ')}`.toLowerCase();
        if (!hay.includes(needle)) continue;
      }
      out.push(e);
      if (out.length >= limit) break;
    }
    if (out.length >= limit) break;
  }
  return out;
}

// ─── Threaticon filters ────────────────────────────────────────────────

export interface TiListThreaticonActorsOptions {
  type?: string;
  country?: string;
  tlp?: string;
  status?: string;
  hasMitre?: boolean;
  keyword?: string;
  limit?: number;
}

export function filterThreaticonActors(
  idx: TiThreaticonIndex,
  opts: TiListThreaticonActorsOptions = {}
): TiThreaticonActorIndexEntry[] {
  const { type, country, tlp, status, hasMitre, keyword, limit = 100 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TiThreaticonActorIndexEntry[] = [];
  for (const a of idx.actors) {
    if (type && !a.types.some((t) => t.toLowerCase().includes(type.toLowerCase()))) continue;
    if (country && a.originCode?.toLowerCase() !== country.toLowerCase()) continue;
    if (tlp && a.tlp?.toUpperCase() !== tlp.toUpperCase()) continue;
    if (status && a.status?.toLowerCase() !== status.toLowerCase()) continue;
    if (hasMitre && !a.mitreId) continue;
    if (needle) {
      const hay = `${a.name} ${a.mitreId ?? ''} ${a.types.join(' ')} ${a.countryOfOrigin ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) continue;
    }
    out.push(a);
    if (out.length >= limit) break;
  }
  return out;
}

export interface TiListThreaticonMalwareOptions {
  category?: string;
  keyword?: string;
  minConfidence?: number;
  limit?: number;
}

export function filterThreaticonMalware(
  body: TiThreaticonMalwareBody,
  opts: TiListThreaticonMalwareOptions = {}
): TiThreaticonMalwareEntry[] {
  const { category, keyword, minConfidence, limit = 200 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TiThreaticonMalwareEntry[] = [];
  for (const f of body.families) {
    if (category && f.category?.toLowerCase() !== category.toLowerCase()) continue;
    if (minConfidence !== undefined && (f.confidence ?? 0) < minConfidence) continue;
    if (needle && !`${f.name} ${f.category ?? ''}`.toLowerCase().includes(needle)) continue;
    out.push(f);
    if (out.length >= limit) break;
  }
  return out;
}

export interface TiListThreaticonCoverageOptions {
  tactic?: string;
  minRules?: number;
  keyword?: string;
  limit?: number;
}

export function filterThreaticonCoverage(
  body: TiThreaticonCoverageBody,
  opts: TiListThreaticonCoverageOptions = {}
): TiThreaticonCoverageTechnique[] {
  const { tactic, minRules, keyword, limit = 500 } = opts;
  const needle = keyword?.toLowerCase();
  const out: TiThreaticonCoverageTechnique[] = [];
  for (const t of body.techniques) {
    if (tactic && t.tactic.toLowerCase() !== tactic.toLowerCase()) continue;
    if (minRules !== undefined && t.rules < minRules) continue;
    if (needle && !`${t.techniqueId} ${t.name}`.toLowerCase().includes(needle)) continue;
    out.push(t);
    if (out.length >= limit) break;
  }
  return out;
}

// ─── Priority scoring ───────────────────────────────────────────────────

/**
 * Derive a 0-100 priority score from CVSS + KEV status + recency + (optional) Argus hype.
 * We intentionally re-derive this from first principles (per the AGPL
 * boundary on OpenThreat) — it's a small formula.
 *
 * Without Argus:
 *   cvss_norm = clamp(cvss / 10, 0, 1)        0-1
 *   kev_boost = 0.35 if inKev else 0
 *   recency   = 1 - days_since_published/365  0-1, drops to 0 at 1 year
 *   score     = round(100 * (0.55 * cvss_norm + kev_boost + 0.10 * recency))
 *
 * With Argus hypeScore (0-100), the CVSS weight shifts to 0.40 and
 * argus_norm = clamp(hypeScore / 100, 0, 1) gets a 0.15 weight:
 *   score     = round(100 * (0.40 * cvss_norm + kev_boost + 0.10 * recency + 0.15 * argus_norm))
 * Total weight always sums to ≤ 1.0, keeping the max at 100.
 */
export function computePriorityScore(opts: {
  cvssV3Score: number | null;
  inKev: boolean;
  publishedAt: string;
  nowMs?: number;
  /** Argus hype score (0-100). When provided, shifts CVSS weight and adds
   *  a trending-signal factor. Pass null to use the original formula. */
  argusHypeScore?: number | null;
}): number {
  const cvssNorm = opts.cvssV3Score === null ? 0 : Math.max(0, Math.min(1, opts.cvssV3Score / 10));
  const kevBoost = opts.inKev ? 0.35 : 0;
  const pub = Date.parse(opts.publishedAt);
  let recency = 0;
  if (!isNaN(pub)) {
    const nowRef = opts.nowMs ?? Date.now();
    const ageDays = (nowRef - pub) / 86_400_000;
    recency = Math.max(0, 1 - ageDays / 365);
  }
  const hasArgus = opts.argusHypeScore != null;
  const argusNorm = hasArgus ? Math.max(0, Math.min(1, opts.argusHypeScore! / 100)) : 0;
  const cvssWeight = hasArgus ? 0.4 : 0.55;
  return Math.round(100 * (cvssWeight * cvssNorm + kevBoost + 0.1 * recency + (hasArgus ? 0.15 * argusNorm : 0)));
}

// ─── Cache stats ───────────────────────────────────────────────────────

export function tiCacheStats(): {
  indexLoaded: boolean;
  indexAgeMs: number | null;
  kevLoaded: boolean;
  kevAgeMs: number | null;
  cves: { size: number; hits: number; misses: number };
  iocs: { size: number; hits: number; misses: number };
  sectors: { size: number; hits: number; misses: number };
  lists: { size: number; hits: number; misses: number };
  darknet: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    sites: { size: number; hits: number; misses: number };
    categories: { size: number; hits: number; misses: number };
  };
  threatcluster: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    clusters: { size: number; hits: number; misses: number };
    vulnerabilities: { size: number; hits: number; misses: number };
    exploits: { size: number; hits: number; misses: number };
    victims: { size: number; hits: number; misses: number };
    entities: {
      indexLoaded: boolean;
      indexAgeMs: number | null;
      bodies: { size: number; hits: number; misses: number };
    };
  };
  threaticon: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    malwareLoaded: boolean;
    coverageLoaded: boolean;
    mapLoaded: boolean;
    actors: { size: number; hits: number; misses: number };
  };
  dphish: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    bodies: { size: number; hits: number; misses: number };
  };
  destroylist: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    buckets: { size: number; hits: number; misses: number };
  };
  livingThreat: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    shards: { size: number; hits: number; misses: number };
  };
  malwareanalyzer: {
    indexLoaded: boolean;
    indexAgeMs: number | null;
    feeds: { size: number; hits: number; misses: number };
  };
} {
  return {
    indexLoaded: cachedIndex !== null,
    indexAgeMs: cachedIndexAt ? Date.now() - cachedIndexAt : null,
    kevLoaded: cachedKev !== null,
    kevAgeMs: cachedKevAt ? Date.now() - cachedKevAt : null,
    cves: { size: cveBodyCache.map.size, hits: cveBodyCache.hits, misses: cveBodyCache.misses },
    iocs: { size: iocBodyCache.map.size, hits: iocBodyCache.hits, misses: iocBodyCache.misses },
    sectors: { size: sectorBodyCache.map.size, hits: sectorBodyCache.hits, misses: sectorBodyCache.misses },
    lists: { size: listBodyCache.map.size, hits: listBodyCache.hits, misses: listBodyCache.misses },
    darknet: {
      indexLoaded: cachedDarknetIndex !== null,
      indexAgeMs: cachedDarknetIndexAt ? Date.now() - cachedDarknetIndexAt : null,
      sites: { size: darknetSiteCache.map.size, hits: darknetSiteCache.hits, misses: darknetSiteCache.misses },
      categories: {
        size: darknetCategoryCache.map.size,
        hits: darknetCategoryCache.hits,
        misses: darknetCategoryCache.misses,
      },
    },
    threatcluster: {
      indexLoaded: cachedTcIndex !== null,
      indexAgeMs: cachedTcIndexAt ? Date.now() - cachedTcIndexAt : null,
      clusters: { size: tcClusterCache.map.size, hits: tcClusterCache.hits, misses: tcClusterCache.misses },
      vulnerabilities: { size: tcVulnCache.map.size, hits: tcVulnCache.hits, misses: tcVulnCache.misses },
      exploits: { size: tcExploitCache.map.size, hits: tcExploitCache.hits, misses: tcExploitCache.misses },
      victims: { size: tcVictimCache.map.size, hits: tcVictimCache.hits, misses: tcVictimCache.misses },
      entities: {
        indexLoaded: cachedTcEntities !== null,
        indexAgeMs: cachedTcEntitiesAt ? Date.now() - cachedTcEntitiesAt : null,
        bodies: { size: tcEntityCache.map.size, hits: tcEntityCache.hits, misses: tcEntityCache.misses },
      },
    },
    threaticon: {
      indexLoaded: cachedTiIndex !== null,
      indexAgeMs: cachedTiIndexAt ? Date.now() - cachedTiIndexAt : null,
      malwareLoaded: cachedTiMalware !== null,
      coverageLoaded: cachedTiCoverage !== null,
      mapLoaded: cachedTiMap !== null,
      actors: { size: tiActorCache.map.size, hits: tiActorCache.hits, misses: tiActorCache.misses },
    },
    dphish: {
      indexLoaded: cachedDphishIndex !== null,
      indexAgeMs: cachedDphishIndexAt ? Date.now() - cachedDphishIndexAt : null,
      bodies: { size: dphishBodyCache.map.size, hits: dphishBodyCache.hits, misses: dphishBodyCache.misses },
    },
    destroylist: {
      indexLoaded: cachedDestroylistIndex !== null,
      indexAgeMs: cachedDestroylistIndexAt ? Date.now() - cachedDestroylistIndexAt : null,
      buckets: {
        size: destroylistBucketCache.map.size,
        hits: destroylistBucketCache.hits,
        misses: destroylistBucketCache.misses,
      },
    },
    livingThreat: {
      indexLoaded: cachedLtIndex !== null,
      indexAgeMs: cachedLtIndexAt ? Date.now() - cachedLtIndexAt : null,
      shards: { size: ltShardCache.map.size, hits: ltShardCache.hits, misses: ltShardCache.misses },
    },
    malwareanalyzer: {
      indexLoaded: cachedMaIndex !== null,
      indexAgeMs: cachedMaIndexAt ? Date.now() - cachedMaIndexAt : null,
      feeds: { size: maFeedCache.map.size, hits: maFeedCache.hits, misses: maFeedCache.misses },
    },
  };
}

export function _resetTiCacheForTests(): void {
  cveBodyCache.map.clear();
  iocBodyCache.map.clear();
  sectorBodyCache.map.clear();
  listBodyCache.map.clear();
  darknetSiteCache.map.clear();
  darknetCategoryCache.map.clear();
  cveBodyCache.hits = cveBodyCache.misses = 0;
  iocBodyCache.hits = iocBodyCache.misses = 0;
  sectorBodyCache.hits = sectorBodyCache.misses = 0;
  listBodyCache.hits = listBodyCache.misses = 0;
  darknetSiteCache.hits = darknetSiteCache.misses = 0;
  darknetCategoryCache.hits = darknetCategoryCache.misses = 0;
  cachedIndex = null;
  cachedIndexAt = null;
  cachedKev = null;
  cachedKevAt = null;
  cachedDarknetIndex = null;
  cachedDarknetIndexAt = null;
  tcClusterCache.map.clear();
  tcVulnCache.map.clear();
  tcExploitCache.map.clear();
  tcVictimCache.map.clear();
  tcEntityCache.map.clear();
  tcClusterCache.hits = tcClusterCache.misses = 0;
  tcVulnCache.hits = tcVulnCache.misses = 0;
  tcExploitCache.hits = tcExploitCache.misses = 0;
  tcVictimCache.hits = tcVictimCache.misses = 0;
  tcEntityCache.hits = tcEntityCache.misses = 0;
  cachedTcIndex = null;
  cachedTcIndexAt = null;
  cachedTcIocs = null;
  cachedTcMisp = null;
  cachedTcEntities = null;
  cachedTcEntitiesAt = null;
  tiActorCache.map.clear();
  tiActorCache.hits = tiActorCache.misses = 0;
  cachedTiIndex = null;
  cachedTiIndexAt = null;
  cachedTiMalware = null;
  cachedTiCoverage = null;
  cachedTiMap = null;
  dphishBodyCache.map.clear();
  dphishBodyCache.hits = dphishBodyCache.misses = 0;
  cachedDphishIndex = null;
  cachedDphishIndexAt = null;
  destroylistBucketCache.map.clear();
  destroylistBucketCache.hits = destroylistBucketCache.misses = 0;
  cachedDestroylistIndex = null;
  cachedDestroylistIndexAt = null;
  cachedDestroylistRoots = null;
  ltShardCache.map.clear();
  ltShardCache.hits = ltShardCache.misses = 0;
  cachedLtIndex = null;
  cachedLtIndexAt = null;
  maFeedCache.map.clear();
  maFeedCache.hits = maFeedCache.misses = 0;
  cachedMaIndex = null;
  cachedMaIndexAt = null;
}

export { severityFromScore };
