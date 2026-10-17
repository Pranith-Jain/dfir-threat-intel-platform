import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { githubHeaders } from '../lib/github-api';

import { fetchResilient } from '../lib/fetch-resilient';
import { readLastGood, writeLastGood } from '../lib/lastgood';

/**
 * GET /api/v1/volexity-threat-intel
 *
 * Mirrors Volexity's public threat-intel repo (github.com/volexity/threat-intel).
 * The repo is organized as per-blogpost research folders: `YYYY/<YYYY-MM-DD Title>/`
 * each carrying an `iocs.csv` (vendor APT indicators) and `*.yar` (YARA) / `*.rules`
 * (Snort) detection files.
 *
 * DESIGN — ONE upstream subrequest per refresh, NEVER a per-folder fan-out:
 *   • List mode (no `?folder=`): we fetch the repo's RECURSIVE git tree once
 *     (`/git/trees/main?recursive=1`, ~210 entries, `truncated:false`). That single
 *     call enumerates every folder AND its files, so we derive the full research-
 *     folder list (name, year, date, indicator-file presence, YARA/Snort download
 *     URLs) without walking each folder. Dual-cached.
 *   • Folder mode (`?folder=<name>`): we re-use the SAME cached tree to validate the
 *     folder exists + locate its `iocs.csv`, then make ONE additional subrequest to
 *     fetch that folder's `iocs.csv` on demand and parse it into typed IOCs
 *     (hashes / domains / ips / urls). The folder's detection-rule URLs come from the
 *     cached tree (no extra fetch). Separately dual-cached per folder.
 *
 * Public, key-gated read (NOT admin-gated). Dual-cache exactly like
 * supply-chain-attacks.ts / cloud-threat-landscape.ts (Cache-API L1 + KV last-good
 * with debounced writes). Untrusted upstream strings are length-capped; every
 * upstream URL is rendered through safeHref in the page.
 *
 * Attribution: Volexity publishes this repo under BSD-2-Clause — free to display
 * and cite with attribution to "Volexity". We echo `source`, `source_url`, and
 * `license` in every response so attribution is structural, and the UI credits +
 * links back. Neutral framing only (no endorsement).
 */

const OWNER = 'volexity';
const REPO = 'threat-intel';
const BRANCH = 'main';
// ONE upstream subrequest: the recursive git tree enumerates the whole repo.
const TREE_UPSTREAM = `https://api.github.com/repos/${OWNER}/${REPO}/git/trees/${BRANCH}?recursive=1`;
// Raw blob host for on-demand per-folder CSV fetches (folder mode).
const RAW_BASE = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/`;

const SOURCE = 'Volexity';
const SOURCE_URL = 'https://github.com/volexity/threat-intel';
const DEFAULT_LICENSE = 'BSD-2-Clause — Volexity threat-intel; free to display and cite with attribution to Volexity.';

const CACHE_TTL_SECONDS = 3600; // 1h — repo changes only when a new blogpost folder lands
const KV_TREE_KEY = 'volexity-ti:tree:lastgood:v1';
const KV_FOLDER_PREFIX = 'volexity-ti:folder:lastgood:v1:';
const KV_LAST_GOOD_TTL_SECONDS = 7 * 24 * 60 * 60;

const MAX_TREE_ENTRIES = 20_000; // defensive cap on an untrusted upstream array
const MAX_FOLDERS = 2000;
const MAX_FOLDER_LIST_LIMIT = 1000;
const MAX_IOCS_PER_FOLDER = 5000;
const MAX_CSV_BYTES = 5 * 1024 * 1024; // 5MB hard cap on a folder's iocs.csv
const MAX_RULE_FILES = 50;

// Detection-rule file extensions Volexity ships alongside iocs.csv.
const YARA_EXTS = ['.yar', '.yara'];
const SNORT_EXTS = ['.rules', '.rule', '.snort'];
// Indicator CSVs are usually `iocs.csv`; accept a couple of historical variants.
const INDICATOR_FILE_NAMES = new Set(['iocs.csv', 'indicators.csv', 'ioc.csv']);

interface RuleFile {
  name: string;
  kind: 'yara' | 'snort';
  download_url: string;
  size: number;
}
interface FolderEntry {
  /** Full repo-relative folder path, e.g. "2025/2025-10-08 UTA0388". */
  name: string;
  /** Display label (the folder's leaf, e.g. "2025-10-08 UTA0388"). */
  label: string;
  year: string;
  /** YYYY-MM-DD parsed from the folder leaf when present, else ''. */
  date: string;
  has_indicators: boolean;
  /** raw.githubusercontent.com URL for the indicators CSV, when present. */
  indicators_url: string;
  rule_files: RuleFile[];
}
interface TreeResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  mode: 'folders';
  /** Folder count AFTER any year/q/limit filter. */
  count: number;
  /** Total research folders BEFORE filtering. */
  total: number;
  /** Folder counts keyed by year (never filtered) so UI chips stay stable. */
  years: Record<string, number>;
  folders: FolderEntry[];
  stale?: boolean;
  upstream_error?: string;
}

interface Ioc {
  value: string;
  /** Normalized indicator kind. */
  kind: 'hash' | 'domain' | 'ipv4' | 'url' | 'email' | 'other';
  /** Upstream `entity_type` column verbatim (length-capped). */
  entity_type: string;
  description: string;
}
interface FolderResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  mode: 'folder';
  folder: string;
  label: string;
  year: string;
  date: string;
  indicators_url: string;
  rule_files: RuleFile[];
  /** IOC count AFTER capping. */
  count: number;
  /** Counts keyed by normalized kind. */
  kinds: Record<string, number>;
  iocs: Ioc[];
  stale?: boolean;
  upstream_error?: string;
}

// ── helpers ──────────────────────────────────────────────────────

function asString(v: unknown, max = 4000): string {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

function lastSegment(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] ?? '';
}

/** Encode each path segment for a raw.githubusercontent URL (spaces etc). */
function encodePath(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/');
}

function fileExt(name: string): string {
  const i = name.lastIndexOf('.');
  return i >= 0 ? name.slice(i).toLowerCase() : '';
}

/** A research folder is a directory directly under a 4-digit year: "YYYY/<leaf>". */
function parseFolderPath(path: string): { year: string; leaf: string } | null {
  const m = /^(\d{4})\/([^/]+)$/.exec(path);
  if (!m) return null;
  return { year: m[1]!, leaf: m[2]! };
}

/** Pull a leading YYYY-MM-DD out of a folder leaf, else ''. */
function dateFromLeaf(leaf: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(leaf);
  return m ? m[1]! : '';
}

/** Normalize an IOC value into a coarse kind for pivot/grouping. */
function classifyIoc(value: string, entityType: string): Ioc['kind'] {
  const et = entityType.toLowerCase();
  const v = value.trim();
  // Trust an explicit hash/file entity_type first.
  if (/(sha256|sha1|md5|hash|imphash|file)/.test(et) && /^[a-fA-F0-9]{32,64}$/.test(v)) {
    return 'hash';
  }
  if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
    return 'hash';
  }
  if (/^https?:\/\//i.test(v) || /^wss?:\/\//i.test(v) || v.includes('://')) return 'url';
  if (v.includes('@') && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return 'email';
  // Strip a trailing :port for IP/host detection.
  const host = v.replace(/:\d+$/, '');
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return 'ipv4';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return 'domain';
  return 'other';
}

/**
 * Minimal RFC-4180-ish CSV parser scoped to the Volexity `value,entity_type,
 * description` shape. Handles quoted fields + embedded commas/newlines/quotes.
 * Returns an array of string[] rows.
 */
function parseCsv(text: string, maxRows: number): string[][] {
  const rows: string[][] = [];
  let field = '';
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      if (rows.length >= maxRows + 1) break; // +1 for header
    } else if (ch === '\r') {
      // swallow; \n handles the row break
    } else {
      field += ch;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function bump(map: Record<string, number>, key: string): void {
  if (!key) return;
  map[key] = (map[key] ?? 0) + 1;
}

// ── tree -> folder list ──────────────────────────────────────────

interface RawTreeNode {
  path?: unknown;
  type?: unknown;
  size?: unknown;
}

function buildFolders(treeNodes: RawTreeNode[]): FolderEntry[] {
  // 1) collect directory paths that are "YYYY/<leaf>".
  const byPath = new Map<string, FolderEntry>();
  for (const n of treeNodes) {
    const path = asString(n.path, 600);
    if (n.type !== 'tree') continue;
    const parsed = parseFolderPath(path);
    if (!parsed) continue;
    if (byPath.size >= MAX_FOLDERS) break;
    const leaf = parsed.leaf;
    byPath.set(path, {
      name: path,
      label: leaf.slice(0, 200),
      year: parsed.year,
      date: dateFromLeaf(leaf),
      has_indicators: false,
      indicators_url: '',
      rule_files: [],
    });
  }

  // 2) attach files (indicators CSV + rule files) to their parent folder. We only
  //    look at blobs whose parent dir is exactly a known research folder.
  for (const n of treeNodes) {
    if (n.type !== 'blob') continue;
    const path = asString(n.path, 600);
    const slash = path.lastIndexOf('/');
    if (slash < 0) continue;
    const dir = path.slice(0, slash);
    const folder = byPath.get(dir);
    if (!folder) continue; // file lives in a subdir (e.g. attachments/) or non-folder
    const fname = lastSegment(path);
    const lower = fname.toLowerCase();
    const size = typeof n.size === 'number' ? n.size : 0;
    if (INDICATOR_FILE_NAMES.has(lower)) {
      folder.has_indicators = true;
      folder.indicators_url = RAW_BASE + encodePath(path);
      continue;
    }
    const ext = fileExt(lower);
    if (YARA_EXTS.includes(ext) || SNORT_EXTS.includes(ext)) {
      if (folder.rule_files.length >= MAX_RULE_FILES) continue;
      folder.rule_files.push({
        name: fname.slice(0, 200),
        kind: YARA_EXTS.includes(ext) ? 'yara' : 'snort',
        download_url: RAW_BASE + encodePath(path),
        size,
      });
    }
  }

  // 3) keep only folders that actually carry an indicator CSV or a detection rule.
  const folders = [...byPath.values()].filter((f) => f.has_indicators || f.rule_files.length > 0);
  // newest first by date (fallback: lexical path desc, which is year-prefixed).
  folders.sort((a, b) => (b.date || b.name).localeCompare(a.date || a.name));
  return folders;
}

function buildYears(folders: FolderEntry[]): Record<string, number> {
  const years: Record<string, number> = {};
  for (const f of folders) bump(years, f.year);
  return years;
}

function applyFolderListFilters(full: TreeResponse, q: { year?: string; q?: string; limit?: number }): TreeResponse {
  let folders = full.folders;
  if (q.year) folders = folders.filter((f) => f.year === q.year);
  if (q.q) {
    const needle = q.q.toLowerCase();
    folders = folders.filter((f) => f.label.toLowerCase().includes(needle));
  }
  if (typeof q.limit === 'number') folders = folders.slice(0, q.limit);
  return { ...full, folders, count: folders.length };
}

// ── main handler ─────────────────────────────────────────────────

export async function volexityThreatIntelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const folderQ = c.req.query('folder')?.trim();
  const year = c.req.query('year')?.trim();
  const q = c.req.query('q')?.trim();
  const limitRaw = c.req.query('limit');
  const limit = limitRaw ? Math.min(parseInt(limitRaw, 10) || MAX_FOLDER_LIST_LIMIT, MAX_FOLDER_LIST_LIMIT) : undefined;

  const cache = (caches as unknown as { default: Cache }).default;
  // api.github.com (git trees API) — shares the Worker egress quota; a 403
  // here blanks the whole VOLT file tree. Authenticated when GITHUB_TOKEN set.
  const ghHeaders: Record<string, string> = githubHeaders(c.env);

  // ─────────── load the repo tree (ONE subrequest, dual-cached) ───────────
  // Both modes need the tree: folder-list mode returns it; folder mode validates
  // the requested folder + sources the rule-file URLs from it.
  async function loadTree(): Promise<{ full: TreeResponse | null; error: string }> {
    let upstreamError = '';
    try {
      const res = await fetchResilient(
        TREE_UPSTREAM,
        { headers: ghHeaders, cf: { cacheTtl: CACHE_TTL_SECONDS, cacheEverything: true } } as RequestInit,
        { attempts: 3, timeoutMs: 20_000 }
      );
      if (res.ok) {
        const data = (await res.json()) as { tree?: unknown };
        const rawNodes = Array.isArray(data.tree) ? (data.tree.slice(0, MAX_TREE_ENTRIES) as RawTreeNode[]) : [];
        const folders = buildFolders(rawNodes);
        const full: TreeResponse = {
          source: SOURCE,
          source_url: SOURCE_URL,
          license: DEFAULT_LICENSE,
          generated_at: new Date().toISOString(),
          mode: 'folders',
          count: folders.length,
          total: folders.length,
          years: buildYears(folders),
          folders,
        };
        return { full, error: '' };
      }
      upstreamError = `upstream ${res.status}`;
    } catch (err) {
      logError('loadTree failed', err);
      upstreamError = err instanceof Error ? err.message : 'fetch failed';
    }
    // fall back to KV last-good tree
    const staleFull = await readLastGood<TreeResponse>(c.env, KV_TREE_KEY, { keyPrefix: '' });
    if (staleFull) {
      return { full: { ...staleFull, stale: true, upstream_error: upstreamError }, error: upstreamError };
    }
    return { full: null, error: upstreamError || 'no data' };
  }

  // ─────────── FOLDER MODE: parse one folder's iocs.csv on demand ──────────
  if (folderQ) {
    const folderCacheKey = new Request(`https://volexity-ti-cache.internal/v1/folder?f=${encodeURIComponent(folderQ)}`);
    const cachedFolder = await cache.match(folderCacheKey);
    if (cachedFolder) return new Response(cachedFolder.body, cachedFolder);

    // We need the (cached) tree to validate the folder + find its files.
    const { full: tree } = await loadTree();
    const meta = tree?.folders.find((f) => f.name === folderQ);
    if (!meta) {
      return c.json(
        {
          error: 'unknown Volexity folder',
          message: 'folder not found in the volexity/threat-intel repo tree',
          source: SOURCE,
          source_url: SOURCE_URL,
        },
        404,
        { 'Cache-Control': 'no-store' }
      );
    }

    let folderResp: FolderResponse | null = null;
    let upstreamError = '';
    if (meta.has_indicators && meta.indicators_url) {
      try {
        const res = await fetchResilient(
          meta.indicators_url,
          {
            headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'text/csv,text/plain' },
            cf: { cacheTtl: CACHE_TTL_SECONDS, cacheEverything: true },
          } as RequestInit,
          { attempts: 3, timeoutMs: 20_000 }
        );
        if (res.ok) {
          let csv = await res.text();
          if (csv.length > MAX_CSV_BYTES) csv = csv.slice(0, MAX_CSV_BYTES);
          const rows = parseCsv(csv, MAX_IOCS_PER_FOLDER);
          // header: value,entity_type,description (case/whitespace tolerant)
          const header = (rows[0] ?? []).map((h) => h.trim().toLowerCase());
          let vi = header.indexOf('value');
          let ti = header.indexOf('entity_type');
          let di = header.indexOf('description');
          let dataRows = rows.slice(1);
          // If there's no recognizable header, treat every row as data, col0=value.
          if (vi < 0 && ti < 0 && di < 0) {
            vi = 0;
            ti = 1;
            di = 2;
            dataRows = rows;
          } else {
            if (vi < 0) vi = 0;
          }
          const kinds: Record<string, number> = {};
          const iocs: Ioc[] = [];
          for (const r of dataRows) {
            const value = asString(r[vi], 1024).trim();
            if (!value) continue;
            const entity_type = ti >= 0 ? asString(r[ti], 80).trim() : '';
            const description = di >= 0 ? asString(r[di], 600).trim() : '';
            const kind = classifyIoc(value, entity_type);
            iocs.push({ value, kind, entity_type, description });
            bump(kinds, kind);
            if (iocs.length >= MAX_IOCS_PER_FOLDER) break;
          }
          folderResp = {
            source: SOURCE,
            source_url: SOURCE_URL,
            license: DEFAULT_LICENSE,
            generated_at: new Date().toISOString(),
            mode: 'folder',
            folder: meta.name,
            label: meta.label,
            year: meta.year,
            date: meta.date,
            indicators_url: meta.indicators_url,
            rule_files: meta.rule_files,
            count: iocs.length,
            kinds,
            iocs,
          };
        } else {
          upstreamError = `upstream ${res.status}`;
        }
      } catch (err) {
        logError('handler failed', err);
        upstreamError = err instanceof Error ? err.message : 'fetch failed';
      }
    } else {
      // No indicator CSV — still a valid folder (rules-only). Return an empty IOC set.
      folderResp = {
        source: SOURCE,
        source_url: SOURCE_URL,
        license: DEFAULT_LICENSE,
        generated_at: new Date().toISOString(),
        mode: 'folder',
        folder: meta.name,
        label: meta.label,
        year: meta.year,
        date: meta.date,
        indicators_url: meta.indicators_url,
        rule_files: meta.rule_files,
        count: 0,
        kinds: {},
        iocs: [],
      };
    }

    // CSV fetch failed → serve KV last-good for this folder, marked stale.
    if (!folderResp) {
      const staleFull = await readLastGood<FolderResponse>(c.env, KV_FOLDER_PREFIX + meta.name, { keyPrefix: '' });
      if (staleFull) {
        return c.json({ ...staleFull, stale: true, upstream_error: upstreamError }, 200, {
          'Cache-Control': 'public, max-age=300',
        });
      }
      return c.json(
        {
          error: 'Volexity indicators unavailable',
          message: upstreamError || 'no data',
          source: SOURCE,
          source_url: SOURCE_URL,
        },
        502,
        { 'Cache-Control': 'no-store' }
      );
    }

    const fResponse = c.json(folderResp, 200, { 'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}` });
    c.executionCtx.waitUntil(cache.put(folderCacheKey, fResponse.clone()));
    c.executionCtx.waitUntil(
      writeLastGood(c.env, KV_FOLDER_PREFIX + meta.name, folderResp, {
        ttlSeconds: KV_LAST_GOOD_TTL_SECONDS,
        keyPrefix: '',
      })
    );
    return fResponse;
  }

  // ─────────── LIST MODE: research-folder listing (dual-cached) ───────────
  const listCacheKey = new Request(
    `https://volexity-ti-cache.internal/v1/folders?y=${year ?? ''}&q=${q ?? ''}&lim=${limit ?? ''}`
  );
  const cachedList = await cache.match(listCacheKey);
  if (cachedList) return new Response(cachedList.body, cachedList);

  const { full, error } = await loadTree();
  const filterQ = { year, q, limit };

  if (!full) {
    return c.json(
      { error: 'volexity/threat-intel unavailable', message: error, source: SOURCE, source_url: SOURCE_URL },
      502,
      { 'Cache-Control': 'no-store' }
    );
  }

  // If `full` came from KV last-good it carries stale:true — propagate it.
  if (full.stale) {
    const out = applyFolderListFilters(full, filterQ);
    return c.json(out, 200, { 'Cache-Control': 'public, max-age=300' });
  }

  const body = applyFolderListFilters(full, filterQ);
  const response = c.json(body, 200, { 'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}` });
  c.executionCtx.waitUntil(cache.put(listCacheKey, response.clone()));

  // Refresh KV last-good with the FULL (unfiltered) tree so any filter combo can
  // degrade gracefully. Debounced so we don't write on every cache miss.
  c.executionCtx.waitUntil(
    writeLastGood(c.env, KV_TREE_KEY, full, { ttlSeconds: KV_LAST_GOOD_TTL_SECONDS, keyPrefix: '' })
  );

  return response;
}
