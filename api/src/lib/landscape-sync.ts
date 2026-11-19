/**
 * Shared sync logic for the curated "landscape" endpoints.
 *
 * Two endpoints, one module:
 *   /api/v1/owasp-ai-landscape — tree of OWASP AI/ML projects, auto-synced
 *     daily from the public `RicoKomenda/owasp-ai-security-visualizer`
 *     data.json (raw.githubusercontent.com serves it without bot
 *     challenges, unlike start.me).
 *
 *   /api/v1/curated-toolbox — start.me "Mastering Threat Intelligence
 *     Platforms" mirror, refreshed via Jina Reader (r.jina.ai) on a
 *     daily cron. Jina gives us a clean markdown rendering even
 *     though start.me is behind a Cloudflare bot challenge.
 *
 *   /api/v1/curated-certs — start.me "Free Certification Courses by
 *     Syberseeker" mirror, sharing the same Jina-Reader pipeline
 *     and the same generic sync/get/get-meta engine (see
 *     syncCuratedMirror / getCuratedHandler / getCuratedMetaHandler).
 *     A new start.me page is one entry in MIRRORS + one SEED, not
 *     a new sync fn.
 *
 * Storage model: one KV value per endpoint at well-known keys. Each
 * value is the full payload the page renders. A `*meta` companion
 * stores last-success + error so the UI can show "synced 3h ago".
 *
 * Cold start: GET returns the bundled seed (in this same module) so a
 * single deploy gives a working page before the first cron fires.
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { kvPutIfChanged } from './safe-catch';

// ── Constants ──────────────────────────────────────────────────────────
export const OWASP_AI_LANDSCAPE_KV_KEY = 'owasp-ai-landscape:v1';
export const OWASP_AI_LANDSCAPE_META_KEY = 'owasp-ai-landscape:meta:v1';
export const CURATED_TOOLBOX_KV_KEY = 'curated-toolbox:v1';
export const CURATED_TOOLBOX_META_KEY = 'curated-toolbox:meta:v1';
export const CURATED_CERTS_KV_KEY = 'curated-certs:v1';
export const CURATED_CERTS_META_KEY = 'curated-certs:meta:v1';
/** 30 days — landscape data is overwritten by daily cron, but a stale
 *  key is still useful fallback. Prevents orphaned keys if sync stops. */
const DATA_TTL_S = 30 * 24 * 3600;
/** 7 days — meta is rewritten every sync; TTL prevents orphaned keys. */
const META_TTL_S = 7 * 24 * 3600;

/**
 * Per-source start.me mirror configuration. Two parallel mirrors live in
 * this module: the long-standing "Mastering Threat Intelligence Platforms"
 * toolbox and the newer "Free Certification Courses by Syberseeker" page.
 * Both share the same Jina-Reader fetch + markdown-parse pipeline; only
 * the upstream URL, KV keys, and bundled seed differ. A future third
 * mirror is one new entry in MIRRORS + one new SEED, not a new sync fn.
 */
export interface CuratedMirror {
  id: 'toolbox' | 'certs';
  startmeUrl: string;
  kvKey: string;
  metaKey: string;
  /** Cache-API shadow discriminator — must be unique per mirror. */
  shadowKind: 'curated' | 'curated-certs';
}

export const MIRRORS: readonly CuratedMirror[] = [
  {
    id: 'toolbox',
    startmeUrl: 'https://start.me/p/gGj8gn/mastering-threat-intelligence-platforms',
    kvKey: CURATED_TOOLBOX_KV_KEY,
    metaKey: CURATED_TOOLBOX_META_KEY,
    shadowKind: 'curated',
  },
  {
    id: 'certs',
    startmeUrl: 'https://start.me/p/xb2ReR/free-certification-courses-by-syberseeker',
    kvKey: CURATED_CERTS_KV_KEY,
    metaKey: CURATED_CERTS_META_KEY,
    shadowKind: 'curated-certs',
  },
] as const;

const USER_AGENT = 'Mozilla/5.0 (compatible; portfolio-landscape-sync/1.0)';
const FETCH_TIMEOUT_MS = 20_000;
const CACHE_MAX_AGE_S = 300; // serve stale up to 5 min while we revalidate

/**
 * Per-colo Cache API shadow for the OWASP AI Landscape / Curated Toolbox
 * payload. KV reads cost quota; per-colo `caches.default` is free. The
 * shape of the data — large JSON, low write rate, identical across colos
 * — is the textbook case for cache-API-as-L1 + KV-as-L2.
 *
 * `writeShadow` runs on the (rare) cron-sync write-through so a freshly
 * fetched payload is available to all colos without each one re-reading
 * from KV. `readShadow` is the hot path: ~1 KV read per colo per TTL
 * window instead of per origin request.
 */
function shadowCacheReq(kind: string, kvKey: string): Request {
  // Encode the KV key into the URL so a key bump (e.g. v1 → v2) auto-busts.
  return new Request(`https://landscape-shadow.internal/v1/${kind}/${encodeURIComponent(kvKey)}`);
}

/* ─────────────────────────── OWASP AI Landscape ─────────────────────── */

export type OwaspNodeType = 'umbrella' | 'sub-umbrella' | 'guide' | 'standard' | 'cheat sheet' | 'tool' | 'ctf';

export interface OwaspNode {
  title: string;
  description: string;
  url: string;
  type: OwaspNodeType;
  children?: OwaspNode[];
}

export interface OwaspLandscapePayload {
  name: string;
  description: string;
  source: string;
  fetchedAt: string;
  nodes: OwaspNode[];
}

interface OwaspMeta {
  source: string;
  fetchedAt: string;
  ok: boolean;
  error?: string;
  counts?: { umbrellas: number; subUmbrellas: number; leaves: number };
}

const OWASP_RAW_URL = 'https://raw.githubusercontent.com/RicoKomenda/owasp-ai-security-visualizer/main/data.json';

/** Loose shape of the upstream tree (fields optional; leaves use `title`,
 *  internal nodes use `name`). */
interface RawOwaspNode {
  title?: unknown;
  name?: unknown;
  description?: unknown;
  url?: unknown;
  type?: unknown;
  children?: RawOwaspNode[];
}

/** Normalize: source uses `name` for internal nodes, `title` for leaves. */
function normalizeNode(raw: RawOwaspNode): OwaspNode | null {
  if (!raw || typeof raw !== 'object') return null;
  const title = (raw.title ?? raw.name ?? '').toString().trim();
  const description = (raw.description ?? '').toString().trim();
  const url = (raw.url ?? '').toString().trim();
  const type = (raw.type ?? 'guide').toString().trim() as OwaspNodeType;
  if (!title) return null;
  const node: OwaspNode = { title, description, url, type };
  if (Array.isArray(raw.children) && raw.children.length > 0) {
    const kids: OwaspNode[] = [];
    for (const c of raw.children) {
      const n = normalizeNode(c);
      if (n) kids.push(n);
    }
    node.children = kids;
  }
  return node;
}

function countNodes(nodes: OwaspNode[]): { umbrellas: number; subUmbrellas: number; leaves: number } {
  let umbrellas = 0;
  let subUmbrellas = 0;
  let leaves = 0;
  const walk = (n: OwaspNode) => {
    if (n.type === 'umbrella') umbrellas += 1;
    else if (n.type === 'sub-umbrella') subUmbrellas += 1;
    else leaves += 1;
    for (const c of n.children ?? []) walk(c);
  };
  for (const n of nodes) walk(n);
  return { umbrellas, subUmbrellas, leaves };
}

/** Manual fallback used until the first successful cron run. */
export const OWASP_AI_LANDSCAPE_SEED: OwaspLandscapePayload = {
  name: 'OWASP AI Security Landscape',
  description: 'A comprehensive overview of OWASP resources for AI and machine learning security.',
  source: 'seed:v1',
  fetchedAt: '1970-01-01T00:00:00.000Z',
  nodes: [
    {
      title: 'OWASP Generative AI',
      description:
        'The OWASP GenAI Security Project — global community delivering peer-reviewed guidance on securing LLMs, generative AI, and agentic systems.',
      url: 'https://genai.owasp.org/',
      type: 'umbrella',
      children: [
        {
          title: 'Agentic Security Initiative',
          description: 'Focused on the unique security challenges of autonomous AI and agentic systems.',
          url: 'https://genai.owasp.org/initiatives/agentic-security-initiative/',
          type: 'sub-umbrella',
          children: [
            {
              title: 'Top 10 for Agentic Applications 2026',
              description: 'Globally peer-reviewed framework for autonomous/agentic AI systems.',
              url: 'https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/',
              type: 'guide',
            },
            {
              title: 'Agentic AI Threats and Mitigations',
              description: 'Threat-model-based reference of emerging agentic threats and mitigations.',
              url: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/',
              type: 'guide',
            },
            {
              title: 'Securing Agentic Applications Guide 1.0',
              description:
                'Practical guidance for designing, developing, and deploying secure LLM-powered agentic applications.',
              url: 'https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/',
              type: 'guide',
            },
          ],
        },
        {
          title: 'GenAI Red Teaming Initiative',
          description: 'Standardized AI red teaming methodologies, benchmarks, and evaluation frameworks for LLMs.',
          url: 'https://genai.owasp.org/initiatives/genai-red-teaming-initiative/',
          type: 'sub-umbrella',
          children: [
            {
              title: 'GenAI Red Teaming Guide',
              description: 'How to red-team generative AI: methodology, scope, reporting.',
              url: 'https://genai.owasp.org/resource/genai-red-teaming-guide/',
              type: 'guide',
            },
          ],
        },
      ],
    },
    {
      title: 'OWASP AI Security & Privacy Guide',
      description: 'Cross-cutting guide covering AI threats, privacy, and engineering best practices.',
      url: 'https://owasp.org/www-project-ai-security-and-privacy-guide/',
      type: 'umbrella',
      children: [
        {
          title: 'AI Security & Privacy Guide',
          description: 'Engineering-level guide to securing AI systems and protecting user privacy.',
          url: 'https://owasp.org/www-project-ai-security-and-privacy-guide/',
          type: 'guide',
        },
        {
          title: 'Cheat Sheet: LLM Prompt Injection',
          description: 'Defensive cheat sheet for prompt-injection-class attacks.',
          url: 'https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html',
          type: 'cheat sheet',
        },
      ],
    },
    {
      title: 'OWASP Machine Learning Top 10',
      description: 'Classic ML (non-LLM) attack taxonomy and mitigations.',
      url: 'https://owasp.org/www-project-machine-learning-security-top-10/',
      type: 'umbrella',
      children: [
        {
          title: 'ML Top 10 (2023)',
          description: 'Ten most critical ML security risks — input manipulation, model theft, data poisoning.',
          url: 'https://owasp.org/www-project-machine-learning-security-top-10/',
          type: 'standard',
        },
      ],
    },
  ],
};

export async function syncOwaspAiLandscape(
  env: Env
): Promise<{ ok: boolean; error?: string; counts?: { umbrellas: number; subUmbrellas: number; leaves: number } }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(OWASP_RAW_URL, {
      headers: { 'user-agent': USER_AGENT, accept: 'application/json' },
      signal: ctrl.signal,
    });
    if (!res.ok) return { ok: false, error: `upstream ${res.status}` };
    const raw = (await res.json()) as { name?: string; description?: string; children?: RawOwaspNode[] };
    const nodes: OwaspNode[] = [];
    for (const c of raw.children ?? []) {
      const n = normalizeNode(c);
      if (n) nodes.push(n);
    }
    const counts = countNodes(nodes);
    const payload: OwaspLandscapePayload = {
      name: raw.name ?? OWASP_AI_LANDSCAPE_SEED.name,
      description: raw.description ?? OWASP_AI_LANDSCAPE_SEED.description,
      source: OWASP_RAW_URL,
      fetchedAt: new Date().toISOString(),
      nodes,
    };
    if (env.KV_CACHE) {
      // Skip the put when the payload is byte-identical to what's already
      // in KV -- the OWASP upstream updates ~once/day, but the hourly cron
      // re-fetches it. Without this guard we burn a free-tier write every
      // tick (1 read + 1 write = 1 wasted write 23 hours out of 24).
      await kvPutIfChanged(env, OWASP_AI_LANDSCAPE_KV_KEY, JSON.stringify(payload), {
        expirationTtl: DATA_TTL_S,
      });
      const meta: OwaspMeta = { source: OWASP_RAW_URL, fetchedAt: payload.fetchedAt, ok: true, counts };
      await env.KV_CACHE.put(OWASP_AI_LANDSCAPE_META_KEY, JSON.stringify(meta), { expirationTtl: META_TTL_S });
      // Write-through to the per-colo cache shadow so readers in colos that
      // already have a stale L1 entry pick up the new value on the next
      // request (instead of serving stale for up to CACHE_MAX_AGE_S).
      try {
        const cache = (caches as unknown as { default: Cache }).default;
        await cache.put(
          shadowCacheReq('owasp', OWASP_AI_LANDSCAPE_KV_KEY),
          new Response(JSON.stringify(payload), {
            headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
          })
        );
        await cache.put(
          shadowCacheReq('owasp-meta', OWASP_AI_LANDSCAPE_META_KEY),
          new Response(JSON.stringify(meta), {
            headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
          })
        );
      } catch {
        /* best-effort */
      }
    }
    return { ok: true, counts };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (env.KV_CACHE) {
      const meta: OwaspMeta = {
        source: OWASP_RAW_URL,
        fetchedAt: new Date().toISOString(),
        ok: false,
        error: msg,
      };
      await env.KV_CACHE.put(OWASP_AI_LANDSCAPE_META_KEY, JSON.stringify(meta), { expirationTtl: META_TTL_S });
    }
    return { ok: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}

export async function getOwaspAiLandscapeHandler(c: Context<{ Bindings: Env }>) {
  const kv = c.env.KV_CACHE;
  if (!kv) {
    return c.json(OWASP_AI_LANDSCAPE_SEED, 200, { 'cache-control': 'public, max-age=60' });
  }
  // L1: per-colo Cache API. Hot path — collapses N origin requests/colo
  // to 1 KV read per TTL window.
  const cache = (caches as unknown as { default: Cache }).default;
  const shadowReq = shadowCacheReq('owasp', OWASP_AI_LANDSCAPE_KV_KEY);
  try {
    const hit = await cache.match(shadowReq);
    if (hit)
      return new Response(hit.body, {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
      });
  } catch {
    /* fall through to KV */
  }
  const raw = await kv.get(OWASP_AI_LANDSCAPE_KV_KEY, 'json');
  if (raw) {
    // Write-through to L1 so the next read in this colo skips KV for 5 min.
    try {
      await cache.put(
        shadowReq,
        new Response(JSON.stringify(raw), {
          headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
        })
      );
    } catch {
      /* best-effort */
    }
    return c.json(raw, 200, { 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` });
  }
  let meta: OwaspMeta | null = null;
  try {
    meta = (await kv.get(OWASP_AI_LANDSCAPE_META_KEY, 'json')) as OwaspMeta | null;
  } catch {
    /* ignore */
  }
  return c.json({ ...OWASP_AI_LANDSCAPE_SEED, meta }, 200, { 'cache-control': 'public, max-age=60' });
}

export async function getOwaspAiLandscapeMetaHandler(c: Context<{ Bindings: Env }>) {
  const kv = c.env.KV_CACHE;
  if (!kv) return c.json({ ok: true, source: 'seed' }, 200, { 'cache-control': 'no-store' });
  // L1: cache-api shadow. META flips only on cron sync (~1×/6h).
  const cache = (caches as unknown as { default: Cache }).default;
  const shadowReq = shadowCacheReq('owasp-meta', OWASP_AI_LANDSCAPE_META_KEY);
  try {
    const hit = await cache.match(shadowReq);
    if (hit)
      return new Response(hit.body, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  } catch {
    /* fall through to KV */
  }
  const raw = await kv.get(OWASP_AI_LANDSCAPE_META_KEY, 'json');
  const value = raw ?? { ok: true, source: 'seed' };
  try {
    await cache.put(
      shadowReq,
      new Response(JSON.stringify(value), {
        headers: { 'content-type': 'application/json', 'cache-control': `max-age=${CACHE_MAX_AGE_S}` },
      })
    );
  } catch {
    /* best-effort */
  }
  return c.json(value, 200, { 'cache-control': 'no-store' });
}

/* ─────────────────────────── Curated Toolbox ───────────────────────── */

export interface CuratedTool {
  section: string;
  title: string;
  url: string;
  description?: string;
}

export interface CuratedToolboxPayload {
  source: string;
  sourceUrl: string;
  fetchedAt: string;
  ok: boolean;
  error?: string;
  sections: { name: string; tools: CuratedTool[] }[];
  totalTools: number;
  totalSections: number;
}

interface CuratedMeta {
  source: string;
  sourceUrl: string;
  fetchedAt: string;
  ok: boolean;
  error?: string;
  totalTools: number;
  totalSections: number;
}

const CURATED_STARTME_URL = 'https://start.me/p/gGj8gn/mastering-threat-intelligence-platforms';
/** Jina Reader renders any URL as clean markdown via real-browser egress.
 *  Only reliable way to read start.me — its Cloudflare bot challenge
 *  blocks every direct fetch. */
const jinaUrl = (startmeUrl: string): string => `https://r.jina.ai/${startmeUrl}`;

/** Parse Jina-reader markdown back into sections of tools.
 *
 *  Jina renders each start.me tool link as:
 *    `[![Image N](host) Title](url "tooltip")`
 *  with the tooltip continued on the next line. We collapse multi-line
 *  bullets, then for each line find the LAST `](https?://...)` (the
 *  outbound tool URL) and the most recent `)` before it (closes the
 *  inner image link). The title is the text in between.
 *
 *  Regex was tried first; the U+200E left-to-right mark that Jina
 *  inserts between the image and the title broke `\s*` matching, and
 *  start.me’s multi-line tooltips broke line-by-line processing. The
 *  indexOf-based scan below sidesteps both. */
function parseStartmeMarkdown(md: string): {
  sections: { name: string; tools: CuratedTool[] }[];
  totalTools: number;
  totalSections: number;
} {
  const sections: { name: string; tools: CuratedTool[] }[] = [];
  let current: { name: string; tools: CuratedTool[] } | null = null;
  // Collapse multi-line bullets: any newline NOT followed by a list
  // marker / blank line / new header is part of the previous bullet.
  const flat = md.replace(/\n(?![#*\-\s])/g, ' ');
  const lines = flat.split(/\r?\n/);
  let start = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const head = lines[i];
    if (head && /^##\s+/.test(head)) {
      start = i;
      break;
    }
  }
  for (let i = start; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const h = line.match(/^##\s+(.+?)\s*$/);
    if (h) {
      if (current) sections.push(current);
      current = { name: (h[1] ?? '').replace(/[*_`]+/g, '').trim(), tools: [] };
      continue;
    }
    if (!current) continue;
    if (!line.startsWith('*') && !line.startsWith('-')) continue;
    const lastHttps = line.lastIndexOf('](https://');
    const lastHttp = line.lastIndexOf('](http://');
    const lastUrlStart = lastHttps >= lastHttp ? lastHttps : lastHttp;
    if (lastUrlStart < 0) continue;
    const urlStart = lastUrlStart + 2;
    const urlEnd = line.indexOf(')', urlStart);
    if (urlEnd < 0) continue;
    const url = line.slice(urlStart, urlEnd).trim();
    if (url.includes('start.me/p/')) continue;
    const innerClose = line.lastIndexOf(')', lastUrlStart);
    let title = '';
    if (innerClose >= 0 && innerClose < lastUrlStart) {
      title = line.slice(innerClose + 1, lastUrlStart).trim();
    } else {
      const openBracket = line.indexOf('[');
      title = line.slice(openBracket + 1, lastUrlStart).trim();
    }
    title = title.replace(/[`*_\u200E\u200F]+/g, '').trim();
    if (!title || !url) continue;
    let description: string | undefined;
    const rest = line.slice(urlEnd + 1).trim();
    const cleaned = rest.replace(/^[)\s"\u2018\u2019]+/, '').replace(/[)\s"\u2018\u2019]+$/, '');
    if (cleaned && cleaned.length > 2 && !cleaned.startsWith('!')) {
      description = cleaned.replace(/\s+/g, ' ').trim().slice(0, 240);
    }
    current.tools.push({ section: current.name, title, url, description });
  }
  if (current) sections.push(current);
  const filtered = sections.filter((s) => s.tools.length > 0);
  const totalTools = filtered.reduce((n, s) => n + s.tools.length, 0);
  return { sections: filtered, totalTools, totalSections: filtered.length };
}

/** Manual fallback used until the first successful cron run. */
export const CURATED_TOOLBOX_SEED: CuratedToolboxPayload = {
  source: 'seed:v1',
  sourceUrl: CURATED_STARTME_URL,
  fetchedAt: '1970-01-01T00:00:00.000Z',
  ok: true,
  sections: [
    {
      name: 'Phishing Analysis',
      tools: [
        {
          section: 'Phishing Analysis',
          title: 'Google Safe Browsing — report_phish',
          url: 'https://safebrowsing.google.com/safebrowsing/report_phish/',
        },
        { section: 'Phishing Analysis', title: 'Phish.report', url: 'https://phish.report/analysis/' },
        {
          section: 'Phishing Analysis',
          title: 'Valimail Domain Lookalike Finder',
          url: 'https://valimail.com/domain-lookalike-finder/',
        },
        { section: 'Phishing Analysis', title: 'PhishTool', url: 'https://www.phishtool.com/' },
        { section: 'Phishing Analysis', title: 'EML Analyzer', url: 'https://eml-analyzer.herokuapp.com/' },
        { section: 'Phishing Analysis', title: 'CyberChef', url: 'https://gchq.github.io/CyberChef/' },
        { section: 'Phishing Analysis', title: 'PhishTank', url: 'https://www.phishtank.com/' },
        { section: 'Phishing Analysis', title: 'OpenPhish', url: 'https://openphish.com/' },
        { section: 'Phishing Analysis', title: 'ScamSearch', url: 'https://scamsearch.io/' },
      ],
    },
    {
      name: 'URL Reputation',
      tools: [
        { section: 'URL Reputation', title: 'VirusTotal', url: 'https://www.virustotal.com/' },
        { section: 'URL Reputation', title: 'URLScan.io', url: 'https://urlscan.io/' },
        { section: 'URL Reputation', title: 'urlscan.io Search', url: 'https://urlscan.io/search/' },
        { section: 'URL Reputation', title: 'AbuseIPDB', url: 'https://www.abuseipdb.com/' },
        { section: 'URL Reputation', title: 'ThreatCrowd', url: 'https://www.threatcrowd.org/' },
      ],
    },
    {
      name: 'File / Malware Analysis',
      tools: [
        { section: 'File / Malware Analysis', title: 'Hybrid Analysis', url: 'https://www.hybrid-analysis.com/' },
        { section: 'File / Malware Analysis', title: 'ANY.RUN', url: 'https://any.run/' },
        { section: 'File / Malware Analysis', title: 'Joe Sandbox', url: 'https://www.joesandbox.com/' },
        { section: 'File / Malware Analysis', title: 'MalShare', url: 'https://malshare.com/' },
        { section: 'File / Malware Analysis', title: 'MalwareBazaar', url: 'https://bazaar.abuse.ch/' },
        { section: 'File / Malware Analysis', title: 'Intezer Analyze', url: 'https://analyze.intezer.com/' },
        { section: 'File / Malware Analysis', title: 'CAPE Sandbox', url: 'https://capesandbox.com/' },
      ],
    },
    {
      name: 'IP Reputation',
      tools: [
        { section: 'IP Reputation', title: 'AbuseIPDB', url: 'https://www.abuseipdb.com/' },
        { section: 'IP Reputation', title: 'GreyNoise', url: 'https://viz.greynoise.io/' },
        { section: 'IP Reputation', title: 'Shodan', url: 'https://www.shodan.io/' },
        { section: 'IP Reputation', title: 'Censys', url: 'https://search.censys.io/' },
        { section: 'IP Reputation', title: 'IPinfo', url: 'https://ipinfo.io/' },
      ],
    },
    {
      name: 'Sigma / YARA / KQL / SPL',
      tools: [
        { section: 'Sigma / YARA / KQL / SPL', title: 'SigmaHQ Rules', url: 'https://github.com/SigmaHQ/sigma' },
        { section: 'Sigma / YARA / KQL / SPL', title: 'YARA Forge', url: 'https://yarahq.github.io/' },
        { section: 'Sigma / YARA / KQL / SPL', title: 'YaraRules Project', url: 'https://github.com/Yara-Rules/rules' },
        {
          section: 'Sigma / YARA / KQL / SPL',
          title: 'Elastic Detection Rules',
          url: 'https://github.com/elastic/detection-rules',
        },
        { section: 'Sigma / YARA / KQL / SPL', title: 'LOLBAS', url: 'https://lolbas-project.github.io/' },
      ],
    },
    {
      name: 'OSINT',
      tools: [
        { section: 'OSINT', title: 'OSINT Framework', url: 'https://osintframework.com/' },
        { section: 'OSINT', title: 'Maltego', url: 'https://www.maltego.com/' },
        { section: 'OSINT', title: 'SpiderFoot', url: 'https://github.com/smicallef/spiderfoot' },
        { section: 'OSINT', title: 'theHarvester', url: 'https://github.com/laramies/theHarvester' },
        { section: 'OSINT', title: 'Intel Techniques', url: 'https://inteltechniques.com/' },
      ],
    },
    {
      name: 'Ransomware',
      tools: [
        { section: 'Ransomware', title: 'Ransomware.live', url: 'https://ransomware.live/' },
        { section: 'Ransomware', title: 'Ransomlook', url: 'https://www.ransomlook.io/' },
        { section: 'Ransomware', title: 'Ransomwatch', url: 'https://ransomwatch.telemetry.ltd/' },
        { section: 'Ransomware', title: 'Ransomwhere', url: 'https://ransomwhere.com/' },
        {
          section: 'Ransomware',
          title: 'Have I Been Pwned (Ransomware tracker)',
          url: 'https://haveibeenpwned.com/Ransomware',
        },
      ],
    },
    {
      name: 'Vulnerability Intelligence',
      tools: [
        {
          section: 'Vulnerability Intelligence',
          title: 'CISA KEV',
          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        },
        { section: 'Vulnerability Intelligence', title: 'NVD', url: 'https://nvd.nist.gov/' },
        { section: 'Vulnerability Intelligence', title: 'Vulners', url: 'https://vulners.com/' },
        { section: 'Vulnerability Intelligence', title: 'VulnCheck', url: 'https://vulncheck.com/' },
        { section: 'Vulnerability Intelligence', title: 'Exploit-DB', url: 'https://www.exploit-db.com/' },
      ],
    },
  ],
  totalTools: 41,
  totalSections: 8,
};

/** Manual fallback used until the first successful cron run.
 *  Curated subset of widely-known free certification tracks — vendor,
 *  university, and community programs. The cron will overwrite this
 *  with the live Syberseeker start.me page within the first daily tick. */
export const CURATED_CERTS_SEED: CuratedToolboxPayload = {
  source: 'seed:v1',
  sourceUrl: 'https://start.me/p/xb2ReR/free-certification-courses-by-syberseeker',
  fetchedAt: '1970-01-01T00:00:00.000Z',
  ok: true,
  sections: [
    {
      name: 'Security Fundamentals',
      tools: [
        {
          section: 'Security Fundamentals',
          title: 'Cisco Introduction to Cybersecurity',
          url: 'https://www.netacad.com/courses/introduction-to-cybersecurity',
        },
        {
          section: 'Security Fundamentals',
          title: 'ISC2 Certified in Cybersecurity (CC) — Free Training',
          url: 'https://www.isc2.org/landing/1mcc',
        },
        {
          section: 'Security Fundamentals',
          title: 'Google Cybersecurity Certificate (audit)',
          url: 'https://www.coursera.org/professional-certificates/google-cybersecurity',
        },
        {
          section: 'Security Fundamentals',
          title: 'IBM Cybersecurity Analyst Professional Certificate (audit)',
          url: 'https://www.coursera.org/professional-certificates/ibm-cybersecurity-analyst',
        },
        {
          section: 'Security Fundamentals',
          title: 'Cybrary Free Cybersecurity Courses',
          url: 'https://www.cybrary.it/free-content/',
        },
        { section: 'Security Fundamentals', title: 'SANS Cyber Aces', url: 'https://www.cyberaces.org/' },
        {
          section: 'Security Fundamentals',
          title: 'Open Security Training',
          url: 'https://opensecuritytraining.info/',
        },
      ],
    },
    {
      name: 'Network & Infrastructure',
      tools: [
        {
          section: 'Network & Infrastructure',
          title: 'Juniper Networking Fundamentals',
          url: 'https://learningportal.juniper.net/juniper/user_activity_info.aspx?id=12960',
        },
        {
          section: 'Network & Infrastructure',
          title: 'Cisco Networking Academy — Free Courses',
          url: 'https://www.netacad.com/',
        },
        {
          section: 'Network & Infrastructure',
          title: 'Fortinet Network Security Expert (NSE) 1–3',
          url: 'https://training.fortinet.com/local/staticpage/view.php?page=nse_certification',
        },
        {
          section: 'Network & Infrastructure',
          title: 'Cloudflare Workers + Pages Free Course',
          url: 'https://workers.cloudflare.com/',
        },
      ],
    },
    {
      name: 'Cloud',
      tools: [
        {
          section: 'Cloud',
          title: 'AWS Cloud Practitioner Essentials',
          url: 'https://aws.amazon.com/training/digital/',
        },
        { section: 'Cloud', title: 'AWS Skill Builder — Free Tier', url: 'https://skillbuilder.aws/' },
        {
          section: 'Cloud',
          title: 'Google Cloud Skills Boost — Free Tier',
          url: 'https://www.cloudskillsboost.google/',
        },
        {
          section: 'Cloud',
          title: 'Microsoft Azure Fundamentals (AZ-900) learning path',
          url: 'https://learn.microsoft.com/en-us/training/paths/az-900-describe-azure-concepts/',
        },
        {
          section: 'Cloud',
          title: 'AWS Security Specialty (free digital course)',
          url: 'https://aws.amazon.com/training/digital/',
        },
        {
          section: 'Cloud',
          title: 'Cloud Security Alliance CCSK',
          url: 'https://cloudsecurityalliance.org/education/ccsk/',
        },
      ],
    },
    {
      name: 'Offensive / Red Team',
      tools: [
        {
          section: 'Offensive / Red Team',
          title: 'TryHackMe — Free Beginner Path',
          url: 'https://tryhackme.com/r/path/outline/presecurity',
        },
        {
          section: 'Offensive / Red Team',
          title: 'HackTheBox Academy — Free Modules',
          url: 'https://academy.hackthebox.com/',
        },
        {
          section: 'Offensive / Red Team',
          title: 'PortSwigger Web Security Academy',
          url: 'https://portswigger.net/web-security',
        },
        { section: 'Offensive / Red Team', title: 'OverTheWire Wargames', url: 'https://overthewire.org/wargames/' },
        { section: 'Offensive / Red Team', title: 'PicoCTF', url: 'https://picoctf.org/' },
        {
          section: 'Offensive / Red Team',
          title: 'Google Bug Hunters University',
          url: 'https://bughunters.google.com/learn',
        },
      ],
    },
    {
      name: 'Blue Team / SOC',
      tools: [
        { section: 'Blue Team / SOC', title: 'LetsDefend — Free SOC Analyst Path', url: 'https://letsdefend.io/' },
        { section: 'Blue Team / SOC', title: 'Blue Team Labs Online', url: 'https://blueteamlabs.online/' },
        {
          section: 'Blue Team / SOC',
          title: 'CyberDefenders — Free Blue Team Challenges',
          url: 'https://cyberdefenders.org/',
        },
        {
          section: 'Blue Team / SOC',
          title: 'Tib3rius — Detection Engineering with Sigma/YARA',
          url: 'https://tib3rius.com/',
        },
        {
          section: 'Blue Team / SOC',
          title: 'Elastic Security Hands-On (free)',
          url: 'https://www.elastic.co/training/',
        },
      ],
    },
    {
      name: 'DFIR / Forensics',
      tools: [
        { section: 'DFIR / Forensics', title: '13Cubed — Free IR & Forensics', url: 'https://13cubed.com/' },
        { section: 'DFIR / Forensics', title: 'SANS DFIR Webcast Archive', url: 'https://www.sans.org/webcasts/' },
        {
          section: 'DFIR / Forensics',
          title: 'Digital Forensics — Autopsy + The Sleuth Kit',
          url: 'https://www.autopsy.com/training/',
        },
        {
          section: 'DFIR / Forensics',
          title: 'Volatility Foundation — Free Memory Forensics',
          url: 'https://www.volatilityfoundation.org/',
        },
      ],
    },
    {
      name: 'GRC / Privacy',
      tools: [
        {
          section: 'GRC / Privacy',
          title: 'ISACA — Free Resources & Certificates',
          url: 'https://www.isaca.org/credentialing/free-resources',
        },
        { section: 'GRC / Privacy', title: 'IAPP Privacy Law & Training (free samples)', url: 'https://iapp.org/' },
        { section: 'GRC / Privacy', title: 'OCEG — Free GRC Resources', url: 'https://www.oceg.org/' },
        {
          section: 'GRC / Privacy',
          title: 'NIST NICE Cybersecurity Workforce Framework',
          url: 'https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center',
        },
      ],
    },
    {
      name: 'OSINT',
      tools: [
        { section: 'OSINT', title: 'TCM Security — Practical OSINT (free tier)', url: 'https://tcm-sec.com/' },
        { section: 'OSINT', title: 'Bellingcat Online Investigation Toolkit', url: 'https://www.bellingcat.com/' },
        { section: 'OSINT', title: 'NixIntel OSINT Resources', url: 'https://nixintel.info/' },
        { section: 'OSINT', title: 'OSINT Dojo', url: 'https://www.osintdojo.com/' },
      ],
    },
  ],
  totalTools: 41,
  totalSections: 8,
};

/* ─── Generic mirror engine (shared by toolbox + certs) ─── */

export async function syncCuratedMirror(
  env: Env,
  config: CuratedMirror
): Promise<{ ok: boolean; error?: string; totalTools?: number; totalSections?: number }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(jinaUrl(config.startmeUrl), {
      headers: { 'user-agent': USER_AGENT, accept: 'text/plain' },
      signal: ctrl.signal,
    });
    if (!res.ok) return { ok: false, error: `jina ${res.status}` };
    const md = await res.text();
    if (md.length < 500) {
      return { ok: false, error: 'jina response too short (likely blocked)' };
    }
    const parsed = parseStartmeMarkdown(md);
    if (parsed.totalTools === 0) {
      return { ok: false, error: 'parsed 0 tools (markdown shape changed?)' };
    }
    const payload: CuratedToolboxPayload = {
      source: 'jina',
      sourceUrl: config.startmeUrl,
      fetchedAt: new Date().toISOString(),
      ok: true,
      sections: parsed.sections,
      totalTools: parsed.totalTools,
      totalSections: parsed.totalSections,
    };
    if (env.KV_CACHE) {
      // Same no-op guard as OWASP above. The startme page is updated
      // ~weekly; the hourly jina fetch should not cost a write on every run.
      await kvPutIfChanged(env, config.kvKey, JSON.stringify(payload), { expirationTtl: DATA_TTL_S });
      const meta: CuratedMeta = {
        source: 'jina',
        sourceUrl: config.startmeUrl,
        fetchedAt: payload.fetchedAt,
        ok: true,
        totalTools: payload.totalTools,
        totalSections: payload.totalSections,
      };
      await env.KV_CACHE.put(config.metaKey, JSON.stringify(meta), { expirationTtl: META_TTL_S });
      // Write-through to per-colo cache shadow (see OWASP handler above).
      try {
        const cache = (caches as unknown as { default: Cache }).default;
        await cache.put(
          shadowCacheReq(config.shadowKind, config.kvKey),
          new Response(JSON.stringify(payload), {
            headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
          })
        );
        await cache.put(
          shadowCacheReq(`${config.shadowKind}-meta`, config.metaKey),
          new Response(JSON.stringify(meta), {
            headers: { 'content-type': 'application/json', 'cache-control': 'max-age=60' },
          })
        );
      } catch {
        /* best-effort */
      }
    }
    return { ok: true, totalTools: payload.totalTools, totalSections: payload.totalSections };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (env.KV_CACHE) {
      const meta: CuratedMeta = {
        source: 'jina',
        sourceUrl: config.startmeUrl,
        fetchedAt: new Date().toISOString(),
        ok: false,
        error: msg,
        totalTools: 0,
        totalSections: 0,
      };
      await env.KV_CACHE.put(config.metaKey, JSON.stringify(meta), { expirationTtl: META_TTL_S });
    }
    return { ok: false, error: msg };
  } finally {
    clearTimeout(timer);
  }
}

export async function getCuratedHandler(
  c: Context<{ Bindings: Env }>,
  config: CuratedMirror,
  seed: CuratedToolboxPayload
) {
  const kv = c.env.KV_CACHE;
  if (!kv) {
    return c.json(seed, 200, { 'cache-control': 'public, max-age=60' });
  }
  // L1: cache-api shadow. Same pattern as the OWASP handler — payload is
  // large JSON, low write rate, identical across colos.
  const cache = (caches as unknown as { default: Cache }).default;
  const shadowReq = shadowCacheReq(config.shadowKind, config.kvKey);
  try {
    const hit = await cache.match(shadowReq);
    if (hit)
      return new Response(hit.body, {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
      });
  } catch {
    /* fall through to KV */
  }
  const raw = await kv.get(config.kvKey, 'json');
  if (raw) {
    try {
      await cache.put(
        shadowReq,
        new Response(JSON.stringify(raw), {
          headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` },
        })
      );
    } catch {
      /* best-effort */
    }
    return c.json(raw, 200, { 'cache-control': `public, max-age=${CACHE_MAX_AGE_S}` });
  }
  let meta: CuratedMeta | null = null;
  try {
    meta = (await kv.get(config.metaKey, 'json')) as CuratedMeta | null;
  } catch {
    /* ignore */
  }
  return c.json({ ...seed, meta }, 200, { 'cache-control': 'public, max-age=60' });
}

export async function getCuratedMetaHandler(c: Context<{ Bindings: Env }>, config: CuratedMirror) {
  const kv = c.env.KV_CACHE;
  if (!kv) return c.json({ ok: true, source: 'seed' }, 200, { 'cache-control': 'no-store' });
  // L1: cache-api shadow (60s TTL is fine for meta — UI just shows the
  // last-updated stamp; the value only flips on cron sync).
  const cache = (caches as unknown as { default: Cache }).default;
  const shadowReq = shadowCacheReq(`${config.shadowKind}-meta`, config.metaKey);
  try {
    const hit = await cache.match(shadowReq);
    if (hit)
      return new Response(hit.body, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  } catch {
    /* fall through to KV */
  }
  const raw = await kv.get(config.metaKey, 'json');
  const value = raw ?? { ok: true, source: 'seed' };
  try {
    await cache.put(
      shadowReq,
      new Response(JSON.stringify(value), {
        headers: { 'content-type': 'application/json', 'cache-control': 'max-age=60' },
      })
    );
  } catch {
    /* best-effort */
  }
  return c.json(value, 200, { 'cache-control': 'no-store' });
}

/* ─── Mirror lookup by id (used by wrappers + scheduled) ─── */

const MIRROR_BY_ID: Record<CuratedMirror['id'], CuratedMirror> = MIRRORS.reduce(
  (acc, m) => {
    acc[m.id] = m;
    return acc;
  },
  {} as Record<CuratedMirror['id'], CuratedMirror>
);

/* ─── Curated Toolbox (back-compat wrappers) ─── */

export async function syncCuratedToolbox(env: Env) {
  return syncCuratedMirror(env, MIRROR_BY_ID.toolbox);
}
export async function getCuratedToolboxHandler(c: Context<{ Bindings: Env }>) {
  return getCuratedHandler(c, MIRROR_BY_ID.toolbox, CURATED_TOOLBOX_SEED);
}
export async function getCuratedToolboxMetaHandler(c: Context<{ Bindings: Env }>) {
  return getCuratedMetaHandler(c, MIRROR_BY_ID.toolbox);
}

/* ─── Curated Certs (Syberseeker start.me mirror) ─── */

export async function syncCuratedCerts(env: Env) {
  return syncCuratedMirror(env, MIRROR_BY_ID.certs);
}
export async function getCuratedCertsHandler(c: Context<{ Bindings: Env }>) {
  return getCuratedHandler(c, MIRROR_BY_ID.certs, CURATED_CERTS_SEED);
}
export async function getCuratedCertsMetaHandler(c: Context<{ Bindings: Env }>) {
  return getCuratedMetaHandler(c, MIRROR_BY_ID.certs);
}
