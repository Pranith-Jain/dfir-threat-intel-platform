/**
 * ai-llm-intel.ts
 *
 * Dedicated AI / LLM threat-intelligence collector.
 *
 * # Why this is a separate module rather than more entries in live-iocs.ts
 *
 * The live-IOC registry is a flat indicator stream: one source id → a list of
 * `value + kind`. That model fits blocklists. It does NOT fit LLM threat intel,
 * which is fundamentally *narrative* — a campaign has a name, an actor has ATT&CK
 * techniques and a distribution method, a write-up has tags and a summary, and
 * a blog post has an author and a reading time. Forcing those through
 * `LiveIoc.context` produced unreadable one-line blobs and threw away every
 * field that made the intel useful.
 *
 * So this module keeps the structured shape and feeds the surfaces that want
 * narrative content — brief, trends, blog — while the two highest-value
 * indicator sets (ai-honeypots, llm-threatintel iocs) are ALSO registered as
 * live-IOC sources so they appear in the tweet-style stream. Deliberate
 * overlap: the stream is for spotting an address; this is for understanding the
 * campaign it belongs to.
 *
 * # Upstreams
 *
 * All five are llm-threatintel.com static JSON, published by a scheduled agent,
 * plus ai-honeypots.com for observed-actor telemetry. Every one was probed live
 * on 2026-10-05 before being wired (see `verifyAiLlmEndpoints`).
 */

import { logError } from './logger';
import { parseAiHoneypots } from './ioc-feed-parsers';

export const AI_LLM_BASE = 'https://llm-threatintel.com';

/** Every upstream this module depends on, with the surface it feeds. */
export interface AiLlmEndpoint {
  id: string;
  url: string;
  /** Which part of the response it populates. */
  feeds: 'iocs' | 'actors' | 'posts' | 'blog' | 'honeypot' | 'honeypot_taxonomy';
  /** Human label for the source-health row. */
  label: string;
}

/**
 * The upstream manifest. Single source of truth — `verifyAiLlmEndpoints` walks
 * it, so adding an endpoint here also adds it to the health check.
 */
export const AI_LLM_ENDPOINTS: readonly AiLlmEndpoint[] = [
  {
    id: 'iocs',
    url: `${AI_LLM_BASE}/data/iocs.json`,
    feeds: 'iocs',
    label: 'LLM ThreatIntel indicators',
  },
  {
    id: 'actors',
    url: `${AI_LLM_BASE}/data/actors.json`,
    feeds: 'actors',
    label: 'LLM ThreatIntel actors & campaigns',
  },
  {
    id: 'posts',
    url: `${AI_LLM_BASE}/data/posts-index.json`,
    feeds: 'posts',
    label: 'LLM ThreatIntel write-ups',
  },
  {
    id: 'blog',
    url: `${AI_LLM_BASE}/data/blog-index.json`,
    feeds: 'blog',
    label: 'LLM ThreatIntel blog',
  },
  {
    id: 'honeypot',
    url: 'https://ai-honeypots.com/feeds/iocs.json',
    feeds: 'honeypot',
    label: 'AI Honeypot Observatory',
  },
  {
    id: 'honeypot_taxonomy',
    url: 'https://ai-honeypots.com/feeds/iocs.json',
    feeds: 'honeypot_taxonomy',
    label: 'AI Honeypot taxonomy',
  },
];

// ── Response shapes ───────────────────────────────────────────────────────

/** A tracked actor, campaign, or supply-chain cluster. */
export interface AiLlmActor {
  id: string;
  names: string[];
  /** e.g. `supply_chain_campaign`, `malware_cluster`, `threat_actor`. */
  type: string;
  first_seen?: string;
  status?: string;
  /** Delivery channels, e.g. "MCP server docs". */
  distribution?: string[];
  /** ATT&CK technique ids with names, e.g. "T1059.001 - PowerShell". */
  ttps?: string[];
  description?: string;
  /** IOCs the upstream attributes to this actor, when it ships them inline. */
  ioc_count?: number;
}

/** A write-up or blog post. */
export interface AiLlmPost {
  id: string;
  title: string;
  /** `YYYY-MM-DD`. */
  date: string;
  author?: string;
  tags: string[];
  tlp?: string;
  excerpt?: string;
  file?: string;
  category?: string;
  readTime?: string;
  /** Absolute permalink on the upstream site. */
  url: string;
}

export interface AiLlmIoc {
  value: string;
  /** domain | ip | url | hash — upstream `type`, not our IocKind. */
  type: string;
  context?: string;
  first_seen?: string;
  source?: string;
  campaign?: string;
}

/** An observed honeypot actor class, aggregated across indicators. */
export interface AiLlmActorClass {
  category: string;
  description?: string;
  count: number;
  /** Distinct IPs observed behaving this way. */
  indicators: number;
}

/** A tag/technique frequency bucket — the "trends" surface. */
export interface AiLlmTrend {
  key: string;
  /** 'tag' | 'actor_type' | 'ttp' | 'honeypot_category' */
  dimension: string;
  count: number;
  /** Most recent item carrying this key, ISO date. */
  latest?: string;
}

export interface AiLlmSourceStatus {
  id: string;
  label: string;
  ok: boolean;
  count: number;
  error?: string;
}

export interface AiLlmIntelResponse {
  generated_at: string;
  /** The newest timestamp seen across all upstreams. */
  last_updated?: string;
  sources: AiLlmSourceStatus[];
  actors: AiLlmActor[];
  posts: AiLlmPost[];
  blog: AiLlmPost[];
  iocs: AiLlmIoc[];
  /** Aggregated honeypot actor classes with the upstream's own definitions. */
  honeypot_actor_classes: AiLlmActorClass[];
  trends: AiLlmTrend[];
  stats: {
    iocs: number;
    active_iocs: number;
    actors: number;
    posts: number;
    blog: number;
    honeypot_indicators: number;
    campaigns: number;
    /** Distinct tags across posts + blog. */
    tags: number;
  };
  /** True when any upstream fetch failed this build. */
  degraded?: boolean;
}

// ── Upstream payload shapes (only the fields we consume) ──────────────────

interface RawLlmIocDoc {
  last_updated?: string;
  iocs?: Array<{
    value?: string;
    type?: string;
    context?: string;
    first_seen?: string;
    source?: string;
    campaign?: string;
    status?: string;
  }>;
}

interface RawLlmActorDoc {
  last_updated?: string;
  entries?: Array<{
    id?: string;
    names?: string[];
    type?: string;
    first_seen?: string;
    status?: string;
    distribution?: string[];
    ttps?: string[];
    description?: string;
  }>;
}

interface RawLlmPostDoc {
  posts?: Array<{
    id?: string;
    title?: string;
    date?: string;
    author?: string;
    tags?: string[];
    tlp?: string;
    excerpt?: string;
    file?: string;
    category?: string;
    readTime?: string;
  }>;
}

interface RawHoneypotDoc {
  published?: string;
  window_days?: number;
  summary?: { total_iocs?: number; by_category?: Record<string, number> };
  taxonomy?: { actor_categories?: Record<string, string> };
  indicators?: Array<{
    value?: string;
    actor_category?: string;
    confidence?: string;
    last_seen?: string;
    first_seen?: string;
  }>;
}

const UA = { 'user-agent': 'pranithjain-dfir/1.0', accept: '*/*' };

/** Fetch JSON with a timeout; null on any failure (never throws). */
async function getJson<T>(url: string, timeoutMs = 20_000): Promise<T | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: UA });
    if (!res.ok) return null;
    const text = await res.text();
    // Same HTML-challenge guard as live-iocs' fetchText: a 200 can still be a
    // Cloudflare interstitial, and JSON.parse on markup throws.
    const head = text.trimStart().slice(0, 16);
    if (head.startsWith('<!DOCTYPE') || head.startsWith('<html')) return null;
    return JSON.parse(text) as T;
  } catch (e) {
    logError('ai-llm-intel fetch failed', e);
    return null;
  }
}

/** Newest-first by date, then title, so ordering is stable across builds. */
function byDateDesc(a: AiLlmPost, b: AiLlmPost): number {
  if (a.date !== b.date) return b.date.localeCompare(a.date);
  return a.title.localeCompare(b.title);
}

/**
 * Normalize an upstream post index. Posts without a title or date are dropped —
 * both are load-bearing for the blog/trend surfaces (a card with no heading, or
 * an item that can never be ordered, is worse than absent).
 */
function normalizePosts(raw: RawLlmPostDoc['posts']): AiLlmPost[] {
  const out: AiLlmPost[] = [];
  for (const p of raw ?? []) {
    const id = (p.id ?? '').trim();
    const title = (p.title ?? '').trim();
    const date = (p.date ?? '').trim();
    if (!id || !title || !date) continue;
    out.push({
      id,
      title,
      date,
      author: p.author,
      tags: Array.isArray(p.tags) ? p.tags.filter((t): t is string => typeof t === 'string') : [],
      tlp: p.tlp,
      excerpt: p.excerpt,
      file: p.file,
      category: p.category,
      readTime: p.readTime,
      url: `${AI_LLM_BASE}/#${id}`,
    });
  }
  return out.sort(byDateDesc);
}

/** Normalize the actor/campaign index, sorted most-recent-first then by id. */
function normalizeActors(raw: RawLlmActorDoc['entries']): AiLlmActor[] {
  const out: AiLlmActor[] = [];
  for (const a of raw ?? []) {
    const id = (a.id ?? '').trim();
    if (!id) continue;
    out.push({
      id,
      names: Array.isArray(a.names) ? a.names.filter((n): n is string => typeof n === 'string') : [id],
      type: (a.type ?? 'unknown').trim(),
      first_seen: a.first_seen,
      status: a.status,
      distribution: Array.isArray(a.distribution) ? a.distribution : undefined,
      ttps: Array.isArray(a.ttps) ? a.ttps : undefined,
      description: a.description,
    });
  }
  return out.sort((a, b) => {
    const af = a.first_seen ?? '';
    const bf = b.first_seen ?? '';
    if (af !== bf) return bf.localeCompare(af);
    return a.id.localeCompare(b.id);
  });
}

interface TrendAccumulator {
  counts: Map<string, { count: number; latest: string }>;
}

function bump(acc: TrendAccumulator, dimension: string, key: string, latest?: string): void {
  const cur = acc.counts.get(`${dimension} ${key}`) ?? { count: 0, latest: '' };
  cur.count += 1;
  if (latest && latest > cur.latest) cur.latest = latest;
  acc.counts.set(`${dimension} ${key}`, cur);
}

function drain(acc: TrendAccumulator, dimension: string, limit: number): AiLlmTrend[] {
  return [...acc.counts.entries()]
    .filter(([k]) => k.startsWith(`${dimension} `))
    .map(([k, v]) => ({ key: k.slice(dimension.length + 1), dimension, count: v.count, latest: v.latest || undefined }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, limit);
}

/**
 * Build the full AI/LLM intel payload from the upstreams.
 *
 * Fetches each distinct URL once and derives every surface that needs it — the
 * honeypot JSON feeds both the indicator list and the taxonomy, so the manifest
 * lists it twice but this only costs one request.
 *
 * Never throws: a failed upstream contributes an `ok:false` source row and is
 * otherwise absent, so a partial outage degrades the response instead of
 * blanking the page.
 */
export async function buildAiLlmIntel(opts: { perCap?: number } = {}): Promise<AiLlmIntelResponse> {
  const IOC_CAP = opts.perCap ?? 500;
  const POST_CAP = 200;
  const ACTOR_CAP = 300;

  const [iocDoc, actorDoc, postDoc, blogDoc, honeypotDoc] = await Promise.all([
    getJson<RawLlmIocDoc>(`${AI_LLM_BASE}/data/iocs.json`),
    getJson<RawLlmActorDoc>(`${AI_LLM_BASE}/data/actors.json`),
    getJson<RawLlmPostDoc>(`${AI_LLM_BASE}/data/posts-index.json`),
    getJson<RawLlmPostDoc>(`${AI_LLM_BASE}/data/blog-index.json`),
    getJson<RawHoneypotDoc>('https://ai-honeypots.com/feeds/iocs.json'),
  ]);

  const sources: AiLlmSourceStatus[] = [];

  // ── Indicators ──────────────────────────────────────────────────────────
  const iocs: AiLlmIoc[] = [];
  if (iocDoc) {
    for (const r of iocDoc.iocs ?? []) {
      const value = (r.value ?? '').trim();
      const type = (r.type ?? '').trim();
      if (!value || !type) continue;
      // Upstream lifecycle states, verified on the live feed 2026-10-05:
      // active 684 / unknown 22 / removed 53 / inactive 10. `removed` and
      // `inactive` are stood-down indicators — serving them keeps an analyst
      // blocking infrastructure the upstream analyst has already retired.
      // `unknown` is kept: it means "not yet triaged", not "retired".
      if (r.status && r.status !== 'active' && r.status !== 'unknown') continue;
      // Fold provenance into the context so a row is self-describing wherever it
      // renders (live-IOC stream, briefing, report export).
      const bits = [r.source, r.campaign].filter(Boolean);
      const base = r.context ?? 'LLM threat intel';
      iocs.push({
        value,
        type,
        context: bits.length ? `${base} (${bits.join(' · ')})` : base,
        first_seen: r.first_seen,
        source: r.source,
        campaign: r.campaign,
      });
      if (iocs.length >= IOC_CAP) break;
    }
  }
  sources.push({
    id: 'iocs',
    label: 'LLM ThreatIntel indicators',
    ok: !!iocDoc,
    count: iocs.length,
    error: iocDoc ? undefined : 'fetch failed',
  });

  // ── Actors ──────────────────────────────────────────────────────────────
  const actors = normalizeActors(actorDoc?.entries).slice(0, ACTOR_CAP);
  sources.push({
    id: 'actors',
    label: 'LLM ThreatIntel actors & campaigns',
    ok: !!actorDoc,
    count: actors.length,
    error: actorDoc ? undefined : 'fetch failed',
  });

  // ── Write-ups + blog ────────────────────────────────────────────────────
  const posts = normalizePosts(postDoc?.posts).slice(0, POST_CAP);
  const blog = normalizePosts(blogDoc?.posts).slice(0, POST_CAP);
  sources.push({
    id: 'posts',
    label: 'LLM ThreatIntel write-ups',
    ok: !!postDoc,
    count: posts.length,
    error: postDoc ? undefined : 'fetch failed',
  });
  sources.push({
    id: 'blog',
    label: 'LLM ThreatIntel blog',
    ok: !!blogDoc,
    count: blog.length,
    error: blogDoc ? undefined : 'fetch failed',
  });

  // ── Honeypot actor classes ──────────────────────────────────────────────
  const classCounts = new Map<string, number>();
  let honeypotIndicators = 0;
  if (honeypotDoc) {
    for (const ind of honeypotDoc.indicators ?? []) {
      const cat = (ind.actor_category ?? '').trim();
      if (!cat) continue;
      honeypotIndicators++;
      classCounts.set(cat, (classCounts.get(cat) ?? 0) + 1);
    }
  }
  // Prefer the upstream's own per-class indicator counts; fall back to counting
  // the indicator rows we actually received.
  const upstreamByCategory = honeypotDoc?.summary?.by_category ?? {};
  const honeypotActorClasses: AiLlmActorClass[] = [...classCounts.entries()]
    .map(([category, count]) => ({
      category,
      description: honeypotDoc?.taxonomy?.actor_categories?.[category],
      // `count` = indicators we saw; `indicators` = upstream's own total, which
      // can be higher when the feed was truncated to its 1,000-row window.
      count,
      indicators: upstreamByCategory[category] ?? count,
    }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
  sources.push({
    id: 'honeypot',
    label: 'AI Honeypot Observatory',
    ok: !!honeypotDoc,
    count: honeypotIndicators,
    error: honeypotDoc ? undefined : 'fetch failed',
  });

  // ── Trends ──────────────────────────────────────────────────────────────
  // Four dimensions off data we already hold — no extra fetches. Honeypot
  // indicators are read through the shared parser so the trend numbers cannot
  // disagree with the live-IOC stream's interpretation of the same feed.
  // Read through the shared parser so the trend numbers cannot disagree with the
  // live-IOC stream's interpretation of the same feed. The parser is the source
  // of the timestamp; the category comes from the source document by INDEX, kept
  // in step with an explicit counter rather than `indexOf` (O(n²) and silently
  // wrong if the parser ever filters a row the trend loop doesn't).
  const honeypotIndicatorRows = honeypotDoc?.indicators ?? [];
  const honeypotParsed = honeypotDoc ? parseAiHoneypots(JSON.stringify(honeypotDoc), IOC_CAP) : [];
  const acc: TrendAccumulator = { counts: new Map() };
  for (const p of posts) for (const t of p.tags) bump(acc, 'tag', t, p.date);
  for (const b of blog) for (const t of b.tags) bump(acc, 'tag', t, b.date);
  for (const a of actors) {
    bump(acc, 'actor_type', a.type, a.first_seen);
    for (const t of a.ttps ?? []) {
      // "T1059.001 - Command and Scripting Interpreter: PowerShell" → keep the
      // technique id as the key so like techniques aggregate across actors.
      const id = t.split(' - ')[0]?.trim();
      if (id) bump(acc, 'ttp', id, a.first_seen);
    }
  }
  for (let i = 0; i < honeypotParsed.length; i++) {
    const cat = (honeypotIndicatorRows[i]?.actor_category ?? '').trim();
    if (cat) bump(acc, 'honeypot_category', cat, honeypotParsed[i]!.timestamp);
  }
  const trends: AiLlmTrend[] = [
    ...drain(acc, 'tag', 24),
    ...drain(acc, 'ttp', 16),
    ...drain(acc, 'actor_type', 12),
    ...drain(acc, 'honeypot_category', 12),
  ];

  // ── Stats + freshness ───────────────────────────────────────────────────
  const tagSet = new Set<string>([...posts, ...blog].flatMap((p) => p.tags));
  // Max across every upstream that reports a timestamp. Compared by parsed time,
  // NOT lexicographically: upstreams mix formats (`…14:03:23.328770Z` from the
  // honeypot vs `…14:03:23Z` from llm-threatintel vs date-only post dates), and
  // a string sort puts `.328770Z` BEFORE `Z` — reporting a stale value as newest.
  const lastUpdatedCandidates = [
    iocDoc?.last_updated,
    actorDoc?.last_updated,
    honeypotDoc?.published,
    posts[0]?.date,
    blog[0]?.date,
  ].filter((d): d is string => typeof d === 'string' && d.length > 0);
  let lastUpdated: string | undefined;
  let lastUpdatedMs = -Infinity;
  for (const candidate of lastUpdatedCandidates) {
    const ms = Date.parse(candidate);
    if (Number.isFinite(ms) && ms > lastUpdatedMs) {
      lastUpdatedMs = ms;
      lastUpdated = candidate;
    }
  }

  const degraded = sources.some((s) => !s.ok);
  return {
    generated_at: new Date().toISOString(),
    last_updated: lastUpdated,
    sources,
    actors,
    posts,
    blog,
    iocs,
    honeypot_actor_classes: honeypotActorClasses,
    trends,
    stats: {
      iocs: iocs.length,
      active_iocs: iocs.length,
      actors: actors.length,
      posts: posts.length,
      blog: blog.length,
      honeypot_indicators: honeypotIndicators,
      campaigns: new Set(iocs.map((i) => i.campaign).filter(Boolean)).size,
      tags: tagSet.size,
    },
    degraded,
  };
}

/**
 * Re-derive the honeypot indicator rows using the same parser the live-IOC
 * source uses. Exported so tests can assert the two paths agree.
 */
export function honeypotIndicatorsFromFeed(doc: RawHoneypotDoc): ReturnType<typeof parseAiHoneypots> {
  return parseAiHoneypots(JSON.stringify(doc), Number.MAX_SAFE_INTEGER);
}

export interface EndpointHealth {
  id: string;
  url: string;
  ok: boolean;
  status?: number;
  bytes: number;
  ms: number;
  error?: string;
}

/**
 * Probe every upstream and report real HTTP status + payload size.
 *
 * Operational, not hot-path — powers `?health=1` and the audit loop. Exists
 * because these upstreams are third-party static JSON with no uptime guarantee;
 * the difference between "the site is down" and "our fetch is broken" is not
 * visible anywhere else.
 */
export async function verifyAiLlmEndpoints(timeoutMs = 20_000): Promise<EndpointHealth[]> {
  return Promise.all(
    AI_LLM_ENDPOINTS.map(async (ep) => {
      const t0 = Date.now();
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      try {
        const res = await fetch(ep.url, { signal: ac.signal, headers: UA, redirect: 'follow' });
        const body = res.ok ? await res.text() : '';
        return {
          id: ep.id,
          url: ep.url,
          ok: res.ok && body.length > 0,
          status: res.status,
          bytes: body.length,
          ms: Date.now() - t0,
          ...(res.ok ? {} : { error: `HTTP ${res.status}` }),
        };
      } catch (e) {
        return {
          id: ep.id,
          url: ep.url,
          ok: false,
          bytes: 0,
          ms: Date.now() - t0,
          error: e instanceof Error ? e.message.slice(0, 120) : 'unknown',
        };
      } finally {
        clearTimeout(timer);
      }
    })
  );
}
