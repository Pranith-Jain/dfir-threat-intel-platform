/**
 * Research orchestration: candidate in, dossier out.
 *
 * This is the stage that was missing. The pipeline used to hand the writer a
 * title and a blob of JSON and trust it to know the difference between what a
 * source said and what it half-remembers. Now, before any prose is generated,
 * the pipeline:
 *
 *   1. identifies the CVEs in the topic and resolves them against NVD +
 *      CISA KEV + FIRST EPSS + public-PoC indexes,
 *   2. fetches the candidate's own cited pages and reads them,
 *   3. asks the platform's own API surfaces what it already knows,
 *   4. mines the evidence for indicators, entities and dated events,
 *   5. writes down what it could NOT establish.
 *
 * Budget discipline: page fetches run three at a time and stop at
 * `MAX_PAGES`, and CVE lookups are capped at 4. Every step is individually
 * best-effort — the worst case is a dossier with fewer sections, never a
 * failed publish.
 */

import type { Candidate } from '../types';
import { extractPage, MAX_PAGES } from './extract';
import { findCveIds, enrichCves, enrichFromPlatform, topicKeyword, type PlatformFacts } from './enrich';
import { renderDossier, type ResearchDossier } from './dossier';

export interface ResearchDeps {
  candidate: Candidate;
  now: Date;
  /** SELF service binding — used to query the platform's own API. */
  self?: { fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response> };
  /** HMAC secret for self-fetch auth. Absent = skip platform enrichment. */
  internalTokenSecret?: string;
  /** Injectable for tests. Defaults to global fetch. */
  fetchFn?: typeof globalThis.fetch;
}

type SelfBinding = NonNullable<ResearchDeps['self']>;

const EMPTY_PLATFORM: PlatformFacts = {
  writeups: [],
  relatedCves: [],
  trendingCves: [],
  actors: [],
  darkweb: [],
};

/** Collect every candidate source URL, preserving order and dropping dupes. */
function candidateUrls(candidate: Candidate): string[] {
  const ev = candidate.evidence ?? {};
  const out: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === 'string' && /^https?:\/\//i.test(v) && !out.includes(v)) out.push(v);
  };
  push(ev.url);
  push(ev.sourceUrl);
  if (Array.isArray(ev.urls)) ev.urls.forEach(push);
  if (Array.isArray(ev.sources)) ev.sources.forEach(push);
  if (Array.isArray(ev.references)) {
    for (const r of ev.references) push((r as Record<string, unknown>)?.url);
  }
  if (Array.isArray(ev.sections)) {
    for (const s of ev.sections) {
      const findings = (s as Record<string, unknown> | null)?.findings;
      if (!Array.isArray(findings)) continue;
      for (const f of findings) push((f as Record<string, unknown> | null)?.source_url);
    }
  }
  // Drop NVD/KEV/MITRE deep links — the CVE lookup covers those properly and
  // fetching them burns budget on a JSON page we already parsed.
  return out
    .filter((u) => !/nvd\.nist\.gov|known-exploited-vulnerabilities|attack\.mitre\.org/i.test(u))
    .slice(0, MAX_PAGES * 2);
}

/** Run `tasks` with at most `limit` in flight at once. */
async function withConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      out[i] = await fn(items[i] as T);
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Build the research dossier for a candidate.
 *
 * Never throws. On total failure (no sources readable, no CVE resolvable)
 * it still returns a dossier — one carrying an explicit, strong gap notice,
 * which is far better prompt input than an empty facts object.
 */
export async function researchCandidate(deps: ResearchDeps): Promise<ResearchDossier> {
  const { candidate, now } = deps;
  const startedAt = Date.now();
  const fetchFn = deps.fetchFn ?? globalThis.fetch;

  // 1. CVEs — resolve in parallel with page fetching.
  const cveIds = findCveIds(candidate.type, candidate.title, candidate.evidence ?? {});
  const urls = candidateUrls(candidate);

  const [cveResults, pageResults] = await Promise.all([
    enrichCves(cveIds).catch(() => []),
    withConcurrency(urls.slice(0, MAX_PAGES), 3, (url) => extractPage(url, fetchFn).catch(() => null)).then((pages) =>
      pages.filter((p): p is NonNullable<typeof p> => p !== null)
    ),
  ]);

  // 2. Platform corpus.
  const keyword = topicKeyword(candidate.title);
  const self: SelfBinding | undefined = deps.self;
  const platform = await enrichFromPlatform(self, { INTERNAL_TOKEN_SECRET: deps.internalTokenSecret }, keyword).catch(
    () => EMPTY_PLATFORM
  );

  // 3. A page that failed is not a source. Keep only readable pages in the
  //    citable list, but record the failures so the writer does not "cite"
  //    something nobody read.
  const pages = pageResults.filter((p) => p.ok);
  const unread = pageResults.filter((p) => !p.ok).map((p) => ({ url: p.url, reason: p.error ?? 'unreadable' }));

  // Import lazily to keep the mining helpers in one module and avoid a cycle
  // with generation/scrub-prompt.
  const { buildDossier } = await import('./build');
  const dossier = buildDossier({
    type: candidate.type,
    title: candidate.title,
    rationale: candidate.rationale,
    evidence: candidate.evidence ?? {},
    cves: cveResults,
    pages,
    platform,
    unread,
    now,
  });

  dossier.meta = {
    pagesFetched: pageResults.length,
    pagesRead: pages.length,
    cvesEnriched: cveResults.length,
    tookMs: Date.now() - startedAt,
  };
  return dossier;
}

/** Convenience wrapper: research then render, for direct use in prompts. */
export async function researchAndRender(deps: ResearchDeps): Promise<{ dossier: ResearchDossier; rendered: string }> {
  const dossier = await researchCandidate(deps);
  return { dossier, rendered: renderDossier(dossier) };
}

export type { ResearchDossier };
