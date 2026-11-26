/**
 * Topic discovery for bare, operator-supplied topics.
 *
 * `researchCandidate` can only fetch pages whose URLs are already in the
 * candidate's evidence. That is correct for discovery candidates (they arrive
 * with source links) but wrong for the admin "Generate" tab: there the
 * operator types a subject, and the old pipeline handed the writer a dossier
 * with *zero* sources read. The grounding contract then told the model not to
 * invent — so it produced a hollow, hedged piece instead of an article.
 *
 * This module closes that gap before the write step:
 *
 *   1. URLs the operator pasted into the supplied content are real sources and
 *      are read like any other (they win over corpus hits).
 *   2. A single authenticated `/api/v1/unified-search?q=<keyword>` SELF call
 *      asks the platform's own corpus (writeups, CVEs, actor timeline,
 *      ransomware, breaches, malpedia, …) for citable hits. One SELF call is
 *      one subrequest from the caller's invocation; the 16 searchers fan out
 *      inside the route's own invocation, so this stays cheap on the free plan.
 *   3. CVE ids found in the supplied text or the corpus hits are enriched by
 *      the existing NVD/KEV/EPSS path in `enrich.ts`.
 *
 * Nothing here asserts a fact. It only finds candidate sources and ids; the
 * pages are then fetched and verified by `extractPage` in `research/index.ts`,
 * and only pages that read successfully reach the writer's dossier.
 */

import { selfFetchJson } from '../../lib/self-fetch';
import { parseRss } from '../../lib/rss-parser';
import { isCanonicalAuthorityUrl } from '../../lib/verify-url';

export interface TopicHit {
  url: string;
  label: string;
  source: string;
  description?: string;
  score?: number;
}

export interface TopicDiscovery {
  hits: TopicHit[];
  cveIds: string[];
}

const URL_RE = /https?:\/\/[^\s<>"']+/gi;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
/** Bounded: the research stage caps page fetches at MAX_PAGES (6). */
const MAX_SUPPLIED = 12;
const MAX_HITS = 12;
const MAX_CVES = 4;
/**
 * Last-resort web fallback for topics the platform corpus has never covered.
 * Bing News RSS is already the platform's allowed mirror surface for
 * bot-blocked publishers (see feeds-aggregate.ts), so this adds no new host.
 */
const BING_NEWS_RSS = 'https://www.bing.com/news/search?format=RSS&mkt=en-US&q=';
const MAX_NEWS_HITS = 5;

/** Minimal SELF binding shape — matches `self-fetch.ts`. */
type SelfFetcher = {
  fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response>;
};

function cleanUrl(raw: string): string {
  return raw.replace(/^<|>$/g, '').replace(/[)\].,;:!?>]+$/, '');
}

/** URLs an operator pasted into the content/notes field, in order. */
export function suppliedUrls(text: string | undefined): TopicHit[] {
  if (!text) return [];
  const out: TopicHit[] = [];
  const seen = new Set<string>();
  for (const match of text.match(URL_RE) ?? []) {
    const url = cleanUrl(match);
    if (!/^https?:\/\/\S+$/i.test(url) || seen.has(url)) continue;
    seen.add(url);
    out.push({ url, label: '', source: 'operator' });
  }
  return out.slice(0, MAX_SUPPLIED);
}

/** CVE ids in operator-supplied text (a bare topic often names one). */
export function suppliedCveIds(text: string | undefined): string[] {
  if (!text) return [];
  return [...new Set((text.match(CVE_RE) ?? []).map((id) => id.toUpperCase()))].slice(0, MAX_CVES);
}

interface CorpusItem {
  label?: string;
  description?: string;
  url?: string;
  source?: string;
  score?: number;
}

interface CorpusSection {
  kind?: string;
  items?: CorpusItem[];
}

interface CorpusResponse {
  sections?: CorpusSection[];
}

/**
 * Ask the unified-search surface for material on a bare topic.
 *
 * Returns `[]` on a missing SELF binding, a missing internal secret, a failed
 * call or an empty corpus. That is the same best-effort contract as
 * `enrichFromPlatform`: research that finds nothing still yields a dossier,
 * just one that honestly says nothing was established.
 */
export async function discoverTopicCorpus(deps: {
  keyword: string;
  self?: SelfFetcher;
  env: { INTERNAL_TOKEN_SECRET?: string };
}): Promise<TopicDiscovery> {
  const empty: TopicDiscovery = { hits: [], cveIds: [] };
  if (!deps.keyword || !deps.self || !deps.env.INTERNAL_TOKEN_SECRET) return empty;

  // unified-search substring-matches the whole query. A reduced keyword like
  // "examplecorp gateway" misses records that only say "Examplecorp edge
  // gateway", so retry once with the single most distinctive token. At most
  // two SELF calls, and the retry only happens when the first found nothing.
  const tokens = deps.keyword.split(' ').filter(Boolean);
  const keywords = tokens.length > 1 ? [deps.keyword, tokens[0] as string] : [deps.keyword];
  let raw: CorpusResponse | null = null;
  for (const keyword of keywords) {
    raw = await selfFetchJson<CorpusResponse>(
      deps.self,
      `/api/v1/unified-search?q=${encodeURIComponent(keyword)}`,
      deps.env
    );
    if (raw && Array.isArray(raw.sections) && raw.sections.some((s) => (s.items ?? []).length > 0)) break;
  }
  if (!raw || !Array.isArray(raw.sections)) return empty;

  const hits: TopicHit[] = [];
  const cveIds = new Set<string>();
  const seen = new Set<string>();

  for (const section of raw.sections) {
    for (const item of section.items ?? []) {
      const label = String(item.label ?? '').slice(0, 160);
      const description = typeof item.description === 'string' ? item.description.slice(0, 240) : undefined;
      for (const id of `${label} ${description ?? ''}`.match(CVE_RE) ?? []) cveIds.add(id.toUpperCase());

      const url = typeof item.url === 'string' ? cleanUrl(item.url) : '';
      if (!/^https?:\/\/\S+$/i.test(url) || seen.has(url)) continue;
      // lookupCve already covers these authoritatively, and their pages are
      // JSON rather than prose. Probing them burns the page budget for nothing.
      if (/nvd\.nist\.gov|known-exploited-vulnerabilities|attack\.mitre\.org/i.test(url)) continue;
      seen.add(url);
      hits.push({
        url,
        label,
        source: section.kind || item.source || 'corpus',
        description,
        score: typeof item.score === 'number' ? item.score : undefined,
      });
    }
  }

  hits.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
  return { hits: hits.slice(0, MAX_HITS), cveIds: [...cveIds].slice(0, MAX_CVES) };
}

/**
 * Keyword-scoped news search, used ONLY when the platform corpus returned no
 * citable URLs for a bare topic. Returns candidates, not facts: the pages are
 * fetched and verified by `research/index.ts` before reaching the writer.
 *
 * Best-effort like every research step — a 403, a timeout or a malformed feed
 * yields [] and the dossier honestly says nothing was established.
 */
export async function searchTopicNews(
  keyword: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch
): Promise<TopicHit[]> {
  if (!keyword) return [];
  try {
    const res = await fetchFn(`${BING_NEWS_RSS}${encodeURIComponent(keyword)}`, {
      headers: {
        accept: 'application/rss+xml, application/xml;q=0.9, */*;q=0.5',
        'user-agent': 'Mozilla/5.0 (compatible; pranithjain-research/1.0)',
      },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const items = parseRss(await res.text());
    return items
      .map((item) => ({
        url: item.link,
        label: item.title,
        source: 'news-web',
        description: item.snippet || undefined,
      }))
      .filter((h) => /^https?:\/\/\S+$/i.test(h.url) && !isCanonicalAuthorityUrl(h.url))
      .slice(0, MAX_NEWS_HITS);
  } catch {
    return [];
  }
}
