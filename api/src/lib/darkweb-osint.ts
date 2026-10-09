/**
 * Dark web OSINT — native TypeScript implementation of TorBot + darkdump
 * capabilities for Cloudflare Workers.
 *
 * TorBot core features replicated:
 *   - Multi-engine .onion search (Ahmia, NotEvil, OnionLand, Tor66)
 *   - Depth-limited BFS crawl with link tree extraction
 *   - Page metadata + email harvesting
 *   - JSON export of crawl tree
 *
 * darkdump core features replicated:
 *   - Multi-engine search across 6 dark web search engines
 *   - Deep scraping (metadata, emails, links, keywords)
 *   - Ahmia abuse blacklist filtering
 *
 * All .onion access goes through tor2web gateways (clearnet proxies).
 * Each fetch = 1 subrequest. Workers budget is 50/invocation, so
 * crawls are depth-capped and result-limited.
 */

// `tor2webUrl` is shared with the darknet vertical rather than re-declared
// here — a third copy of this builder previously drifted to the broken path
// form (`<onion>/<gateway>`), which never resolves.
import { tor2webUrl, extractOnionHostname } from './darknet';

const UA = 'pranithjain-darkweb-osint/1.0';
const TOR2WEB_GATEWAYS = ['tor2web.io', 'onion.ws', 'onion.sh', 'tor2web.org'] as const;
const MAX_CRAWL_PAGES = 15;
const MAX_CRAWL_DEPTH = 2;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const ONION_RE = /(?:https?:\/\/)?[a-z2-7]{16,56}\.onion(?:\/[^\s"'<>]*)?/gi;

// ─── Types ────────────────────────────────────────────────────────────────

export interface DarkwebSearchResult {
  engine: string;
  title: string;
  url: string;
  description: string;
}

export interface DarkwebSearchResponse {
  query: string;
  engines_queried: string[];
  total_results: number;
  results: DarkwebSearchResult[];
  errors: Array<{ engine: string; error: string }>;
}

export interface CrawlPage {
  url: string;
  hostname: string;
  title: string;
  status_code: number;
  body_text: string;
  links: Array<{ text: string; href: string; is_onion: boolean }>;
  emails: string[];
  onion_refs: string[];
  depth: number;
  fetched_via: string;
}

export interface CrawlTree {
  seed_url: string;
  pages_crawled: number;
  pages: CrawlPage[];
  all_emails: string[];
  all_onion_refs: string[];
  link_tree: Array<{
    parent: string;
    children: Array<{ href: string; text: string }>;
  }>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Extract a validated v2/v3 onion hostname, or null.
 *
 * #300: this used to carry its own inline regex — `/^[a-z2-7]{16,56}\.onion$/`
 * — which disagreed with `isValidOnionAddress` in ./darknet (exactly 16 or 56).
 * It accepted lengths in between, so an invalid address could produce a tor2web
 * URL resolving to a stranger's gateway subdomain. Now delegates to the shared
 * validator; the two entry points cannot drift again.
 */
function onionHost(input: string): string | null {
  return extractOnionHostname(input);
}

function extractEmails(text: string): string[] {
  const found = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = EMAIL_RE.exec(text)) !== null) {
    const email = m[0].toLowerCase();
    if (!email.endsWith('.png') && !email.endsWith('.jpg') && !email.endsWith('.gif')) {
      found.add(email);
    }
  }
  return [...found];
}

function extractOnionRefs(text: string): string[] {
  const found = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = ONION_RE.exec(text)) !== null) {
    const raw = m[0].replace(/^https?:\/\//, '').replace(/\/+$/, '');
    if (/^[a-z2-7]{16,56}\.onion$/i.test(raw)) found.add(raw);
  }
  return [...found];
}

function parseBasicHtml(html: string): {
  title: string;
  links: Array<{ text: string; href: string }>;
  bodyText: string;
} {
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const title = titleMatch?.[1]?.trim() ?? '';

  const links: Array<{ text: string; href: string }> = [];
  const linkRe = /<a\s+[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) !== null) {
    const href = (m[1] ?? '').trim();
    const text = (m[2] ?? '').replace(/<[^>]+>/g, '').trim();
    if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
      links.push({ text: text || href, href });
    }
  }

  const bodyText = html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z]+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 50_000);

  return { title, links, bodyText };
}

// ─── Multi-Engine Search ──────────────────────────────────────────────────

async function searchAhmia(query: string, limit: number): Promise<DarkwebSearchResult[]> {
  try {
    const res = await fetch(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`, {
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*', 'Accept-Language': 'en-US,en;q=0.5' },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) return [];
    const html = await res.text();
    const results: DarkwebSearchResult[] = [];
    const liRe = /<li[^>]*class\s*=\s*["']result["'][^>]*>([\s\S]*?)<\/li>/gi;
    let m: RegExpExecArray | null;
    while ((m = liRe.exec(html)) !== null) {
      const li = m[1] ?? '';
      const titleMatch = /<a[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/i.exec(li);
      const descMatch = /<p[^>]*>([\s\S]*?)<\/p>/i.exec(li);
      if (titleMatch) {
        let href = (titleMatch[1] ?? '').trim();
        const title = (titleMatch[2] ?? '').replace(/<[^>]+>/g, '').trim();
        const description = descMatch ? (descMatch[1] ?? '').replace(/<[^>]+>/g, '').trim() : '';
        if (href.includes('redirect_url=')) {
          try {
            href = new URL(href, 'https://ahmia.fi').searchParams.get('redirect_url') ?? href;
          } catch {
            /* */
          }
        }
        if (title && href) results.push({ engine: 'ahmia', title, url: href, description });
      }
    }
    return results.slice(0, limit);
  } catch {
    return [];
  }
}

async function searchOnionLand(query: string, limit: number): Promise<DarkwebSearchResult[]> {
  try {
    const res = await fetch(`https://onionlandsearchengine.net/search?q=${encodeURIComponent(query)}`, {
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) return [];
    const html = await res.text();
    const results: DarkwebSearchResult[] = [];
    const itemRe = /<div[^>]*class\s*=\s*["'][^"']*result[^"']*["'][^>]*>([\s\S]*?)<\/div>/gi;
    let m: RegExpExecArray | null;
    while ((m = itemRe.exec(html)) !== null) {
      const block = m[1] ?? '';
      const titleMatch = /<a[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/i.exec(block);
      const descMatch = /<p[^>]*>([\s\S]*?)<\/p>/i.exec(block);
      if (titleMatch) {
        const href = (titleMatch[1] ?? '').trim();
        const title = (titleMatch[2] ?? '').replace(/<[^>]+>/g, '').trim();
        const description = descMatch ? (descMatch[1] ?? '').replace(/<[^>]+>/g, '').trim() : '';
        if (title && href) results.push({ engine: 'onionland', title, url: href, description });
      }
    }
    return results.slice(0, limit);
  } catch {
    return [];
  }
}

async function searchTor66(query: string, limit: number): Promise<DarkwebSearchResult[]> {
  try {
    const searchHost = 'tor66searchbtpgl32.onion';
    const url = tor2webUrl(searchHost, TOR2WEB_GATEWAYS[0]);
    const res = await fetch(`${url}/search?q=${encodeURIComponent(query)}`, {
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) return [];
    const html = await res.text();
    const results: DarkwebSearchResult[] = [];
    const re =
      /<div[^>]*class\s*=\s*["']result["'][^>]*>[\s\S]*?<a[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>[\s\S]*?<\/div>/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      const href = (m[1] ?? '').trim();
      const title = (m[2] ?? '').replace(/<[^>]+>/g, '').trim();
      if (title && href) results.push({ engine: 'tor66', title, url: href, description: '' });
    }
    return results.slice(0, limit);
  } catch {
    return [];
  }
}

async function searchDarkwebTools(query: string, limit: number): Promise<DarkwebSearchResult[]> {
  try {
    const res = await fetch(`https://darkweblink.com/search?q=${encodeURIComponent(query)}`, {
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) return [];
    const html = await res.text();
    const results: DarkwebSearchResult[] = [];
    const re = /<a[^>]*href\s*=\s*["']([^"']*\.onion[^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      const href = (m[1] ?? '').trim();
      const title = (m[2] ?? '').replace(/<[^>]+>/g, '').trim();
      if (title && href) results.push({ engine: 'darkweblink', title, url: href, description: '' });
    }
    return results.slice(0, limit);
  } catch {
    return [];
  }
}

export async function darkwebMultiSearch(
  query: string,
  engines: string[] = ['ahmia', 'onionland', 'tor66', 'darkweblink'],
  limitPerEngine = 20
): Promise<DarkwebSearchResponse> {
  const tasks: Array<{ engine: string; fn: Promise<DarkwebSearchResult[]> }> = [];
  if (engines.includes('ahmia')) tasks.push({ engine: 'ahmia', fn: searchAhmia(query, limitPerEngine) });
  if (engines.includes('onionland')) tasks.push({ engine: 'onionland', fn: searchOnionLand(query, limitPerEngine) });
  if (engines.includes('tor66')) tasks.push({ engine: 'tor66', fn: searchTor66(query, limitPerEngine) });
  if (engines.includes('darkweblink'))
    tasks.push({ engine: 'darkweblink', fn: searchDarkwebTools(query, limitPerEngine) });

  const settled = await Promise.allSettled(tasks.map(async (t) => ({ engine: t.engine, results: await t.fn })));

  const allResults: DarkwebSearchResult[] = [];
  const errors: DarkwebSearchResponse['errors'] = [];
  const queried: string[] = [];

  for (const r of settled) {
    if (r.status === 'fulfilled') {
      queried.push(r.value.engine);
      allResults.push(...r.value.results);
    } else {
      errors.push({ engine: 'unknown', error: r.reason?.message ?? 'unknown error' });
    }
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  const deduped = allResults.filter((r) => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });

  return {
    query,
    engines_queried: queried,
    total_results: deduped.length,
    results: deduped,
    errors,
  };
}

/**
 * Search .onion sites — wrapper around darkwebMultiSearch that returns just
 * the results array for the /onion-search endpoint.
 */
export async function torSearchOnion(query: string, limit: number): Promise<DarkwebSearchResult[]> {
  const resp = await darkwebMultiSearch(query, ['ahmia', 'onionland', 'tor66'], limit);
  return resp.results.slice(0, limit);
}

// ─── Crawl + Link Tree (TorBot BFS) ──────────────────────────────────────

export async function darkwebCrawl(
  seedUrl: string,
  opts: { maxDepth?: number; maxPages?: number; extractEmails?: boolean } = {}
): Promise<CrawlTree> {
  const maxDepth = Math.min(opts.maxDepth ?? MAX_CRAWL_DEPTH, 3);
  const maxPages = Math.min(opts.maxPages ?? MAX_CRAWL_PAGES, 20);

  const hostname = onionHost(seedUrl);
  if (!hostname) throw new Error(`Invalid .onion URL: ${seedUrl}`);

  const visited = new Set<string>();
  const pages: CrawlPage[] = [];
  const allEmails = new Set<string>();
  const allOnionRefs = new Set<string>();
  const linkTree: CrawlTree['link_tree'] = [];

  // BFS queue: [url, depth]
  const queue: Array<{ url: string; depth: number; parent: string }> = [{ url: hostname, depth: 0, parent: 'seed' }];

  while (queue.length > 0 && pages.length < maxPages) {
    const { url: currentHost, depth, parent: _parent } = queue.shift()!;
    if (visited.has(currentHost)) continue;
    if (depth > maxDepth) continue;
    visited.add(currentHost);

    // Fetch via tor2web
    const gw = TOR2WEB_GATEWAYS[pages.length % TOR2WEB_GATEWAYS.length] ?? TOR2WEB_GATEWAYS[0];
    const fetchUrl = tor2webUrl(currentHost, gw);
    try {
      const res = await fetch(fetchUrl, {
        headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
        redirect: 'follow',
        signal: AbortSignal.timeout(10_000),
      });
      const html = await res.text();
      const { title, links, bodyText } = parseBasicHtml(html);

      // Extract emails
      const emails = opts.extractEmails !== false ? extractEmails(bodyText) : [];
      emails.forEach((e) => allEmails.add(e));

      // Extract .onion references
      const onionRefs = extractOnionRefs(bodyText + ' ' + links.map((l) => l.href).join(' '));
      onionRefs.forEach((o) => allOnionRefs.add(o));

      // Resolve links
      const resolvedLinks = links.map((l) => {
        let href = l.href;
        if (href.startsWith('/')) href = `http://${currentHost}${href}`;
        else if (!href.includes('.onion') && !href.startsWith('http')) href = `http://${currentHost}/${href}`;
        else if (href.includes('.onion') && !href.startsWith('http')) href = `http://${href}`;
        const isOnion = /[a-z2-7]{16,56}\.onion/i.test(href);
        return { text: l.text, href, is_onion: isOnion };
      });

      const page: CrawlPage = {
        url: currentHost,
        hostname: currentHost,
        title,
        status_code: res.status,
        body_text: bodyText.slice(0, 5_000),
        links: resolvedLinks.slice(0, 100),
        emails,
        onion_refs: [...onionRefs],
        depth,
        fetched_via: `${currentHost}.${gw}`,
      };
      pages.push(page);

      // Record link tree edge
      const childOnions = resolvedLinks
        .filter((l) => l.is_onion)
        .slice(0, 20)
        .map((l) => ({ href: l.href, text: l.text }));
      if (childOnions.length > 0) {
        linkTree.push({ parent: currentHost, children: childOnions });
      }

      // Enqueue .onion children for next depth level
      if (depth < maxDepth) {
        for (const link of resolvedLinks) {
          if (link.is_onion && !visited.has(link.href)) {
            const childHost = onionHost(link.href);
            if (childHost && !visited.has(childHost)) {
              queue.push({ url: childHost, depth: depth + 1, parent: currentHost });
            }
          }
        }
      }
    } catch {
      // Failed to fetch — record empty page
      pages.push({
        url: currentHost,
        hostname: currentHost,
        title: '(fetch failed)',
        status_code: 0,
        body_text: '',
        links: [],
        emails: [],
        onion_refs: [],
        depth,
        fetched_via: `FAILED via ${currentHost}.${gw}`,
      });
    }
  }

  return {
    seed_url: hostname,
    pages_crawled: pages.length,
    pages,
    all_emails: [...allEmails],
    all_onion_refs: [...allOnionRefs],
    link_tree: linkTree,
  };
}

// ─── Single Page Deep Scrape (darkdump -s equivalent) ────────────────────

export interface ScrapeDeepResult {
  url: string;
  hostname: string;
  title: string;
  status_code: number;
  fetched_via: string;
  body_text: string;
  links: Array<{ text: string; href: string; is_onion: boolean }>;
  emails: string[];
  onion_refs: string[];
  metadata: {
    description: string | null;
    keywords: string[];
    og_title: string | null;
    og_description: string | null;
    language: string | null;
  };
}

export async function darkwebScrapeDeep(onionUrl: string): Promise<ScrapeDeepResult> {
  const hostname = onionHost(onionUrl);
  if (!hostname) throw new Error(`Invalid .onion URL: ${onionUrl}`);

  const gw = TOR2WEB_GATEWAYS[0];
  const fetchUrl = tor2webUrl(hostname, gw);
  const res = await fetch(fetchUrl, {
    headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
    redirect: 'follow',
    signal: AbortSignal.timeout(12_000),
  });
  const html = await res.text();
  const { title, links, bodyText } = parseBasicHtml(html);

  // Extract emails
  const emails = extractEmails(bodyText);

  // Extract onion references
  const onionRefs = extractOnionRefs(bodyText + ' ' + links.map((l) => l.href).join(' '));

  // Extract metadata
  const metaDesc = /<meta[^>]*name\s*=\s*["']description["'][^>]*content\s*=\s*["']([^"']*)["']/i.exec(html);
  const metaKeywords = /<meta[^>]*name\s*=\s*["']keywords["'][^>]*content\s*=\s*["']([^"']*)["']/i.exec(html);
  const ogTitle = /<meta[^>]*property\s*=\s*["']og:title["'][^>]*content\s*=\s*["']([^"']*)["']/i.exec(html);
  const ogDesc = /<meta[^>]*property\s*=\s*["']og:description["'][^>]*content\s*=\s*["']([^"']*)["']/i.exec(html);
  const lang = /<html[^>]*lang\s*=\s*["']([^"']*)["']/i.exec(html);

  return {
    url: hostname,
    hostname,
    title,
    status_code: res.status,
    fetched_via: `${hostname}.${gw}`,
    body_text: bodyText,
    links: links.map((l) => ({
      text: l.text,
      href: l.href,
      is_onion: /[a-z2-7]{16,56}\.onion/i.test(l.href),
    })),
    emails,
    onion_refs: onionRefs,
    metadata: {
      description: metaDesc?.[1] ?? null,
      keywords:
        metaKeywords?.[1]
          ?.split(',')
          .map((k) => k.trim())
          .filter(Boolean) ?? [],
      og_title: ogTitle?.[1] ?? null,
      og_description: ogDesc?.[1] ?? null,
      language: lang?.[1] ?? null,
    },
  };
}
