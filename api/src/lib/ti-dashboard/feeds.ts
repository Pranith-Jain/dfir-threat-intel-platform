import type { D1Database } from '@cloudflare/workers-types';
import { NEWS_FEEDS, SUPPLY_CHAIN_FEED, type Article, type RawSupplyChainIncident } from './types';
import { unwrapBingNewsLink } from '../rss-parser';

const UA = 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)';

interface ParsedRssItem {
  title: string;
  url: string;
  published_date: string;
  summary: string;
}

function extractTag(text: string, tag: string): string {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const m = re.exec(text);
  if (!m) return '';
  return m[1]!.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim();
}

function parseRssItems(xml: string): ParsedRssItem[] {
  const items: ParsedRssItem[] = [];
  const itemRegex = /<(?:item|entry)>([\s\S]*?)<\/(?:item|entry)>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRegex.exec(xml)) !== null) {
    const body = m[1]!;
    const title = extractTag(body, 'title');
    const url = extractTag(body, 'link') || extractTag(body, 'guid');
    if (!title || !url) continue;
    const pubStr = extractTag(body, 'pubDate') || extractTag(body, 'published') || extractTag(body, 'updated');
    const published_date = pubStr ? new Date(pubStr).toISOString() : new Date().toISOString();
    const summaryRaw =
      extractTag(body, 'description') || extractTag(body, 'summary') || extractTag(body, 'content\\:encoded') || '';
    const summary = summaryRaw.replace(/<[^>]*>/g, '').slice(0, 500);
    // Unwrap first (the Bing redirect hides the real scheme), then normalize.
    items.push({ title, url: unwrapBingNewsLink(url).replace(/^http:\/\//, 'https://'), published_date, summary });
  }
  return items;
}

async function fetchRssFeed(feed: (typeof NEWS_FEEDS)[number], signal?: AbortSignal): Promise<Article[]> {
  try {
    const res = await fetch(feed.url, {
      headers: { 'user-agent': UA, accept: 'application/rss+xml, application/xml, text/xml' },
      signal,
      cf: { cacheTtlByStatus: { '200-299': 600, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    if (!res.ok) return [];
    const text = await res.text();
    const parsed = parseRssItems(text);
    return parsed
      .map((p) => ({
        id: 0,
        title: p.title,
        url: p.url,
        published_date: p.published_date,
        source_type: feed.type,
        summary: p.summary,
        feed_source: feed.id,
      }))
      .slice(0, 30);
  } catch {
    return [];
  }
}

export async function collectNewsArticles(signal?: AbortSignal): Promise<Article[]> {
  const results = await Promise.allSettled(NEWS_FEEDS.map((f) => fetchRssFeed(f, signal)));
  const articles: Article[] = [];
  const seen = new Set<string>();
  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    for (const a of r.value) {
      const key = a.url.toLowerCase().replace(/[?#].*$/, '');
      if (seen.has(key)) continue;
      seen.add(key);
      articles.push(a);
    }
  }
  articles.sort((a, b) => new Date(b.published_date).getTime() - new Date(a.published_date).getTime());
  return articles;
}

export async function persistArticles(db: D1Database, articles: Article[]): Promise<number> {
  let inserted = 0;
  for (const a of articles) {
    try {
      await db
        .prepare(
          'INSERT OR IGNORE INTO articles (title, url, published_date, source_type, summary, feed_source) VALUES (?, ?, ?, ?, ?, ?)'
        )
        .bind(a.title, a.url, a.published_date, a.source_type, a.summary || null, a.feed_source || null)
        .run();
      inserted++;
    } catch {
      /* noop */
    }
  }
  return inserted;
}

export async function fetchRecentArticles(db: D1Database, limit = 100): Promise<Article[]> {
  const res = await db
    .prepare('SELECT * FROM articles ORDER BY published_date DESC LIMIT ?')
    .bind(limit)
    .all<Article>();
  return res.results ?? [];
}

function _extractSupplyChainItem(line: string): RawSupplyChainIncident | null {
  const titleMatch = line.match(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+,\s+\d{4}(.+?)(?:\n|$)/);
  if (!titleMatch) return null;

  const dateMatch = line.match(/^([A-Z][a-z]+ \d+, \d{4})/);
  const published_date = dateMatch?.[1] ? new Date(dateMatch[1]).toISOString() : new Date().toISOString();

  const title = titleMatch[1]!.trim();
  const lower = line.toLowerCase();

  let ecosystem = 'other';
  let attack_vector = 'other';
  let severity = 'medium';
  const status: string[] = [];
  let threat_actor: string | null = null;

  if (lower.includes('npm')) ecosystem = 'npm';
  else if (lower.includes('pypi')) ecosystem = 'PyPI';
  else if (lower.includes('maven') || lower.includes('java')) ecosystem = 'Maven';
  else if (lower.includes('rubygems') || lower.includes('gem')) ecosystem = 'RubyGems';
  else if (lower.includes('nuget') || lower.includes('.net')) ecosystem = 'NuGet';
  else if (lower.includes('go ') || lower.includes('golang')) ecosystem = 'Go';
  else if (lower.includes('cargo') || lower.includes('rust')) ecosystem = 'Cargo';
  else if (lower.includes('container') || lower.includes('docker')) ecosystem = 'Container registry';
  else if (lower.includes('model hub') || lower.includes('huggingface')) ecosystem = 'Model hub';
  else if (lower.includes('ai agent') || lower.includes('mcp')) ecosystem = 'AI agents & skills';
  else if (lower.includes('ci/cd') || lower.includes('github action')) ecosystem = 'CI/CD';
  else if (lower.includes('hardware') || lower.includes('firmware')) ecosystem = 'Hardware';
  else if (lower.includes('vendor') || lower.includes('saas') || lower.includes('third-party'))
    ecosystem = 'Vendor / SaaS';

  if (lower.includes('compromised package') || lower.includes('malicious package'))
    attack_vector = 'Compromised package';
  else if (lower.includes('malicious commit') || lower.includes('typosquat')) attack_vector = 'Typosquatting';
  else if (lower.includes('dependency confusion')) attack_vector = 'Dependency confusion';
  else if (lower.includes('build-system') || lower.includes('build system')) attack_vector = 'Build-system compromise';
  else if (lower.includes('account takeover')) attack_vector = 'Account takeover';
  else if (lower.includes('update server') || lower.includes('update-server'))
    attack_vector = 'Update-server compromise';
  else if (lower.includes('signing key')) attack_vector = 'Stolen signing key';

  if (lower.includes('critical')) severity = 'critical';
  else if (lower.includes('high')) severity = 'high';
  else if (lower.includes('medium')) severity = 'medium';
  else if (lower.includes('low')) severity = 'low';

  if (lower.includes('active')) status.push('active');
  else if (lower.includes('contained')) status.push('contained');
  else if (lower.includes('resolved')) status.push('resolved');
  else if (lower.includes('disputed')) status.push('disputed');

  const actorMatch = line.match(/threat actor[:\s]+([A-Z][a-z0-9\s-]+?)(?=\.|$)/i);
  if (actorMatch?.[1]) threat_actor = actorMatch[1].trim();

  const url = `https://www.supplychainattack.org/?search=${encodeURIComponent(title.slice(0, 40))}`;
  const summary = line.replace(/<[^>]*>/g, '').slice(0, 300);

  return {
    title,
    url,
    ecosystem,
    attack_vector,
    severity,
    status: status[0] || 'active',
    threat_actor,
    published_date,
    summary,
  };
}

export async function fetchSupplyChainIncidents(signal?: AbortSignal): Promise<RawSupplyChainIncident[]> {
  try {
    const res = await fetch(SUPPLY_CHAIN_FEED, {
      headers: { 'user-agent': UA, accept: 'text/html' },
      signal,
      cf: { cacheTtlByStatus: { '200-299': 600, '400-599': 0 }, cacheEverything: true },
    } as RequestInit);
    if (!res.ok) return [];
    const html = await res.text();
    const incidents: RawSupplyChainIncident[] = [];

    const cards = html.match(/<a[^>]*class="[^"]*incident-card[^"]*"[^>]*>[\s\S]*?<\/a>/gi) || [];
    for (const card of cards) {
      const titleMatch = card.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
      if (!titleMatch) continue;
      const title = titleMatch[1]!.replace(/<[^>]*>/g, '').trim();
      if (!title) continue;

      const urlMatch = card.match(/href="([^"]+)"/);
      const url = urlMatch?.[1]
        ? `https://www.supplychainattack.org${urlMatch[1].replace(/^https?:\/\/[^\/]+/, '')}`
        : SUPPLY_CHAIN_FEED;

      const dateMatch = card.match(/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+,\s+\d{4}/);
      const published_date = dateMatch ? new Date(dateMatch[0]).toISOString() : new Date().toISOString();

      const metaEls =
        card.match(/<span[^>]*class="[^"]*(?:ecosystem|severity|status|vector)[^"]*"[^>]*>([\s\S]*?)<\/span>/gi) || [];
      let ecosystem = 'other',
        attack_vector = 'other',
        severity = 'medium',
        status = 'active';
      const threat_actor: string | null = null;

      for (const el of metaEls) {
        const text = el
          .replace(/<[^>]*>/g, '')
          .trim()
          .toLowerCase();
        if (
          ['npm', 'pypi', 'maven', 'rubygems', 'nuget', 'go', 'cargo', 'container', 'hardware', 'other'].includes(text)
        )
          ecosystem = text;
        else if (['critical', 'high', 'medium', 'low'].includes(text)) severity = text;
        else if (['active', 'contained', 'resolved', 'disputed'].includes(text)) status = text;
        else if (
          text.includes('compromised') ||
          text.includes('malicious') ||
          text.includes('typosquat') ||
          text.includes('dependency') ||
          text.includes('build') ||
          text.includes('account') ||
          text.includes('update') ||
          text.includes('signing')
        ) {
          attack_vector = text.charAt(0).toUpperCase() + text.slice(1);
        }
      }

      const summary = card
        .replace(/<[^>]*>/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 300);

      incidents.push({
        title,
        url,
        ecosystem,
        attack_vector,
        severity,
        status,
        threat_actor,
        published_date,
        summary,
      });
    }
    return incidents;
  } catch {
    return [];
  }
}

export async function persistSupplyChainIncidents(
  db: D1Database,
  incidents: RawSupplyChainIncident[]
): Promise<number> {
  let inserted = 0;
  for (const inc of incidents) {
    try {
      await db
        .prepare(
          'INSERT OR IGNORE INTO supply_chain_incidents (title, url, ecosystem, attack_vector, severity, status, threat_actor, published_date, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        )
        .bind(
          inc.title,
          inc.url,
          inc.ecosystem,
          inc.attack_vector,
          inc.severity,
          inc.status,
          inc.threat_actor,
          inc.published_date,
          inc.summary
        )
        .run();
      inserted++;
    } catch {
      /* noop */
    }
  }
  return inserted;
}

export async function fetchRecentSupplyChainIncidents(db: D1Database, limit = 50): Promise<RawSupplyChainIncident[]> {
  const res = await db
    .prepare('SELECT * FROM supply_chain_incidents ORDER BY published_date DESC LIMIT ?')
    .bind(limit)
    .all<RawSupplyChainIncident>();
  return res.results ?? [];
}
