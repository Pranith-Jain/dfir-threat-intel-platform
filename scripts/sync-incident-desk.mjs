#!/usr/bin/env node
/**
 * Sync the Incident Desk feed (iamnicholasmartin.co.uk) into staging.
 *
 * The Incident Desk is an identity-lens incident briefing feed — short
 * analytical write-ups on live security incidents (CA-key handling, identity
 * supply chains, AI-key theft, secret management failures). Public RSS 2.0,
 * no key:
 *
 *   GET https://iamnicholasmartin.co.uk/incidents/feed.xml
 *
 * Fields per item: title, link, guid, pubDate, description, enclosure(image).
 * The RSS is simple and static (no CDATA, no namespaced content beyond the
 * atom:link self reference), so parsing is a small regex reader — same
 * approach as the other keyless syncs; no XML dependency is pulled in.
 *
 * Output:
 *   threat-intel-staging/incident-desk/posts.json
 *
 * Run:  node scripts/sync-incident-desk.mjs
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'incident-desk');
const FEED_URL = 'https://iamnicholasmartin.co.uk/incidents/feed.xml';
const UA = 'pranithjain-threat-intel-sync/1.0 (+https://pranithjain.qzz.io)';

export const INCIDENT_DESK = {
  source: 'iamnicholasmartin.co.uk/incidents',
  sourceUrl: 'https://iamnicholasmartin.co.uk/incidents',
  feedUrl: FEED_URL,
  description:
    'Incident Desk — emergency briefings on live security incidents through an identity lens (machine identity, CA misissuance, identity supply chains, secret management).',
  license: 'Copyright the author; briefs linked back to the source site',
};

const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = [2000, 5000, 10_000];

function ensureOut() {
  if (!existsSync(STAGING)) mkdirSync(STAGING, { recursive: true });
}

async function fetchTextWithRetry(url) {
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const wait = RETRY_BACKOFF_MS[attempt - 1] ?? 15_000;
      console.log(`  ⚠ feed attempt ${attempt}/${MAX_RETRIES} failed — retrying in ${wait / 1000}s`);
      await new Promise((r) => setTimeout(r, wait));
    }
    try {
      const res = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/rss+xml,application/xml,text/xml' } });
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      return await res.text();
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`fetch failed after ${MAX_RETRIES} retries: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
}

function decodeEntities(s) {
  return (s ?? '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&amp;/g, '&');
}

function tagText(block, tag) {
  const m = block.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`));
  return m ? decodeEntities(m[1].trim()) : null;
}

/** RSS is defined on RFC-822 dates; Date.parse handles the common forms. */
function normalizeDate(raw) {
  if (!raw) return null;
  const t = Date.parse(raw.replace(/\s+/g, ' ').trim());
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

/**
 * Slugify the guid/link tail for stable cross-run identity. The feed marks
 * every item with `guid isPermaLink="true"` pointing at the canonical post,
 * so the last path segment is a natural durable key.
 */
function slugOf(link, guid) {
  const base = link || guid || '';
  const tail = base.split('?')[0].replace(/\/+$/, '').split('/').pop() ?? '';
  return (
    tail
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 120) || 'untitled'
  );
}

function parseFeed(xml) {
  const feedTitle = tagText(xml.match(/<channel>([\s\S]*?)<\/channel>/)?.[1] ?? '', 'title');
  const items = [];
  const blocks = xml.match(/<item>([\s\S]*?)<\/item>/g) ?? [];
  for (const block of blocks) {
    const title = tagText(block, 'title');
    const link = tagText(block, 'link');
    const guid = tagText(block, 'guid');
    const pubDateRaw = tagText(block, 'pubDate');
    const description = tagText(block, 'description');
    const enclosure = block.match(/<enclosure\s+[^>]*url="([^"]+)"/);
    if (!title && !link && !description) continue;
    items.push({
      title,
      link,
      guid,
      published: normalizeDate(pubDateRaw),
      publishedRaw: pubDateRaw,
      description,
      imageUrl: enclosure ? decodeEntities(enclosure[1]) : null,
      slug: slugOf(link, guid),
    });
  }
  return { feedTitle, items };
}

async function main() {
  console.log('Incident Desk sync — fetching', FEED_URL);
  const xml = await fetchTextWithRetry(FEED_URL);
  const { feedTitle, items } = parseFeed(xml);
  if (items.length === 0) {
    console.error('  ✘ feed parsed to zero items — aborting (refusing to wipe staging with an empty parse)');
    process.exit(1);
  }
  // Newest first: the build and the page both expect the lead item to be the
  // freshest briefing (RSS doesn't guarantee order).
  items.sort((a, b) => String(b.published ?? '').localeCompare(String(a.published ?? '')));

  ensureOut();
  const staged = {
    ...INCIDENT_DESK,
    feedTitle,
    syncedAt: new Date().toISOString(),
    itemCount: items.length,
    items,
  };
  const p = join(STAGING, 'posts.json');
  writeFileSync(p, JSON.stringify(staged));
  const bytes = Buffer.byteLength(JSON.stringify(staged), 'utf8');
  console.log(`    ✔ staged ${items.length} briefs → ${p} (${(bytes / 1e3).toFixed(0)} KB)`);
}

main().catch((e) => {
  console.error('  ✘', e instanceof Error ? e.message : e);
  process.exit(1);
});
