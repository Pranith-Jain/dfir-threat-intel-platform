#!/usr/bin/env node
/**
 * Mirror Global Hack Map's public RSS incident feed into site data.
 *
 * https://globalhackmap.vercel.app/feed.xml publishes the latest ~50 publicly
 * reported incidents with the honest status taxonomy (Confirmed / Reported /
 * Claimed / Precautionary / Disputed), a short factual description, the
 * reporting date and a deep link to the original incident page. This is a
 * structured mirror: no upstream code or images, and every row deep-links the
 * source.
 *
 * Output: public/data/global-hack-map/incidents.json
 *         public/data/global-hack-map/patches.json
 * Run:    node scripts/sync-ghm-feed.mjs
 *
 * REA verification (browser scenario on globalhackmap.vercel.app plus the
 * Next.js route chunks) found a second PUBLIC feed: `GET /api/patch` needs no
 * key and returns 14 records with a concrete `fix`, the affected population
 * (`who`), KEV date, EPSS, CVSS and news volume — the actionable companion to
 * the incident map. The site's other API routes are gated: `/api/research`
 * needs Valyu sign-in (401), and `/api/brief`, `/api/check` and `/api/track`
 * are POST-only browser-context endpoints (400/405). `robots.txt` disallows
 * `/api/`, but this one endpoint is a public JSON feed served to every
 * visitor, so it is mirrored as structured metadata with attribution.
 */
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'global-hack-map', 'incidents.json');
const PATCH_OUT = join(ROOT, 'public', 'data', 'global-hack-map', 'patches.json');
const FEED = 'https://globalhackmap.vercel.app/feed.xml';
const PATCH_FEED = 'https://globalhackmap.vercel.app/api/patch';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const MAX_ITEMS = 50;

/** Country name → centroid. Used only when the feed names a location; never a street address. */
const PLACES = {
  'United States': [39.8, -98.6], 'USA': [39.8, -98.6], 'U.S.': [39.8, -98.6],
  'United Kingdom': [55.4, -3.4], 'UK': [55.4, -3.4], 'England': [52.4, -1.5],
  'Germany': [51.2, 10.5], 'France': [46.6, 2.2], 'Spain': [40.4, -3.7],
  'Italy': [41.9, 12.6], 'Netherlands': [52.1, 5.3], 'Ireland': [53.4, -8.2],
  'Canada': [56.1, -106.3], 'Australia': [-25.3, 133.8], 'New Zealand': [-40.9, 174.9],
  'Brazil': [-14.2, -51.9], 'Mexico': [23.6, -102.5], 'Argentina': [-38.4, -63.6],
  'India': [20.6, 78.9], 'China': [35.9, 104.2], 'Japan': [36.2, 138.3],
  'South Korea': [35.9, 127.8], 'Singapore': [1.35, 103.8], 'Taiwan': [23.7, 121.0],
  'Hong Kong': [22.3, 114.2], 'Indonesia': [-0.8, 113.9], 'Malaysia': [4.2, 101.9],
  'Philippines': [12.9, 121.8], 'Thailand': [15.9, 101.0], 'Vietnam': [14.1, 108.3],
  'South Africa': [-29.0, 24.7], 'Nigeria': [9.1, 8.7], 'Kenya': [-0.02, 37.9],
  'Egypt': [26.8, 30.8], 'Israel': [31.5, 34.9], 'Saudi Arabia': [23.9, 45.1],
  'United Arab Emirates': [23.4, 53.8], 'Turkey': [39.0, 35.2], 'Ukraine': [48.4, 31.2],
  'Poland': [52.1, 19.1], 'Sweden': [60.1, 18.6], 'Norway': [60.5, 8.5],
  'Denmark': [56.3, 9.5], 'Finland': [61.9, 25.7], 'Switzerland': [46.8, 8.2],
  'Austria': [47.5, 14.6], 'Belgium': [50.5, 4.5], 'Portugal': [39.4, -8.2],
  'Czech Republic': [49.8, 15.5], 'Greece': [39.1, 21.8], 'Romania': [45.9, 25.0],
  'Russia': [61.5, 105.3], 'Colombia': [4.6, -74.1], 'Chile': [-35.7, -71.5],
  'Peru': [-9.2, -75.0], 'Costa Rica': [9.9, -84.1], 'Pakistan': [30.4, 69.3],
  'Bangladesh': [23.7, 90.4], 'Sri Lanka': [7.9, 80.8], 'Kazakhstan': [48.0, 67.3],
  'Morocco': [31.8, -7.1], 'Tunisia': [33.9, 9.6], 'Ghana': [7.9, -1.0],
};

const STATUSES = new Set(['confirmed', 'reported', 'claimed', 'precautionary', 'disputed']);
const decode = (s = '') =>
  s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&apos;/g, "'").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/<[^>]+>/g, '').trim();

const tag = (block, name) => decode(block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'))?.[1] ?? '');

function parseRecords(text) {
  let best = 0;
  const take = (n, scale = 1) => {
    if (Number.isFinite(n) && n * scale > best) best = n * scale;
  };
  for (const m of text.matchAll(/\b(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s*(million|billion|[KMB])\b/gi)) {
    take(Number(m[1].replace(/,/g, '')), /billion|^b$/i.test(m[2]) ? 1e9 : /million|^m$/i.test(m[2]) ? 1e6 : 1e3);
  }
  for (const m of text.matchAll(/\b(\d{1,3}(?:,\d{3})+)\b/g)) take(Number(m[1].replace(/,/g, '')));
  return best || null;
}

function parseLocation(text) {
  // The feed puts the place at the end of the description ("Dunedin, New Zealand.").
  const tail = text.split(/(?<=[.!?])\s+/).pop() ?? '';
  const parts = tail.split(',').map((p) => p.replace(/[.!]+$/, '').trim()).filter(Boolean);
  for (const part of [...parts].reverse()) {
    if (PLACES[part]) return { place: parts.join(', '), country: part, coords: PLACES[part] };
  }
  return { place: parts.join(', ').slice(0, 80) || null, country: null, coords: null };
}

export function parseIncident(block) {
  const title = tag(block, 'title');
  const url = tag(block, 'link');
  if (!title || !url) return null;
  const description = tag(block, 'description');
  const categories = [...block.matchAll(/<category>([\s\S]*?)<\/category>/gi)].map((m) => decode(m[1]));
  const status = categories.find((c) => STATUSES.has(c.toLowerCase()))?.toLowerCase() ?? 'reported';
  const type = categories.find((c) => !STATUSES.has(c.toLowerCase())) ?? 'Cyberattack';
  const loc = parseLocation(description);
  const actorMatch = title.match(/claimed by\s+([^,:;]+)/i) ?? description.match(/([A-Z][\w.-]+)\s+claims?\s/i);
  const victim = (title.split(/\s*(?::|\bConfirmed\b|\bReported\b|\bClaimed\b|\bDisputed\b|\bPrecautionary\b)/i)[0] ?? title).trim();
  return {
    id: url.split('/').filter(Boolean).pop() ?? victim.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    victim: victim.slice(0, 120),
    title: title.slice(0, 240),
    description: description.slice(0, 900),
    status,
    type,
    actor: actorMatch?.[1]?.trim() ?? null,
    records: parseRecords(description),
    place: loc.place,
    country: loc.country,
    lat: loc.coords?.[0] ?? 0,
    lng: loc.coords?.[1] ?? 0,
    published: tag(block, 'pubDate'),
    url,
  };
}

export function parseFeed(xml) {
  if (typeof xml !== 'string') return [];
  return [...xml.matchAll(/<item>([\s\S]*?)<\/item>/gi)]
    .map((m) => parseIncident(m[1]))
    .filter(Boolean)
    .slice(0, MAX_ITEMS);
}

async function fetchFeed(url, accept, attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { headers: { 'user-agent': UA, accept }, signal: AbortSignal.timeout(30_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
    }
  }
  throw new Error(`${url}: ${last?.message ?? 'fetch failed'}`);
}

/**
 * `GET /api/patch` returns `{items: [...]}`. Keep only the documented fields,
 * validate the CVE ids, and dedupe by `key` (vendor|product) so an upstream
 * duplicate cannot occupy two dock slots.
 */
export function parsePatches(raw) {
  let parsed;
  try {
    parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return [];
  }
  const rows = Array.isArray(parsed) ? parsed : parsed?.items ?? parsed?.patches ?? [];
  if (!Array.isArray(rows)) return [];
  const text = (v) => (typeof v === 'string' ? v.trim().slice(0, 1200) : '');
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const seen = new Set();
  const out = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const vendor = text(row.vendor);
    const product = text(row.product);
    const key = text(row.key) || [vendor, product].filter(Boolean).join('|').toLowerCase();
    if (!key || seen.has(key)) continue;
    const cves = (Array.isArray(row.cves) ? row.cves : [])
      .filter((c) => typeof c === 'string' && /^CVE-\d{4}-\d{4,7}$/i.test(c.trim()))
      .map((c) => c.trim().toUpperCase())
      .slice(0, 20);
    const title = text(row.title);
    const fix = text(row.fix);
    if (!title && !fix) continue;
    seen.add(key);
    out.push({
      key,
      vendor: vendor || null,
      product: product || null,
      cves,
      exploited: Boolean(row.exploited),
      ransomware: Boolean(row.ransomware),
      newsCount: num(row.newsCount) ?? 0,
      kevAdded: /^\d{4}-\d{2}-\d{2}$/.test(String(row.kevAdded ?? '')) ? row.kevAdded : null,
      epss: num(row.epss),
      cvss: num(row.cvss),
      domain: text(row.domain) || null,
      title,
      who: text(row.who),
      fix,
      explained: Boolean(row.explained),
      url: `https://globalhackmap.vercel.app/cve/${cves[0] ?? ''}`.replace(/\/$/, ''),
    });
    if (out.length >= 50) break;
  }
  return out;
}

async function main() {
  console.log('  fetching Global Hack Map incident feed');
  const incidents = parseFeed(await fetchFeed(FEED, 'application/rss+xml, application/xml'));
  if (!incidents.length) throw new Error('no incidents parsed — upstream feed changed');
  const byStatus = {};
  for (const i of incidents) byStatus[i.status] = (byStatus[i.status] ?? 0) + 1;
  const payload = {
    generatedAt: new Date().toISOString(),
    upstream: { site: 'https://globalhackmap.vercel.app', feed: FEED, note: 'Structured incident metadata + factual summaries; every row deep-links the original.' },
    count: incidents.length,
    byStatus,
    incidents,
  };
  writeJsonIfChanged(OUT, payload);
  console.log(`  ✓ ${incidents.length} incidents → ${OUT}`);

  // The patch feed is optional: a transient 5xx must not discard the incident
  // mirror (the two upstream pages are independent and the workflow step is
  // one script). Log the failure loudly instead.
  try {
    const patches = parsePatches(await fetchFeed(PATCH_FEED, 'application/json'));
    if (!patches.length) throw new Error('no patches parsed — upstream shape changed');
    const patchPayload = {
      generatedAt: new Date().toISOString(),
      upstream: {
        site: 'https://globalhackmap.vercel.app',
        endpoint: PATCH_FEED,
        note: 'Public JSON feed. Only factual patch metadata is mirrored; every row deep-links the relevant CVE page.',
      },
      count: patches.length,
      exploited: patches.filter((p) => p.exploited).length,
      ransomware: patches.filter((p) => p.ransomware).length,
      inKev: patches.filter((p) => p.kevAdded).length,
      patches,
    };
    writeJsonIfChanged(PATCH_OUT, patchPayload);
    console.log(`  ✓ ${patches.length} patch advisories → ${PATCH_OUT}`);
  } catch (e) {
    console.warn(`  ! patch feed unavailable: ${e.message}`);
  }
  console.log('');
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`ghm feed sync failed: ${e.message}`); process.exit(1); });
