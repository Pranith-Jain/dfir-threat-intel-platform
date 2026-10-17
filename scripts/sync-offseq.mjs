#!/usr/bin/env node
/**
 * Sync the OffSeq Threat Radar (radar.offseq.com) public threat feed.
 *
 * OffSeq aggregates ~40 upstream sources (NCSC UK, JVN, AWS, GCP, CERT/CC,
 * Talos, Unit 42, OTX, ThreatFox, …) and AI-enriches every threat with
 * summaries, KEV correlation and Mirage honeypot exploitation telemetry.
 * The site exposes a public anonymous JSON API that the SPA itself calls:
 *
 *   GET /api/threats?limit=&page=&sort=-publishedDate&days=&type=
 *   GET /api/threats/tags
 *   GET /api/threats/stats/overview
 *
 * Anonymous tier advertises ~100 req/window (x-ratelimit-limit-threats);
 * setting OFFSEQ_API_KEY sends X-API-Key and lifts the ceiling. We stay well
 * under the anonymous limit (a few pages + 2 metadata calls) so sync works
 * without a key.
 *
 * Run by:
 *   1. GitHub Action (.github/workflows/threat-intel-sync.yml)
 *   2. Manual: `node scripts/sync-offseq.mjs`
 *
 * After sync, run `node scripts/build-offseq.mjs`.
 *
 * Source: https://radar.offseq.com/ (free public API, no key required)
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging');
const OUT = join(STAGING, 'offseq');
const UA = 'pranithjain-threat-intel-sync/1.0 (+https://pranithjain.qzz.io)';
const API = 'https://radar.offseq.com/api/threats';
const API_KEY = process.env.OFFSEQ_API_KEY || null;

export const OFFSEQ = {
  source: 'radar.offseq.com',
  sourceUrl: 'https://radar.offseq.com/',
  description:
    'Aggregated threat-intel feed (~40 upstream sources) with AI-enriched summaries, KEV correlation and Mirage honeypot exploitation telemetry.',
  license: 'Public API (anonymous tier; optional key lifts rate limits)',
};

const PAGE_SIZE = 25;
const MAX_PAGES = 8;
const DAYS = 30;

function ensureOut() {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
}

async function fetchJson(url) {
  const headers = { 'user-agent': UA, accept: 'application/json' };
  if (API_KEY) headers['X-API-Key'] = API_KEY;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`OffSeq fetch failed: ${url} → ${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchThreats({ days = DAYS } = {}) {
  const threats = [];
  let total = 0;
  let page = 1;
  for (let p = 0; p < MAX_PAGES; p++) {
    const url = new URL(API);
    url.searchParams.set('limit', String(PAGE_SIZE));
    url.searchParams.set('page', String(page));
    url.searchParams.set('sort', '-publishedDate');
    url.searchParams.set('days', String(days));
    // eslint-disable-next-line no-await-in-loop
    const body = await fetchJson(url.toString());
    const batch = Array.isArray(body.threats) ? body.threats : [];
    for (const t of batch) threats.push(t);
    if (typeof body?.pagination?.total === 'number') total = body.pagination.total;
    if (batch.length < PAGE_SIZE) break;
    if (typeof body?.pagination?.pages === 'number' && page >= body.pagination.pages) break;
    page += 1;
  }
  // de-dupe by externalId/slug/title
  const seen = new Set();
  const deduped = [];
  for (const t of threats) {
    const key = t.externalId || t.slug || t.title || '';
    if (key && seen.has(key)) continue;
    if (key) seen.add(key);
    deduped.push(t);
  }
  return { threats: deduped, total: total || deduped.length };
}

function readStaging() {
  const p = join(OUT, 'offseq.json');
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

export async function main() {
  console.log('OffSeq sync — staging into', OUT);
  ensureOut();

  const prev = readStaging();

  let threats = [];
  let total = 0;
  try {
    const r = await fetchThreats();
    threats = r.threats;
    total = r.total;
    console.log(`    fetched ${threats.length} threats (upstream total ${total})`);
  } catch (err) {
    if (prev && Array.isArray(prev.threats) && prev.threats.length > 0) {
      console.error(`  ✘ fetch failed (${err instanceof Error ? err.message : err}) — keeping existing staging`);
      return prev.threats.length;
    }
    throw err;
  }

  let tags = null;
  let overview = null;
  try {
    tags = await fetchJson('https://radar.offseq.com/api/threats/tags');
  } catch (err) {
    console.warn(`  ⚠ tags fetch failed: ${err instanceof Error ? err.message : err}`);
  }
  try {
    overview = await fetchJson('https://radar.offseq.com/api/threats/stats/overview');
  } catch (err) {
    console.warn(`  ⚠ overview fetch failed: ${err instanceof Error ? err.message : err}`);
  }

  const nowIso = new Date().toISOString();
  const staged = {
    source: OFFSEQ.source,
    sourceUrl: OFFSEQ.sourceUrl,
    description: OFFSEQ.description,
    license: OFFSEQ.license,
    syncedAt: nowIso,
    days: DAYS,
    total,
    rawFetched: threats.length,
    overview,
    tags,
    threats,
  };
  writeFileSync(join(OUT, 'offseq.json'), JSON.stringify(staged, null, 2));
  console.log(`    ✔ staged ${threats.length} threats`);
  console.log('\nNext: node scripts/build-offseq.mjs');
  return threats.length;
}

main().catch((err) => {
  console.error('✘ sync failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
