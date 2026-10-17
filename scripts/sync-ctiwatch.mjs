#!/usr/bin/env node
/**
 * Sync the CTIWatch (ctiwatch.com) public threat-intel API.
 *
 * CTIWatch exposes ~2.1M IOCs, ~360k CVEs (incl. KEV), ~10.8k threat
 * actors, ~35k ransomware victims and ~112 active campaigns behind a
 * public REST API (most reads open, with an anonymous session cookie).
 *
 * We sample the most recent records from each collection so the replicated
 * vertical stays small enough for the static-asset budget:
 *   - IOCs:        recent active indicators (confidence-graded)
 *   - Vulnerabilities: recent CVEs + the KEV subset
 *   - Threat actors: recent (ransomware/apt/malware)
 *   - Victims:     recent leak-site claims
 *   - Campaigns:   active campaigns
 *   - Stats:       headline counters
 *
 * Auth: anonymous session cookie minted by loading any HTML page, OR
 * CTIWATCH_API_KEY (X-Api-Key) when set. Anonymous scope is capped at
 * offset=1000 per collection and 150 req/window — we stay well under both.
 *
 * Run by:
 *   1. GitHub Action (.github/workflows/threat-intel-sync.yml)
 *   2. Manual: `node scripts/sync-ctiwatch.mjs`
 *
 * After sync, run `node scripts/build-ctiwatch.mjs`.
 *
 * Source: https://ctiwatch.com/ (free public API, anonymous session)
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging');
const OUT = join(STAGING, 'ctiwatch');
const UA = 'pranithjain-threat-intel-sync/1.0 (+https://pranithjain.qzz.io)';
const BASE = 'https://ctiwatch.com/api/v1';
const API_KEY = process.env.CTIWATCH_API_KEY || null;

export const CTIWATCH = {
  source: 'ctiwatch.com',
  sourceUrl: 'https://ctiwatch.com/',
  description:
    'Public vulnerability + IOC database (2M+ IOCs, 400k+ CVEs, 4k+ KEV, 10k+ threat actors, 35k+ victims).',
  license: 'Public API (anonymous session; free key lifts quotas)',
};

function ensureOut() {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
}

let sessionCookie = null;
async function bootstrapSession() {
  if (API_KEY) return null;
  const res = await fetch('https://ctiwatch.com/', { headers: { 'user-agent': UA, accept: 'text/html' }, signal: AbortSignal.timeout(30_000) });
  const setCookie = res.headers.get('set-cookie') ?? '';
  const m = /cti_anon=([^;]+)/.exec(setCookie);
  if (!m) throw new Error('ctiwatch session mint failed (no cti_anon cookie)');
  sessionCookie = m[1];
  return sessionCookie;
}

async function fetchJson(path, params = {}) {
  const url = new URL(BASE + path);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  const headers = { 'user-agent': UA, accept: 'application/json' };
  if (API_KEY) headers['X-Api-Key'] = API_KEY;
  else if (sessionCookie) headers.cookie = `cti_anon=${sessionCookie}`;
  const res = await fetch(url.toString(), { headers, signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`CTIWatch fetch failed: ${path} → ${res.status} ${res.statusText}`);
  return res.json();
}

async function paged(path, params, maxPages = 3, pageSize = 100) {
  const out = [];
  let offset = 0;
  for (let p = 0; p < maxPages; p++) {
    // eslint-disable-next-line no-await-in-loop
    const body = await fetchJson(path, { ...params, limit: pageSize, offset });
    const items = Array.isArray(body.items) ? body.items : (Array.isArray(body) ? body : []);
    for (const it of items) out.push(it);
    const total = typeof body.total === 'number' ? body.total : null;
    if (items.length < pageSize) break;
    if (total !== null && offset + items.length >= total) break;
    offset += items.length;
  }
  return out;
}

function readStaging() {
  const p = join(OUT, 'ctiwatch.json');
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; }
}

export async function main() {
  console.log('CTIWatch sync — staging into', OUT);
  ensureOut();
  await bootstrapSession();
  if (API_KEY) console.log('  using API key');
  else console.log('  minted anonymous session');

  const prev = readStaging();
  const staged = {
    source: CTIWATCH.source,
    sourceUrl: CTIWATCH.sourceUrl,
    description: CTIWATCH.description,
    license: CTIWATCH.license,
    syncedAt: new Date().toISOString(),
  };

  // stats
  try { staged.stats = await fetchJson('/stats'); } catch (e) { console.warn('  ⚠ stats failed:', e.message); staged.stats = prev?.stats ?? null; }
  // iocs (recent active)
  try { staged.iocs = await paged('/iocs', { is_active: 'true', sort: 'last_seen', order: 'desc' }, 3, 100); console.log(`  iocs: ${staged.iocs.length}`); }
  catch (e) { console.warn('  ⚠ iocs failed:', e.message); staged.iocs = prev?.iocs ?? []; }
  // vulnerabilities (recent)
  try { staged.vulnerabilities = await paged('/vulnerabilities', { sort: 'published_date', order: 'desc' }, 2, 100); console.log(`  vulnerabilities: ${staged.vulnerabilities.length}`); }
  catch (e) { console.warn('  ⚠ vulnerabilities failed:', e.message); staged.vulnerabilities = prev?.vulnerabilities ?? []; }
  // kev
  try { staged.kev = await paged('/vulnerabilities', { is_kev: 'true', sort: 'published_date', order: 'desc' }, 1, 100); console.log(`  kev: ${staged.kev.length}`); }
  catch (e) { console.warn('  ⚠ kev failed:', e.message); staged.kev = prev?.kev ?? []; }
  // threat actors
  try { staged.actors = await paged('/threat-actors', { sort: 'last_seen', order: 'desc' }, 2, 100); console.log(`  actors: ${staged.actors.length}`); }
  catch (e) { console.warn('  ⚠ actors failed:', e.message); staged.actors = prev?.actors ?? []; }
  // victims
  try { staged.victims = await paged('/victims', { sort: 'attack_date', order: 'desc' }, 2, 100); console.log(`  victims: ${staged.victims.length}`); }
  catch (e) { console.warn('  ⚠ victims failed:', e.message); staged.victims = prev?.victims ?? []; }
  // campaigns
  try { staged.campaigns = await paged('/campaigns', { active: 'true' }, 1, 50); console.log(`  campaigns: ${staged.campaigns.length}`); }
  catch (e) { console.warn('  ⚠ campaigns failed:', e.message); staged.campaigns = prev?.campaigns ?? []; }
  // victims stats
  try { staged.victimStats = await fetchJson('/victims/stats'); } catch (e) { console.warn('  ⚠ victim stats failed:', e.message); staged.victimStats = prev?.victimStats ?? null; }

  writeFileSync(join(OUT, 'ctiwatch.json'), JSON.stringify(staged, null, 2));
  console.log('\n  ✔ staged');
  console.log('\nNext: node scripts/build-ctiwatch.mjs');
  return (staged.iocs?.length ?? 0) + (staged.vulnerabilities?.length ?? 0);
}

main().catch((err) => {
  console.error('✘ sync failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
