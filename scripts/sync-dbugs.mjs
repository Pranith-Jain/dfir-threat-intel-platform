#!/usr/bin/env node
/**
 * Mirror the public dbugs (https://dbu.gs) vulnerability index into site data.
 *
 * REA browser capture confirmed the pages are Next.js SSR with no public API;
 * the rows live in the `__NEXT_DATA__` script. We mirror the public trend list
 * and the public vulnerability rows (CVSS, vendor/product, exploit/fix flags,
 * references, descriptions) plus aggregate stats. Sign-in-gated features are
 * not mirrored and no private endpoint is used.
 *
 * Output: public/data/dbugs/index.json
 * Run:    node scripts/sync-dbugs.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'dbugs');
const BASE = 'https://dbu.gs';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

async function fetchText(url, attempts = 2) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'text/html,*/*' },
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) { last = e; }
  }
  throw new Error(`${url}: ${last?.message ?? 'fetch failed'}`);
}

/** Pull the `__NEXT_DATA__` JSON blob out of a rendered Next.js page. */
export function nextData(html) {
  const m = String(html ?? '').match(/<script id="__NEXT_DATA__" type="application\/json">([\s\S]*?)<\/script>/);
  if (!m) throw new Error('__NEXT_DATA__ not found — upstream markup changed');
  return JSON.parse(m[1]);
}

const pick = (o, ...keys) => {
  for (const k of keys) if (o && o[k] != null) return o[k];
  return null;
};

/** Normalise one public vulnerability row. */
export function normalizeVuln(row) {
  const locales = row.locales ?? {};
  const firstLocale = Object.values(locales)[0] ?? {};
  const en = firstLocale?.En ?? firstLocale ?? {};
  return {
    id: String(row.vulner_id ?? ''),
    cveId: String(row.cve_id ?? ''),
    score: typeof row.max_score === 'number' ? row.max_score : null,
    severity: String(row.max_severity ?? ''),
    created: String(row.created ?? ''),
    updated: String(row.updated ?? ''),
    vendors: Array.isArray(row.vendors) ? row.vendors : [],
    products: Array.isArray(row.products) ? row.products : [],
    hasFix: row.has_fix === true,
    hasExploits: row.has_exploits === true,
    impacts: Array.isArray(row.impacts) ? row.impacts : [],
    cwe: Array.isArray(row.cwe_ids) ? row.cwe_ids : [],
    description: String(pick(en, 'description') ?? ''),
    references: Array.isArray(row.references)
      ? row.references.filter((r) => r && typeof r.ref_url === 'string').slice(0, 8).map((r) => ({ url: r.ref_url, source: String(r.source ?? ''), domain: String(r.domain ?? '') }))
      : [],
    url: `${BASE}/vulnerability/${row.vulner_id ?? ''}`,
  };
}

/** Normalise a trend row: tweet/audience counts and the nested vulnerability. */
export function normalizeTrend(row) {
  const timeline = row.twitter_timeline ?? {};
  const counts = (obj) => (obj && typeof obj === 'object' ? Object.values(obj).reduce((a, b) => a + (Number(b) || 0), 0) : 0);
  return {
    rank: typeof row.lvl === 'number' ? row.lvl : null,
    postsCount: typeof row.posts_count === 'number' ? row.posts_count : 0,
    tweets: counts(timeline.tweets),
    audience: counts(timeline.audience),
    retweets: counts(timeline.retweets),
    lastTweets: Array.isArray(row.last_tweets)
      ? row.last_tweets.slice(0, 3).map((t) => ({ url: String(t.url ?? ''), text: String(t.text ?? ''), published: String(t.published ?? '') }))
      : [],
    vulnerability: row.vulnerability ? normalizeVuln(row.vulnerability) : null,
  };
}

async function main() {
  console.log('  fetching dbugs public index');
  const html = await fetchText(`${BASE}/`);
  const fb = nextData(html)?.props?.pageProps?.fallback ?? {};
  const vulnKey = Object.keys(fb).find((k) => k.startsWith('@"PREDEFINED_FILTERS_LIST"'));
  const trendKey = Object.keys(fb).find((k) => k.startsWith('@"VULNERABILITY_TRENDS"'));
  const vulns = ((vulnKey && fb[vulnKey]?.rows) ?? []).map(normalizeVuln).filter((v) => v.id);
  const trends = ((trendKey && fb[trendKey]?.rows) ?? []).map(normalizeTrend).filter((t) => t.vulnerability);
  if (!vulns.length || !trends.length) throw new Error('no dbugs rows parsed — upstream payload changed');
  const payload = {
    generatedAt: new Date().toISOString(),
    upstream: { site: BASE, home: `${BASE}/`, vulnerabilities: `${BASE}/vulnerability`, trends: `${BASE}/trends` },
    stats: {
      vulnerabilities: vulns.length,
      trends: trends.length,
      withExploits: vulns.filter((v) => v.hasExploits).length,
      withFix: vulns.filter((v) => v.hasFix).length,
    },
    trends,
    vulnerabilities: vulns,
  };
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'index.json'), `${JSON.stringify(payload, null, 2)}\n`);
  console.log(`  ✓ ${vulns.length} vulnerabilities · ${trends.length} trends → ${OUT}/index.json\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`dbugs sync failed: ${e.message}`); process.exit(1); });
