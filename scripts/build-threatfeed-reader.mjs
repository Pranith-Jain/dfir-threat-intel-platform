#!/usr/bin/env node
/**
 * Mirror jozeta/ThreatFeed's published article snapshot (MIT) as the dataset
 * for our own in-site reader. REA confirmed the site reads data/snapshot.json,
 * data/entities.json and data/seed-articles.json; it fetches feed bodies at
 * runtime through third-party CORS proxies, which we deliberately avoid — the
 * snapshot plus direct article links is enough for a working reader.
 *
 * Visitor state (read/viewed/bookmarked) is stripped: that belongs in the
 * browser, not in mirrored data.
 *
 * Output: public/data/threatfeed-reader/index.json
 * Run:    node scripts/build-threatfeed-reader.mjs [--source-dir <dir>]
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'threatfeed-reader', 'index.json');
const SITE = 'https://jozeta.github.io/ThreatFeed/';
const REPO = 'https://github.com/jozeta/ThreatFeed';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

export function parseSnapshot(snapshot, entities, feeds = []) {
  const categoryBySource = new Map(
    feeds.map((f) => [String(f.id), String(f.category ?? 'Uncategorised')])
  );
  const articles = Array.isArray(snapshot?.articles) ? snapshot.articles : [];
  const slim = articles
    .filter((a) => a?.id && a?.title && a?.url)
    .slice(0, 2500)
    .map((a) => ({
      id: String(a.id).slice(0, 160),
      title: String(a.title).slice(0, 400),
      url: /^https?:\/\//i.test(String(a.url)) ? String(a.url).slice(0, 1200) : null,
      sourceId: String(a.sourceId ?? '').slice(0, 120),
      sourceName: String(a.sourceName ?? '').slice(0, 120),
      description: String(a.description ?? '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 700),
      author: String(a.author ?? '').slice(0, 120),
      feedCategory: categoryBySource.get(String(a.sourceId ?? '')) ?? 'Uncategorised',
      publishedAt: a.publishedAt ?? null,
      fetchedAt: a.fetchedAt ?? null,
      tags: Array.isArray(a.tags) ? a.tags.slice(0, 12).map((t) => String(t).slice(0, 60)) : [],
      categories: Array.isArray(a.categories) ? a.categories.slice(0, 6).map((c) => String(c).slice(0, 60)) : [],
      cves: Array.isArray(a.cves) ? a.cves.slice(0, 12).map((c) => String(c).slice(0, 24)) : [],
      severity: String(a.severity ?? 'unknown').slice(0, 24),
      severityScore: typeof a.severityScore === 'number' ? a.severityScore : null,
    }))
    .filter((a) => a.url)
    .sort((a, b) => String(b.publishedAt ?? '').localeCompare(String(a.publishedAt ?? '')));

  // Upstream's /#/sources view is built from feeds.json (catalogue) joined
  // with snapshot.feedHealth (runtime status). Mirror that join so the in-site
  // Sources tab shows the same 158 feeds with health, latency and article
  // counts, without calling any upstream CORS proxy at runtime.
  const health = snapshot?.feedHealth && typeof snapshot.feedHealth === 'object' ? snapshot.feedHealth : {};
  const catalog = new Map(feeds.map((f) => [String(f.id), f]));
  const sourceIds = new Set([...catalog.keys(), ...Object.keys(health)]);
  const sources = [...sourceIds]
    .map((id) => {
      const f = catalog.get(id) ?? {};
      const h = health[id] ?? {};
      return {
        id,
        name: String(f.name ?? h.feedId ?? id).slice(0, 120),
        url: /^https?:\/\//i.test(String(f.url ?? '')) ? String(f.url).slice(0, 800) : null,
        category: String(f.category ?? 'Uncategorised').slice(0, 80),
        tags: Array.isArray(f.tags) ? f.tags.slice(0, 8).map((t) => String(t).slice(0, 40)) : [],
        enabled: f.enabled !== false,
        status: String(h.status ?? 'unknown').slice(0, 24),
        httpStatus: typeof h.httpStatus === 'number' ? h.httpStatus : null,
        latencyMs: typeof h.latencyMs === 'number' ? h.latencyMs : null,
        articleCount: typeof h.articleCount === 'number' ? h.articleCount : null,
        lastFetchedAt: h.lastFetchedAt ?? null,
        lastSuccessAt: h.lastSuccessAt ?? null,
        gatewayUsed: String(h.gatewayUsed ?? '').slice(0, 60),
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const counts = {
    articles: slim.length,
    sources: sources.length,
    categories: new Set(slim.map((a) => a.feedCategory)).size,
    critical: slim.filter((a) => a.severity === 'critical').length,
    withCves: slim.filter((a) => a.cves.length > 0).length,
    sourcesHealthy: sources.filter((s) => s.status === 'healthy').length,
    sourcesUnhealthy: sources.filter((s) => s.status !== 'healthy').length,
  };
  const vendors = Array.isArray(entities?.vendors) ? entities.vendors.slice(0, 40) : [];
  const actors = Array.isArray(entities?.actors) ? entities.actors.slice(0, 40) : [];
  const groups = Array.isArray(entities?.groups) ? entities.groups.slice(0, 40) : [];
  return {
    articles: slim,
    sources,
    counts,
    generatedAt: snapshot?.generatedAt ?? null,
    feedHealth: snapshot?.feedHealth ?? {},
    trending: { vendors, actors, groups },
  };
}

async function main() {
  const arg = process.argv.indexOf('--source-dir');
  const dir = arg > 0 ? process.argv[arg + 1] : null;
  const load = async (file) => {
    if (dir) return JSON.parse(readFileSync(join(dir, file), 'utf8'));
    const res = await fetch(`${SITE}data/${file}`, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(60_000) });
    if (!res.ok) throw new Error(`${file}: HTTP ${res.status}`);
    return res.json();
  };
  const snapshot = await load('snapshot.json');
  let entities = {};
  try { entities = await load('entities.json'); } catch { /* trending is optional */ }
  let feeds = [];
  try { feeds = (await load('feeds.json')).feeds ?? []; } catch { /* category mapping is optional */ }
  const parsed = parseSnapshot(snapshot, entities, feeds);
  if (!parsed.articles.length) throw new Error('no articles parsed — upstream snapshot shape changed');
  writeJsonIfChanged(OUT, {
    generatedAt: new Date().toISOString(),
    source: 'ThreatFeed',
    sourceUrl: SITE,
    repoUrl: REPO,
    license: 'MIT — https://github.com/jozeta/ThreatFeed/blob/main/LICENSE',
    note: 'Article metadata + short descriptions mirrored from the public snapshot. No upstream code, CORS proxies or article bodies are vendored; visitor state is browser-local.',
    ...parsed,
  });
  console.log(`  ✓ ThreatFeed reader: ${parsed.counts.articles} articles / ${parsed.counts.sources} sources → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`threatfeed reader build failed: ${e.message}`); process.exit(1); });
