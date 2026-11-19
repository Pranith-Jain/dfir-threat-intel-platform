#!/usr/bin/env node
/**
 * Sync the ARTEX Intel threat tracker (artexintel.com) into staging + site data.
 *
 * Upstream is a static tracker site rebuilt daily (~08:04 SGT) that publishes
 * its underlying data as JSON next to the HTML:
 *   - /data/site.json     daily report-count trend + trending keywords
 *   - /data/iocs.json     every tracked indicator (defanged, with sources)
 *   - /data/exposure.json exposed-instance snapshot (upstream feed: ThreatBook)
 *   - /timeline           event list as <li class="ev"> rows
 *   - /events/<slug>.html one detail page per event (attribute table + prose)
 *
 * Staging layout (threat-intel-staging/artex/, gitignored working copy):
 *   site.json iocs.json exposure.json timeline.html events/<slug>.html
 *
 * Site data (public/data/artex/, committed deliverable):
 *   index.json    processed overview: stats, trend, keywords, events,
 *                 top IoCs, notable samples, traces, country breakdown
 *   events.json   full parsed event list with per-event detail
 *   iocs.json     verbatim upstream copy (page paginates client-side)
 *   exposure.json verbatim upstream copy (page paginates client-side)
 *
 * Every network step is isolated: one flaky fetch must not abort the rest.
 * Run: node scripts/sync-artex.mjs
 */
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'artex');
const OUT = join(ROOT, 'public', 'data', 'artex');
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const BASE = 'https://artexintel.com';

/** Fetch text with a bounded timeout; throws with the status on failure. */
async function fetchText(url) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: '*/*' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`fetch failed: ${url} -> ${res.status} ${res.statusText}`);
  return await res.text();
}

async function fetchJson(url) {
  return JSON.parse(await fetchText(url));
}

function decodeEntities(s) {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .trim();
}

/** Strip tags for a text-only read of a small HTML fragment. */
function stripTags(s) {
  return decodeEntities(
    s
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
  );
}

/**
 * Parse the /timeline event list. Rows are:
 *   <li class="ev" data-cat="attack|tool" data-art="" data-conf="ok"
 *       data-text="lowercased title"> <div class="when">2026-11-13</div>
 *   <div class="card"> <img class="ic" src="assets/icons/x.png">
 *   <div class="cbody"> <div class="rtype">Type</div>
 *   <h3><a href="events/slug.html">Title</a></h3> <p>summary</p> ...
 */
function parseTimeline(html) {
  const events = [];
  const liRe = /<li class="ev"([^>]*)>([\s\S]*?)<\/li>/g;
  let m;
  while ((m = liRe.exec(html)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const attr = (name) => {
      const r = new RegExp(`${name}="([^"]*)"`);
      return decodeEntities((attrs.match(r) || [])[1] || '');
    };
    const when = stripTags((body.match(/<div class="when">([\s\S]*?)<\/div>/) || [])[1] || '');
    const rtype = stripTags((body.match(/<div class="rtype">([\s\S]*?)<\/div>/) || [])[1] || '');
    const link = body.match(/<h3><a href="([^"]+)">([\s\S]*?)<\/a><\/h3>/);
    const href = link ? decodeEntities(link[1]) : '';
    const title = link ? stripTags(link[2]) : '';
    const summary = stripTags((body.match(/<p>([\s\S]*?)<\/p>/) || [])[1] || '');
    const icon = decodeEntities((body.match(/<img class="ic" src="([^"]+)"/) || [])[1] || '');
    // Region / actor / confidence live in trailing .card meta chips; the
    // timeline row carries the machine-readable confidence in data-conf.
    const region = stripTags((body.match(/<div class="rreg">([\s\S]*?)<\/div>/) || [])[1] || '');
    const actor = stripTags((body.match(/<div class="ract">([\s\S]*?)<\/div>/) || [])[1] || '');
    events.push({
      slug: href.replace(/^events\//, '').replace(/\.html$/, ''),
      title,
      url: href ? `${BASE}/${href}` : '',
      cat: attr('data-cat'),
      confidence: attr('data-conf'),
      type: rtype,
      region,
      actor,
      icon: icon ? `${BASE}/${icon}` : '',
      disclosed: when,
      summary,
    });
  }
  return events;
}

/**
 * Parse one event detail page: h1 title + the first attribute table
 * (key/value rows) + remaining prose paragraphs + the source list.
 */
function parseEventPage(html) {
  const h1 = stripTags((html.match(/<h1>([\s\S]*?)<\/h1>/) || [])[1] || '');
  const mainMatch = html.match(/<main class="wrap">([\s\S]*?)<\/main>/);
  const main = mainMatch ? mainMatch[1] : html;
  const attrs = {};
  const tables = main.match(/<table[\s\S]*?<\/table>/g) || [];
  for (const row of (tables[0] || '').match(/<tr>([\s\S]*?)<\/tr>/g) || []) {
    const cells = [...row.matchAll(/<(?:th|td)>([\s\S]*?)<\/(?:th|td)>/g)].map((c) => stripTags(c[1]));
    if (cells.length >= 2 && cells[0]) attrs[cells[0]] = cells.slice(1).join(' / ');
  }
  const sources = [];
  for (const row of (tables[1] || '').match(/<tr>([\s\S]*?)<\/tr>/g) || []) {
    const link = row.match(/<a href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    if (link) sources.push({ publisher: stripTags(link[2]), url: decodeEntities(link[1]) });
  }
  // Prose: paragraphs outside the tables.
  const prose = main
    .replace(/<table[\s\S]*?<\/table>/g, ' ')
    .replace(/<h2>/g, '\n<h2>')
    .match(/<p>([\s\S]*?)<\/p>/g);
  const body = (prose || []).map((p) => stripTags(p.slice(3, -4))).filter(Boolean);
  return { title: h1, attributes: attrs, sources, body };
}

function isHash(v) {
  return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(v);
}

async function main() {
  const problems = [];
  const note = (label, err) => {
    problems.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
    console.error(`[artex] ${label} failed: ${err instanceof Error ? err.message : err}`);
  };

  rmSync(STAGING, { recursive: true, force: true });
  mkdirSync(join(STAGING, 'events'), { recursive: true });
  mkdirSync(OUT, { recursive: true });

  // 1. The three JSON data files the tracker publishes next to its HTML.
  let site = null;
  let iocs = null;
  let exposure = null;
  try {
    site = await fetchJson(`${BASE}/data/site.json`);
    writeFileSync(join(STAGING, 'site.json'), JSON.stringify(site));
  } catch (err) {
    note('data/site.json', err);
  }
  try {
    iocs = await fetchJson(`${BASE}/data/iocs.json`);
    writeFileSync(join(STAGING, 'iocs.json'), JSON.stringify(iocs));
  } catch (err) {
    note('data/iocs.json', err);
  }
  try {
    exposure = await fetchJson(`${BASE}/data/exposure.json`);
    writeFileSync(join(STAGING, 'exposure.json'), JSON.stringify(exposure));
  } catch (err) {
    note('data/exposure.json', err);
  }

  // 2. Timeline event list.
  let events = [];
  try {
    const timelineHtml = await fetchText(`${BASE}/timeline`);
    writeFileSync(join(STAGING, 'timeline.html'), timelineHtml);
    events = parseTimeline(timelineHtml);
    if (events.length === 0) throw new Error('parsed 0 events from /timeline markup');
  } catch (err) {
    note('timeline', err);
  }

  // 2b. Fail before touching the committed deliverable if any critical
  // upstream document is missing. Previously a successful /timeline fetch
  // with the three JSON files missing overwrote public/data/artex/index.json
  // with empty IOCs, trend and keywords and still exited 0.
  if (!site || !iocs || !exposure || events.length === 0) {
    console.error('[artex] critical upstream data missing — refusing to rebuild committed data');
    process.exitCode = 1;
    return;
  }

  // 3. Per-event detail pages (bounded, sequential; one failure never
  // drops the event from the list - it only drops the detail block).
  const details = {};
  for (const ev of events) {
    if (!ev.slug) continue;
    try {
      const html = await fetchText(`${BASE}/events/${ev.slug}.html`);
      writeFileSync(join(STAGING, 'events', `${ev.slug}.html`), html);
      details[ev.slug] = parseEventPage(html);
    } catch (err) {
      note(`events/${ev.slug}.html`, err);
    }
  }

  // 4. Assemble the processed overview from whatever arrived.
  const eventsFull = events.map((ev) => {
    const d = details[ev.slug];
    return {
      ...ev,
      attributes: d?.attributes || {},
      sources: d?.sources || [],
      body: d?.body || [],
    };
  });

  const disclosedDates = eventsFull.map((e) => e.disclosed).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d));
  const firstPublic = disclosedDates.length ? disclosedDates.reduce((a, b) => (a < b ? a : b)) : null;
  const lastPublic = disclosedDates.length ? disclosedDates.reduce((a, b) => (a > b ? a : b)) : null;
  const attackEvents = eventsFull.filter((e) => e.cat !== 'tool').length;
  const toolUpdates = eventsFull.filter((e) => e.cat === 'tool').length;
  const daysTracked =
    firstPublic && lastPublic
      ? Math.round((new Date(lastPublic).getTime() - new Date(firstPublic).getTime()) / 86_400_000) + 1
      : null;

  // Country breakdown from the exposure snapshot (fallback: none).
  const countryCounts = new Map();
  if (exposure?.items) {
    for (const it of exposure.items) {
      const c = it.country_en || it.country || 'Unknown';
      countryCounts.set(c, (countryCounts.get(c) || 0) + 1);
    }
  }
  const countries = [...countryCounts.entries()]
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count);

  // Top IoCs: first eight of each type in upstream order (the tracker
  // ranks its list; we preserve the order instead of inventing our own).
  const topIocs = {};
  const wantedTypes = ['domain', 'ip', 'exposed', 'hash'];
  for (const t of wantedTypes) {
    topIocs[t] = (iocs || [])
      .filter((e) => e.type === t && e.defanged)
      .slice(0, 8)
      .map((e) => ({ value: e.defanged, roles: e.roles || [], sources: (e.sources || []).map((s) => s.publisher) }));
  }

  // Notable samples: hash IoCs that carry roles + sources (same rows the
  // upstream homepage highlights).
  const samples = (iocs || [])
    .filter((e) => e.type === 'hash' && isHash(e.value) && (e.sources || []).length > 0)
    .slice(0, 24)
    .map((e) => ({
      hash: e.value,
      notes: (e.roles || []).join('; '),
      status: e.status || '',
      sources: (e.sources || []).map((s) => ({ publisher: s.publisher, url: s.url })),
    }));

  // Traces: file paths + GitHub repos + fingerprints observed in incidents.
  const traces = (iocs || [])
    .filter((e) => ['file_path', 'github_repo', 'fingerprint'].includes(e.type))
    .slice(0, 40)
    .map((e) => e.defanged || e.value);

  const index = {
    generated_at: new Date().toISOString(),
    upstream: {
      site: `${BASE}/`,
      last_updated:
        lastPublic && exposure?.feed_updated
          ? lastPublic >= exposure.feed_updated.slice(0, 10)
            ? `${lastPublic} (events) / ${exposure.feed_updated} (exposure feed)`
            : `${exposure.feed_updated} (exposure feed) / ${lastPublic} (events)`
          : lastPublic || exposure?.feed_updated || null,
      exposure_feed: exposure?.feed_url || null,
      exposure_feed_updated: exposure?.feed_updated || null,
    },
    sync_problems: problems,
    stats: {
      attack_events: attackEvents,
      tool_updates: toolUpdates,
      events_total: eventsFull.length,
      first_public: firstPublic,
      last_public: lastPublic,
      days_tracked: daysTracked,
      iocs: Array.isArray(iocs) ? iocs.length : null,
      exposed: exposure?.items?.length ?? null,
    },
    countries,
    trend: site?.trend || null,
    keywords: site?.kw || null,
    events: eventsFull.map((e) => ({
      slug: e.slug,
      title: e.title,
      url: e.url,
      cat: e.cat,
      confidence: e.confidence,
      type: e.type,
      region: e.region,
      actor: e.actor,
      icon: e.icon,
      disclosed: e.disclosed,
      summary: e.summary,
      attributes: e.attributes,
      sources: e.sources,
      body: e.body,
    })),
    top_iocs: topIocs,
    samples,
    traces,
  };

  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));

  // 5. Verbatim deliverables for the deep-browse tabs. Reuse the staging
  // bytes so the committed copy is byte-identical to upstream.
  for (const [src, dest] of [
    [join(STAGING, 'iocs.json'), join(OUT, 'iocs.json')],
    [join(STAGING, 'exposure.json'), join(OUT, 'exposure.json')],
  ]) {
    if (existsSync(src)) writeFileSync(dest, readFileSync(src));
  }

  console.log(
    `[artex] events=${eventsFull.length} iocs=${index.stats.iocs ?? 'n/a'} exposed=${
      index.stats.exposed ?? 'n/a'
    } problems=${problems.length}`
  );
  if (problems.length && events.length === 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error('[artex] sync failed:', err);
  process.exitCode = 1;
});
