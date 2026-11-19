#!/usr/bin/env node
/**
 * Build the data snapshot for the Cheyenne working-tool replication.
 *
 * Cheyenne (github.com/MJCruickshank/cheyenne) is a local Python server plus
 * a browser board that tracks imaging satellites, predicts passes over a
 * place, searches archived scenes and overlays fire / ship / weather data.
 * It publishes no reuse licence, so this replication does not vendor upstream
 * prose or code. It re-implements the core in-site and stores only the
 * machine-readable inputs needed to do so:
 *
 *   - web/catalog.json  -> fleet definitions (names, match patterns, sensor
 *                          geometry, colours, collection ids, links)
 *   - CelesTrak GP active TLEs -> orbital elements filtered to catalog
 *                          members using the same name patterns upstream uses
 *
 * Everything else upstream (sentinel imagery tiles, ESA tasking KML, FIRMS,
 * AIS websocket feeds, geostationary weather, Telegram intel, place search)
 * requires a backend, keys, or a live third-party API and is deep-linked from
 * the page rather than mirrored.
 *
 * Emits:
 *   public/data/cheyenne-tool/index.json     slim catalog + stats
 *   public/data/cheyenne-tool/tle.json       filtered orbital elements
 *
 * Usage: node scripts/build-cheyenne-tool.mjs [--catalog <file>] [--tle <file>]
 * Safe to run repeatedly — wipes public/data/cheyenne-tool/ on each run.
 */
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'cheyenne-tool');
const BASE = 'https://raw.githubusercontent.com/MJCruickshank/cheyenne/main';
const REPO = 'https://github.com/MJCruickshank/cheyenne';
const CELESTRAK = 'https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=tle';
const SOURCE = 'MJCruickshank/cheyenne';
const LICENSE = 'Upstream has no reuse licence — re-implemented in-site; factual metadata only';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';

const args = process.argv.slice(2);
function argValue(name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
}
const LOCAL_CATALOG = argValue('--catalog');
const LOCAL_TLE = argValue('--tle');

async function fetchText(url) {
  const resp = await fetch(url, {
    headers: { 'user-agent': UA, accept: '*/*' },
    signal: AbortSignal.timeout(60_000),
  });
  if (!resp.ok) throw new Error(`fetch ${url}: ${resp.status} ${resp.statusText}`);
  return await resp.text();
}

function loadCatalog() {
  const raw = LOCAL_CATALOG ? readFileSync(LOCAL_CATALOG, 'utf8') : null;
  return raw ? JSON.parse(raw) : null;
}

/** Same grouping rule as upstream server.py:tle_payload(). */
function filterTle(raw, constellations) {
  const lines = raw.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim());
  const rules = constellations.map((c) => ({
    id: c.id,
    patterns: (c.match ?? []).map((p) => new RegExp(p)),
  }));
  const sats = [];
  for (let i = 0; i < lines.length - 2; i += 3) {
    const name = lines[i].trim();
    const l1 = lines[i + 1];
    const l2 = lines[i + 2];
    if (!l1.startsWith('1 ') || !l2.startsWith('2 ')) continue;
    for (const rule of rules) {
      if (rule.patterns.some((p) => p.test(name))) {
        sats.push({ c: rule.id, name, norad: Number(l1.slice(2, 7)), l1, l2 });
        break;
      }
    }
  }
  return sats;
}

async function main() {
  const builtAt = new Date().toISOString();
  const catalog = loadCatalog() ?? JSON.parse(await fetchText(`${BASE}/web/catalog.json`));
  const constellations = catalog.constellations ?? [];
  if (constellations.length === 0) throw new Error('no constellations in upstream catalog');

  const rawTle = LOCAL_TLE ? readFileSync(LOCAL_TLE, 'utf8') : await fetchText(CELESTRAK);
  if (rawTle.split(/\r?\n/).length < 300 || !/^1 \d{5}/m.test(rawTle)) {
    throw new Error('unexpected CelesTrak GP response');
  }
  const sats = filterTle(rawTle, constellations);
  if (sats.length === 0) throw new Error('no catalogue satellites matched the TLE set');

  const byConstellation = {};
  for (const s of sats) byConstellation[s.c] = (byConstellation[s.c] ?? 0) + 1;

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(OUT, { recursive: true });

  writeFileSync(
    join(OUT, 'tle.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: REPO,
        license: LICENSE,
        builtAt,
        orbitSource: 'CelesTrak GP (active)',
        orbitSourceUrl: CELESTRAK,
        count: sats.length,
        sats,
      },
      null,
      2,
    ) + '\n',
  );

  writeFileSync(
    join(OUT, 'index.json'),
    JSON.stringify(
      {
        source: SOURCE,
        sourceUrl: REPO,
        license: LICENSE,
        builtAt,
        catalogSource: `${BASE}/web/catalog.json`,
        orbitSource: CELESTRAK,
        groups: catalog.groups ?? [],
        constellations: constellations.map((c) => ({
          id: c.id,
          name: c.name,
          group: c.group,
          operator: c.operator,
          sensor: c.sensor,
          instrument: c.instrument,
          gsd: c.gsd,
          revisit: c.revisit,
          color: c.color,
          defaultVisible: !!c.defaultVisible,
          access: c.access ?? null,
          geom: c.geom ?? {},
          links: c.links ?? [],
          trackedSats: byConstellation[c.id] ?? 0,
        })),
        counts: {
          groups: (catalog.groups ?? []).length,
          fleets: constellations.length,
          trackedSats: sats.length,
        },
        liveOnly: [
          'sentinel imagery tiles + downloads (Microsoft Planetary Computer)',
          'ESA acquisition-plan KML tasking',
          'NASA FIRMS fire detections',
          'AIS ship feeds (aisstream / Fintraffic / Open Waters / Pelyr)',
          'geostationary weather imagery (NASA GIBS / EUMETSAT)',
          'Telegram intel posts and place extraction',
        ],
      },
      null,
      2,
    ) + '\n',
  );

  console.log(`[cheyenne-tool] fleets=${constellations.length} sats=${sats.length} groups=${(catalog.groups ?? []).length}`);
}

const isMain = (() => {
  try {
    return resolvePath(process.argv[1] ?? '') === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();
if (isMain) {
  main().catch((e) => {
    console.error(`[cheyenne-tool] build failed: ${e.message}`);
    process.exit(1);
  });
}

export { filterTle };
