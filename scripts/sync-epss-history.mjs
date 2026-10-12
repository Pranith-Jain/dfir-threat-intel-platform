#!/usr/bin/env node
/**
 * Build the EPSS score-history series for KEV entries.
 *
 * FIRST publishes a gzipped CSV per day at
 * `epss_scores-YYYY-MM-DD.csv.gz`, each ~2.7 MB compressed and ~11 MB of
 * `cve,epss,percentile`. The API endpoint returns only the current score, so
 * without this there is no way to answer "is this being actively weaponised
 * right now" as opposed to "is this likely to be exploited in the next month".
 *
 * Sampling strategy: five dates spread over 30 days (today, 7, 14, 21, 28 days
 * ago) rather than all thirty. Thirty fetches is 80 MB of downloads to produce
 * a series that is read as a slope, not a curve. Five points resolve a trend
 * that matters; more would only cost build time. Dates are aligned to EPSS's
 * own daily release, so a missing file means that day genuinely had no release
 * and the series simply skips it.
 *
 * Only KEV ids are retained, so the emitted artifact is ~1.7k entries rather
 * than the full ~290k-row corpus.
 *
 * Emits: public/data/detection-coverage/epss-history.json
 *
 * Run:  node scripts/sync-epss-history.mjs
 */
import { gunzipSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'detection-coverage');
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_CSV = (date) => `https://epss.empiricalsecurity.com/epss_scores-${date}.csv.gz`;
const FETCH_TIMEOUT_MS = 45_000;

/** Days-back offsets sampled. Five points is enough to resolve a slope. */
const SAMPLE_OFFSETS = [0, 7, 14, 21, 28];

function isoDaysAgo(days) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

/**
 * Pull `cve -> score` out of one daily CSV.
 *
 * Only ids we actually care about are retained. Holding the full ~290k-row map
 * per date and intersecting afterwards would work but would allocate ~100 MB
 * across five samples; filtering on the way in keeps peak memory to the output.
 */
function parseCsv(gzipped, wanted) {
  const text = gunzipSync(gzipped).toString('utf8');
  const out = {};
  for (const line of text.split('\n')) {
    const c = line.indexOf(',');
    if (c < 0) continue;
    const id = line.slice(0, c).trim().toUpperCase();
    if (!wanted.has(id)) continue;
    const score = Number(line.slice(c + 1).split(',')[0]);
    if (Number.isFinite(score)) out[id] = score;
  }
  return out;
}

async function fetchKevIds() {
  const res = await fetch(KEV_URL, {
    headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`KEV -> HTTP ${res.status}`);
  const body = await res.json();
  const vulns = Array.isArray(body.vulnerabilities) ? body.vulnerabilities : [];
  return new Set(vulns.map((v) => String(v.cveID ?? '').toUpperCase()).filter(Boolean));
}

async function main() {
  console.log('🔨 Building EPSS history series');

  const wanted = await fetchKevIds();
  console.log(`  · ${wanted.size} KEV ids to track`);
  if (wanted.size === 0) throw new Error('KEV returned no ids; refusing to write an empty series');

  /** cve -> [{date, score}], ascending by date. */
  const series = {};
  let fetched = 0;
  let failed = 0;

  // Sequential on purpose: five ~2.7 MB fetches will not strain any budget, and
  // going parallel would make EPSS see five simultaneous bulk pulls.
  for (const offset of SAMPLE_OFFSETS) {
    const date = isoDaysAgo(offset);
    process.stdout.write(`  ↓ ${date} `);
    try {
      const res = await fetch(EPSS_CSV(date), {
        headers: { 'User-Agent': 'pranithjain-dfir/1.0' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const scores = parseCsv(Buffer.from(await res.arrayBuffer()), wanted);
      for (const [id, score] of Object.entries(scores)) {
        (series[id] ??= []).push({ date, score });
      }
      fetched += 1;
      console.log(`${Object.keys(scores).length} ids`);
    } catch (err) {
      // A missing daily release is expected and is not fatal: the series just
      // has a gap. Losing one sample costs trend resolution, not correctness.
      failed += 1;
      console.log(`skipped (${err.message ?? err})`);
    }
  }

  if (fetched < 2) {
    throw new Error(
      `Only ${fetched} EPSS samples retrieved; a trend needs at least 2. Refusing to write a series that would render every trend as null.`
    );
  }

  // Ascending by date so consumers can take [0] and [n-1] as endpoints without
  // sorting, and drop any CVE with a single point (no trend computable).
  const cleaned = {};
  for (const [id, points] of Object.entries(series)) {
    if (points.length < 2) continue;
    cleaned[id] = points.sort((a, b) => a.date.localeCompare(b.date));
  }

  const withRise = Object.values(cleaned).filter(
    (p) => p[p.length - 1].score - p[0].score > 0.001
  ).length;

  mkdirSync(OUT, { recursive: true });
  writeFileSync(
    join(OUT, 'epss-history.json'),
    JSON.stringify({
      schemaVersion: 'epss-history-v1',
      generatedAt: new Date().toISOString(),
      samples: SAMPLE_OFFSETS.length,
      samplesRetrieved: fetched,
      samplesFailed: failed,
      series: cleaned,
    })
  );

  console.log(`  ✓ ${Object.keys(cleaned).length} CVEs with ${SAMPLE_OFFSETS.length}-point series`);
  console.log(`  ✓ ${withRise} rising more than 0.1pp over the window`);
  console.log(`  → public/data/detection-coverage/epss-history.json\n`);
}

main().catch((err) => {
  console.error(`  ✗ ${err.message ?? err}`);
  process.exit(1);
});