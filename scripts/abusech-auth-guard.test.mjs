/**
 * Guard against the 2026-10-21 abuse.ch export outage recurring quietly.
 *
 * On that date abuse.ch retired every anonymous bulk export:
 *
 *   https://urlhaus.abuse.ch/downloads/csv_recent/
 *   https://urlhaus.abuse.ch/downloads/csv_online/
 *   https://bazaar.abuse.ch/export/csv/recent/
 *   https://threatfox.abuse.ch/export/csv/recent/
 *   https://threatfox.abuse.ch/export/csv/urls/recent/
 *   https://threatfox.abuse.ch/downloads/hostfile/
 *
 * Every one of them answers HTTP 410 forever. Before the fix the URLs and
 * their auth headers were copy-pasted into ~12 files, so the outage broke the
 * briefing builder, the live IOC firehose, the threat map, IOC correlation,
 * the malware pages and the CTI collector independently — and each copy had
 * to be found and fixed by hand, which is exactly how the site froze for days.
 *
 * The replacement mechanism (`*-api.abuse.ch/v2/files/exports/<Auth-Key>/…`
 * and the ThreatFox JSON `get_iocs` POST) is centralised in
 * `api/src/lib/abusech.ts`. These guards keep it that way:
 *
 *   1. No runtime code may hard-code a retired anonymous export URL — the
 *      only sanctioned copy is the no-key fallback constant in abusech.ts.
 *   2. The shared helper must keep its documented exports, so the next
 *      consumer actually has somewhere centralised to go.
 *
 * Comments are stripped first: the repo documents WHY urls retired in prose
 * near the consumers, and that prose must not trip the guard.
 *
 * Run: node --test scripts/abusech-auth-guard.test.mjs
 * Wired into `npm run test:scripts`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HELPER = join(ROOT, 'api/src/lib/abusech.ts');

/** Source files we consider runtime code (not tests, not generated output). */
const SCAN_DIRS = ['api/src', 'worker'];
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '__tests__', 'generated']);
const CODE_EXT = /\.(ts|tsx|mts|mjs|js)$/;

function walk(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name) || name.startsWith('.')) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, out);
    else if (CODE_EXT.test(name) && !/\.test\.(ts|mjs)$/.test(name)) out.push(full);
  }
  return out;
}

function read(file) {
  return readFileSync(file, 'utf8');
}

/**
 * Strip comments so explanatory prose about a retirement isn't mistaken for
 * the retirement itself. Naive, but adequate: worst case it is slightly
 * permissive, never wrong in the direction of false failures.
 */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

const RETIRED_EXPORT_URLS = [
  'urlhaus.abuse.ch/downloads/csv_recent/',
  'urlhaus.abuse.ch/downloads/csv_online/',
  'bazaar.abuse.ch/export/csv/recent/',
  'threatfox.abuse.ch/export/csv/recent/',
  'threatfox.abuse.ch/export/csv/urls/recent/',
  'threatfox.abuse.ch/downloads/hostfile/',
];

test('no runtime code hard-codes a retired anonymous abuse.ch export URL', () => {
  const offenders = [];
  for (const file of walk(join(ROOT, '.'))) {
    if (!SCAN_DIRS.some((d) => file.includes(`${d}/`))) continue;
    if (file === HELPER) continue; // the sanctioned no-key fallback constant
    const src = stripComments(read(file));
    for (const url of RETIRED_EXPORT_URLS) {
      if (src.includes(url)) offenders.push(`${file.slice(ROOT.length + 1)} → ${url}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `retired abuse.ch export URLs are hard-coded again (410 upstream): ${offenders.join('; ')}. ` +
      `Fetch through api/src/lib/abusech.ts instead — abuseChFeedRequestForEnv()/abuseChExportUrl()`
  );
});

test('the shared abuse.ch helper keeps its documented exports', () => {
  const src = read(HELPER);
  for (const name of [
    'LEGACY_ABUSECH_URLS',
    'THREATFOX_API_URL',
    'THREATFOX_MAX_DAYS',
    'abuseChHeaders',
    'abuseChExportUrl',
    'abuseChApiUrl',
    'abuseChFeedRequest',
    'abuseChFeedRequestForEnv',
    'fetchThreatfoxExport',
    'looksLikeJson',
  ]) {
    assert.match(src, new RegExp(`export (const|async function|function) ${name}\\b`), `abusech.ts lost ${name}`);
  }
  // The v2 export roots must stay path-keyed (abuse.ch's documented form for
  // file exports) — a header-only implementation returns 401 on every fetch.
  assert.match(src, /urlhaus-api\.abuse\.ch\/v2\/files\/exports/);
  assert.match(src, /mb-api\.abuse\.ch\/v2\/files\/exports/);
});

test('every consumer module that fetches abuse.ch imports the shared helper', () => {
  // These files each used to hand-roll their own URLs/headers; if a future
  // edit copies a URL back in rather than importing the helper, guard #1
  // catches the literal — this test pins the intended dependency direction.
  const CONSUMERS = [
    'api/src/lib/briefing-builder/feeds.ts',
    'api/src/routes/ioc-feeds.ts',
    'api/src/routes/ioc-snapshot.ts',
    'api/src/routes/abuse-rss.ts',
    'api/src/routes/live-iocs.ts',
    'api/src/routes/malware-samples.ts',
    'api/src/routes/malware-capabilities.ts',
    'api/src/routes/ioc-correlation.ts',
    'api/src/routes/threat-map.ts',
    'api/src/routes/c2-tracker.ts',
    'api/src/routes/graph-ingest.ts',
    'api/src/lib/cti-collector.ts',
  ];
  for (const rel of CONSUMERS) {
    const src = read(join(ROOT, rel));
    assert.match(src, /from '[^']*abusech'/,
      `${rel} no longer imports lib/abusech — abuse.ch URLs must be built in one place`);
  }
});
