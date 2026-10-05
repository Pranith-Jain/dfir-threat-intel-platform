#!/usr/bin/env node
/**
 * audit-feed-health.mjs
 *
 * Re-probe every IOC feed upstream and report liveness + real row counts.
 *
 * # Why this exists
 *
 * Feed rot is invisible by default. A dead upstream still answers with a 404 (or
 * worse, a 200 with an HTML shell), the live-IOC source reports `ok:false`, and
 * the only symptom a reader sees is a source that quietly stopped contributing.
 * Nothing in the build fails. That is exactly how `webamon-campaigns` sat in
 * the registry returning 403 on every build, and how `threatbase` stayed wired
 * after its upstream repo was deleted.
 *
 * This is the pre-flight check for `api/src/lib/feed-curation.ts`. Run it before
 * promoting a new feed, and on a schedule, to catch rot early.
 *
 * # Two failure modes it distinguishes
 *
 *  1. **Dead** — non-2xx, DNS failure, or connection reset.
 *  2. **200 but not a feed** — an HTML page, a JS bundle, a ToS interstitial, or
 *     an empty stub. A status-code-only health check passes these, which is why
 *     `ellio`, `netcraft`, `snort`, and the `sslbl` IP lists were adopted from a
 *     third-party catalogue as "Active" while contributing zero indicators.
 *
 * # Usage
 *
 *   node scripts/audit-feed-health.mjs              # registry only
 *   node scripts/audit-feed-health.mjs --all        # + retired feeds (confirms rot)
 *   node scripts/audit-feed-health.mjs --json       # machine-readable
 *   node scripts/audit-feed-health.mjs --refresh    # update auditRows in feed-curation.ts
 *
 * Exit code is 1 when any REGISTERED feed is unhealthy, so it can gate CI.
 * Retired feeds are reported but never fail the run — several are expected to
 * still be dead, and that is the point of the check.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

const argv = new Set(process.argv.slice(2));
const WANT_ALL = argv.has('--all');
const AS_JSON = argv.has('--json');
const REFRESH = argv.has('--refresh');

const UA = { 'user-agent': 'pranithjain-dfir/1.0 (feed-health-audit)', accept: '*/*' };
const TIMEOUT_MS = 20_000;

/** Live-IOC registry sources whose URL lives inside a bespoke closure. */
const REGISTRY_EXTRAS = {
  'crypto-scam':
    'https://raw.githubusercontent.com/spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed/main/detected_urls.json',
};

/**
 * Sources whose URL is deliberately NOT probeable as a plain GET.
 *
 * These would otherwise report as "unhealthy" on every run and train everyone to
 * ignore the audit — the exact failure mode this script exists to prevent.
 *
 *  - `malwarebazaar` is a POST API needing an abuse.ch auth key; `GET /api/v1/`
 *    is 401 by design. Probed as a GET it can never pass.
 *  - `phishing` resolves to PhishTank's `online-valid.csv` only when
 *    PHISHTANK_API_KEY is set; the keyless path 404s by design (see
 *    api/src/routes/phishing-urls.ts, which documents the key requirement).
 *    The route has its own last-good KV fallback, so a keyless deploy degrades
 *    to a stale-but-working source rather than an empty one.
 *
 * Verified by reading the route source, not by probing. Their real health is
 * observable at runtime via `?debug=1` on /api/v1/live-iocs.
 */
const NOT_PLAIN_GET = new Set([
  'malwarebazaar',
  'phishing',
  'phishtank',
  'webamon-campaigns', // 403 without WEBAMON_API_KEY — retired from the registry
]);

/**
 * Extract the { id: { url, fallbackUrls } } shape from live-iocs.ts.
 *
 * Parsed rather than imported because that module pulls in the whole live-iocs
 * dependency graph (D1 binding, confidence scoring, analytics) and cannot be
 * imported outside a Worker runtime. The debug mirror is the one place every
 * registry source's URL is written down in plain data, which makes it the right
 * thing to audit.
 */
async function readRegistryUrls() {
  const src = await readFile(join(ROOT, 'api/src/routes/live-iocs.ts'), 'utf8');
  const start = src.indexOf('export const FEED_SOURCE_DEBUG_URLS');
  if (start === -1) throw new Error('FEED_SOURCE_DEBUG_URLS not found in live-iocs.ts');

  // Anchor on the ASSIGNED object literal, not the first `{` after the marker —
  // the declaration's type annotation `Record<string, { url: string; … }>` also
  // contains a `{` and sits between the two, so scanning from there captures the
  // type and yields zero feeds.
  const eq = src.indexOf('=', start);
  if (eq === -1) throw new Error('FEED_SOURCE_DEBUG_URLS has no initializer');
  const open = src.indexOf('{', eq);
  if (open === -1) throw new Error('FEED_SOURCE_DEBUG_URLS initializer has no object literal');

  // Walk braces to find the matching close, ignoring braces inside strings.
  let depth = 0;
  let end = -1;
  let inStr = null;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (inStr) {
      if (ch === '\\') i++;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') inStr = ch;
    else if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) throw new Error('could not find the end of FEED_SOURCE_DEBUG_URLS');

  const body = src.slice(open, end + 1);

  // Two shapes live in this map:
  //   1. literal   `id: { url: '…', fallbackUrls: [ … ] }`
  //   2. generated `...Object.fromEntries(CURATED_FEEDS.map(…))`
  // Shape 2 has no literal entries at all, so the curated feeds can only come
  // from feed-curation.ts.
  //
  // `url:` then `fallbackUrls: [ … ]` then `}` — matching on `[^\}]*?` instead
  // breaks on the array literal inside a fallbackUrls entry and silently drops
  // the whole source.
  // Hand-written entries come in two source layouts and a single regex that
  // requires both can't see them all:
  //   `id: { url: '…' },`                                    (one line)
  //   `'quoted-id': {\n    url: '…',\n    fallbackUrls: [...],\n  },`  (multi-line)
  // The one-line form matched first and its `\s*\}` consumed the closing brace of
  // the FOLLOWING entry for the quoted-key layout, collapsing ~35 sources. Both
  // forms are matched independently, then de-duped by id.
  const ONE_LINE = /([A-Za-z0-9_-]+|'[a-z0-9-]+'):\s*\{\s*url:\s*'([^']+)'\s*\},?\n/g;
  const MULTI_LINE = /'?([A-Za-z0-9_-]+)'?:\s*\{\s*\n\s*url:\s*'([^']+)',?\s*(?:\n\s*fallbackUrls:\s*\[([^\]]*)\],?)?\s*\n\s*\}/g;

  const byId = new Map();
  const add = (rawId, url, fbBlock) => {
    const id = rawId.replace(/^'|'$/g, '');
    const fallbackUrls = fbBlock ? [...fbBlock.matchAll(/'([^']+)'/g)].map((x) => x[1]) : [];
    // First writer wins; both regexes must not produce two records per source.
    if (!byId.has(id)) byId.set(id, { id, url, fallbackUrls, from: 'registry' });
  };

  let m;
  while ((m = ONE_LINE.exec(body)) !== null) add(m[1], m[2]);
  while ((m = MULTI_LINE.exec(body)) !== null) add(m[1], m[2], m[3]);

  return [...byId.values()];
  return out;
}

/** Parse CURATED_FEEDS entries out of feed-curation.ts. */
async function readCuratedFeeds() {
  const src = await readFile(join(ROOT, 'api/src/lib/feed-curation.ts'), 'utf8');
  const out = [];
  const re = /\{\s*id:\s*'([a-z0-9-]+)',\s*name:\s*'([^']+)',\s*url:\s*'([^']+)',([\s\S]*?)\n  \}/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const [, id, name, url, rest] = m;
    const fbBlock = /fallbackUrls:\s*\[([\s\S]*?)\]/.exec(rest);
    const fallbackUrls = fbBlock ? [...fbBlock[1].matchAll(/'(https?:\/\/[^']+)'/g)].map((x) => x[1]) : [];
    const audit = /auditRows:\s*(\d+)/.exec(rest);
    out.push({ id, name, url, fallbackUrls, auditRows: audit ? Number(audit[1]) : undefined });
  }
  return out;
}

/** Parse RETIRED_FEEDS entries out of feed-curation.ts. */
async function readRetiredFeeds() {
  const src = await readFile(join(ROOT, 'api/src/lib/feed-curation.ts'), 'utf8');
  const start = src.indexOf('export const RETIRED_FEEDS');
  const end = src.indexOf('];', start);
  if (start === -1 || end === -1) return [];
  const body = src.slice(start, end);
  const out = [];
  const re = /url:\s*'([^']+)',\s*reason:\s*'([a-z-]+)',\s*note:\s*'([^']*)'/g;
  let m;
  while ((m = re.exec(body)) !== null) out.push({ url: m[1], reason: m[2], note: m[3] });
  return out;
}

async function probe(url) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: ac.signal, redirect: 'follow', headers: UA });
    const body = res.ok ? await res.text() : '';
    const head = body.trimStart().slice(0, 16);
    const html = head.startsWith('<!DOCTYPE') || head.startsWith('<html');
    const rows = body
      .split('\n')
      .filter((l) => {
        const t = l.trim();
        return t.length > 0 && !t.startsWith('#') && !t.startsWith(';') && !t.startsWith('!');
      }).length;
    return {
      ok: res.ok && !html && rows > 0,
      status: res.status,
      bytes: body.length,
      rows,
      html,
      ms: Date.now() - t0,
      note: !res.ok
        ? `HTTP ${res.status}`
        : html
          ? 'HTML page, not a feed'
          : rows === 0
            ? '200 but no indicator rows'
            : undefined,
    };
  } catch (e) {
    return { ok: false, bytes: 0, rows: 0, html: false, ms: Date.now() - t0, note: e instanceof Error ? e.message.slice(0, 60) : 'error' };
  } finally {
    clearTimeout(timer);
  }
}

/** Probe a primary, falling back to the fallback chain like the runtime does. */
async function probeWithFallback(entry) {
  if (entry.skipProbe) {
    return {
      ok: true,
      skipped: true,
      rows: 0,
      bytes: 0,
      ms: 0,
      via: 'skipped',
      note: 'not a plain-GET endpoint (key-gated POST API / key-dependent path) — see NOT_PLAIN_GET',
    };
  }
  const primary = await probe(entry.url);
  if (primary.ok) return { ...primary, via: 'primary' };
  const fallbacks = entry.fallbackUrls ?? [];
  if (fallbacks.length === 0) return { ...primary, via: 'primary' };
  for (const fb of fallbacks) {
    const p = await probe(fb);
    if (p.ok) return { ...p, via: 'fallback', primaryNote: primary.note };
  }
  return { ...primary, via: 'primary' };
}

const ICONS = { ok: '✔', bad: '✘', warn: '!' };

async function main() {
  const curated = await readCuratedFeeds();
  const curatedById = new Map(curated.map((c) => [c.id, c]));

  // The debug mirror holds the hand-written sources; the 15 curated feeds are
  // spread into it at runtime from CURATED_FEEDS, so they only exist in
  // feed-curation.ts. Merge both, de-duping by id with the curated metadata
  // winning (it carries `auditRows`, which the registry copy lacks).
  const registry = await readRegistryUrls();
  // Sources whose URL lives inside a bespoke closure are absent from the mirror.
  for (const [id, url] of Object.entries(REGISTRY_EXTRAS)) {
    if (!registry.some((r) => r.id === id)) registry.push({ id, url, fallbackUrls: [], from: 'registry-extra' });
  }
  // Keep the entries so the report is complete, but never probe them: they
  // cannot answer a plain GET by design (see NOT_PLAIN_GET).
  for (const r of registry) {
    if (NOT_PLAIN_GET.has(r.id)) r.skipProbe = true;
  }
  for (const c of curated) {
    if (!registry.some((r) => r.id === c.id)) {
      registry.push({ id: c.id, url: c.url, fallbackUrls: c.fallbackUrls, from: 'curated' });
    }
  }

  const seen = new Set();
  const targets = [];
  for (const r of registry) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    const c = curatedById.get(r.id);
    targets.push({ ...r, ...(c ? { auditRows: c.auditRows } : {}) });
  }

  const results = [];
  const CONCURRENCY = 6;
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const slice = targets.slice(i, i + CONCURRENCY);
    const probed = await Promise.all(
      slice.map(async (t) => ({ ...t, ...(await probeWithFallback(t)) }))
    );
    results.push(...probed);
    if (!AS_JSON) process.stderr.write('.');
  }
  if (!AS_JSON) process.stderr.write('\n');

  const retired = WANT_ALL ? await readRetiredFeeds() : [];
  const retiredResults = [];
  for (let i = 0; i < retired.length; i += CONCURRENCY) {
    const slice = retired.slice(i, i + CONCURRENCY);
    const probed = await Promise.all(
      slice.map(async (r) => {
        const p = await probe(r.url);
        // A retired feed that has RECOVERED is the interesting case: it may be
        // worth re-adopting.
        return { ...r, ...p, recovered: p.ok };
      })
    );
    retiredResults.push(...probed);
    if (!AS_JSON) process.stderr.write('.');
  }
  if (retired.length && !AS_JSON) process.stderr.write('\n');

  const unhealthy = results.filter((r) => !r.ok && !r.skipped);
  const skipped = results.filter((r) => r.skipped).length;

  if (AS_JSON) {
    console.log(
      JSON.stringify(
        {
          audited_at: new Date().toISOString(),
          registered: results,
          retired: retiredResults,
          summary: {
            registered: results.length,
            healthy: results.length - unhealthy.length - skipped,
            unhealthy: unhealthy.length,
            skipped,
            on_fallback: results.filter((r) => r.via === 'fallback').length,
            recovered_retired: retiredResults.filter((r) => r.recovered).length,
          },
        },
        null,
        2
      )
    );
    process.exit(unhealthy.length > 0 ? 1 : 0);
  }

  console.log('\n  REGISTERED FEEDS');
  console.log(`  ${'─'.repeat(96)}`);
  for (const r of results.sort((a, b) => a.id.localeCompare(b.id))) {
    if (r.skipped) {
      console.log(`  ~ ${r.id.padEnd(26)} ${'—'.padEnd(4)} ${'skipped'.padStart(8)}         (key-gated, not a plain GET)`);
      continue;
    }
    const icon = r.ok ? ICONS.ok : ICONS.bad;
    const via = r.via === 'fallback' ? ` (via fallback${r.primaryNote ? `: ${r.primaryNote}` : ''})` : '';
    // Drift is only meaningful when the PRIMARY answered. `auditRows` records the
    // primary's size, so comparing a fallback's row count against it manufactures
    // a collapse warning out of a working source — and it fired spuriously when
    // threatcluster-domains briefly fell back to the sibling IP list (110 rows
    // vs 451).
    const drift =
      r.ok && r.via === 'primary' && r.auditRows !== undefined && r.rows > 0
        ? r.rows < r.auditRows * 0.25
          ? `  ⚠ collapsed: ${r.auditRows} → ${r.rows}`
          : ''
        : '';
    console.log(
      `  ${icon} ${r.id.padEnd(26)} ${String(r.status ?? 'ERR').padEnd(4)} ${String(r.rows).padStart(8)} rows  ${String(r.bytes).padStart(11)}b  ${r.ms}ms${via}${drift}`
    );
    if (!r.ok && r.note) console.log(`      └─ ${r.note}`);
  }
  console.log(
    `  ${'─'.repeat(96)}\n  ${results.length - unhealthy.length - skipped}/${results.length - skipped} healthy · ${results.filter((r) => r.via === 'fallback').length} on fallback · ${skipped} skipped (key-gated)`
  );

  if (retiredResults.length) {
    console.log('\n  RETIRED FEEDS (informational — these are expected to be dead)');
    console.log(`  ${'─'.repeat(96)}`);
    for (const r of retiredResults) {
      const icon = r.recovered ? ICONS.warn : ICONS.ok;
      const tag = r.recovered ? 'RECOVERED — may be re-adoptable' : `still ${r.reason}`;
      console.log(`  ${icon} ${r.url.slice(0, 74).padEnd(76)} ${tag}`);
    }
    const recovered = retiredResults.filter((r) => r.recovered);
    console.log(
      `  ${'─'.repeat(96)}\n  ${recovered.length} of ${retiredResults.length} retired feeds now respond with usable data`
    );
  }

  if (REFRESH) {
    console.log('\n  --refresh is not wired up yet; update auditRows in api/src/lib/feed-curation.ts by hand.');
  }

  if (unhealthy.length) {
    console.log(`\n  ${ICONS.bad} ${unhealthy.length} registered feed(s) unhealthy — a source is dead, stubbed, or returning HTML.`);
    for (const r of unhealthy) console.log(`      ${r.id}: ${r.note}`);
    process.exit(1);
  }
  console.log(`\n  ${ICONS.ok} all registered feeds healthy\n`);
}

main().catch((e) => {
  console.error('audit-feed-health failed:', e);
  process.exit(2);
});
