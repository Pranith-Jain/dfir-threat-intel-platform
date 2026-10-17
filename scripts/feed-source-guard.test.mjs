/**
 * Tests for the feed-source guards — the two failure modes that shipped broken
 * in production for months before the 2026-10-16 feed-health pass:
 *
 *   1. **Allowlist drift.** `blog.trailofbits.com` was present in the proxy
 *      allowlist (feeds.ts) and missing from the copy inlined into
 *      feeds-aggregate.ts, the route the SPA actually calls — so the aggregator
 *      answered `host_not_in_allowlist` for a healthy feed. Two hand-maintained
 *      copies of one list is the defect; the fix was one shared module.
 *   2. **Google News re-entry.** news.google.com 503s Cloudflare Worker egress.
 *      28 catalog feeds, the BleepingComputer mirror and ~10 server-side
 *      consumers depended on it and were all failing; the catalog had already
 *      been half-amputated in response. Bing News replaced them.
 *
 * These are static guards on purpose: both bugs were invisible to unit tests and
 * to the build, and both come back from a plausible-looking one-line edit.
 *
 * Run: node --test scripts/feed-source-guard.test.mjs
 * Wired into `npm run test:scripts` (and therefore `npm run test:all`-style
 * script gates).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

/** Source files we consider runtime code (not tests, not generated output). */
const SCAN_DIRS = ['api/src', 'worker', 'src', 'scripts'];
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
 * Strip comments so explanatory prose about a migration isn't mistaken for the
 * migration itself — this repo documents its reasoning heavily, and
 * "was news.google.com/rss/search" is worth keeping. Naive, but adequate:
 * a `//` or quoted `//` inside a string literal would be trimmed too, which
 * only makes the guards below slightly more permissive, never wrong.
 */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

function codeFiles() {
  return SCAN_DIRS.flatMap((d) => walk(join(ROOT, d)));
}

test('neither RSS route declares its own host allowlist', () => {
  // The single most valuable guard here: the drift that broke Trail of Bits.
  for (const rel of ['api/src/routes/feeds.ts', 'api/src/routes/feeds-aggregate.ts']) {
    const src = read(join(ROOT, rel));
    assert.ok(
      !/const ALLOWED_HOSTS\s*=\s*new Set/.test(src),
      `${rel} declares its own ALLOWED_HOSTS — the allowlist must come from api/src/lib/feed-hosts.ts ` +
        `(a second inline copy is what let blog.trailofbits.com drift and break the aggregator)`
    );
    assert.match(src, /from '\.\.\/lib\/feed-hosts'/, `${rel} must import FEED_ALLOWED_HOSTS from ../lib/feed-hosts`);
  }
});

test('api/src/lib/feed-hosts.ts exists and holds the shared list', () => {
  const src = read(join(ROOT, 'api/src/lib/feed-hosts.ts'));
  assert.match(src, /export const FEED_ALLOWED_HOSTS = new Set<string>\(\[/, 'missing FEED_ALLOWED_HOSTS export');
  // Hosts this pass added — each one corresponds to a production failure or a
  // requested feature, so a silent removal should fail loudly.
  for (const host of ['blog.trailofbits.com', 'www.bing.com', 'radar.offseq.com']) {
    assert.ok(src.includes(`'${host}'`), `feed-hosts.ts is missing '${host}'`);
  }
});

test('no runtime code fetches news.google.com search RSS', () => {
  // news.google.com 503s Worker egress IPs. It stays listed in the allowlist
  // only so an old cached redirect target can't 403 during a rollout; no code
  // may point a feed at it. Comments are stripped so migration notes survive.
  const offenders = [];
  for (const file of codeFiles()) {
    const src = stripComments(read(file));
    if (src.includes('news.google.com/rss/')) offenders.push(file.slice(ROOT.length + 1));
  }
  assert.deepEqual(
    offenders,
    [],
    `news.google.com RSS is back in runtime code (${offenders.join(', ')}) — it 503s Worker egress; use Bing News`
  );
});

test('the ARGUS feed sources match the Worker proxy allowlist', () => {
  // The view and the proxy keep separate lists; when they diverge the view
  // requests a URL the proxy refuses and the source silently vanishes (which
  // is how a Google News URL survived there after the proxy moved to Bing).
  const view = stripComments(read(join(ROOT, 'src/pages/argus/views/FeedView.tsx')));
  const proxy = stripComments(read(join(ROOT, 'worker/argus-feed.ts')));
  const viewUrls = [...view.matchAll(/url:\s*'(https?:\/\/[^']+)'/g)].map((m) => m[1]);
  assert.ok(viewUrls.length > 0, 'no RSS source URLs found in FeedView');
  const missing = viewUrls.filter((u) => !proxy.includes(`'${u}'`));
  assert.deepEqual(missing, [], `ARGUS sources not allowed by worker/argus-feed.ts: ${missing.join(', ')}`);
});

test('every Bing News query in the catalog survives the OR operator', () => {
  // Bing's RSS endpoint ANDs terms and returns ZERO items for `a OR b`.
  // A query reintroducing OR silently yields an empty feed.
  const src = read(join(ROOT, 'src/data/rssFeeds.ts'));
  const bad = [...src.matchAll(/https:\/\/www\.bing\.com\/news\/search\?q=([^'&\s]+)[^']*/g)]
    .map((m) => m[1])
    .filter((q) => /(^|\+)OR(\+|$)/i.test(q));
  assert.deepEqual(bad, [], `Bing News queries contain OR, which returns 0 items: ${bad.join(', ')}`);
});

test('the BleepingComputer mirror is Bing, in both routes', () => {
  for (const rel of ['api/src/routes/feeds.ts', 'api/src/routes/feeds-aggregate.ts']) {
    const src = read(join(ROOT, rel));
    assert.match(
      src,
      /bing\.com\/news\/search\?q=site%3Ableepingcomputer\.com/,
      `${rel} must fetch the BleepingComputer mirror from Bing News (the origin 403s datacenter egress)`
    );
  }
});

test('the Bing click redirector is unwrapped wherever feeds are parsed', () => {
  // A silent regression here is invisible: items still render, they just link
  // through Bing's tracker instead of the publisher.
  const helpers = ['api/src/lib/rss-parser.ts', 'src/services/rssService.ts'];
  for (const rel of helpers) {
    assert.match(read(join(ROOT, rel)), /export function unwrapBingNewsLink/, `${rel} must export unwrapBingNewsLink`);
  }
  // Parsers that consume a Bing mirror must route their link through it.
  const consumers = [
    'api/src/routes/feeds-aggregate.ts',
    'api/src/routes/ironsight.ts',
    'api/src/lib/cyber-news-feeds.ts',
    'api/src/lib/cti-collector.ts',
    'api/src/lib/ti-dashboard/feeds.ts',
    'api/src/case-study/discovery/rss-util.ts',
    'api/src/routes/cybercrime.ts',
  ];
  for (const rel of consumers) {
    assert.match(read(join(ROOT, rel)), /unwrapBingNewsLink/, `${rel} must unwrap Bing click links`);
  }
});
