/** Offline parser tests for the ThreatFeed reader snapshot mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSnapshot } from './build-threatfeed-reader.mjs';

const snapshot = {
  generatedAt: '2026-11-27T00:00:00Z',
  articles: [
    {
      id: 'a1', title: 'CVE-2026-1 in Product X', url: 'https://example/a', sourceId: 'src-1',
      sourceName: 'Source One', description: '<p>Short &amp; useful.</p>', tags: ['CVE', 'News'],
      categories: ['noise'], cves: ['CVE-2026-1'], severity: 'critical', severityScore: 95,
      publishedAt: '2026-11-27T10:00:00Z', read: true, bookmarked: true,
    },
    { id: 'a2', title: 'Bad link', url: 'javascript:alert(1)', sourceId: 'src-2', sourceName: 'Two' },
  ],
  feedHealth: { 'src-1': { ok: true } },
};
const feeds = [{ id: 'src-1', category: 'Vulnerabilities' }, { id: 'src-2', category: 'Other' }];

test('parses articles, assigns feed categories and strips visitor state', () => {
  const r = parseSnapshot(snapshot, { vendors: ['A'], actors: [], groups: [] }, feeds);
  assert.equal(r.articles.length, 1); // the javascript: URL is dropped
  assert.equal(r.articles[0].feedCategory, 'Vulnerabilities');
  assert.equal(r.articles[0].description, 'Short & useful.');
  assert.equal(r.articles[0].severity, 'critical');
  assert.equal(r.articles[0].cves[0], 'CVE-2026-1');
  assert.equal(r.articles[0].read, undefined);
  assert.equal(r.articles[0].bookmarked, undefined);
  assert.equal(r.counts.articles, 1);
  assert.equal(r.counts.critical, 1);
  assert.equal(r.counts.withCves, 1);
  assert.equal(r.trending.vendors.length, 1);
});

test('joins the feed catalogue with feedHealth into a Sources view', () => {
  const health = {
    'src-1': { status: 'healthy', latencyMs: 120, articleCount: 10, httpStatus: 200, lastFetchedAt: '2026-11-27T00:00:00Z' },
    'src-3': { status: 'http_error', httpStatus: 503 },
  };
  const r = parseSnapshot(
    { articles: snapshot.articles, feedHealth: health },
    {},
    [
      { id: 'src-1', name: 'Source One', url: 'https://one.test/feed', category: 'Vulnerabilities', tags: ['cve'], enabled: true },
      { id: 'src-2', name: 'Source Two', category: 'News', enabled: false },
    ]
  );
  assert.equal(r.sources.length, 3); // 2 catalogued + 1 health-only
  const one = r.sources.find((s) => s.id === 'src-1');
  assert.equal(one.name, 'Source One');
  assert.equal(one.category, 'Vulnerabilities');
  assert.equal(one.status, 'healthy');
  assert.equal(one.latencyMs, 120);
  assert.equal(r.sources.find((s) => s.id === 'src-2').enabled, false);
  // Health-only feed still gets a usable label from feedId.
  assert.equal(r.sources.find((s) => s.id === 'src-3').status, 'http_error');
  assert.equal(r.counts.sources, 3);
  assert.equal(r.counts.sourcesHealthy, 1);
  assert.equal(r.counts.sourcesUnhealthy, 2);
});

test('degrades cleanly on a missing snapshot', () => {
  const r = parseSnapshot({}, {}, []);
  assert.deepEqual(r.articles, []);
  assert.equal(r.counts.articles, 0);
});
