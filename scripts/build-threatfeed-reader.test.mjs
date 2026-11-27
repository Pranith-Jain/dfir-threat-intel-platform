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

test('degrades cleanly on a missing snapshot', () => {
  const r = parseSnapshot({}, {}, []);
  assert.deepEqual(r.articles, []);
  assert.equal(r.counts.articles, 0);
});
