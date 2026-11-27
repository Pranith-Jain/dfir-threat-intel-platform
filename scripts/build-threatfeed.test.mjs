/** Offline parser test for the MIT ThreatFeed catalog mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseThreatFeed } from './build-threatfeed.mjs';

test('parses feeds, categories, tags and retired state', () => {
  const raw = {
    version: 2,
    updatedAt: '2026-11-27T00:00:00Z',
    retiredFeedIds: ['old-feed'],
    feeds: [
      { id: 'hn', name: 'The Hacker News', url: 'https://feeds.example/hn', category: 'Security News', tags: ['news'], enabled: true },
      { id: 'bad', name: 'Bad URL', url: 'javascript:alert(1)', category: 'Other', tags: [], enabled: false },
    ],
  };
  const r = parseThreatFeed(raw);
  assert.equal(r.feeds.length, 2);
  assert.equal(r.categories.length, 2);
  assert.equal(r.feeds[0].url, 'https://feeds.example/hn');
  assert.equal(r.feeds[1].url, null);
  assert.equal(r.feeds[1].enabled, false);
  assert.equal(r.retiredFeedIds, 1);
  assert.equal(r.version, 2);
});

test('degrades cleanly on an empty or malformed payload', () => {
  assert.deepEqual(parseThreatFeed({}).feeds, []);
  assert.deepEqual(parseThreatFeed('{"feeds":null}').feeds, []);
});
