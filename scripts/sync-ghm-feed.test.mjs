import assert from 'node:assert/strict';
import test from 'node:test';
import { parseFeed, parseIncident } from './sync-ghm-feed.mjs';

const XML = `<?xml version="1.0"?><rss><channel>
<item><title>Allied Media / Allied Press: Confirmed cyberattack</title>
<link>https://globalhackmap.vercel.app/incident/allied-media-allied-press-2026-11</link>
<pubDate>Tue, 24 Nov 2026 12:00:00 GMT</pubDate>
<description>Confirmed by the organisation. Allied Media experienced a cyberattack. Dunedin, New Zealand.</description>
<category>Confirmed</category><category>Cyberattack</category></item>
<item><title>Yahoo: Claimed by Medusa Locker, not confirmed</title>
<link>https://globalhackmap.vercel.app/incident/yahoo-2026-11</link>
<pubDate>Tue, 24 Nov 2026 00:00:00 GMT</pubDate>
<description>Medusa Locker claims Yahoo. Attackers published 355,000 records. United States.</description>
<category>Claimed</category><category>Data breach</category></item>
</channel></rss>`;

test('parseFeed extracts both incidents with honest statuses', () => {
  const rows = parseFeed(XML);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].status, 'confirmed');
  assert.equal(rows[0].type, 'Cyberattack');
  assert.equal(rows[0].victim, 'Allied Media / Allied Press');
  assert.equal(rows[0].country, 'New Zealand');
  assert.equal(rows[0].lat, -40.9);
  assert.equal(rows[1].status, 'claimed');
  assert.equal(rows[1].actor, 'Medusa Locker');
  assert.equal(rows[1].records, 355000);
  assert.match(rows[1].url, /incident\/yahoo-2026-11$/);
});

test('parseIncident rejects malformed rows and degrades gracefully', () => {
  assert.equal(parseIncident('<item><title>x</title></item>'), null);
  assert.deepEqual(parseFeed('<rss></rss>'), []);
  assert.deepEqual(parseFeed(null), []);
});
