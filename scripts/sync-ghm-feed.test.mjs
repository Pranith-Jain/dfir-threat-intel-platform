import assert from 'node:assert/strict';
import test from 'node:test';
import { parseFeed, parseIncident, parsePatches } from './sync-ghm-feed.mjs';

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

const PATCH_JSON = JSON.stringify({
  items: [
    {
      key: 'drupal|core',
      vendor: 'Drupal',
      product: 'Core',
      cves: ['CVE-2026-132165', 'not a cve'],
      exploited: true,
      ransomware: false,
      newsCount: 11,
      kevAdded: '2026-11-24',
      epss: 0.11053,
      cvss: 9.8,
      title: 'Drupal attackers take over sites via installer without login',
      who: 'Anyone running an unpatched Drupal core site',
      fix: 'Upgrade to Drupal 11.4.14, 11.3.23 or 10.6.23 and block /core/install.php',
      explained: true,
    },
    // Duplicate key — must not occupy a second slot.
    { key: 'drupal|core', title: 'duplicate', fix: 'duplicate' },
    // No title or fix — skip.
    { key: 'empty|row', vendor: 'Empty' },
  ],
});

test('parsePatches keeps only validated, actionable advisories', () => {
  const rows = parsePatches(PATCH_JSON);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.key, 'drupal|core');
  assert.deepEqual(row.cves, ['CVE-2026-132165']);
  assert.equal(row.exploited, true);
  assert.equal(row.kevAdded, '2026-11-24');
  assert.equal(row.epss, 0.11053);
  assert.equal(row.cvss, 9.8);
  assert.match(row.fix, /block \/core\/install\.php/);
  assert.match(row.url, /\/cve\/CVE-2026-132165$/);
});

test('parsePatches tolerates a bare array, bad JSON and a changed shape', () => {
  const bare = parsePatches([{ key: 'a', title: 'A', fix: 'Upgrade' }]);
  assert.equal(bare.length, 1);
  assert.equal(bare[0].vendor, null);
  assert.deepEqual(parsePatches('{not json'), []);
  assert.deepEqual(parsePatches({ unexpected: true }), []);
});
