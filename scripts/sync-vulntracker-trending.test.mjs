import assert from 'node:assert/strict';
import test from 'node:test';
import { buildDataset, extractRscItems, normalizeItems } from './sync-vulntracker-trending.mjs';

function rscChunk(data) {
  const inner = `4:${JSON.stringify(['$', '$Ld', null, { window: '24h', data }])}`;
  return `<script>self.__next_f.push([1,${JSON.stringify(inner)}])</script>`;
}

const ROWS = [
  {
    cve_id: 'CVE-2026-134624', people: 29, posts: 32,
    last_posted_at: '2026-11-24T13:00:02.388Z', severity: 'CRITICAL', base_score: 9.3,
    is_exploited: true, published_date: '2026-11-22T19:10:45.282Z',
    title: 'MailAssure / SpamExperts: SSRF in relay LDAP connection check [confirmed]',
  },
  {
    cve_id: 'CVE-2026-76466', people: 27, posts: 29,
    last_posted_at: '2026-11-24T13:31:21.385Z', severity: 'CRITICAL', base_score: 9.8,
    is_exploited: true, published_date: '2026-10-21T16:14:19.225Z',
    title: 'Cisco Expressway Series "Remote Code Execution" Vulnerability',
  },
];

test('extractRscItems reads data.items including ] in titles', () => {
  const parsed = extractRscItems(`<html>${rscChunk({ items: ROWS })}</html>`);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].cve_id, 'CVE-2026-134624');
  assert.match(parsed[0].title, /\[confirmed\]$/);
  assert.equal(parsed[1].title, 'Cisco Expressway Series "Remote Code Execution" Vulnerability');
});

test('extractRscItems ignores unrelated chunks and malformed HTML', () => {
  assert.deepEqual(extractRscItems('<html>no rsc here</html>'), []);
  assert.deepEqual(extractRscItems(rscChunk({ other: [1, 2, 3] })), []);
  assert.deepEqual(extractRscItems(rscChunk({ items: 'not an array' })), []);
  assert.deepEqual(extractRscItems(null), []);
});

test('normalizeItems maps fields, validates ids and dedupes', () => {
  const items = normalizeItems([...ROWS, ROWS[0], { cve_id: 'not-a-cve', people: 5, title: 'junk' }]);
  assert.equal(items.length, 2);
  assert.equal(items[0].id, 'CVE-2026-134624');
  assert.equal(items[0].rank, 1);
  assert.equal(items[0].cvss, 9.3);
  assert.equal(items[0].exploited, true);
  assert.equal(items[0].url, 'https://vulntracker.io/cves/CVE-2026-134624');
});

test('normalizeItems tolerates missing fields and enforces the cap', () => {
  const rows = Array.from({ length: 60 }, (_, i) => ({
    cve_id: `CVE-2099-${String(1000 + i)}`, people: 'many', posts: -1, severity: null,
    base_score: '9.9', is_exploited: 'false', published_date: 'yesterday',
    title: i < 5 ? 'A real title' : '',
  }));
  rows[5].title = 'A real title';
  assert.equal(normalizeItems(rows).length, 6);
  const items = normalizeItems(rows, 5);
  assert.equal(items.length, 5);
  assert.equal(items[0].people, 0);
  assert.equal(items[0].severity, 'UNKNOWN');
  assert.equal(items[0].cvss, null);
  assert.equal(items[0].exploited, false);
  assert.deepEqual(normalizeItems(undefined), []);
});

test('buildDataset carries attribution and a stable shape', () => {
  const payload = buildDataset(extractRscItems(rscChunk({ items: ROWS })));
  assert.equal(payload.window, '24h');
  assert.equal(payload.count, 2);
  assert.equal(payload.upstream.site, 'https://vulntracker.io');
  assert.match(payload.upstream.attribution, /Bluesky/);
  assert.match(payload.generatedAt, /^\d{4}-\d{2}-\d{2}T/);
});
