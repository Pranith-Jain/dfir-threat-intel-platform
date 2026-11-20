/** Offline parser tests for the Cloudflare Radar Zero Wire feed mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeItem, summarize } from './sync-zero-wire.mjs';

const BRIEFING = {
  id: 'https://radar.cloudflare.com/zero-wire/example',
  url: 'https://radar.cloudflare.com/zero-wire/example',
  title: 'Example briefing',
  summary: 'Short summary.',
  content_text: 'Longer text.',
  date_published: '2026-11-19T12:00:00Z',
  date_modified: '2026-11-19T13:00:00Z',
  tags: ['PHP', 'RCE'],
  image: 'https://radar.cloudflare.com/api/og/pages/zero-wire',
  _zero_wire: { slug: 'example', main_action: 'patch', cves: ['CVE-2026-11111'], recommended_action_steps: [{ text: 'Upgrade.' }] },
};

const CVE = {
  id: 'https://radar.cloudflare.com/zero-wire/cves/CVE-2026-22222',
  url: 'https://radar.cloudflare.com/zero-wire/cves/CVE-2026-22222',
  title: 'CVE-2026-22222: Example product flaw',
  summary: 'A flaw.',
  content_text: 'A flaw.\n\nCVSS 4.0 score: 9.8 (Critical)',
  date_published: '2026-11-20T15:00:00Z',
  tags: ['Critical'],
  _cve: { id: 'CVE-2026-22222', severity: 'CRITICAL', score: 9.8, cvss_version: '4.0' },
};

test('normalizeItem keeps briefing prose and the _zero_wire extension', () => {
  const item = normalizeItem(BRIEFING, 'briefings');
  assert.equal(item.title, 'Example briefing');
  assert.equal(item.contentText, 'Longer text.');
  assert.equal(item.published, '2026-11-19T12:00:00Z');
  assert.deepEqual(item.tags, ['PHP', 'RCE']);
  assert.equal(item.ext.slug, 'example');
  assert.deepEqual(item.ext.cves, ['CVE-2026-11111']);
});

test('normalizeItem pulls CVE id, severity and CVSS from the _cve extension', () => {
  const item = normalizeItem(CVE, 'cves');
  assert.equal(item.cveId, 'CVE-2026-22222');
  assert.equal(item.severity, 'CRITICAL');
  assert.equal(item.score, 9.8);
  assert.equal(item.cvssVersion, '4.0');
});

test('normalizeItem tolerates missing optional feed fields', () => {
  const item = normalizeItem({ title: 'No dates', tags: null }, 'briefings');
  assert.equal(item.published, null);
  assert.deepEqual(item.tags, []);
  assert.deepEqual(item.ext, {});
});

test('summarize counts both feeds and buckets CVE severity', () => {
  const cves = [CVE, { ...CVE, _cve: { id: 'CVE-2026-1', severity: 'LOW' } }].map((i) => normalizeItem(i, 'cves'));
  const stats = summarize([normalizeItem(BRIEFING, 'briefings')], cves);
  assert.deepEqual(stats, { briefings: 1, cves: 2, bySeverity: { CRITICAL: 1, LOW: 1 } });
});
