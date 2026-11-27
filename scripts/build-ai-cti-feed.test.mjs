/** Offline parser test for the OWASP GenAI STIX mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAiCti } from './build-ai-cti-feed.mjs';

const BUNDLE = {
  type: 'bundle',
  objects: [
    { type: 'intrusion-set', id: 'intrusion-set--aaa', name: 'Actor A', description: 'Uses AI', labels: ['owasp-genai-category-a'], created: '2026-01-01T00:00:00.000Z', external_references: [{ source_name: 'mitre-attack', external_id: 'G0001', url: 'https://example/g' }] },
    { type: 'intrusion-set', id: 'intrusion-set--bbb', name: 'Actor B', labels: ['owasp-genai-category-b'] },
    { type: 'attack-pattern', id: 'attack-pattern--ccc', name: 'Prompt injection', labels: ['owasp-genai-category-b'] },
    { type: 'indicator', id: 'indicator--ddd', name: 'Indicator', labels: ['owasp-genai-category-a'] },
    { type: 'relationship', id: 'relationship--eee', relationship_type: 'uses', source_ref: 'intrusion-set--aaa', target_ref: 'attack-pattern--ccc' },
  ],
};

test('parses STIX objects, category labels and relationships', () => {
  const r = parseAiCti(BUNDLE);
  assert.equal(r.counts.objects, 5);
  assert.equal(r.counts.actors, 2);
  assert.equal(r.counts.techniques, 1);
  assert.equal(r.counts.indicators, 1);
  assert.equal(r.counts.relationships, 1);
  assert.equal(r.actors[0].category, 'A');
  assert.equal(r.actors[1].category, 'B');
  assert.equal(r.actors[0].refs[0].id, 'G0001');
  assert.equal(r.actors[0].links[0].type, 'uses');
});

test('degrades cleanly on a missing or empty bundle', () => {
  assert.equal(parseAiCti({}).counts.objects, 0);
  assert.equal(parseAiCti(null).counts.objects, 0);
});
