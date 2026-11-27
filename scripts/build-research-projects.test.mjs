/** Offline tests for the metadata-only research-projects mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { headingsFrom } from './build-research-projects.mjs';

test('headingsFrom keeps public structure without body prose', () => {
  const md = '# Grid-STIX\n## Key Features\n- 230 classes\n### Details\nBody text here.\n';
  assert.deepEqual(headingsFrom(md), ['Grid-STIX', 'Key Features', 'Details']);
});

test('headingsFrom degrades on empty input', () => {
  assert.deepEqual(headingsFrom(''), []);
  assert.deepEqual(headingsFrom(null), []);
});
