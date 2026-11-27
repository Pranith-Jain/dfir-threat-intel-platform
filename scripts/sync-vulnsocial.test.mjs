/** Offline parser tests for the VulnSocial RSC decision mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { balancedObject, flightText, parseCvePage, parseHomeIds } from './sync-vulnsocial.mjs';

const DECISION = {
  shareUrl: 'https://vulnsocial.com/cve/CVE-2026-1001',
  totalMentions: 42,
  totalDays: 5,
  topClassification: 'Disclosure',
  summary: { vendors: ['oracle'], products: ['jdk'], versions: ['17.0.1'] },
  cvssScore: 9.8,
  cvssSeverity: 'CRITICAL',
  cvssSource: 'Oracle',
  inCisaKev: true,
  kevDueDate: '2026-12-01',
  hasActiveExploitation: true,
  hasExploitCode: true,
  hasPoc: true,
  hasPatch: true,
  slaWindow: '< 24 hours',
  urgencyLabel: 'Emergency',
  directive: 'Patch immediately.',
  pocUrls: ['https://github.com/x/poc'],
  patchUrls: ['https://example.com/patch'],
};

/** Build a minimal RSC flight stream with one decision object. */
function page(cveId, decision = DECISION, plain = null) {
  const decisionProps = JSON.stringify({ variant: 'inline', cveId, ...decision }).slice(1, -1);
  const flight = [`["$","div",null,{"children":${JSON.stringify(plain)}}]`, `["$","$L1",null,{${decisionProps}}]`].join('');
  return `<script>self.__next_f.push([1,${JSON.stringify(flight)}]);</script>`;
}

test('flightText and balancedObject extract structured data without executing code', () => {
  const text = flightText(page('CVE-2026-1001'));
  assert.match(text, /CVE-2026-1001/);
  const at = text.lastIndexOf('{', text.indexOf('"cveId":"CVE-2026-1001"'));
  const obj = balancedObject(text, at);
  assert.equal(obj.cveId, 'CVE-2026-1001');
  assert.equal(obj.totalMentions, 42);
  assert.equal(balancedObject('{not json', 0), null);
});

test('parseCvePage maps the decision object and plain-English brief', () => {
  const body = parseCvePage(page('CVE-2026-1001', DECISION, 'Severity: Critical. Impact: RCE.'), 'CVE-2026-1001');
  assert.ok(body);
  assert.equal(body.urgency, 'Emergency');
  assert.equal(body.sla, '< 24 hours');
  assert.equal(body.inKev, true);
  assert.equal(body.activeExploitation, true);
  assert.equal(body.plainEnglish, 'Severity: Critical. Impact: RCE.');
  assert.deepEqual(body.vendors, ['oracle']);
  assert.equal(body.pocUrls[0], 'https://github.com/x/poc');
  assert.equal(body.directive, 'Patch immediately.');
});

test('parseCvePage returns null when the page has no matching decision', () => {
  assert.equal(parseCvePage('<html></html>', 'CVE-2026-1001'), null);
  assert.equal(parseCvePage(page('CVE-2026-1001'), 'CVE-2026-1002'), null);
});

test('parseHomeIds deduplicates CVE ids from the radar RSC', () => {
  const html =
    'self.__next_f.push([1,"CVE-2026-1001 and CVE-2026-1002"]);\n' +
    'self.__next_f.push([1,"CVE-2026-1001 again"]);';
  assert.deepEqual(parseHomeIds(html).sort(), ['CVE-2026-1001', 'CVE-2026-1002']);
});
