import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCvdHtml, summarise } from './sync-anthropic-glasswing.mjs';

/**
 * Fixtures mirror the real markup at red.anthropic.com/2026/cvd as of the last
 * sync. The `·` separators are HTML entities in the source, and the record body
 * nests a severity <span> and an <a> inside the meta span — both of which a
 * naive textContent split gets wrong, which is what these cases pin down.
 */

const RECORD = `<div class="card id-record" data-sev="low" data-discovered="2026-03-24" data-sev-cells="high|high|low">
  <a class="id-record-id" href="https://nvd.nist.gov/vuln/detail/CVE-2026-12340" rel="noopener noreferrer">CVE-2026-12340</a>
  <span class="id-record-meta">wolfssl/wolfssl &middot; heap-buffer-overflow &middot; <span class="sev-low">low</span> &middot; <a href="findings/ANT-2026-87DJGDRB.html">ANT-2026-87DJGDRB</a>
</span>
<span class="id-record-title">Heap-buffer-overflow in sha.c:733</span>  </div>`;

const CRITICAL = `<div class="card id-record" data-sev="critical" data-discovered="2026-04-19" data-sev-cells="critical|critical|critical">
  <a class="id-record-id" href="https://nvd.nist.gov/vuln/detail/CVE-2026-46633" rel="noopener noreferrer">CVE-2026-46633</a>
  <span class="id-record-meta">twigphp/twig &middot; code-injection &middot; <span class="sev-critical">critical</span> &middot; <a href="findings/ANT-2026-J3EVXWDY.html">ANT-2026-J3EVXWDY</a>
</span>
<span class="id-record-title">PHP code injection via single quote in template name</span>  </div>`;

test('extracts every field from a record card', () => {
  const [r] = parseCvdHtml(RECORD);
  assert.equal(r.cveId, 'CVE-2026-12340');
  assert.equal(r.findingId, 'ANT-2026-87DJGDRB');
  assert.equal(r.ecosystem, 'wolfssl/wolfssl');
  assert.equal(r.weakness, 'heap-buffer-overflow');
  assert.equal(r.severity, 'low');
  assert.equal(r.discoveredAt, '2026-03-24');
  assert.equal(r.title, 'Heap-buffer-overflow in sha.c:733');
  assert.equal(r.nvdUrl, 'https://nvd.nist.gov/vuln/detail/CVE-2026-12340');
});

test('absolutises the relative finding link', () => {
  const [r] = parseCvdHtml(RECORD);
  assert.equal(r.findingUrl, 'https://red.anthropic.com/2026/findings/ANT-2026-87DJGDRB.html');
});

test('does not let the nested severity span leak into ecosystem or weakness', () => {
  const [r] = parseCvdHtml(CRITICAL);
  assert.equal(r.ecosystem, 'twigphp/twig');
  assert.equal(r.weakness, 'code-injection');
  assert.ok(!r.ecosystem.includes('critical'));
  assert.ok(!r.weakness.includes('critical'));
});

test('handles both the entity and literal middot separators', () => {
  const literal = RECORD.replace(/&middot;/g, '·');
  assert.deepEqual(parseCvdHtml(literal), parseCvdHtml(RECORD));
});

test('parses multiple records', () => {
  const records = parseCvdHtml(`<div>${RECORD}${CRITICAL}</div>`);
  assert.equal(records.length, 2);
  assert.deepEqual(
    records.map((r) => r.cveId),
    ['CVE-2026-12340', 'CVE-2026-46633']
  );
});

test('skips a card with no CVE anchor rather than emitting a broken record', () => {
  const broken = `<div class="card id-record" data-sev="low"><span class="id-record-meta">x</span></div>`;
  assert.deepEqual(parseCvdHtml(broken), []);
});

test('returns an empty list for markup with no records', () => {
  assert.deepEqual(parseCvdHtml('<div class="id-record-list"></div>'), []);
  assert.deepEqual(parseCvdHtml(''), []);
});

test('degrades missing optional fields to null instead of throwing', () => {
  const sparse = `<div class="card id-record"><a class="id-record-id">CVE-2026-99999</a></div>`;
  const [r] = parseCvdHtml(sparse);
  assert.equal(r.cveId, 'CVE-2026-99999');
  assert.equal(r.findingId, null);
  assert.equal(r.ecosystem, null);
  assert.equal(r.severity, null);
  assert.equal(r.discoveredAt, null);
});

test('summarise counts severities and ranks them by risk, not alphabetically', () => {
  const s = summarise(parseCvdHtml(RECORD + CRITICAL));
  assert.equal(s.total, 2);
  assert.deepEqual(
    s.severityRanked.map((x) => x.id),
    ['critical', 'low']
  );
  assert.equal(s.earliestDiscovery, '2026-03-24');
});

test('summarise counts ecosystems per project, not per ecosystem string', () => {
  // twigphp/twig appears twice across different CVEs; it must be one project
  // with 2 findings, and it must not merge with a same-prefixed sibling.
  const retarget = (rec, project, cve) =>
    rec.replace(/wolfssl\/wolfssl/g, project).replace(/CVE-2026-12340/g, cve);
  const s = summarise(
    parseCvdHtml(retarget(RECORD, 'twigphp/twig', 'CVE-2026-00001') + retarget(RECORD, 'twigphp/twig', 'CVE-2026-00002'))
  );
  assert.equal(s.total, 2);
  assert.equal(s.topEcosystems[0].id, 'twigphp');
  assert.equal(s.topEcosystems[0].findings, 2);
  assert.equal(s.ecosystemCount, 1);
});

test('summarise handles an empty dataset without dividing by zero', () => {
  const s = summarise([]);
  assert.equal(s.total, 0);
  assert.equal(s.ecosystemCount, 0);
  assert.equal(s.earliestDiscovery, null);
});