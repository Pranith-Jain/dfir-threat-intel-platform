import { describe, it, expect } from 'vitest';
import { snapshotDossier, renderFactsSnapshot, type ResearchDossier } from '../../../src/case-study/research/dossier';
import type { CveFacts } from '../../../src/case-study/research/enrich';

/**
 * The persisted research snapshot is what lets social copy generated AFTER
 * publish cite the same exact facts the article was written from. Before it
 * existed, `postToSource` handed the LinkedIn/X prompts only the article
 * body, so affected versions and CVSS numbers were paraphrased or dropped.
 *
 * Fixtures are synthetic (CVE-2099-*) so they never rot against real NVD
 * record amendments.
 */

const SYNTHETIC_CVE = 'CVE-2099-0001';
const EXACT_RANGE = 'examplecorp edge gateway: >= 4.2 and < 4.6';

const cve: CveFacts = {
  id: SYNTHETIC_CVE,
  description: 'A synthetic fixture vulnerability used by tests.',
  published: '2026-08-01T00:00:00.000Z',
  cvss: {
    version: '3.1',
    base_score: 9.8,
    severity: 'CRITICAL',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  },
  cwe: ['CWE-287'],
  products: ['examplecorp edge gateway'],
  affectedVersions: [EXACT_RANGE],
  kev: { in_kev: true, date_added: '2026-08-05', due_date: '2026-08-26' },
  references: [`https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}`],
};

const dossier: ResearchDossier = {
  subject: `${SYNTHETIC_CVE} — synthetic vendor auth bypass`,
  cves: [cve],
  pages: [
    {
      url: 'https://blog.talosintelligence.com/vuln/synthetic-fixture',
      ok: true,
      status: 200,
      title: 'Synthetic vendor patches an authentication bypass',
      publisher: 'blog.talosintelligence.com',
      publishedAt: '2026-08-06',
      text: 'This excerpt text lives only in the live dossier, never the snapshot.',
    },
  ],
  platform: { writeups: [], relatedCves: [], trendingCves: [], actors: [], victimClaims: [] },
  timeline: [{ date: '2026-08-05', event: 'Added to CISA KEV' }],
  indicators: [{ type: 'ipv4', values: ['203.0.113.10'], total: 1 }],
  entities: { vendors: ['examplecorp'], products: ['edge gateway'], actors: [], techniques: ['T1190'] },
  gaps: ['No tracked actor is associated with this topic.'],
  unread: [],
  meta: { pagesFetched: 1, pagesRead: 1, cvesEnriched: 1, tookMs: 120 },
};

describe('snapshotDossier', () => {
  it('keeps the structured facts and drops the page excerpts', () => {
    const snap = snapshotDossier(dossier);
    expect(snap.cves[0]?.affectedVersions).toEqual([EXACT_RANGE]);
    expect(snap.timeline).toEqual(dossier.timeline);
    expect(snap.entities.vendors).toEqual(['examplecorp']);
    expect(snap.gaps).toEqual(dossier.gaps);
    // Page text and build metadata are the bulky parts and are not needed —
    // social copy works from the facts, not the excerpts.
    expect(snap).not.toHaveProperty('pages');
    expect(snap).not.toHaveProperty('meta');
    expect(snap).not.toHaveProperty('unread');
  });
});

describe('renderFactsSnapshot', () => {
  it('renders the exact affected-versions line the article dossier uses', () => {
    const out = renderFactsSnapshot(snapshotDossier(dossier));
    expect(out).toContain(`- Affected versions (exact, from NVD): ${EXACT_RANGE}`);
    expect(out).toContain('CVSS 3.1: 9.8 CRITICAL');
    expect(out).toContain('IN CISA KEV');
    expect(out).toContain('Added to CISA KEV');
    expect(out).toContain('No tracked actor is associated with this topic.');
  });

  it('never leaks page excerpts into the snapshot render', () => {
    const out = renderFactsSnapshot(snapshotDossier(dossier));
    expect(out).not.toContain('This excerpt text lives only in the live dossier');
  });

  it('truncates at the budget with a marker', () => {
    const out = renderFactsSnapshot(snapshotDossier(dossier), { budget: 200 });
    expect(out.endsWith('[research snapshot truncated]')).toBe(true);
    expect(out.length).toBeLessThanOrEqual(200 + '\n[research snapshot truncated]'.length);
  });
});

describe('renderFactsSnapshot — family-aware facts', () => {
  const releakDossier: ResearchDossier = {
    ...dossier,
    type: 'darkweb',
    cves: [],
    claims: [
      { label: 'Claimed victim', value: 'Example Medical Group' },
      { label: 'Groups making the claim', value: 'ExampleGroupA, ExampleGroupB' },
      { label: 'Distinct groups claiming', value: '2' },
      { label: 'Sector', value: 'healthcare' },
    ],
  };

  it('renders discovery claims as the verified facts for underground topics', () => {
    const out = renderFactsSnapshot(snapshotDossier(releakDossier));
    expect(out).toContain('=== VERIFIED FACTS (from the discovery evidence) ===');
    expect(out).toContain('- Claimed victim: Example Medical Group');
    expect(out).toContain('- Groups making the claim: ExampleGroupA, ExampleGroupB');
  });

  it('never shows the CVE-apology placeholder for underground topics', () => {
    const out = renderFactsSnapshot(snapshotDossier(releakDossier));
    expect(out).not.toContain('(no CVE could be resolved for this topic)');
  });

  it('keeps the CVE-led facts block for vulnerability topics', () => {
    const out = renderFactsSnapshot(snapshotDossier({ ...dossier, type: 'cve' }));
    expect(out).toContain('=== VERIFIED FACTS (authoritative: NVD, CISA KEV, FIRST EPSS, CISA ADP) ===');
    expect(out).toContain(SYNTHETIC_CVE);
  });

  it('carries the type into the snapshot', () => {
    expect(snapshotDossier(releakDossier).type).toBe('darkweb');
    expect(snapshotDossier(releakDossier).claims?.length).toBe(4);
  });
});
