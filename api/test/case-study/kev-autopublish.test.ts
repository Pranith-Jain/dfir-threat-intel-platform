import { describe, it, expect } from 'vitest';
import {
  buildKevCandidate,
  fetchKevAdditions,
  formatKevTitle,
  isKevPublishEligible,
  selectKevBatch,
  KEV_AUTOPUBLISH_MAX_PER_TICK,
} from '../../src/case-study/kev-autopublish';
import type { Candidate, DedupRecord } from '../../src/case-study/types';

/**
 * The KEV auto-publish rules.
 *
 * This path publishes without a human in the loop, so the rules that stop it
 * from double-posting or flooding are the whole safety story. They are pinned
 * here: an off-by-one in the republish window or a missing eligibility filter
 * is an irreversible public duplicate.
 */

const NOW = new Date('2026-10-19T12:00:00Z');

function kevEntry(over: Record<string, unknown> = {}) {
  return {
    cveID: 'CVE-2026-12345',
    vendorProject: 'Acme',
    product: 'Edge Gateway',
    vulnerabilityName: 'Acme Edge Gateway OS Command Injection Vulnerability',
    dateAdded: '2026-10-19',
    shortDescription: 'Acme Edge Gateway contains an OS command injection vulnerability.',
    knownRansomwareCampaignUse: 'Unknown',
    ...over,
  };
}

function candidate(over: Partial<Candidate> = {}): Candidate {
  return {
    key: 'cve-2026-12345',
    type: 'cve',
    title: 'CVE-2026-12345 — Acme Edge Gateway',
    rationale: '',
    score: 0.8,
    evidence: { cveId: 'CVE-2026-12345', kevAddedAt: '2026-10-19T00:00:00.000Z' },
    discoveredAt: NOW.toISOString(),
    status: 'pending',
    ...over,
  };
}

describe('formatKevTitle', () => {
  it('does not repeat the vendor when the KEV name already starts with it', () => {
    const title = formatKevTitle(kevEntry());
    expect(title).toBe('CVE-2026-12345 — Acme Edge Gateway OS Command Injection Vulnerability');
    expect(title.match(/Acme/g)).toHaveLength(1);
  });

  it('prepends vendor + product when the name carries neither', () => {
    expect(formatKevTitle(kevEntry({ vulnerabilityName: 'OS Command Injection', product: 'Gateway' }))).toBe(
      'CVE-2026-12345 — Acme Gateway OS Command Injection'
    );
  });
});

describe('isKevPublishEligible', () => {
  it('accepts an unknown key', () => {
    expect(isKevPublishEligible(null, NOW)).toBe(true);
  });

  it('rejects a key published inside the republish window', () => {
    const rec: DedupRecord = { lastSeenAt: '2026-10-01T00:00:00Z', publishedSlug: 'cve-2026-12345-post' };
    expect(isKevPublishEligible(rec, NOW)).toBe(false);
  });

  it('accepts a key last published outside the 30-day window', () => {
    const rec: DedupRecord = { lastSeenAt: '2026-08-01T00:00:00Z', publishedSlug: 'old-post' };
    expect(isKevPublishEligible(rec, NOW)).toBe(true);
  });

  it('honors an explicit suppression (the failure backoff path)', () => {
    const rec: DedupRecord = { lastSeenAt: '2026-10-19T00:00:00Z', suppressedUntil: '2026-10-20T00:00:00Z' };
    expect(isKevPublishEligible(rec, NOW)).toBe(false);
  });
});

describe('selectKevBatch', () => {
  it('caps the batch and takes the newest KEV addition first', () => {
    const older = candidate({
      key: 'cve-1',
      score: 0.99,
      evidence: { kevAddedAt: '2026-10-18T00:00:00.000Z' },
    });
    const newer = candidate({ key: 'cve-2', score: 0.5, evidence: { kevAddedAt: '2026-10-19T00:00:00.000Z' } });
    const newest = candidate({ key: 'cve-3', score: 0.1, evidence: { kevAddedAt: '2026-10-19T06:00:00.000Z' } });
    const batch = selectKevBatch([older, newer, newest], {}, NOW, 2);
    expect(batch.map((c) => c.key)).toEqual(['cve-3', 'cve-2']);
  });

  it('skips already-published keys even when they are the newest', () => {
    const published: DedupRecord = { lastSeenAt: '2026-10-19T05:00:00Z', publishedSlug: 'already-there' };
    const batch = selectKevBatch(
      [candidate({ key: 'cve-2' }), candidate({ key: 'cve-9' })],
      { 'cve-2': published },
      NOW,
      5
    );
    expect(batch.map((c) => c.key)).toEqual(['cve-9']);
  });

  it('returns nothing at a zero cap', () => {
    expect(selectKevBatch([candidate()], {}, NOW, 0)).toEqual([]);
  });

  it('defaults to the configured per-tick cap', () => {
    const many = Array.from({ length: 10 }, (_, i) =>
      candidate({ key: `cve-${i}`, score: 1 - i / 100, evidence: { kevAddedAt: NOW.toISOString() } })
    );
    expect(selectKevBatch(many, {}, NOW)).toHaveLength(KEV_AUTOPUBLISH_MAX_PER_TICK);
  });
});

describe('buildKevCandidate', () => {
  it('marks the origin so a post with no human approval is explainable in /admin', async () => {
    const c = await buildKevCandidate(kevEntry(), { now: NOW, getDedup: async () => null });
    expect(c.type).toBe('cve');
    expect(c.key).toBe('cve-2026-12345');
    expect(c.evidence).toMatchObject({
      cveId: 'CVE-2026-12345',
      kev: true,
      kevAutoPublish: true,
      ransomwareUse: false,
      urls: ['https://nvd.nist.gov/vuln/detail/CVE-2026-12345'],
    });
    expect(c.rationale).toContain('Auto-published');
  });

  it('merges NVD enrichment and survives an enrichment failure', async () => {
    const enriched = await buildKevCandidate(kevEntry(), {
      now: NOW,
      getDedup: async () => null,
      enrich: async () => ({ cvss: { score: 9.8, severity: 'CRITICAL' }, cwe: 'CWE-78' }),
    });
    expect(enriched.evidence.cvss).toEqual({ score: 9.8, severity: 'CRITICAL' });
    expect(enriched.evidence.cwe).toBe('CWE-78');

    const degraded = await buildKevCandidate(kevEntry(), {
      now: NOW,
      getDedup: async () => null,
      enrich: async () => {
        throw new Error('NVD rate limited');
      },
    });
    expect(degraded.evidence.cvss).toBeUndefined();
    expect(degraded.evidence.kev).toBe(true);
  });
});

describe('fetchKevAdditions', () => {
  // 48h BECAUSE `dateAdded` is date-only: at 12:00 on the 19th, an entry added
  // on the 18th parses to the 18th 00:00 and is already 36h old.
  it('keeps the current and previous calendar day, drops older', async () => {
    const fetchFn = (async () =>
      new Response(
        JSON.stringify({
          vulnerabilities: [
            kevEntry({ cveID: 'CVE-2026-1', dateAdded: '2026-10-19' }),
            kevEntry({ cveID: 'CVE-2026-2', dateAdded: '2026-10-18' }),
            kevEntry({ cveID: 'CVE-2026-3', dateAdded: '2026-09-01' }),
          ],
        }),
        { status: 200 }
      )) as unknown as typeof globalThis.fetch;

    const out = await fetchKevAdditions({ fetch: fetchFn, now: NOW });
    expect(out.map((e) => e.cveID)).toEqual(['CVE-2026-1', 'CVE-2026-2']);

    // A narrower window silently drops yesterday's additions — the bug the
    // 48h window exists to prevent.
    const tooNarrow = await fetchKevAdditions({ fetch: fetchFn, now: NOW, windowHours: 26 });
    expect(tooNarrow.map((e) => e.cveID)).toEqual(['CVE-2026-1']);
  });

  it('skips entries with an unparseable date instead of treating them as fresh', async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ vulnerabilities: [kevEntry({ dateAdded: '' })] }), {
        status: 200,
      })) as unknown as typeof globalThis.fetch;
    expect(await fetchKevAdditions({ fetch: fetchFn, now: NOW })).toEqual([]);
  });

  it('throws on an upstream error so the caller can log and skip the tick', async () => {
    const fetchFn = (async () => new Response('nope', { status: 503 })) as unknown as typeof globalThis.fetch;
    await expect(fetchKevAdditions({ fetch: fetchFn, now: NOW })).rejects.toThrow(/KEV feed 503/);
  });
});
